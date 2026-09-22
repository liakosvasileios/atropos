"""Replay tests: the last-writer relation over registers, flags and memory."""

from __future__ import annotations

import pytest

from atropos import analyse, backward_slice, build_criterion, MODES
from atropos.arch import lanes as L
from atropos.ddg import SPACE_MEM, SPACE_REG
from atropos.shadow import LIVE_IN
from atropos.testkit import MiniVM, Program, build_bundle


def slice_of(tmp_path, source, order, locations, at=None, mode="value", memory=None,
             blocks=None):
    program = Program()
    if blocks:
        for name, lines in blocks:
            program.block(name, lines)
    else:
        program.block("main", source)
    vm = MiniVM(dict(memory or {}))
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, order, vm=vm)
    analysis = analyse(bundle)
    point = at or f"seq={analysis.ddg.n_nodes - 1}"
    criterion = build_criterion(point, locations, analysis.result)
    return analysis, backward_slice(analysis.result, criterion, MODES[mode]), vm


# --------------------------------------------------------------------------
# The worked example from design v0.2 section 6.2
# --------------------------------------------------------------------------


def test_byte_lane_worked_example(tmp_path):
    """Slicing AL after `add al, ah` must include `mov ah` and exclude noise.

    This is the example the design document uses to justify byte lanes, so it
    is the one that must hold: get the model wrong and you either drop the
    `mov ah` (treating AH as part of AL's write) or drag in unrelated
    instructions (treating a 32-bit write as touching only four lanes).
    """
    analysis, result, _ = slice_of(
        tmp_path,
        [
            "mov eax, 0x10",   # defines RAX[0..7]
            "mov ah, 0x20",    # defines RAX[1] only
            "add al, ah",      # uses RAX[0] and RAX[1]
            "mov ebx, 0x99",   # pure noise
            "ret",
        ],
        ["main"],
        ["al"],
        at="seq=2",
    )
    assert result.nodes == [0, 1, 2]


def test_upper_lanes_of_a_32bit_write_are_not_a_dependence(tmp_path):
    """Slicing AH must not pull in an instruction that only wrote AL."""
    analysis, result, _ = slice_of(
        tmp_path,
        ["mov eax, 0x10", "mov al, 0x01", "mov bl, ah", "ret"],
        ["main"],
        ["bl"],
        at="seq=2",
    )
    # `mov al` writes lane 0; AH is lane 1, still owned by `mov eax`.
    assert result.nodes == [0, 2]


# --------------------------------------------------------------------------
# Multi-writer run splitting (section 5.2)
# --------------------------------------------------------------------------


def test_a_multibyte_read_has_multiple_defs(tmp_path):
    """A qword read of a byte-wise-built buffer must reach every writer.

    v0.1's `last_writer_at()` returned a single definition.  Under the byte-lane
    model that is not merely imprecise, it silently drops real contributors —
    which is exactly what a byte-wise decode loop produces.
    """
    program = Program()
    program.block("main", [
        "mov rdi, 0x30000",
        "mov al, 0x11",
        "mov [rdi], al",
        "mov rbx, 0x30001",
        "mov al, 0x22",
        "mov [rbx], al",
        "mov rdx, [rdi]",      # reads both bytes, plus six unwritten ones
        "ret",
    ])
    vm = MiniVM()
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=vm)
    analysis = analyse(bundle)

    edges = analysis.ddg.edges_of(6)  # the qword load
    mem_edges = [e for e in edges if e.space == SPACE_MEM]
    # Three runs: byte 0 from seq 2, byte 1 from seq 5, bytes 2..7 live-in.
    assert len(mem_edges) == 3
    assert [(e.def_seq, e.length) for e in mem_edges] == [(2, 1), (5, 1), (LIVE_IN, 6)]


def test_partial_overwrite_is_exact(tmp_path):
    """A 1-byte store over the middle of an 8-byte store splits the read."""
    program = Program()
    program.block("main", [
        "mov rdi, 0x30000",
        "mov rax, 0x1122334455667788",
        "mov [rdi], rax",
        "mov rbx, 0x30003",
        "mov al, 0xff",
        "mov [rbx], al",
        "mov rdx, [rdi]",
        "ret",
    ])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    mem_edges = [e for e in analysis.ddg.edges_of(6) if e.space == SPACE_MEM]
    assert [(e.def_seq, e.loc - 0x30000, e.length) for e in mem_edges] == [
        (2, 0, 3), (5, 3, 1), (2, 4, 4)
    ]


# --------------------------------------------------------------------------
# Memory (section 5.3)
# --------------------------------------------------------------------------


def test_decode_loop_isolates_one_output_byte(tmp_path):
    """Slicing output byte 2 reaches input byte 2 and the key — nothing else.

    Four iterations run; three are discarded.  This is the unpacking workflow
    reduced to its essentials, and it only works because shadow memory is
    byte-granular and effective addresses are concrete.
    """
    program = Program()
    program.block("setup", [
        "mov rsi, 0x20000", "mov rdi, 0x30000", "mov rcx, 4", "mov dl, 0x5a",
    ])
    program.block("body", [
        "mov al, [rsi]", "xor al, dl", "mov [rdi], al",
        "inc rsi", "inc rdi", "dec rcx", "jnz -17",
    ])
    program.block("done", ["ret"])

    vm = MiniVM({0x20000 + i: 0x10 + i for i in range(4)})
    bundle, vm = build_bundle(
        tmp_path / "run.atrace", program, ["setup"] + ["body"] * 4 + ["done"], vm=vm
    )
    analysis = analyse(bundle)
    criterion = build_criterion(
        f"seq={analysis.ddg.n_nodes - 1}", ["mem=0x30002+1"], analysis.result
    )
    result = backward_slice(analysis.result, criterion, MODES["value"])

    assert len(result.nodes) == 4
    assert len(result.inputs) == 1
    leaf = result.inputs[0]
    assert leaf.space == SPACE_MEM and leaf.loc == 0x20002 and leaf.length == 1

    # The decoded output is what the VM actually computed.
    assert vm.mem[0x30002] == (0x12 ^ 0x5A)


def test_address_edges_are_separable_from_value_edges(tmp_path):
    """Value mode must not drag in the pointer arithmetic; addr mode must.

    Without this split, RSP and every induction variable become universal
    attractors and the slice fills with plumbing (design v0.2 section 5.4).
    """
    program = Program()
    program.block("setup", ["mov rsi, 0x20000", "mov rdi, 0x30000"])
    program.block("body", ["mov rax, [rsi]", "mov [rdi], rax", "ret"])
    vm = MiniVM({0x20000 + i: i for i in range(8)})
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["setup", "body"], vm=vm)
    analysis = analyse(bundle)

    criterion = build_criterion(
        f"seq={analysis.ddg.n_nodes - 1}", ["mem=0x30000+8"], analysis.result
    )
    value_only = backward_slice(analysis.result, criterion, MODES["value"])
    with_addr = backward_slice(analysis.result, criterion, MODES["value+addr"])

    assert len(with_addr.nodes) > len(value_only.nodes)
    # `mov rsi, ...` is pointer setup: address mode reaches it, value mode does not.
    assert 0 not in value_only.nodes
    assert 0 in with_addr.nodes


# --------------------------------------------------------------------------
# Idioms, in the replay rather than the model
# --------------------------------------------------------------------------


def test_zeroing_xor_cuts_the_chain(tmp_path):
    """After `xor rax, rax`, nothing upstream of RAX is in the slice."""
    analysis, result, _ = slice_of(
        tmp_path,
        ["mov rax, 0x1234", "xor rax, rax", "mov rbx, rax", "ret"],
        ["main"],
        ["rbx"],
        at="seq=2",
    )
    assert result.nodes == [1, 2]


def test_lea_is_not_a_memory_access(tmp_path):
    """`lea` contributes value edges on its base and index, and no MEM record.

    If the model thought `lea` accessed memory, the integrity checker would
    fire on a count mismatch — so this test also pins the agent/host contract.
    """
    program = Program()
    program.block("main", ["mov rax, 0x100", "mov rbx, 0x2", "lea rdx, [rax + rbx*4]", "ret"])
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    assert analysis.integrity.n_errors == 0
    assert vm.regs["rdx"] == 0x100 + 2 * 4

    criterion = build_criterion("seq=2", ["rdx"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    assert result.nodes == [0, 1, 2]


# --------------------------------------------------------------------------
# Value-dependent flags (section 6.7)
# --------------------------------------------------------------------------


def test_zero_count_shift_defines_nothing(tmp_path):
    """`shl rax, cl` with CL = 0 must not become RAX's last writer.

    Recording a def here inserts a phantom hop: the slice would show the shift
    as producing a value it demonstrably did not touch.
    """
    program = Program()
    program.block("main", [
        "mov rcx, 0",
        "mov rax, 0x1234",
        "shl rax, cl",     # count 0: no destination write, no flag write
        "mov rbx, rax",
        "ret",
    ])
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    assert analysis.result.stats["shift_zero_count"] == 1
    assert vm.regs["rbx"] == 0x1234

    criterion = build_criterion("seq=3", ["rbx"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    assert 2 not in result.nodes, "the zero-count shift should not be in the slice"
    assert 1 in result.nodes


def test_nonzero_count_shift_is_in_the_chain(tmp_path):
    program = Program()
    program.block("main", [
        "mov rcx, 4", "mov rax, 0x1234", "shl rax, cl", "mov rbx, rax", "ret",
    ])
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    assert vm.regs["rbx"] == 0x1234 << 4
    criterion = build_criterion("seq=3", ["rbx"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    assert {1, 2, 3}.issubset(result.nodes)


# --------------------------------------------------------------------------
# rep (section 6.6)
# --------------------------------------------------------------------------


def test_rep_movsb_is_one_bulk_node(tmp_path):
    """A `rep movsb` copying 8 bytes is one node defining an 8-byte range."""
    program = Program()
    program.block("main", [
        "mov rsi, 0x20000", "mov rdi, 0x30000", "mov rcx, 8",
        "rep_movsb",
        "mov rax, [rdi]",
        "ret",
    ])
    vm = MiniVM({0x20000 + i: 0xA0 + i for i in range(8)})
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=vm)
    analysis = analyse(bundle)

    assert analysis.result.stats["rep_bulk"] == 1
    assert [b for b in analysis.ddg.defs_of(3) if b[0] == SPACE_MEM] == [
        (SPACE_MEM, 0x30000, 8)
    ]
    assert analysis.integrity.n_errors == 0
    assert [vm.mem[0x30000 + i] for i in range(8)] == [0xA0 + i for i in range(8)]


def test_rep_with_zero_count_does_nothing(tmp_path):
    """`rep` with RCX = 0 executes no iterations and defines nothing.

    Emitting defs for RSI/RDI/RCX here would make this instruction their last
    writer and break every chain that runs through them.
    """
    program = Program()
    program.block("main", [
        "mov rsi, 0x20000", "mov rdi, 0x30000", "mov rcx, 0", "rep_movsb", "ret",
    ])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    assert analysis.ddg.defs_of(3) == []


# --------------------------------------------------------------------------
# Read-before-write ordering (invariant 3)
# --------------------------------------------------------------------------


def test_read_modify_write_reads_the_previous_value(tmp_path):
    """`add [mem], rax` must depend on the prior writer of that memory."""
    program = Program()
    program.block("main", [
        "mov rdi, 0x30000",
        "mov rax, 5",
        "mov [rdi], rax",     # seq 2 writes the memory
        "mov rbx, 7",
        "add [rdi], rbx",     # seq 4 reads it, then writes it
        "ret",
    ])
    bundle, vm = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    mem_edges = [e for e in analysis.ddg.edges_of(4) if e.space == SPACE_MEM]
    assert [e.def_seq for e in mem_edges] == [2]
    assert vm.read(0x30000, 8) == 12
