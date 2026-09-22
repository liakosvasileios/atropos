"""A second, independent slicer — the differential oracle.

Design v0.2 section 11.2.  The problem this solves: the effect model
(:mod:`atropos.arch.effects`) is intricate, and every bug in it produces a
*plausible* slice rather than an error.  Reviewing hand-written assembly
fixtures catches the bugs you thought of.  It does not catch the ones you did
not, which are the ones that matter.

So there are two implementations:

* the real one — Capstone plus an override table, driven by a captured trace;
* this one — the fixture's own source text, walked line by line, with the
  read/write sets written out longhand from the Intel manual.

They share nothing but the fixture.  This one is deliberately slow, small, and
stupid; its only job is to be *obviously* correct by inspection.  Where they
disagree, the disagreement is a bug in one of them, and finding out which is
much easier than noticing that a slice was subtly wrong.

:func:`differential_check` is the assertion; :func:`random_program` generates
fixtures for the fuzzing loop of section 11.2.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .arch import lanes as L
from .ddg import SPACE_MEM, SPACE_REG
from .shadow import LIVE_IN
from .testkit import ALU_OPCODES, MiniVM, Program, REG8, REG32, REG64, _is_imm, _parse_mem

LIVE = LIVE_IN


@dataclass
class OracleTrace:
    """Per-step read and write sets, computed from first principles."""

    reads: list[list[tuple[int, int, int]]] = field(default_factory=list)
    writes: list[list[tuple[int, int, int]]] = field(default_factory=list)
    text: list[str] = field(default_factory=list)


def _reg(name: str) -> tuple[int, int, int]:
    """Read/use footprint of a named register, as lanes."""
    slot = L.lookup(name)
    return (SPACE_REG, slot.lane, slot.size)


def _reg_def(name: str) -> tuple[int, int, int]:
    """Write footprint, applying the 32-bit zero-extension rule by hand."""
    slot = L.lookup(name)
    if slot.size == 4:  # a 32-bit write clears the top half of the register
        return (SPACE_REG, slot.parent_lane, slot.parent_size)
    return (SPACE_REG, slot.lane, slot.size)


def _flags(*names: str) -> list[tuple[int, int, int]]:
    return [(SPACE_REG, L.flag_lane(L.FLAG_NAMES.index(n)), 1) for n in names]


ARITH_FLAGS = ("CF", "PF", "AF", "ZF", "SF", "OF")


def run_oracle(program: Program, order: list[str], vm: MiniVM | None = None) -> tuple[OracleTrace, MiniVM]:
    """Execute the fixture, recording longhand read/write sets per step."""
    vm = vm or MiniVM()
    trace = OracleTrace()

    for name in order:
        block = program.by_name(name)
        for line in block.source:
            reads, writes = _effects_of(line, vm)
            trace.reads.append(reads)
            trace.writes.append(writes)
            trace.text.append(line)
            program._step(vm, line, 0, _NullRecord())
            vm.step += 1
    return trace, vm


class _NullRecord:
    """Absorbs the VM's memory-access log; the oracle recomputes it itself."""

    accesses: list = []
    reps: list = []
    shift_counts: list = []

    def __init__(self) -> None:
        self.accesses = []
        self.reps = []
        self.shift_counts = []


def _ea(vm: MiniVM, text: str) -> int | None:
    operand = _parse_mem(text)
    if operand is None:
        return None
    address = vm.get(operand.base) + operand.disp
    if operand.index:
        address += vm.get(operand.index) * operand.scale
    return address & 0xFFFFFFFFFFFFFFFF


def _addr_regs(text: str) -> list[tuple[int, int, int]]:
    """Registers that feed an effective-address computation.

    Atropos calls these *address* uses and tags them separately (design v0.2
    section 5.4); the oracle has no such notion and simply reports them as
    reads.  The differential comparison therefore runs in ``value+addr`` mode,
    where the two agree on the set of contributing instructions.
    """
    operand = _parse_mem(text)
    if operand is None:
        return []
    regs = [_reg(operand.base)]
    if operand.index:
        regs.append(_reg(operand.index))
    return regs


def _size_of(name: str) -> int:
    if name in REG64:
        return 8
    if name in REG32:
        return 4
    return 1


def _effects_of(line: str, vm: MiniVM):
    """The read and write sets of one instruction, written out longhand.

    Everything here is stated directly rather than derived: `mov` reads its
    source and writes its destination; `add` reads both operands, writes the
    destination and all six arithmetic flags; `lea` reads its base and index
    and touches neither memory nor flags.  That is the point — no shared logic
    with the model under test.
    """
    parts = line.strip().lower().split(None, 1)
    mnem = parts[0]
    ops = [p.strip() for p in parts[1].split(",")] if len(parts) > 1 else []

    reads: list[tuple[int, int, int]] = []
    writes: list[tuple[int, int, int]] = []

    if mnem == "mov":
        dst, src = ops
        address = _ea(vm, src)
        if address is not None:
            reads.extend(_addr_regs(src))
            reads.append((SPACE_MEM, address, _size_of(dst)))
            writes.append(_reg_def(dst))
            return reads, writes
        address = _ea(vm, dst)
        if address is not None:
            reads.extend(_addr_regs(dst))
            reads.append(_reg(src))
            writes.append((SPACE_MEM, address, _size_of(src)))
            return reads, writes
        if not _is_imm(src):
            reads.append(_reg(src))
        writes.append(_reg_def(dst))
        return reads, writes

    if mnem in ALU_OPCODES:
        dst, src = ops
        dst_address = _ea(vm, dst)
        if dst_address is not None:
            # Read-modify-write on memory.
            reads.extend(_addr_regs(dst))
            reads.append((SPACE_MEM, dst_address, 8))
            if not _is_imm(src):
                reads.append(_reg(src))
            if mnem != "cmp":
                writes.append((SPACE_MEM, dst_address, 8))
            writes.extend(_flags(*ARITH_FLAGS))
            return reads, writes
        # `xor r, r` and `sub r, r` produce a constant regardless of the prior
        # value, so *neither* operand is read — not just the destination.
        zeroing = mnem in ("xor", "sub") and dst == src
        address = _ea(vm, src)
        if address is not None:
            reads.extend(_addr_regs(src))
            reads.append((SPACE_MEM, address, 8))
        elif not _is_imm(src) and not zeroing:
            reads.append(_reg(src))
        if not zeroing:
            reads.append(_reg(dst))
        if mnem != "cmp":
            writes.append(_reg_def(dst))
        writes.extend(_flags(*ARITH_FLAGS))
        return reads, writes

    if mnem in ("inc", "dec"):
        reads.append(_reg(ops[0]))
        writes.append(_reg_def(ops[0]))
        writes.extend(_flags("PF", "AF", "ZF", "SF", "OF"))  # inc/dec leave CF
        return reads, writes

    if mnem == "test":
        reads.append(_reg(ops[0]))
        reads.append(_reg(ops[1]))
        writes.extend(_flags(*ARITH_FLAGS))
        return reads, writes

    if mnem == "lea":
        dst, src = ops
        operand = _parse_mem(src)
        reads.append(_reg(operand.base))
        if operand.index:
            reads.append(_reg(operand.index))
        writes.append(_reg_def(dst))
        return reads, writes  # no memory access, no flags

    if mnem in ("shl", "shr"):
        dst = ops[0]
        count = vm.get("cl") & 0x3F
        reads.append(_reg("cl"))
        reads.append(_reg(dst))
        if count:  # a zero count modifies neither destination nor flags
            writes.append(_reg_def(dst))
            writes.extend(_flags(*ARITH_FLAGS))
        return reads, writes

    if mnem == "push":
        reads.append(_reg(ops[0]))
        reads.append(_reg("rsp"))
        writes.append((SPACE_MEM, (vm.get("rsp") - 8) & 0xFFFFFFFFFFFFFFFF, 8))
        writes.append(_reg_def("rsp"))
        return reads, writes

    if mnem == "pop":
        reads.append(_reg("rsp"))
        reads.append((SPACE_MEM, vm.get("rsp"), 8))
        writes.append(_reg_def(ops[0]))
        writes.append(_reg_def("rsp"))
        return reads, writes

    if mnem == "ret":
        reads.append(_reg("rsp"))
        reads.append((SPACE_MEM, vm.get("rsp"), 8))
        writes.append(_reg_def("rsp"))
        return reads, writes

    if mnem in ("jz", "je", "jnz", "jne"):
        reads.extend(_flags("ZF"))
        return reads, writes

    if mnem in ("jmp", "nop"):
        return reads, writes

    raise NotImplementedError(f"oracle has no semantics for {line!r}")


# --------------------------------------------------------------------------
# Slicing, longhand
# --------------------------------------------------------------------------


def oracle_slice(trace: OracleTrace, step: int, location: tuple[int, int, int]) -> set[int]:
    """Backward slice by direct simulation of the last-writer relation."""
    last: dict[tuple[int, int], int] = {}
    reaching: list[set[int]] = []

    for index in range(len(trace.text)):
        producers: set[int] = set()
        for space, loc, length in trace.reads[index]:
            for byte in range(loc, loc + length):
                writer = last.get((space, byte))
                if writer is not None:
                    producers.add(writer)
        reaching.append(producers)
        for space, loc, length in trace.writes[index]:
            for byte in range(loc, loc + length):
                last[(space, byte)] = index

    # Seed: what reached `location` as of `step`.
    last = {}
    for index in range(min(step + 1, len(trace.text))):
        for space, loc, length in trace.writes[index]:
            for byte in range(loc, loc + length):
                last[(space, byte)] = index

    space, loc, length = location
    frontier = {
        last[(space, byte)]
        for byte in range(loc, loc + length)
        if (space, byte) in last
    }
    included: set[int] = set()
    while frontier:
        node = frontier.pop()
        if node in included:
            continue
        included.add(node)
        frontier |= reaching[node] - included
    return included


# --------------------------------------------------------------------------
# The differential assertion
# --------------------------------------------------------------------------


def differential_check(
    program: Program,
    order: list[str],
    criterion_location: tuple[int, int, int],
    tmp_path,
    memory: dict[int, int] | None = None,
) -> tuple[set[int], set[int]]:
    """Slice the same fixture both ways and return both node sets.

    The two agree on *step index* because the oracle executes exactly the same
    instruction sequence the bundle records, one node per instruction.
    """
    from .analysis import analyse
    from .criterion import Criterion, Location
    from .slicer import MODES, backward_slice
    from .testkit import build_bundle

    oracle_vm = MiniVM(dict(memory or {}))
    trace, _ = run_oracle(program, order, oracle_vm)
    last_step = len(trace.text) - 1
    expected = oracle_slice(trace, last_step, criterion_location)

    bundle_vm = MiniVM(dict(memory or {}))
    bundle, _ = build_bundle(tmp_path, program, order, vm=bundle_vm)
    analysis = analyse(bundle, skip_control=True)
    space, loc, length = criterion_location
    criterion = Criterion(
        seq=analysis.ddg.n_nodes - 1,
        locations=[Location(space, loc, length)],
        description="differential",
    )
    actual = set(
        backward_slice(analysis.result, criterion, MODES["value+addr"]).nodes
    )
    return expected, actual


# --------------------------------------------------------------------------
# Fixture generation for the fuzzing loop
# --------------------------------------------------------------------------

_SAFE_REGS = ["rax", "rbx", "rdx", "r8", "r9", "r10"]
_SAFE_8 = ["al", "bl", "dl", "ah", "bh", "dh"]


def random_program(rng: random.Random, length: int = 24) -> tuple[Program, list[str]]:
    """Generate a straight-line fixture over the modelled instruction subset.

    Straight-line on purpose: control dependence has its own tests, and mixing
    the two would make a failure ambiguous about which subsystem broke.
    """
    lines = ["mov rsi, 0x20000", "mov rdi, 0x30000", "mov rcx, 3"]
    for _ in range(length):
        choice = rng.randrange(8)
        dst = rng.choice(_SAFE_REGS)
        src = rng.choice(_SAFE_REGS)
        if choice == 0:
            lines.append(f"mov {dst}, {rng.randrange(0, 0x10000)}")
        elif choice == 1:
            lines.append(f"mov {dst}, {src}")
        elif choice == 2:
            lines.append(f"{rng.choice(['add', 'sub', 'xor', 'and', 'or'])} {dst}, {src}")
        elif choice == 3:
            lines.append(f"mov {rng.choice(_SAFE_8)}, {rng.randrange(0, 256)}")
        elif choice == 4:
            lines.append(f"mov {dst}, [rsi]")
        elif choice == 5:
            lines.append(f"mov [rdi], {src}")
        elif choice == 6:
            lines.append(f"lea {dst}, [rsi + {rng.choice(_SAFE_REGS[:3])}*{rng.choice([1,2,4,8])}]")
        else:
            lines.append(f"shl {dst}, cl")
    lines.append("mov [rdi], rax")

    program = Program()
    program.block("fuzz", lines)
    return program, ["fuzz"]
