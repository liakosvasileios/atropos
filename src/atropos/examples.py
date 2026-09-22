"""Worked fixtures for the two motivating workflows.

Design v0.2 section 1.2 names two workflows the tool must serve well.  These
build small, self-contained traces that exercise each of them end to end
without a target process, so ``atropos demo`` works immediately after install
and so the regression suite has something meaningful to assert against.

They are deliberately *small enough to check by hand*.  The value of a fixture
whose correct answer you cannot independently work out is close to zero.
"""

from __future__ import annotations

from pathlib import Path

from .testkit import MiniVM, Program, build_bundle

SRC = 0x0002_0000
DST = 0x0003_0000
KEY_BUF = 0x0004_0000


def xor_decoder(path) -> tuple:
    """The unpacking workflow, in miniature.

    A four-byte XOR decode loop.  The interesting property is that slicing one
    *output* byte must reach exactly one *input* byte plus the key — not the
    whole source buffer, and not the other three iterations.  Getting that
    right is the whole point of byte-granular shadow memory (section 5.3) and
    of last-writer run splitting (section 5.2).
    """
    program = Program()
    program.block("setup", [
        "mov rsi, 0x20000",   # source
        "mov rdi, 0x30000",   # destination
        "mov rcx, 4",         # count
        "mov dl, 0x5a",       # the key byte
    ])
    program.block("body", [
        "mov al, [rsi]",
        "xor al, dl",
        "mov [rdi], al",
        "inc rsi",
        "inc rdi",
        "dec rcx",
        "jnz -17",
    ])
    program.block("done", ["ret"])

    vm = MiniVM({SRC + i: 0x10 + i for i in range(4)})
    bundle, vm = build_bundle(
        path, program, ["setup"] + ["body"] * 4 + ["done"], vm=vm, marks={5: 1}
    )
    note = (
        "XOR decode loop, 4 iterations over [0x20000..0x20004) -> [0x30000..0x30004).\n"
        "Criterion: the third output byte, at the end of the run.\n"
        "Expected: 4 instructions in value mode (the key, the load, the xor, the\n"
        "store) and one input leaf — source byte 0x20002. The other three\n"
        "iterations and all the loop plumbing are correctly discarded."
    )
    return bundle, ("mark=1", ["mem=0x30002+1"]), note


def key_derivation(path) -> tuple:
    """The crypto workflow, in miniature.

    A key is built from two sources: a hardcoded constant and an environmental
    value delivered by an API (modelled with a ``source`` summary, section 4.5).
    Slicing the key buffer must find both and say which is which — that is the
    input report of section 9.4, and it is the actual deliverable for this
    workflow.  The listing of the arithmetic is secondary.
    """
    program = Program()
    program.block("prologue", [
        "mov rbx, 0x40000",      # where the key will live
        "mov r9, 0x40100",       # the API will write the volume serial here
        "mov rcx, 5",            # a rotation amount used by the mixer
    ])
    # A `source` summary stands in for GetVolumeInformationW writing 8 bytes.
    program.block("mix", [
        "mov rax, [r9]",         # environmental input
        "mov rdx, 0x9e3779b9",   # a hardcoded constant
        "xor rax, rdx",          # round 1
        "mov r8, rax",
        "shl rax, cl",
        "add rax, r8",           # round 2
        "mov [rbx], rax",        # the derived key
    ])
    program.block("use", ["ret"])

    vm = MiniVM({KEY_BUF + 0x100 + i: 0xC0 + i for i in range(8)})

    bundle, vm = build_bundle(
        path,
        program,
        ["prologue", "mix", "use"],
        vm=vm,
        # GetVolumeInformationW(id=21) writes 8 bytes at arg1 before "mix" runs.
        summaries=[(1, 21, [0, KEY_BUF + 0x100, 0, 0])],
        marks={2: 1},
    )
    note = (
        "Key derivation: key = f(volume serial from GetVolumeInformationW,\n"
        "hardcoded 0x9e3779b9). Criterion: the 8-byte key buffer at 0x40000.\n"
        "Expected: the derivation chain, with the API summary appearing as a\n"
        "source leaf — which is the answer the analyst actually wanted."
    )
    return bundle, ("mark=1", [f"mem=0x{KEY_BUF:x}+8"]), note


def self_modifying(path) -> tuple:
    """A packer-shaped fixture: the same address, two different instructions.

    Exercises the code-version keying of section 4.6.  If code were keyed by
    address alone, the second execution would be decoded with the first
    version's semantics and the slice would be quietly wrong — with no error
    and no way for the analyst to notice.
    """
    program = Program(base_address=0x1400_2000)
    program.block("v0_stub", ["mov rax, 0x1111", "ret"])
    program.block("v1_stub", ["mov rbx, 0x2222", "ret"])
    # Place the second block at the *same* address as the first, as a rewrite
    # would.  The bundle records both, under different code versions.
    program.by_name("v1_stub").address = program.by_name("v0_stub").address

    from .bundle import BundleWriter, TraceBundle
    from .format import TAG_VERSION

    writer = BundleWriter(
        path,
        meta={
            "capture": {"agent": "examples.self_modifying"},
            "modules": [{
                "name": "packed.exe", "base": 0x1400_2000, "size": 0x1000,
                "path": "C:\\fixtures\\packed.exe",
            }],
        },
    )
    v0 = writer.add_block(0, 0x1400_2000, program.by_name("v0_stub").raw)
    v1 = writer.add_block(1, 0x1400_2000, program.by_name("v1_stub").raw)

    writer.emit_block(v0)
    writer.emit_mem(1, 0x7FFF_0000, 8, 1)  # the ret's stack read
    writer.emit(TAG_VERSION, 1)
    writer.emit_block(v1)
    writer.emit_mem(1, 0x7FFF_0000, 8, 1)
    writer.close()

    bundle = TraceBundle(writer.path)
    note = (
        "Self-modifying stub: address 0x140002000 holds `mov rax, 0x1111` under\n"
        "code version 0 and `mov rbx, 0x2222` under version 1.\n"
        "Expected: both decode correctly, and `atropos info` reports the version\n"
        "change. Keyed by address alone, the second would decode as the first."
    )
    return bundle, ("seq=2", ["rbx"]), note


WORKFLOWS = {
    "xor-decoder": xor_decoder,
    "key-derivation": key_derivation,
    "self-modifying": self_modifying,
}
