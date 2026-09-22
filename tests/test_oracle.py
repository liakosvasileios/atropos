"""Differential tests against the independent oracle (design v0.2 section 11.2).

The effect model and the oracle share nothing but the fixture text.  Where they
disagree, one of them is wrong — and finding out which is far easier than
noticing, months later, that a slice was quietly missing an instruction.

The fuzzing loop is the point.  Hand-written fixtures catch the bugs you thought
of; randomly generated instruction sequences catch the ones you did not, which
is the category every bug in section 6 belongs to.
"""

from __future__ import annotations

import random

import pytest

from atropos.arch import lanes as L
from atropos.ddg import SPACE_MEM, SPACE_REG
from atropos.oracle import differential_check, random_program

RAX = (SPACE_REG, L.lookup("rax").lane, 8)
DST = (SPACE_MEM, 0x30000, 8)


def _memory():
    return {0x20000 + i: (i * 7) & 0xFF for i in range(64)}


def test_oracle_agrees_on_a_straight_line_chain(tmp_path):
    from atropos.testkit import Program

    program = Program()
    program.block("main", [
        "mov rax, 5",
        "mov rbx, 7",
        "add rax, rbx",
        "mov rdi, 0x30000",
        "mov [rdi], rax",
    ])
    expected, actual = differential_check(
        program, ["main"], DST, tmp_path / "a.atrace", memory=_memory()
    )
    assert expected == actual


def test_oracle_agrees_on_the_zeroing_idiom(tmp_path):
    """The idiom must cut the chain in *both* implementations.

    If the model's override were missing, its slice would include the earlier
    `mov rax` and the oracle's would not — which is exactly the signal wanted.
    """
    from atropos.testkit import Program

    program = Program()
    program.block("main", [
        "mov rax, 0x1234",
        "xor rax, rax",
        "mov rdi, 0x30000",
        "mov [rdi], rax",
    ])
    expected, actual = differential_check(
        program, ["main"], DST, tmp_path / "b.atrace", memory=_memory()
    )
    assert expected == actual


def test_oracle_agrees_on_sub_register_writes(tmp_path):
    from atropos.testkit import Program

    program = Program()
    program.block("main", [
        "mov rax, 0x1122334455667788",
        "mov al, 0x99",
        "mov ah, 0x88",
        "mov rdi, 0x30000",
        "mov [rdi], rax",
    ])
    expected, actual = differential_check(
        program, ["main"], DST, tmp_path / "c.atrace", memory=_memory()
    )
    assert expected == actual


def test_oracle_agrees_on_a_zero_count_shift(tmp_path):
    from atropos.testkit import Program

    program = Program()
    program.block("main", [
        "mov rcx, 0",
        "mov rax, 0x1234",
        "shl rax, cl",
        "mov rdi, 0x30000",
        "mov [rdi], rax",
    ])
    expected, actual = differential_check(
        program, ["main"], DST, tmp_path / "d.atrace", memory=_memory()
    )
    assert expected == actual


def test_oracle_agrees_on_lea(tmp_path):
    from atropos.testkit import Program

    program = Program()
    program.block("main", [
        "mov rsi, 0x20000",
        "mov rbx, 4",
        "lea rax, [rsi + rbx*8]",
        "mov rdi, 0x30000",
        "mov [rdi], rax",
    ])
    expected, actual = differential_check(
        program, ["main"], DST, tmp_path / "e.atrace", memory=_memory()
    )
    assert expected == actual


@pytest.mark.parametrize("seed", range(40))
def test_differential_fuzz(seed, tmp_path):
    """Random straight-line programs must slice identically both ways.

    Forty seeds in the default run keeps CI fast; the same function with a
    wider range is the soak test.  Straight-line on purpose — control
    dependence has its own tests, and mixing them would make a failure
    ambiguous about which subsystem broke.
    """
    rng = random.Random(seed)
    program, order = random_program(rng, length=20)
    expected, actual = differential_check(
        program, order, DST, tmp_path / f"fuzz{seed}.atrace", memory=_memory()
    )
    assert expected == actual, (
        f"seed {seed}: model and oracle disagree\n"
        f"  only in oracle: {sorted(expected - actual)}\n"
        f"  only in model:  {sorted(actual - expected)}"
    )
