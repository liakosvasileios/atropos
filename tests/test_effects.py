"""Effect-model tests: one per rule in design v0.2 section 6.

These are the tests that matter most.  Every rule below is a place where the
obvious implementation is wrong in a way that produces a plausible slice rather
than an error, so a passing slice is not evidence that any of them are right.
Only these assertions are.
"""

from __future__ import annotations

import pytest

from atropos.arch import lanes as L
from atropos.arch.effects import EffectModel


@pytest.fixture(scope="module")
def model():
    return EffectModel()


def uses(effects):
    return set(effects.reg_value_uses)


def addr_uses(effects):
    return set(effects.reg_addr_uses)


def defs(effects):
    return set(effects.reg_defs)


def lanes_of(name):
    slot = L.lookup(name)
    return (slot.lane, slot.size)


def parent_of(name):
    slot = L.lookup(name)
    return (slot.parent_lane, slot.parent_size)


# --------------------------------------------------------------------------
# 6.1  Sub-register aliasing and zero-extension
# --------------------------------------------------------------------------


def test_32bit_write_zero_extends_to_all_eight_lanes(model):
    """`mov eax, imm` defines RAX[0..7], not RAX[0..3].

    The top four bytes become a *defined* zero whose writer is this
    instruction.  Modelling only four lanes leaves the old writer in place for
    the top half, so a later 64-bit read of RAX picks up a stale dependence
    that the hardware demonstrably erased.
    """
    eff = model.effects_for(bytes.fromhex("b810000000"))  # mov eax, 0x10
    assert defs(eff) == {parent_of("rax")}


def test_8bit_write_preserves_upper_lanes(model):
    """`mov al, imm` defines exactly one lane."""
    eff = model.effects_for(bytes.fromhex("b001"))  # mov al, 1
    assert defs(eff) == {(L.lookup("rax").lane, 1)}


def test_16bit_write_preserves_upper_lanes(model):
    eff = model.effects_for(bytes.fromhex("6689c8"))  # mov ax, cx
    assert defs(eff) == {(L.lookup("rax").lane, 2)}
    assert uses(eff) == {(L.lookup("rcx").lane, 2)}


def test_ah_is_lane_one_and_independent_of_al(model):
    """AH must be RAX[1].  Fold it onto RAX[0] and `add al, ah` self-aliases."""
    eff = model.effects_for(bytes.fromhex("88e0"))  # mov al, ah
    assert defs(eff) == {(L.lookup("rax").lane + 0, 1)}
    assert uses(eff) == {(L.lookup("rax").lane + 1, 1)}


def test_legacy_sse_write_does_not_zero_upper_lanes(model):
    eff = model.effects_for(bytes.fromhex("0f10c1"))  # movups xmm0, xmm1
    lane = L.lookup("xmm0").lane
    assert defs(eff) == {(lane, 16)}


def test_vex_write_zero_extends_the_whole_vector_register(model):
    eff = model.effects_for(bytes.fromhex("c5f928c1"))  # vmovapd xmm0, xmm1
    slot = L.lookup("xmm0")
    assert defs(eff) == {(slot.parent_lane, slot.parent_size)}


# --------------------------------------------------------------------------
# 6.3  Implicit operands
# --------------------------------------------------------------------------


def test_push_reads_and_writes_rsp_and_touches_memory(model):
    eff = model.effects_for(bytes.fromhex("50"))  # push rax
    assert lanes_of("rsp") in uses(eff)
    assert lanes_of("rsp") in defs(eff)
    assert len(eff.mem) == 1
    assert eff.mem[0].writes and eff.mem[0].implicit_stack


def test_ret_reads_the_stack(model):
    eff = model.effects_for(bytes.fromhex("c3"))
    assert eff.is_ret
    assert len(eff.mem) == 1
    assert eff.mem[0].reads and eff.mem[0].implicit_stack


def test_mul_touches_rax_and_rdx_implicitly(model):
    eff = model.effects_for(bytes.fromhex("f7e3"))  # mul ebx
    assert parent_of("rax") in defs(eff)
    assert parent_of("rdx") in defs(eff)
    assert (L.lookup("eax").lane, 4) in uses(eff)


def test_call_has_two_memory_accesses_in_canonical_order(model):
    """`call [rax+0x10]` reads the target then writes the return address.

    The order is normative — the capture agent emits MEM records in it, and
    the integrity checker compares counts against this model.
    """
    eff = model.effects_for(bytes.fromhex("ff5010"))
    assert [(m.reads, m.writes, m.implicit_stack) for m in eff.mem] == [
        (True, False, False),
        (False, True, True),
    ]


# --------------------------------------------------------------------------
# 6.4  Idioms
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoding,name",
    [
        ("4831c0", "xor rax, rax"),
        ("4829c0", "sub rax, rax"),
        ("660f76c0", "pcmpeqd xmm0, xmm0"),
        ("c5f1efc9", "vpxor xmm1, xmm1, xmm1"),
    ],
)
def test_zeroing_idioms_define_without_using(model, encoding, name):
    """`xor rax, rax` does not read RAX.

    Treating it as a read injects a false dependence on whatever last wrote
    RAX — and because the idiom is ubiquitous in compiler output, that false
    edge appears in essentially every slice through essentially every function.
    """
    eff = model.effects_for(bytes.fromhex(encoding))
    assert uses(eff) == set(), f"{name} should have no register value uses"
    assert defs(eff), f"{name} should still define its destination"


def test_sbb_self_is_not_an_idiom(model):
    """`sbb rax, rax` genuinely reads CF — it is the carry-broadcast pattern.

    It looks exactly like `sub rax, rax` and matching on operand identity alone
    would wrongly classify it, silently deleting the CF dependence that is the
    entire purpose of the instruction.
    """
    eff = model.effects_for(bytes.fromhex("4819c0"))
    assert uses(eff) == {lanes_of("rax")}
    assert eff.flag_uses & L.CF


def test_lea_accesses_no_memory_and_no_flags(model):
    """`lea` is arithmetic, not a load, and its base/index are *value* uses."""
    eff = model.effects_for(bytes.fromhex("488d0c98"))  # lea rcx, [rax+rbx*4]
    assert eff.mem == ()
    assert eff.flag_defs == 0 and eff.flag_maydefs == 0
    assert uses(eff) == {lanes_of("rax"), lanes_of("rbx")}
    assert addr_uses(eff) == set()


def test_nop_has_no_effect(model):
    eff = model.effects_for(bytes.fromhex("90"))
    assert not uses(eff) and not defs(eff)
    assert eff.flag_defs == 0


def test_cmov_reads_its_destination(model):
    """When the condition is false the destination keeps its old value.

    Capstone reports the destination as write-only, which would break the
    dependence on the not-taken value.
    """
    eff = model.effects_for(bytes.fromhex("0f45c1"))  # cmovne eax, ecx
    assert (L.lookup("eax").lane, 4) in uses(eff)
    assert parent_of("rax") in defs(eff)  # the zero-extension still applies


# --------------------------------------------------------------------------
# 5.4  Address versus value dependences
# --------------------------------------------------------------------------


def test_load_separates_pointer_from_payload(model):
    """`mov rax, [rbx+8]` address-depends on RBX and value-depends on memory.

    Conflating them makes RSP a universal attractor and every slice fills with
    stack plumbing (design v0.2 section 5.4).
    """
    eff = model.effects_for(bytes.fromhex("488b4308"))
    assert addr_uses(eff) == {lanes_of("rbx")}
    assert uses(eff) == set()
    assert len(eff.mem) == 1 and eff.mem[0].reads


def test_segment_base_is_an_address_use(model):
    """`mov rax, gs:[0x30]` depends on the GS base — the TEB read on Windows."""
    eff = model.effects_for(bytes.fromhex("65488b042530000000"))
    assert lanes_of("gs") in addr_uses(eff)


# --------------------------------------------------------------------------
# 6.5  Flags at bit granularity
# --------------------------------------------------------------------------


def test_conditional_branches_read_only_their_own_flags(model):
    """`jz` reads ZF; `jl` reads SF and OF; `ja` reads CF and ZF.

    A monolithic RFLAGS location would make every branch depend on every prior
    flag writer, which is what turns control-dependence chains into noise.
    """
    assert model.effects_for(bytes.fromhex("7405")).flag_uses == L.ZF
    assert model.effects_for(bytes.fromhex("7c05")).flag_uses == L.SF | L.OF
    assert model.effects_for(bytes.fromhex("7705")).flag_uses == L.CF | L.ZF


def test_cmp_defines_the_arithmetic_flags(model):
    eff = model.effects_for(bytes.fromhex("4839d8"))  # cmp rax, rbx
    assert eff.flag_defs == L.ALL_ARITH_FLAGS


def test_undefined_flags_are_may_defs_not_defs(model):
    """`and` leaves AF architecturally undefined.

    Recording it as a plain def would claim a value the ISA does not promise;
    recording nothing would break the last-writer chain for anyone who reads it.
    The may-def does both: it takes the last-writer slot and marks the edge.
    """
    eff = model.effects_for(bytes.fromhex("4821d8"))  # and rax, rbx
    assert eff.flag_maydefs & L.AF
    assert not eff.flag_defs & L.AF


# --------------------------------------------------------------------------
# 6.6 / 6.7  rep and value-dependent flags
# --------------------------------------------------------------------------


def test_rep_string_op_emits_no_per_operand_memory_records(model):
    """A `rep movs` is one instruction performing RCX accesses.

    Its memory effect comes from the REP record as a bulk range, so the
    per-operand MEM records must not be expected — or the integrity check
    would fire on every string operation in the trace.
    """
    eff = model.effects_for(bytes.fromhex("f348a5"))  # rep movsq
    assert eff.is_rep and eff.element_size == 8
    assert eff.mem == ()
    assert eff.flag_uses & L.DF  # direction controls which way the ranges run


def test_variable_shift_is_flagged_as_count_dependent(model):
    eff = model.effects_for(bytes.fromhex("48d3e0"))  # shl rax, cl
    assert eff.is_shift_by_cl
    assert (L.lookup("cl").lane, 1) in uses(eff)


def test_immediate_shift_is_not_count_dependent(model):
    eff = model.effects_for(bytes.fromhex("48c1e004"))  # shl rax, 4
    assert not eff.is_shift_by_cl


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_indirect_branch_is_detected(model):
    eff = model.effects_for(bytes.fromhex("ffe0"))  # jmp rax
    assert eff.is_indirect and eff.is_uncond_branch
    assert uses(eff) == {lanes_of("rax")}


def test_direct_jump_is_not_indirect(model):
    eff = model.effects_for(bytes.fromhex("eb05"))
    assert eff.is_uncond_branch and not eff.is_indirect


def test_undecodable_bytes_do_not_raise_by_default(model):
    """A packer's garbage byte must not abort the whole replay."""
    eff = model.effects_for(b"\xff\xff\xff\xff")
    assert "undecodable" in eff.notes


def test_effects_are_cached_by_bytes(model):
    first = model.effects_for(bytes.fromhex("4831c0"))
    second = model.effects_for(bytes.fromhex("4831c0"))
    assert first is second
