"""The x86-64 effect model: instruction bytes in, storage-location effects out.

This is the module design v0.2 section 6 specifies, and the one most likely to
be wrong in any tool of this class.  It is deliberately host-side (section 3) so
that fixing a modelling bug means re-replaying an existing trace rather than
re-running the target.

The strategy is Capstone for the 95 % and an explicit override table for the
cases where Capstone's answer is correct-as-disassembly but wrong-as-semantics:

* zeroing idioms that appear to read their destination (section 6.4);
* ``lea``, which Capstone models with a memory operand it never accesses;
* per-condition flag read masks (section 6.5);
* ``rep``-prefixed string operations, which run a whole loop as one
  instruction (section 6.6);
* variable shifts, whose flag effects depend on a runtime value (section 6.7).

Every override here has a corresponding unit test in ``tests/test_effects.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import capstone
from capstone import x86 as cs_x86
from capstone import x86_const as xc

from . import lanes as L

# --------------------------------------------------------------------------
# Access-kind constants
# --------------------------------------------------------------------------

ACC_READ = 1
ACC_WRITE = 2

KIND_VALUE = 0
KIND_ADDR = 1
KIND_CONTROL = 2
KIND_NAMES = {KIND_VALUE: "value", KIND_ADDR: "addr", KIND_CONTROL: "control"}

# Edge annotation bits, orthogonal to the kind (design v0.2 section 9.6).
EF_IMPRECISE = 1 << 0  # derived from an ISA-undefined value
EF_BULK = 1 << 1  # from a bulk `rep` effect, not byte-exact
EF_SUMMARY = 1 << 2  # produced by an API summary rather than a traced insn


# --------------------------------------------------------------------------
# Flag mask translation
# --------------------------------------------------------------------------

_FLAG_BITS = {
    "CF": L.CF,
    "PF": L.PF,
    "AF": L.AF,
    "ZF": L.ZF,
    "SF": L.SF,
    "OF": L.OF,
    "DF": L.DF,
}


def _build_flag_tables() -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[tuple[int, int]]]:
    """Precompute (capstone_bit, our_mask) pairs for read / write / may-write."""
    reads: list[tuple[int, int]] = []
    writes: list[tuple[int, int]] = []
    maywrites: list[tuple[int, int]] = []
    for name, ours in _FLAG_BITS.items():
        for prefix, target in (
            ("TEST", reads),
            ("PRIOR", reads),
            ("MODIFY", writes),
            ("SET", writes),
            ("RESET", writes),
            ("UNDEFINED", maywrites),
        ):
            const = getattr(xc, f"X86_EFLAGS_{prefix}_{name}", None)
            if const:
                target.append((const, ours))
    return reads, writes, maywrites


_FLAG_READ_TBL, _FLAG_WRITE_TBL, _FLAG_MAYWRITE_TBL = _build_flag_tables()


def _decode_eflags(eflags: int) -> tuple[int, int, int]:
    reads = writes = maywrites = 0
    for const, ours in _FLAG_READ_TBL:
        if eflags & const:
            reads |= ours
    for const, ours in _FLAG_WRITE_TBL:
        if eflags & const:
            writes |= ours
    for const, ours in _FLAG_MAYWRITE_TBL:
        if eflags & const:
            maywrites |= ours
    # A flag that is both written and left undefined is undefined: the
    # UNDEFINED bit wins, because "the value is architecturally garbage" is a
    # strictly stronger statement than "it changed".
    writes &= ~maywrites
    return reads, writes, maywrites


# --------------------------------------------------------------------------
# Effects
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MemAccess:
    """One memory access slot, in canonical order.

    The canonical order is *normative*: the capture agent must emit its ``MEM``
    records in exactly this order, or the ``insn_index`` cross-check in
    :mod:`atropos.integrity` will fire.  It is:

    1. explicit memory operands, in Capstone operand order;
    2. the implicit stack access, for push/pop/call/ret/leave/enter/pushf/popf.
    """

    index: int
    size: int
    reads: bool
    writes: bool
    implicit_stack: bool = False


@dataclass(frozen=True)
class Effects:
    """Everything one static instruction does to storage, modulo dynamic EAs."""

    mnemonic: str
    op_str: str
    size: int

    reg_value_uses: tuple[tuple[int, int], ...] = ()
    reg_addr_uses: tuple[tuple[int, int], ...] = ()
    reg_defs: tuple[tuple[int, int], ...] = ()

    flag_uses: int = 0
    flag_defs: int = 0
    flag_maydefs: int = 0

    mem: tuple[MemAccess, ...] = ()

    is_cond_branch: bool = False
    is_uncond_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_indirect: bool = False
    is_syscall: bool = False
    is_rep: bool = False
    is_shift_by_cl: bool = False
    is_string_op: bool = False
    element_size: int = 0
    branch_target: int | None = None

    notes: tuple[str, ...] = ()

    @property
    def n_mem(self) -> int:
        return len(self.mem)

    @property
    def is_branch(self) -> bool:
        return self.is_cond_branch or self.is_uncond_branch or self.is_call or self.is_ret

    def describe(self) -> str:  # pragma: no cover - human output
        parts = [f"{self.mnemonic} {self.op_str}".strip()]
        if self.reg_value_uses:
            parts.append("use=" + ",".join(L.render_range(a, b) for a, b in self.reg_value_uses))
        if self.reg_addr_uses:
            parts.append("addr=" + ",".join(L.render_range(a, b) for a, b in self.reg_addr_uses))
        if self.reg_defs:
            parts.append("def=" + ",".join(L.render_range(a, b) for a, b in self.reg_defs))
        if self.flag_uses:
            parts.append("fuse=" + L.format_flag_mask(self.flag_uses))
        if self.flag_defs:
            parts.append("fdef=" + L.format_flag_mask(self.flag_defs))
        if self.flag_maydefs:
            parts.append("fmay=" + L.format_flag_mask(self.flag_maydefs))
        if self.notes:
            parts.append("[" + " ".join(self.notes) + "]")
        return "  ".join(parts)


# --------------------------------------------------------------------------
# Idiom recognition (design v0.2 section 6.4)
# --------------------------------------------------------------------------

#: Mnemonics whose destination is set to a constant when their sources are the
#: same register.  ``sbb`` is deliberately absent: ``sbb r, r`` genuinely reads
#: CF and is the standard carry-broadcast pattern.
_ZEROING_IDIOMS = frozenset(
    {
        "xor", "sub",
        "pxor", "vpxor", "xorps", "vxorps", "xorpd", "vxorpd",
        "pandn", "vpandn",
        "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpeqq",
        "vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpeqq",
        "psubb", "psubw", "psubd", "psubq",
    }
)

_STRING_OPS = frozenset(
    {"movsb", "movsw", "movsd", "movsq",
     "stosb", "stosw", "stosd", "stosq",
     "lodsb", "lodsw", "lodsd", "lodsq",
     "cmpsb", "cmpsw", "cmpsd", "cmpsq",
     "scasb", "scasw", "scasd", "scasq"}
)

_ELEMENT_SIZE = {"b": 1, "w": 2, "d": 4, "q": 8}

#: Instructions with an implicit stack memory access, and its direction.
_STACK_ACCESS = {
    "push": (ACC_WRITE, None),
    "pushfq": (ACC_WRITE, 8),
    "pushf": (ACC_WRITE, 8),
    "pop": (ACC_READ, None),
    "popfq": (ACC_READ, 8),
    "popf": (ACC_READ, 8),
    "call": (ACC_WRITE, 8),
    "ret": (ACC_READ, 8),
    "retf": (ACC_READ, 8),
    "leave": (ACC_READ, 8),
}


class UnsupportedInstruction(Exception):
    """The bytes could not be decoded at all."""


# --------------------------------------------------------------------------
# The model
# --------------------------------------------------------------------------


class EffectModel:
    """Decodes instruction bytes into :class:`Effects`, with caching.

    Effects are a pure function of the instruction *bytes* — not of the
    address, because ``RIP`` is not modelled as a dependence (section 6.1).
    That makes the cache key just the bytes, which matters: a decode-loop body
    is decoded once no matter how many million times it executes.
    """

    def __init__(self, strict: bool = False) -> None:
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True
        self._cache: dict[bytes, Effects] = {}
        self.strict = strict
        self.decode_failures: dict[bytes, str] = {}

    # -- public -----------------------------------------------------------

    def effects_for(self, raw: bytes) -> Effects:
        cached = self._cache.get(raw)
        if cached is not None:
            return cached
        eff = self._compute(raw)
        self._cache[raw] = eff
        return eff

    def disassemble(self, raw: bytes, address: int) -> tuple[str, str]:
        """Return ``(mnemonic, op_str)`` rendered at a real address.

        Separate from :meth:`effects_for` because the operand text of a
        RIP-relative instruction depends on where it lives, while its effects
        do not.
        """
        for insn in self._md.disasm(raw, address, count=1):
            return insn.mnemonic, insn.op_str
        return "(bad)", raw.hex()

    # -- internals --------------------------------------------------------

    def _compute(self, raw: bytes) -> Effects:
        insn = None
        for decoded in self._md.disasm(raw, 0x1000, count=1):
            insn = decoded
            break
        if insn is None:
            if self.strict:
                raise UnsupportedInstruction(f"cannot decode {raw.hex()}")
            self.decode_failures[raw] = "capstone could not decode"
            return Effects(mnemonic="(bad)", op_str=raw.hex(), size=len(raw),
                           notes=("undecodable",))

        mnem = insn.mnemonic
        base_mnem = mnem.split()[-1] if " " in mnem else mnem
        notes: list[str] = []

        value_uses: list[tuple[int, int]] = []
        addr_uses: list[tuple[int, int]] = []
        defs: list[tuple[int, int]] = []
        mem: list[MemAccess] = []

        is_vex = base_mnem.startswith("v")
        is_lea = base_mnem == "lea"

        # --- explicit operands -------------------------------------------
        reg_ops: list[tuple[str, int]] = []  # (name, access) in operand order
        for op in insn.operands:
            if op.type == cs_x86.X86_OP_REG:
                name = insn.reg_name(op.reg)
                reg_ops.append((name, op.access))
                slot = L.lookup(name)
                if op.access & ACC_READ:
                    value_uses.append((slot.lane, slot.size))
                if op.access & ACC_WRITE:
                    defs.append(self._def_range(slot, is_vex))
            elif op.type == cs_x86.X86_OP_MEM:
                m = op.mem
                target = value_uses if is_lea else addr_uses
                if m.base:
                    s = L.lookup(insn.reg_name(m.base))
                    target.append((s.lane, s.size))
                if m.index:
                    s = L.lookup(insn.reg_name(m.index))
                    target.append((s.lane, s.size))
                if m.segment:
                    s = L.lookup(insn.reg_name(m.segment))
                    # A segment base is an address input even for `lea`-like
                    # forms; it never contributes a value.
                    addr_uses.append((s.lane, s.size))
                if not is_lea:
                    mem.append(
                        MemAccess(
                            index=len(mem),
                            size=op.size,
                            reads=bool(op.access & ACC_READ),
                            writes=bool(op.access & ACC_WRITE),
                        )
                    )
            # Immediates contribute nothing: a constant has no last writer.

        if is_lea:
            notes.append("lea:no-memory-access")

        # --- implicit registers ------------------------------------------
        for reg in insn.regs_read:
            name = insn.reg_name(reg)
            if name in ("rflags", "eflags", "flags", "rip", "eip"):
                continue
            slot = L.lookup(name)
            value_uses.append((slot.lane, slot.size))
        for reg in insn.regs_write:
            name = insn.reg_name(reg)
            if name in ("rflags", "eflags", "flags", "rip", "eip"):
                continue
            slot = L.lookup(name)
            defs.append(self._def_range(slot, is_vex))

        # --- flags --------------------------------------------------------
        flag_uses, flag_defs, flag_maydefs = _decode_eflags(insn.eflags)

        # --- classification ----------------------------------------------
        groups = set(insn.groups)
        is_call = xc.X86_GRP_CALL in groups
        is_ret = xc.X86_GRP_RET in groups
        is_jump = xc.X86_GRP_JUMP in groups
        is_cond = is_jump and flag_uses != 0 and base_mnem not in ("jmp",)
        if base_mnem in ("jrcxz", "jecxz", "loop", "loope", "loopne"):
            is_cond = True
        is_uncond = (is_jump and not is_cond) or base_mnem == "jmp"
        is_indirect = (is_call or is_jump) and any(
            op.type != cs_x86.X86_OP_IMM for op in insn.operands
        )
        is_syscall = base_mnem in ("syscall", "sysenter", "int")

        branch_target = None
        if (is_jump or is_call) and insn.operands and insn.operands[0].type == cs_x86.X86_OP_IMM:
            branch_target = insn.operands[0].imm

        # --- implicit stack access ---------------------------------------
        stack = _STACK_ACCESS.get(base_mnem)
        if stack is not None:
            direction, fixed_size = stack
            size = fixed_size
            if size is None:
                size = insn.operands[0].size if insn.operands else 8
            slot = L.lookup("rsp")
            addr_uses.append((slot.lane, slot.size))
            mem.append(
                MemAccess(
                    index=len(mem),
                    size=size,
                    reads=bool(direction & ACC_READ),
                    writes=bool(direction & ACC_WRITE),
                    implicit_stack=True,
                )
            )

        # --- string / rep -------------------------------------------------
        is_string = base_mnem in _STRING_OPS
        element_size = _ELEMENT_SIZE.get(base_mnem[-1], 0) if is_string else 0
        is_rep = is_string and ("rep" in mnem.split()[0] if " " in mnem else False)
        if not is_rep and is_string:
            # Capstone folds the prefix into the mnemonic string for some
            # builds ("rep movsq") and into insn.prefix for others.
            is_rep = any(
                p in (xc.X86_PREFIX_REP, xc.X86_PREFIX_REPNE) for p in insn.prefix
            )
        if is_rep:
            # The whole loop is one instruction; its memory effect is a bulk
            # range synthesised from the REP record, so the per-operand MEM
            # accesses do not appear in the stream (section 6.6).
            mem = [m for m in mem if m.implicit_stack]
            notes.append("rep:bulk")

        # --- overrides ----------------------------------------------------
        eff_notes, value_uses, flag_defs, flag_maydefs = self._apply_overrides(
            base_mnem, reg_ops, insn, value_uses, flag_defs, flag_maydefs, notes
        )

        is_shift_by_cl = base_mnem in (
            "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "shld", "shrd"
        ) and any(name == "cl" for name, acc in reg_ops if acc & ACC_READ)
        if is_shift_by_cl:
            eff_notes.append("shift:count-dependent-flags")

        return Effects(
            mnemonic=mnem,
            op_str=insn.op_str,
            size=insn.size,
            reg_value_uses=tuple(_dedup(value_uses)),
            reg_addr_uses=tuple(_dedup(addr_uses)),
            reg_defs=tuple(_dedup(defs)),
            flag_uses=flag_uses,
            flag_defs=flag_defs,
            flag_maydefs=flag_maydefs,
            mem=tuple(mem),
            is_cond_branch=is_cond,
            is_uncond_branch=is_uncond,
            is_call=is_call,
            is_ret=is_ret,
            is_indirect=is_indirect,
            is_syscall=is_syscall,
            is_rep=is_rep,
            is_shift_by_cl=is_shift_by_cl,
            is_string_op=is_string,
            element_size=element_size,
            branch_target=branch_target,
            notes=tuple(eff_notes),
        )

    # -- override table ---------------------------------------------------

    def _apply_overrides(
        self,
        mnem: str,
        reg_ops: list[tuple[str, int]],
        insn,
        value_uses: list[tuple[int, int]],
        flag_defs: int,
        flag_maydefs: int,
        notes: list[str],
    ) -> tuple[list[str], list[tuple[int, int]], int, int]:
        """Corrections to Capstone's answer.  Design v0.2 section 6.4/6.8."""
        notes = list(notes)

        # --- nop and no-effect forms -------------------------------------
        if mnem in ("nop", "endbr64", "endbr32", "pause", "hint_nop"):
            return notes + ["nop:no-effect"], [], 0, 0

        # --- zeroing idioms ----------------------------------------------
        if mnem in _ZEROING_IDIOMS:
            src_names = [n for n, acc in reg_ops if acc & ACC_READ]
            dst_names = [n for n, acc in reg_ops if acc & ACC_WRITE]
            zeroed = False
            if len(reg_ops) == 2 and len(set(n for n, _ in reg_ops)) == 1:
                # Two-operand form: `xor rax, rax`.
                zeroed = True
            elif len(reg_ops) == 3:
                # VEX three-operand form: `vpxor xmm0, xmm1, xmm1` zeroes only
                # when the two *sources* match, regardless of the destination.
                if src_names and len(set(src_names)) == 1 and len(src_names) >= 2:
                    zeroed = True
                elif len(src_names) == 2 and src_names[0] == src_names[1]:
                    zeroed = True
            if zeroed:
                dropped = {L.lookup(n).parent_lane for n in set(src_names) | set(dst_names)}
                value_uses = [
                    (lane, size)
                    for lane, size in value_uses
                    if _parent_of(lane) not in dropped
                ]
                notes.append(f"idiom:{mnem}-constant")

        # --- constant-producing forms ------------------------------------
        if mnem in ("and", "imul") and _has_zero_immediate(insn):
            value_uses = []
            notes.append(f"idiom:{mnem}-zero")
        elif mnem == "or" and _has_all_ones_immediate(insn):
            value_uses = []
            notes.append("idiom:or-ones")

        # --- cmovcc reads its destination --------------------------------
        # Capstone marks `cmovne eax, ecx` as write-only on the destination,
        # but when the condition is false the destination keeps its previous
        # value — so it is genuinely read.  (The 32-bit zero-extension still
        # applies unconditionally, which is why the *def* stays widened.)
        if mnem.startswith("cmov") and reg_ops:
            dst = L.lookup(reg_ops[0][0])
            value_uses = value_uses + [(dst.lane, dst.size)]
            notes.append("cmov:reads-destination")

        # --- xchg with identical operands is a nop -----------------------
        if mnem == "xchg" and len(reg_ops) == 2 and reg_ops[0][0] == reg_ops[1][0]:
            notes.append("idiom:xchg-self")

        return notes, value_uses, flag_defs, flag_maydefs

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _def_range(slot: L.RegSlot, is_vex: bool) -> tuple[int, int]:
        """Widen a def per the zero-extension rules of section 6.1.

        * A 32-bit GPR write zero-extends: all eight lanes are defined here.
        * A VEX/EVEX vector write zeroes the upper bits: the full register.
        * Everything else — 8-, 16-, 64-bit GPR writes, legacy SSE writes —
          defines only its own lanes and leaves the rest alone.
        """
        if slot.kind == "gpr" and slot.size == 4:
            return (slot.parent_lane, slot.parent_size)
        if slot.kind == "vec" and is_vex:
            return (slot.parent_lane, slot.parent_size)
        return (slot.lane, slot.size)


def _parent_of(lane: int) -> int:
    if lane < L.FLAG_BASE:
        return lane - (lane % L.GPR_WIDTH)
    if L.VEC_BASE <= lane < L.SEG_BASE:
        off = lane - L.VEC_BASE
        return L.VEC_BASE + off - (off % L.VEC_WIDTH)
    return lane


def _has_zero_immediate(insn) -> bool:
    return any(op.type == cs_x86.X86_OP_IMM and op.imm == 0 for op in insn.operands)


def _has_all_ones_immediate(insn) -> bool:
    return any(
        op.type == cs_x86.X86_OP_IMM and op.imm in (-1, 0xFFFFFFFFFFFFFFFF)
        for op in insn.operands
    )


def _dedup(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge duplicate and adjacent lane ranges, preserving a stable order."""
    seen: dict[tuple[int, int], None] = {}
    for item in ranges:
        if item[1] > 0:
            seen[item] = None
    return list(seen)


#: A module-level default model.  Constructing a Capstone handle is not free and
#: the model is stateless apart from its cache, so sharing one is correct.
DEFAULT_MODEL = EffectModel()
