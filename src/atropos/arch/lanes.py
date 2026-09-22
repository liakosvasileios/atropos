"""The storage-location model: registers as byte lanes, flags as bits.

Design v0.2 section 6.1.  Everything downstream of this module reasons about
*lanes*, never about register names.  ``RAX`` is not a location; ``RAX[0]`` is.

Why this matters, restated in one line each:

* ``mov al, 1`` must not clobber the last-writer of ``RAX[1..7]``.
* ``mov eax, x`` must clobber all eight lanes, because a 32-bit write
  zero-extends — the top four bytes get a *defined* zero whose writer is this
  instruction.
* ``AH`` is ``RAX[1]``, and must be independent of ``AL`` (``RAX[0]``).

Get any of those wrong and every slice through the function is quietly wrong.

Lane space layout (see the table in design v0.2 section 6.1)::

    GPR    0    .. 127     16 registers x 8 bytes
    FLAG   128  .. 143     one lane per modelled flag bit
    VEC    144  .. 2191    32 registers x 64 bytes (ZMM width)
    SEG    2192 .. 2239    segment bases (gs:[0x30] matters on Windows)
    MMX    2240 .. 2303    8 x 8
    X87    2304 .. 2383    8 x 10
    EXTRA  2384 .. 2639    catch-all for registers we do not model explicitly

``RIP`` is deliberately absent: it is a constant per instruction instance, so
RIP-relative addressing contributes a constant rather than a dependence.
"""

from __future__ import annotations

from typing import Iterable, NamedTuple

# --------------------------------------------------------------------------
# Lane space
# --------------------------------------------------------------------------

GPR_BASE = 0
GPR_COUNT = 16
GPR_WIDTH = 8
FLAG_BASE = 128
FLAG_SLOTS = 16
VEC_BASE = 144
VEC_COUNT = 32
VEC_WIDTH = 64
SEG_BASE = 2192
SEG_COUNT = 6
SEG_WIDTH = 8
MMX_BASE = 2240
MMX_COUNT = 8
MMX_WIDTH = 8
X87_BASE = 2304
X87_COUNT = 8
X87_WIDTH = 10
EXTRA_BASE = 2384
EXTRA_COUNT = 32
EXTRA_WIDTH = 8

N_LANES = EXTRA_BASE + EXTRA_COUNT * EXTRA_WIDTH  # 2640

# --------------------------------------------------------------------------
# Flags.  One lane per bit; see design v0.2 section 6.5 for why a monolithic
# RFLAGS location over-couples every conditional branch to every arithmetic
# instruction that happened to run before it.
# --------------------------------------------------------------------------

FLAG_CF = 0
FLAG_PF = 1
FLAG_AF = 2
FLAG_ZF = 3
FLAG_SF = 4
FLAG_OF = 5
FLAG_DF = 6

FLAG_NAMES = ["CF", "PF", "AF", "ZF", "SF", "OF", "DF"]
N_FLAGS = len(FLAG_NAMES)

CF = 1 << FLAG_CF
PF = 1 << FLAG_PF
AF = 1 << FLAG_AF
ZF = 1 << FLAG_ZF
SF = 1 << FLAG_SF
OF = 1 << FLAG_OF
DF = 1 << FLAG_DF

ALL_ARITH_FLAGS = CF | PF | AF | ZF | SF | OF


def flag_lane(bit: int) -> int:
    return FLAG_BASE + bit


def flag_mask_to_lanes(mask: int) -> list[int]:
    return [FLAG_BASE + bit for bit in range(N_FLAGS) if mask & (1 << bit)]


def format_flag_mask(mask: int) -> str:
    names = [FLAG_NAMES[bit] for bit in range(N_FLAGS) if mask & (1 << bit)]
    return "|".join(names) if names else "-"


# --------------------------------------------------------------------------
# Register naming
# --------------------------------------------------------------------------

GPR64 = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
GPR32 = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]
GPR16 = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
]
GPR8L = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]
GPR8H = ["ah", "ch", "dh", "bh"]  # index 0..3, lane offset 1

SEG_NAMES = ["es", "cs", "ss", "ds", "fs", "gs"]


class RegSlot(NamedTuple):
    """Where a named register lives in lane space.

    ``lane`` is the first lane, ``size`` the number of lanes it occupies, and
    ``parent_lane`` / ``parent_size`` describe the full architectural register
    it is a view of — which is what the zero-extension rules of section 6.1
    need in order to widen a def.
    """

    name: str
    lane: int
    size: int
    parent_lane: int
    parent_size: int
    kind: str  # "gpr" | "flag" | "vec" | "seg" | "mmx" | "x87" | "extra"


def _build_registry() -> dict[str, RegSlot]:
    reg: dict[str, RegSlot] = {}

    for i, name in enumerate(GPR64):
        base = GPR_BASE + i * GPR_WIDTH
        reg[name] = RegSlot(name, base, 8, base, 8, "gpr")
    for i, name in enumerate(GPR32):
        base = GPR_BASE + i * GPR_WIDTH
        reg[name] = RegSlot(name, base, 4, base, 8, "gpr")
    for i, name in enumerate(GPR16):
        base = GPR_BASE + i * GPR_WIDTH
        reg[name] = RegSlot(name, base, 2, base, 8, "gpr")
    for i, name in enumerate(GPR8L):
        base = GPR_BASE + i * GPR_WIDTH
        reg[name] = RegSlot(name, base, 1, base, 8, "gpr")
    for i, name in enumerate(GPR8H):
        base = GPR_BASE + i * GPR_WIDTH
        reg[name] = RegSlot(name, base + 1, 1, base, 8, "gpr")

    for i in range(VEC_COUNT):
        base = VEC_BASE + i * VEC_WIDTH
        reg[f"xmm{i}"] = RegSlot(f"xmm{i}", base, 16, base, VEC_WIDTH, "vec")
        reg[f"ymm{i}"] = RegSlot(f"ymm{i}", base, 32, base, VEC_WIDTH, "vec")
        reg[f"zmm{i}"] = RegSlot(f"zmm{i}", base, 64, base, VEC_WIDTH, "vec")

    for i, name in enumerate(SEG_NAMES):
        base = SEG_BASE + i * SEG_WIDTH
        reg[name] = RegSlot(name, base, 8, base, 8, "seg")

    for i in range(MMX_COUNT):
        base = MMX_BASE + i * MMX_WIDTH
        reg[f"mm{i}"] = RegSlot(f"mm{i}", base, 8, base, 8, "mmx")

    for i in range(X87_COUNT):
        base = X87_BASE + i * X87_WIDTH
        reg[f"st({i})"] = RegSlot(f"st({i})", base, 10, base, 10, "x87")

    return reg


REGISTRY: dict[str, RegSlot] = _build_registry()


class _ExtraAllocator:
    """Deterministic lane assignment for registers we do not model explicitly.

    Rather than crashing on an unmodelled register (which loses the whole
    slice) or folding everything onto one lane (which invents dependences),
    each distinct unknown register name gets its own eight lanes in the EXTRA
    region.  Allocation is by first-seen order and is therefore deterministic
    for a given trace, which keeps runs reproducible.
    """

    def __init__(self) -> None:
        self._map: dict[str, RegSlot] = {}
        self._next = 0
        self.overflowed: set[str] = set()

    def get(self, name: str) -> RegSlot:
        slot = self._map.get(name)
        if slot is not None:
            return slot
        if self._next >= EXTRA_COUNT:
            # Out of catch-all space: fold onto the last slot and remember that
            # we did, so the precision banner can report it (section 9.6).
            self.overflowed.add(name)
            index = EXTRA_COUNT - 1
        else:
            index = self._next
            self._next += 1
        base = EXTRA_BASE + index * EXTRA_WIDTH
        slot = RegSlot(name, base, EXTRA_WIDTH, base, EXTRA_WIDTH, "extra")
        self._map[name] = slot
        return slot


EXTRA = _ExtraAllocator()


def lookup(name: str) -> RegSlot:
    """Resolve a register name (lower-case) to its lane slot."""
    slot = REGISTRY.get(name)
    if slot is not None:
        return slot
    return EXTRA.get(name)


def lane_name(lane: int) -> str:
    """Render a lane index as a human-readable location, e.g. ``rax[1]``."""
    if GPR_BASE <= lane < GPR_BASE + GPR_COUNT * GPR_WIDTH:
        idx, off = divmod(lane - GPR_BASE, GPR_WIDTH)
        return f"{GPR64[idx]}[{off}]"
    if FLAG_BASE <= lane < FLAG_BASE + FLAG_SLOTS:
        bit = lane - FLAG_BASE
        return FLAG_NAMES[bit] if bit < N_FLAGS else f"flag?{bit}"
    if VEC_BASE <= lane < VEC_BASE + VEC_COUNT * VEC_WIDTH:
        idx, off = divmod(lane - VEC_BASE, VEC_WIDTH)
        return f"zmm{idx}[{off}]"
    if SEG_BASE <= lane < SEG_BASE + SEG_COUNT * SEG_WIDTH:
        idx, off = divmod(lane - SEG_BASE, SEG_WIDTH)
        return f"{SEG_NAMES[idx]}[{off}]"
    if MMX_BASE <= lane < MMX_BASE + MMX_COUNT * MMX_WIDTH:
        idx, off = divmod(lane - MMX_BASE, MMX_WIDTH)
        return f"mm{idx}[{off}]"
    if X87_BASE <= lane < X87_BASE + X87_COUNT * X87_WIDTH:
        idx, off = divmod(lane - X87_BASE, X87_WIDTH)
        return f"st({idx})[{off}]"
    idx, off = divmod(lane - EXTRA_BASE, EXTRA_WIDTH)
    return f"extra{idx}[{off}]"


def render_range(lane: int, length: int) -> str:
    """Render a lane run compactly, collapsing whole registers where possible."""
    if FLAG_BASE <= lane < FLAG_BASE + FLAG_SLOTS:
        bits = [lane_name(lane + i) for i in range(length)]
        return "|".join(bits)
    if GPR_BASE <= lane < GPR_BASE + GPR_COUNT * GPR_WIDTH:
        idx, off = divmod(lane - GPR_BASE, GPR_WIDTH)
        if off == 0 and length == 8:
            return GPR64[idx]
        if off == 0 and length == 4:
            return GPR32[idx]
        if off == 0 and length == 2:
            return GPR16[idx]
        if off == 0 and length == 1:
            return GPR8L[idx]
        if off == 1 and length == 1 and idx < 4:
            return GPR8H[idx]
        end = off + length - 1
        return f"{GPR64[idx]}[{off}:{end}]"
    if length == 1:
        return lane_name(lane)
    return f"{lane_name(lane)}..+{length}"


def expand(ranges: Iterable[tuple[int, int]]) -> list[int]:
    """Flatten ``(lane, length)`` pairs into individual lane indices."""
    out: list[int] = []
    for lane, length in ranges:
        out.extend(range(lane, lane + length))
    return out
