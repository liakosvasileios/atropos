"""Slicing criteria: turning an analyst's question into ``(seq, locations)``.

Design v0.2 section 8.1.  Every front-end reduces to the same pair: a point in
the execution, and a set of storage locations at that point.

Point syntax (``--at``)::

    seq=41792                  raw trace index
    addr=0x140001a2f@3         the 4th execution of that address (0-based)
    addr=target.exe+0x1a2f@3   same, rebased
    mark=7                     the point where the agent emitted MARK 7

Location syntax (``--loc``, repeatable)::

    rax                        all eight lanes
    eax                        lanes 0..3
    al / ah                    one lane each
    rbx[0:3]                   an explicit lane range, inclusive
    zf                         one flag bit
    mem=0x7ff6c0001000+16      sixteen bytes of memory
    mem=@rsp+64                sixteen bytes relative to a register is *not*
                               supported: the slicer has no register values, by
                               design (section 4.4).  Resolve the address in the
                               agent hook and pass it literally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .arch import lanes as L
from .ddg import SPACE_MEM, SPACE_REG


class CriterionError(ValueError):
    """The criterion could not be parsed or resolved against the trace."""


@dataclass(frozen=True)
class Location:
    space: int
    loc: int
    length: int

    def render(self) -> str:
        if self.space == SPACE_REG:
            return L.render_range(self.loc, self.length)
        return f"[0x{self.loc:x}..+{self.length}]"

    def __str__(self) -> str:
        return self.render()


@dataclass
class Criterion:
    """A resolved slicing criterion."""

    seq: int
    locations: list[Location] = field(default_factory=list)
    description: str = ""

    def render(self) -> str:
        locs = ", ".join(loc.render() for loc in self.locations)
        return f"#{self.seq} {{{locs}}}" + (f"  ({self.description})" if self.description else "")


# --------------------------------------------------------------------------
# Location parsing
# --------------------------------------------------------------------------

_RANGE_RE = re.compile(r"^(?P<name>[a-z0-9()]+)\[(?P<lo>\d+):(?P<hi>\d+)\]$")
_MEM_RE = re.compile(r"^mem=(?P<addr>0x[0-9a-f]+|\d+)\+(?P<len>0x[0-9a-f]+|\d+)$")


def parse_location(text: str) -> Location:
    spec = text.strip().lower()

    match = _MEM_RE.match(spec)
    if match:
        address = int(match.group("addr"), 0)
        length = int(match.group("len"), 0)
        if length <= 0:
            raise CriterionError(f"memory length must be positive: {text!r}")
        return Location(SPACE_MEM, address, length)

    if spec.startswith("mem"):
        raise CriterionError(
            f"malformed memory location {text!r}; expected mem=<address>+<length>"
        )

    match = _RANGE_RE.match(spec)
    if match:
        slot = L.lookup(match.group("name"))
        lo = int(match.group("lo"))
        hi = int(match.group("hi"))
        if hi < lo:
            raise CriterionError(f"inverted lane range in {text!r}")
        if hi >= slot.parent_size:
            raise CriterionError(
                f"lane {hi} is outside {match.group('name')} "
                f"(width {slot.parent_size})"
            )
        return Location(SPACE_REG, slot.parent_lane + lo, hi - lo + 1)

    upper = spec.upper()
    if upper in L.FLAG_NAMES:
        return Location(SPACE_REG, L.flag_lane(L.FLAG_NAMES.index(upper)), 1)

    if spec in L.REGISTRY:
        slot = L.REGISTRY[spec]
        return Location(SPACE_REG, slot.lane, slot.size)

    raise CriterionError(
        f"unrecognised location {text!r}; expected a register name, "
        "a flag, reg[lo:hi], or mem=<address>+<length>"
    )


# --------------------------------------------------------------------------
# Point parsing and resolution
# --------------------------------------------------------------------------

_ADDR_RE = re.compile(r"^addr=(?P<addr>[^@]+)(?:@(?P<occ>\d+))?$")


@dataclass
class PointSpec:
    """An unresolved point, parsed but not yet located in a specific trace."""

    kind: str  # "seq" | "addr" | "mark"
    value: int | str
    occurrence: int = 0
    raw: str = ""


def parse_point(text: str) -> PointSpec:
    spec = text.strip()
    if spec.startswith("seq="):
        return PointSpec("seq", int(spec[4:], 0), raw=spec)
    if spec.startswith("mark="):
        return PointSpec("mark", int(spec[5:], 0), raw=spec)
    match = _ADDR_RE.match(spec)
    if match:
        occ = int(match.group("occ") or 0)
        return PointSpec("addr", match.group("addr").strip(), occ, raw=spec)
    raise CriterionError(
        f"unrecognised point {text!r}; expected seq=N, addr=<address>[@occurrence], "
        "or mark=N"
    )


def resolve_address(bundle, text: str) -> int:
    """Resolve ``0x…`` or ``module+0x…`` against the bundle's module map."""
    spec = text.strip()
    if "+" in spec:
        name, _, offset = spec.partition("+")
        name = name.strip().lower()
        for module in bundle.modules:
            if module.name.lower() == name or module.name.lower().startswith(name):
                return module.base + int(offset, 0)
        raise CriterionError(
            f"no module named {name!r} in this bundle "
            f"(have: {', '.join(m.name for m in bundle.modules) or 'none'})"
        )
    return int(spec, 0)


def resolve_point(point: PointSpec, result) -> int:
    """Turn a :class:`PointSpec` into a concrete trace sequence index."""
    ddg = result.ddg
    if point.kind == "seq":
        seq = int(point.value)
        if not 0 <= seq < ddg.n_nodes:
            raise CriterionError(
                f"seq {seq} is outside this trace (0..{ddg.n_nodes - 1})"
            )
        return seq

    if point.kind == "mark":
        for mark_id, seq in ddg.marks:
            if mark_id == point.value:
                return seq
        known = sorted({m for m, _ in ddg.marks})
        raise CriterionError(
            f"no MARK {point.value} in this trace"
            + (f" (have: {known})" if known else " (the trace has no marks)")
        )

    address = resolve_address(result.bundle, str(point.value))
    wanted = point.occurrence
    seen = 0
    for seq in range(ddg.n_nodes):
        if ddg.node_addr[seq] == address:
            if seen == wanted:
                return seq
            seen += 1
    if seen:
        raise CriterionError(
            f"address {result.bundle.rebase(address)} executed {seen} time(s); "
            f"occurrence {wanted} does not exist"
        )
    raise CriterionError(
        f"address {result.bundle.rebase(address)} never executed in this trace"
    )


def build_criterion(point_text: str, location_texts: list[str], result) -> Criterion:
    point = parse_point(point_text)
    seq = resolve_point(point, result)
    locations = [parse_location(text) for text in location_texts]
    if not locations:
        raise CriterionError("a criterion needs at least one --loc")
    return Criterion(seq=seq, locations=locations, description=point.raw)
