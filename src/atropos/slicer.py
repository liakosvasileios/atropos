"""The backward slice: graph reachability over the precomputed DDG.

Design v0.2 section 8.  All the analysis happened during the forward replay;
what is left is a walk.  This is why slicing is cheap even when tracing is not:
the cost is proportional to the size of the *slice*, not of the trace, and a
5 000-instruction slice out of a 5 000 000-instruction run costs 5 000 steps.

Relationship to the pseudocode in the design document
-----------------------------------------------------

Section 8 keys the frontier by ``(seq, space, start, len)``.  This implementation
keys it by ``seq`` alone once a node is in the slice, which is *equivalent* and
strictly cheaper: including an instruction in the slice means following all of
its uses, so once a node is enqueued there is nothing a finer key could add.
The byte-range frontier is still required for the one place it genuinely
matters — seeding the criterion, where a location is named at a point in the
execution that need not correspond to any edge.  That is
:func:`resolve_criterion_defs`.

Termination is structural: every edge points strictly backward in trace order
(a definition precedes its use), so the reachable set is a finite DAG and the
visited set bounds the walk.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .arch.effects import KIND_ADDR, KIND_CONTROL, KIND_NAMES, KIND_VALUE
from .criterion import Criterion, Location
from .ddg import DDG, Edge, SPACE_MEM, SPACE_REG, NF_SUMMARY
from .shadow import LIVE_IN


@dataclass(frozen=True)
class SliceMode:
    """Which edge kinds the walk is allowed to follow (section 7.3)."""

    name: str
    follow_value: bool = True
    follow_addr: bool = False
    follow_control: bool = False

    def allows(self, kind: int) -> bool:
        if kind == KIND_VALUE:
            return self.follow_value
        if kind == KIND_ADDR:
            return self.follow_addr
        if kind == KIND_CONTROL:
            return self.follow_control
        return False

    def describe(self) -> str:
        kinds = []
        if self.follow_value:
            kinds.append("value")
        if self.follow_addr:
            kinds.append("address")
        if self.follow_control:
            kinds.append("control")
        return "+".join(kinds) or "nothing"


MODES = {
    "value": SliceMode("value"),
    "value+addr": SliceMode("value+addr", follow_addr=True),
    "value+ctrl": SliceMode("value+ctrl", follow_control=True),
    "full": SliceMode("full", follow_addr=True, follow_control=True),
}

DEFAULT_MODE = MODES["value"]


@dataclass
class Inclusion:
    """Why one node is in the slice — the answer to "why is this here?"."""

    seq: int
    via_seq: int  # the node whose use pulled this one in; -1 for the criterion
    kind: int
    space: int = SPACE_REG
    loc: int = 0
    length: int = 0
    control_depth: int = 0

    def render(self, ddg: DDG) -> str:
        if self.via_seq < 0:
            return "slicing criterion"
        if self.kind == KIND_CONTROL:
            return f"guards #{self.via_seq}"
        edge = Edge(self.via_seq, self.seq, self.space, self.loc, self.length, self.kind)
        return f"defines {edge.render_location()} used by #{self.via_seq} ({KIND_NAMES[self.kind]})"


@dataclass
class InputLeaf:
    """A location the slice bottomed out on: a live-in of this execution."""

    space: int
    loc: int
    length: int
    used_by: int
    kind: int

    def render(self) -> str:
        if self.space == SPACE_REG:
            from .arch import lanes as L

            where = L.render_range(self.loc, self.length)
        else:
            where = f"[0x{self.loc:x}..+{self.length}]"
        return f"{where} read by #{self.used_by} ({KIND_NAMES[self.kind]})"


@dataclass
class SliceResult:
    criterion: Criterion
    mode: SliceMode
    nodes: list[int] = field(default_factory=list)
    inclusions: dict[int, Inclusion] = field(default_factory=dict)
    inputs: list[InputLeaf] = field(default_factory=list)
    truncated: bool = False
    truncation_reason: str = ""
    stats: dict = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.nodes)

    def contains(self, seq: int) -> bool:
        return seq in self.inclusions


# --------------------------------------------------------------------------
# Criterion seeding
# --------------------------------------------------------------------------


def resolve_criterion_defs(
    result, seq: int, location: Location
) -> list[tuple[int, int, int, int]]:
    """Find the definitions reaching ``location`` as of just before ``seq``.

    Returns ``(def_seq, space, start, length)`` runs, with ``def_seq ==
    LIVE_IN`` for byte ranges nothing in the trace wrote.

    This replays the *write history* only — a forward scan over the def
    columns, which is roughly an order of magnitude cheaper than a second full
    replay and needs no shadow memory.  The scan stops at ``seq`` because a
    criterion asks what reached that point, not what happened afterwards.
    """
    ddg = result.ddg
    space = location.space
    lo = location.loc
    hi = lo + location.length
    writers = [LIVE_IN] * location.length

    for node in range(min(seq + 1, ddg.n_nodes)):
        for i in ddg.def_range(node):
            if ddg.def_space[i] != space:
                continue
            d_lo = ddg.def_loc[i]
            d_hi = d_lo + ddg.def_len[i]
            if d_hi <= lo or d_lo >= hi:
                continue
            start = max(d_lo, lo)
            end = min(d_hi, hi)
            for offset in range(start - lo, end - lo):
                writers[offset] = node

    runs: list[tuple[int, int, int, int]] = []
    start = 0
    for index in range(1, location.length + 1):
        if index == location.length or writers[index] != writers[start]:
            runs.append((writers[start], space, lo + start, index - start))
            start = index
    return runs


# --------------------------------------------------------------------------
# The walk
# --------------------------------------------------------------------------


def backward_slice(
    result,
    criterion: Criterion,
    mode: SliceMode = DEFAULT_MODE,
    max_nodes: int | None = None,
    max_control_depth: int | None = None,
) -> SliceResult:
    ddg: DDG = result.ddg
    out = SliceResult(criterion=criterion, mode=mode)

    frontier: list[int] = []
    control_depth: dict[int, int] = {}

    # -- seed from the criterion ---------------------------------------
    for location in criterion.locations:
        for def_seq, space, start, length in resolve_criterion_defs(
            result, criterion.seq, location
        ):
            if def_seq == LIVE_IN:
                out.inputs.append(
                    InputLeaf(space, start, length, criterion.seq, KIND_VALUE)
                )
                continue
            if def_seq not in out.inclusions:
                out.inclusions[def_seq] = Inclusion(
                    def_seq, -1, KIND_VALUE, space, start, length
                )
                control_depth[def_seq] = 0
                frontier.append(def_seq)

    # -- walk ------------------------------------------------------------
    visited_edges = 0
    while frontier:
        node = frontier.pop()
        depth = control_depth.get(node, 0)

        for i in ddg.edge_range(node):
            visited_edges += 1
            kind = ddg.edge_kind[i]
            if not mode.allows(kind):
                continue
            def_seq = ddg.edge_def[i]
            if def_seq == LIVE_IN:
                out.inputs.append(
                    InputLeaf(
                        ddg.edge_space[i], ddg.edge_loc[i], ddg.edge_len[i], node, kind
                    )
                )
                continue
            if def_seq in out.inclusions:
                continue
            if max_nodes is not None and len(out.inclusions) >= max_nodes:
                out.truncated = True
                out.truncation_reason = f"node cap of {max_nodes} reached"
                frontier.clear()
                break
            out.inclusions[def_seq] = Inclusion(
                def_seq, node, kind,
                ddg.edge_space[i], ddg.edge_loc[i], ddg.edge_len[i],
                control_depth=depth,
            )
            control_depth[def_seq] = depth
            frontier.append(def_seq)

        if mode.follow_control and not out.truncated:
            guard = ddg.node_ctrl[node]
            if guard != LIVE_IN and guard not in out.inclusions:
                if max_control_depth is not None and depth >= max_control_depth:
                    out.truncated = True
                    out.truncation_reason = (
                        f"control depth cap of {max_control_depth} reached"
                    )
                elif max_nodes is not None and len(out.inclusions) >= max_nodes:
                    out.truncated = True
                    out.truncation_reason = f"node cap of {max_nodes} reached"
                else:
                    out.inclusions[guard] = Inclusion(
                        guard, node, KIND_CONTROL, control_depth=depth + 1
                    )
                    control_depth[guard] = depth + 1
                    frontier.append(guard)

    out.nodes = sorted(out.inclusions)
    out.stats = {
        "nodes": len(out.nodes),
        "inputs": len(out.inputs),
        "edges_visited": visited_edges,
        "trace_nodes": ddg.n_nodes,
        "reduction": (
            1.0 - len(out.nodes) / ddg.n_nodes if ddg.n_nodes else 0.0
        ),
    }
    return out


# --------------------------------------------------------------------------
# Forward slicing and chopping — the same graph, walked the other way.
# --------------------------------------------------------------------------


def _build_forward_index(ddg: DDG) -> dict[int, list[int]]:
    """Map each definition node to the nodes that use it.

    Built on demand because backward slicing — the common case — does not need
    it, and it costs a full pass over the edge columns.
    """
    index: dict[int, list[int]] = {}
    for seq in range(ddg.n_nodes):
        for i in ddg.edge_range(seq):
            def_seq = ddg.edge_def[i]
            if def_seq != LIVE_IN:
                index.setdefault(def_seq, []).append(seq)
    return index


def forward_slice(
    result, criterion: Criterion, mode: SliceMode = DEFAULT_MODE,
    max_nodes: int | None = None,
) -> SliceResult:
    """"What did this value go on to affect?" — impact analysis.

    Design v0.2 section 12.  Cheap once the DDG exists, because it is the same
    reachability with the edge direction reversed.
    """
    ddg: DDG = result.ddg
    index = _build_forward_index(ddg)
    out = SliceResult(criterion=criterion, mode=mode)

    frontier = [criterion.seq]
    out.inclusions[criterion.seq] = Inclusion(criterion.seq, -1, KIND_VALUE)

    while frontier:
        node = frontier.pop()
        for user in index.get(node, ()):
            if user in out.inclusions:
                continue
            if max_nodes is not None and len(out.inclusions) >= max_nodes:
                out.truncated = True
                out.truncation_reason = f"node cap of {max_nodes} reached"
                frontier.clear()
                break
            out.inclusions[user] = Inclusion(user, node, KIND_VALUE)
            frontier.append(user)

    out.nodes = sorted(out.inclusions)
    out.stats = {"nodes": len(out.nodes), "trace_nodes": ddg.n_nodes}
    return out


def chop(
    result,
    source: Criterion,
    sink: Criterion,
    mode: SliceMode = DEFAULT_MODE,
) -> SliceResult:
    """The instructions on a path from ``source`` to ``sink``.

    The intersection of a forward slice from the source and a backward slice
    from the sink — "how does this input reach that buffer", which is usually a
    much smaller and more readable answer than either slice alone.
    """
    ahead = forward_slice(result, source, mode)
    behind = backward_slice(result, sink, mode)
    common = sorted(set(ahead.nodes) & set(behind.nodes))
    out = SliceResult(criterion=sink, mode=mode)
    out.nodes = common
    out.inclusions = {seq: behind.inclusions[seq] for seq in common}
    out.inputs = [leaf for leaf in behind.inputs if leaf.used_by in set(common)]
    out.stats = {
        "nodes": len(common),
        "forward_nodes": len(ahead.nodes),
        "backward_nodes": len(behind.nodes),
        "trace_nodes": result.ddg.n_nodes,
    }
    return out
