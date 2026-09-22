"""The dynamic dependence graph.

Nodes are executed instruction *instances* — the k-th time an instruction ran,
identified by its sequence index in the trace.  Edges are the value, address and
control dependences of design v0.2 sections 5.4 and 7.

Representation
--------------

Everything is a parallel typed array.  This is not premature optimisation; it is
design v0.2 section 10.5, and it buys two specific things:

1. **Memory.** Ten million edges as Python objects is several gigabytes.  As six
   ``array`` columns it is a few hundred megabytes, which is the difference
   between slicing a real trace and swapping.
2. **A free index.** The forward replay emits every edge of instruction *n*
   before any edge of instruction *n+1*, so an instruction's edges are
   *contiguous*.  ``node_edge_start[seq] .. node_edge_start[seq+1]`` is the
   complete use-set of a node with no auxiliary index at all.

Control dependence is stored as one entry per node rather than as an edge,
because the Korel-Laski relation used here gives each instance exactly one
guarding branch (design v0.2 section 7.2).
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field

from .arch import lanes as L
from .arch.effects import (
    EF_BULK,
    EF_IMPRECISE,
    EF_SUMMARY,
    KIND_ADDR,
    KIND_CONTROL,
    KIND_NAMES,
    KIND_VALUE,
)
from .shadow import LIVE_IN

SPACE_REG = 0
SPACE_MEM = 1
SPACE_NAMES = {SPACE_REG: "reg", SPACE_MEM: "mem"}

# Node flag bits
NF_BULK = 1 << 0  # instruction had a bulk (rep) effect
NF_IMPRECISE = 1 << 1  # some effect derived from an ISA-undefined value
NF_SUMMARY = 1 << 2  # synthesised from an API summary, not a traced insn
NF_SUSPECT = 1 << 3  # inside a trace range flagged by the integrity checker
NF_CD_UNRELIABLE = 1 << 4  # control dependence here is not to be trusted
NF_ABORTED = 1 << 5  # block containing this node did not run to completion

NODE_FLAG_NAMES = [
    (NF_BULK, "bulk"),
    (NF_IMPRECISE, "imprecise"),
    (NF_SUMMARY, "summary"),
    (NF_SUSPECT, "suspect"),
    (NF_CD_UNRELIABLE, "cd-unreliable"),
    (NF_ABORTED, "aborted"),
]


def format_node_flags(flags: int) -> str:
    names = [name for bit, name in NODE_FLAG_NAMES if flags & bit]
    return ",".join(names)


@dataclass
class Edge:
    """A materialised edge, for output and testing.  Not used in the hot loop."""

    use_seq: int
    def_seq: int
    space: int
    loc: int
    length: int
    kind: int
    flags: int = 0

    @property
    def is_live_in(self) -> bool:
        return self.def_seq == LIVE_IN

    def render_location(self) -> str:
        if self.space == SPACE_REG:
            return L.render_range(self.loc, self.length)
        return f"[0x{self.loc:x}..+{self.length}]"

    def __str__(self) -> str:  # pragma: no cover - human output
        src = "LIVE-IN" if self.is_live_in else f"#{self.def_seq}"
        return f"#{self.use_seq} <-{KIND_NAMES[self.kind]}- {src} on {self.render_location()}"


class DDG:
    """Column store for nodes and edges, built once by the forward replay."""

    def __init__(self) -> None:
        # -- node columns, indexed by seq ---------------------------------
        self.node_addr = array("q")
        self.node_block = array("l")
        self.node_index = array("i")  # instruction index within its block
        self.node_version = array("i")
        self.node_tid = array("i")
        self.node_flags = array("i")
        self.node_ctrl = array("q")  # guarding branch seq, or LIVE_IN
        self.node_edge_start = array("q")
        self.node_def_start = array("q")

        # -- edge columns, in emission (i.e. use_seq) order ----------------
        self.edge_def = array("q")
        self.edge_space = array("b")
        self.edge_loc = array("q")
        self.edge_len = array("i")
        self.edge_kind = array("b")
        self.edge_flags = array("b")

        # -- def columns: what each node *wrote*, in node order ------------
        # Symmetric with the edge columns and contiguous for the same reason.
        # Kept because a slicing criterion names a location at a point in the
        # execution, not an edge, and resolving it needs the write history
        # (criterion.py).  It is also what lets the listing say what an
        # instruction produced, not only what it consumed.
        self.def_space = array("b")
        self.def_loc = array("q")
        self.def_len = array("i")

        # -- side tables ---------------------------------------------------
        self.marks: list[tuple[int, int]] = []  # (mark_id, seq)
        self.version_changes: list[tuple[int, int]] = []  # (seq, code_version)
        self.summary_nodes: dict[int, str] = {}  # seq -> summary name
        self.summary_kinds: dict[int, str] = {}  # seq -> transform|source|alloc|free
        self.notes: list[str] = []

    # -- construction -----------------------------------------------------

    def add_node(
        self,
        address: int,
        block_id: int,
        insn_index: int,
        code_version: int,
        tid: int,
        flags: int = 0,
    ) -> int:
        seq = len(self.node_addr)
        self.node_addr.append(address)
        self.node_block.append(block_id)
        self.node_index.append(insn_index)
        self.node_version.append(code_version)
        self.node_tid.append(tid)
        self.node_flags.append(flags)
        self.node_ctrl.append(LIVE_IN)
        self.node_edge_start.append(len(self.edge_def))
        self.node_def_start.append(len(self.def_space))
        return seq

    def add_edge(
        self,
        def_seq: int,
        space: int,
        loc: int,
        length: int,
        kind: int,
        flags: int = 0,
    ) -> None:
        self.edge_def.append(def_seq)
        self.edge_space.append(space)
        self.edge_loc.append(loc)
        self.edge_len.append(length)
        self.edge_kind.append(kind)
        self.edge_flags.append(flags)

    def add_def(self, space: int, loc: int, length: int) -> None:
        self.def_space.append(space)
        self.def_loc.append(loc)
        self.def_len.append(length)

    def finish(self) -> None:
        """Seal the graph by appending the end sentinels for the range columns."""
        self.node_edge_start.append(len(self.edge_def))
        self.node_def_start.append(len(self.def_space))

    # -- access -----------------------------------------------------------

    @property
    def n_nodes(self) -> int:
        return len(self.node_addr)

    @property
    def n_edges(self) -> int:
        return len(self.edge_def)

    def edge_range(self, seq: int) -> range:
        return range(self.node_edge_start[seq], self.node_edge_start[seq + 1])

    def def_range(self, seq: int) -> range:
        return range(self.node_def_start[seq], self.node_def_start[seq + 1])

    def defs_of(self, seq: int) -> list[tuple[int, int, int]]:
        return [
            (self.def_space[i], self.def_loc[i], self.def_len[i])
            for i in self.def_range(seq)
        ]

    def edges_of(self, seq: int) -> list[Edge]:
        return [
            Edge(
                use_seq=seq,
                def_seq=self.edge_def[i],
                space=self.edge_space[i],
                loc=self.edge_loc[i],
                length=self.edge_len[i],
                kind=self.edge_kind[i],
                flags=self.edge_flags[i],
            )
            for i in self.edge_range(seq)
        ]

    def edge_at(self, i: int, use_seq: int) -> Edge:
        return Edge(
            use_seq=use_seq,
            def_seq=self.edge_def[i],
            space=self.edge_space[i],
            loc=self.edge_loc[i],
            length=self.edge_len[i],
            kind=self.edge_kind[i],
            flags=self.edge_flags[i],
        )

    def guarding_branch(self, seq: int) -> int:
        return self.node_ctrl[seq]

    # -- occurrence numbering ---------------------------------------------

    def occurrence_index(self) -> array:
        """For each node, which execution of its static address it is.

        Computed lazily and cached, because it is only needed for human output
        and costs a full pass over the trace.
        """
        cached = getattr(self, "_occurrence", None)
        if cached is not None:
            return cached
        counts: dict[tuple[int, int], int] = {}
        out = array("i", [0]) * self.n_nodes
        for seq in range(self.n_nodes):
            key = (self.node_addr[seq], self.node_version[seq])
            n = counts.get(key, 0)
            out[seq] = n
            counts[key] = n + 1
        self._occurrence = out
        return out

    # -- diagnostics ------------------------------------------------------

    def edge_kind_histogram(self) -> dict[str, int]:
        hist = {name: 0 for name in KIND_NAMES.values()}
        hist["live-in"] = 0
        for i in range(self.n_edges):
            hist[KIND_NAMES[self.edge_kind[i]]] += 1
            if self.edge_def[i] == LIVE_IN:
                hist["live-in"] += 1
        return hist

    def flag_histogram(self) -> dict[str, int]:
        hist = {name: 0 for _bit, name in NODE_FLAG_NAMES}
        for flags in self.node_flags:
            for bit, name in NODE_FLAG_NAMES:
                if flags & bit:
                    hist[name] += 1
        return hist

    def approx_bytes(self) -> int:
        cols = (
            self.node_addr, self.node_block, self.node_index, self.node_version,
            self.node_tid, self.node_flags, self.node_ctrl, self.node_edge_start,
            self.edge_def, self.edge_space, self.edge_loc, self.edge_len,
            self.edge_kind, self.edge_flags,
            self.node_def_start, self.def_space, self.def_loc, self.def_len,
        )
        return sum(c.buffer_info()[1] * c.itemsize for c in cols)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DDG nodes={self.n_nodes} edges={self.n_edges} "
            f"~{self.approx_bytes() / 1e6:.1f}MB>"
        )


__all__ = [
    "DDG",
    "Edge",
    "SPACE_REG",
    "SPACE_MEM",
    "SPACE_NAMES",
    "KIND_VALUE",
    "KIND_ADDR",
    "KIND_CONTROL",
    "KIND_NAMES",
    "EF_BULK",
    "EF_IMPRECISE",
    "EF_SUMMARY",
    "NF_BULK",
    "NF_IMPRECISE",
    "NF_SUMMARY",
    "NF_SUSPECT",
    "NF_CD_UNRELIABLE",
    "NF_ABORTED",
    "format_node_flags",
]
