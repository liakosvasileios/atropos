"""DDG export: Graphviz DOT and machine-readable JSON.

Design v0.2 section 9.2.  The graph view answers a different question from the
listing: not "what ran" but "what depends on what".  Loop bodies are the reason
this needs care — a slice through a 4 000-iteration decode loop has 4 000 copies
of three nodes, which as a picture is unreadable and as a file is enormous.

``collapse=True`` groups instances of one static address into one node and keeps
the edge multiset, which turns that picture back into three boxes and a
self-loop labelled x4000.  That is almost always what you want to look at, so it
is the default for DOT and off for JSON (where a consumer wants the real graph).
"""

from __future__ import annotations

import json

from ..arch.effects import KIND_CONTROL, KIND_NAMES
from ..ddg import format_node_flags
from ..shadow import LIVE_IN
from ..slicer import SliceResult

_KIND_STYLE = {
    0: ("black", "solid"),  # value
    1: ("#3b7dd8", "dashed"),  # address
    2: ("#c0392b", "dotted"),  # control
}


def to_dot(
    analysis,
    slice_result: SliceResult,
    collapse: bool = True,
    show_control: bool = True,
) -> str:
    ddg = analysis.ddg
    bundle = analysis.bundle
    model = analysis.result.model
    included = set(slice_result.nodes)

    def label_of(seq: int) -> str:
        block_id = ddg.node_block[seq]
        if block_id < 0:
            return ddg.summary_nodes.get(seq, "<summary>")
        block = bundle.blocks.get(block_id)
        raw = block.insns[ddg.node_index[seq]].raw if block else b""
        mnemonic, op_str = model.disassemble(raw, ddg.node_addr[seq])
        return f"{mnemonic} {op_str}".strip()

    def node_key(seq: int):
        return ddg.node_addr[seq] if collapse else seq

    counts: dict[object, int] = {}
    representative: dict[object, int] = {}
    for seq in slice_result.nodes:
        key = node_key(seq)
        counts[key] = counts.get(key, 0) + 1
        representative.setdefault(key, seq)

    edges: dict[tuple[object, object, int], int] = {}
    for seq in slice_result.nodes:
        for i in ddg.edge_range(seq):
            def_seq = ddg.edge_def[i]
            if def_seq == LIVE_IN or def_seq not in included:
                continue
            if not slice_result.mode.allows(ddg.edge_kind[i]):
                continue
            key = (node_key(def_seq), node_key(seq), ddg.edge_kind[i])
            edges[key] = edges.get(key, 0) + 1
        if show_control and slice_result.mode.follow_control:
            guard = ddg.node_ctrl[seq]
            if guard != LIVE_IN and guard in included:
                key = (node_key(guard), node_key(seq), KIND_CONTROL)
                edges[key] = edges.get(key, 0) + 1

    out = [
        "digraph atropos_slice {",
        '  graph [rankdir=BT, fontname="Helvetica", bgcolor="transparent"];',
        '  node  [shape=box, style="rounded,filled", fillcolor="#f4f4f5", '
        'fontname="Menlo,Consolas,monospace", fontsize=10, color="#c8c8cc"];',
        '  edge  [fontname="Helvetica", fontsize=8];',
    ]

    for key, seq in representative.items():
        text = label_of(seq).replace('"', r"\"")
        where = bundle.rebase(ddg.node_addr[seq])
        repeat = counts[key]
        flags = format_node_flags(ddg.node_flags[seq])
        label = f"{where}\\n{text}"
        if collapse and repeat > 1:
            label += f"\\n(x{repeat})"
        if flags:
            label += f"\\n[{flags}]"
        fill = "#fdf0d5" if flags else "#f4f4f5"
        if seq == slice_result.criterion.seq or slice_result.inclusions.get(seq, None) and slice_result.inclusions[seq].via_seq < 0:
            fill = "#d7f0d7"
        out.append(f'  n{_ident(key)} [label="{label}", fillcolor="{fill}"];')

    for (src, dst, kind), count in edges.items():
        colour, style = _KIND_STYLE.get(kind, ("black", "solid"))
        label = KIND_NAMES.get(kind, "?")
        if count > 1:
            label += f" x{count}"
        out.append(
            f'  n{_ident(dst)} -> n{_ident(src)} '
            f'[label="{label}", color="{colour}", style={style}];'
        )

    out.append("}")
    return "\n".join(out)


def _ident(key) -> str:
    return str(key).replace("-", "_")


def to_json(analysis, slice_result: SliceResult, collapse: bool = False) -> str:
    """A complete, machine-readable dump of the slice.

    Everything a downstream tool needs and nothing it has to re-derive: the
    edges carry their kind and byte range, the nodes carry their code version
    and annotations, and the precision banner travels with the data rather than
    being left behind in a terminal.
    """
    ddg = analysis.ddg
    bundle = analysis.bundle
    model = analysis.result.model
    included = set(slice_result.nodes)
    occurrence = ddg.occurrence_index()

    nodes = []
    for seq in slice_result.nodes:
        block_id = ddg.node_block[seq]
        entry = {
            "seq": seq,
            "address": ddg.node_addr[seq],
            "location": bundle.rebase(ddg.node_addr[seq]),
            "code_version": ddg.node_version[seq],
            "occurrence": occurrence[seq],
            "thread": ddg.node_tid[seq],
            "flags": format_node_flags(ddg.node_flags[seq]),
        }
        if block_id < 0:
            entry["summary"] = ddg.summary_nodes.get(seq, "<summary>")
        else:
            block = bundle.blocks.get(block_id)
            raw = block.insns[ddg.node_index[seq]].raw if block else b""
            mnemonic, op_str = model.disassemble(raw, ddg.node_addr[seq])
            entry["text"] = f"{mnemonic} {op_str}".strip()
            entry["bytes"] = raw.hex()
        inclusion = slice_result.inclusions.get(seq)
        if inclusion is not None:
            entry["why"] = inclusion.render(ddg)
        nodes.append(entry)

    edges = []
    for seq in slice_result.nodes:
        for i in ddg.edge_range(seq):
            def_seq = ddg.edge_def[i]
            if def_seq == LIVE_IN or def_seq not in included:
                continue
            if not slice_result.mode.allows(ddg.edge_kind[i]):
                continue
            edges.append({
                "use": seq,
                "def": def_seq,
                "kind": KIND_NAMES[ddg.edge_kind[i]],
                "space": "reg" if ddg.edge_space[i] == 0 else "mem",
                "loc": ddg.edge_loc[i],
                "length": ddg.edge_len[i],
            })
        guard = ddg.node_ctrl[seq]
        if slice_result.mode.follow_control and guard != LIVE_IN and guard in included:
            edges.append({"use": seq, "def": guard, "kind": "control"})

    return json.dumps(
        {
            "atropos": {"format": 1},
            "criterion": {
                "seq": slice_result.criterion.seq,
                "description": slice_result.criterion.description,
                "locations": [loc.render() for loc in slice_result.criterion.locations],
            },
            "mode": slice_result.mode.describe(),
            "stats": slice_result.stats,
            "truncated": slice_result.truncated,
            "truncation_reason": slice_result.truncation_reason,
            "precision": analysis.precision_banner(),
            "nodes": nodes,
            "edges": edges,
            "inputs": [
                {
                    "space": "reg" if leaf.space == 0 else "mem",
                    "loc": leaf.loc,
                    "length": leaf.length,
                    "used_by": leaf.used_by,
                    "render": leaf.render(),
                }
                for leaf in slice_result.inputs
            ],
        },
        indent=2,
    )
