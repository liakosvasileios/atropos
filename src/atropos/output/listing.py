"""The annotated linear listing — the primary artifact.

Design v0.2 section 9.1.  A set of sequence numbers is not an answer; an
analyst needs to read the slice as code, in execution order, with each line
saying *why it is there*.  That last part is success criterion 3, and it is
what separates a slicer from a filter: every line carries the definition it
satisfies, for which use, and by which kind of edge.

Loop summarisation (section 9.5) is folded in here rather than in a separate
pass, because "the same three instructions, four thousand times" is a property
of the rendering, not of the graph.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..arch.effects import KIND_CONTROL, KIND_NAMES
from ..ddg import format_node_flags
from ..slicer import SliceResult


@dataclass
class ListingOptions:
    show_why: bool = True
    show_flags: bool = True
    fold_loops: bool = False
    #: When folding, a static address executed at least this many times in the
    #: slice is collapsed to one line with a count.
    fold_threshold: int = 3
    context: int = 0
    max_lines: int | None = None
    colour: bool = False


_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def render_listing(
    analysis, slice_result: SliceResult, options: ListingOptions | None = None
) -> str:
    options = options or ListingOptions()
    ddg = analysis.ddg
    bundle = analysis.bundle
    model = analysis.result.model
    occurrence = ddg.occurrence_index()

    lines: list[str] = []
    lines.extend(_header(analysis, slice_result))

    if options.fold_loops:
        rows = _fold(ddg, slice_result, options)
    else:
        rows = [(seq, 1) for seq in slice_result.nodes]

    if options.max_lines is not None and len(rows) > options.max_lines:
        omitted = len(rows) - options.max_lines
        rows = rows[: options.max_lines]
    else:
        omitted = 0

    for seq, repeat in rows:
        lines.append(
            _render_row(
                analysis, slice_result, seq, repeat, occurrence, model, bundle, options
            )
        )

    if omitted:
        lines.append(f"    ... {omitted} more line(s) not shown (--max-lines)")

    if slice_result.truncated:
        lines.append("")
        lines.append(f"!! SLICE TRUNCATED: {slice_result.truncation_reason}")
        lines.append("   The chain above is incomplete. Raise the cap to see the rest.")

    return "\n".join(lines)


def _header(analysis, slice_result: SliceResult) -> list[str]:
    stats = slice_result.stats
    reduction = stats.get("reduction", 0.0) * 100
    lines = [
        "=" * 78,
        f"ATROPOS backward slice  —  criterion {slice_result.criterion.render()}",
        f"mode: {slice_result.mode.describe()}"
        f"   |   {stats.get('nodes', 0)} of {stats.get('trace_nodes', 0)} "
        f"instruction instances ({reduction:.1f}% discarded)",
        "-" * 78,
    ]
    for line in analysis.precision_banner():
        lines.append(f"  {line}")
    lines.append("=" * 78)
    lines.append("")
    return lines


def _fold(ddg, slice_result: SliceResult, options: ListingOptions):
    """Collapse repeated executions of one static address into a single row."""
    counts: dict[int, int] = {}
    for seq in slice_result.nodes:
        key = ddg.node_addr[seq]
        counts[key] = counts.get(key, 0) + 1

    rows: list[tuple[int, int]] = []
    emitted: set[int] = set()
    for seq in slice_result.nodes:
        key = ddg.node_addr[seq]
        if counts[key] >= options.fold_threshold:
            if key in emitted:
                continue
            emitted.add(key)
            rows.append((seq, counts[key]))
        else:
            rows.append((seq, 1))
    return rows


def _render_row(
    analysis, slice_result, seq, repeat, occurrence, model, bundle, options
) -> str:
    ddg = analysis.ddg
    block_id = ddg.node_block[seq]

    if block_id < 0:
        name = ddg.summary_nodes.get(seq, "<summary>")
        text = f"{name}(...)"
        where = "[summary]"
    else:
        block = bundle.blocks.get(block_id)
        raw = block.insns[ddg.node_index[seq]].raw if block else b""
        mnemonic, op_str = model.disassemble(raw, ddg.node_addr[seq])
        text = f"{mnemonic} {op_str}".strip()
        where = bundle.rebase(ddg.node_addr[seq])

    occ = occurrence[seq]
    version = ddg.node_version[seq]
    prefix = f"  #{seq:<8d} {where:<28s}"
    if repeat > 1:
        body = f"{text:<34s} x{repeat}"
    else:
        body = f"{text:<34s}"

    parts = [prefix + body]

    tags = []
    if occ:
        tags.append(f"occ={occ}")
    if version:
        tags.append(f"v{version}")
    if options.show_flags:
        flags = format_node_flags(ddg.node_flags[seq])
        if flags:
            tags.append(flags)
    if tags:
        parts.append(f"  [{' '.join(tags)}]")

    if options.show_why:
        inclusion = slice_result.inclusions.get(seq)
        if inclusion is not None:
            parts.append(f"\n{' ' * 14}<- {inclusion.render(ddg)}")

    return "".join(parts)


def render_inputs(analysis, slice_result: SliceResult) -> str:
    """The live-in report (design v0.2 section 9.4).

    For the crypto workflow this *is* the answer.  A slice that bottoms out in
    "a hardcoded constant and the volume serial number from
    ``GetVolumeInformationW``" has told the analyst what the key is derived
    from; the instruction listing above it is merely the derivation.

    Three kinds of leaf, and the distinction is the whole point:

    *Environmental* — an API summary of kind ``source`` fed the slice.  Named,
    with the API that produced it.  This is the interesting one.

    *Immediate* — a node in the slice consumes nothing, so its contribution is
    a constant baked into the code.  A hardcoded seed shows up here.

    *Unwritten storage* — memory or a register nothing in the trace wrote:
    initial image data, state that predates the trace window, or a write by
    something untraced.  The three are distinguished where the module map
    allows it and reported honestly where it does not.
    """
    ddg = analysis.ddg

    environmental: list[tuple[int, str]] = []
    immediates: list[int] = []
    for seq in slice_result.nodes:
        kind = ddg.summary_kinds.get(seq)
        if kind in ("source", "alloc", "unknown"):
            environmental.append((seq, ddg.summary_nodes.get(seq, "<summary>")))
            continue
        if kind is not None:
            continue
        if not any(
            slice_result.mode.allows(ddg.edge_kind[i]) for i in ddg.edge_range(seq)
        ):
            immediates.append(seq)

    grouped: dict[str, list] = {}
    for leaf in slice_result.inputs:
        grouped.setdefault(_classify_input(analysis, leaf), []).append(leaf)

    if not (grouped or environmental or immediates):
        return "inputs: none — the slice is closed within the traced execution."

    lines = ["INPUTS — where this value ultimately came from", "-" * 78]

    if environmental:
        lines.append(f"  environmental (from outside the process)  ({len(environmental)})")
        for seq, name in environmental[:12]:
            kind = ddg.summary_kinds.get(seq, "?")
            lines.append(f"      #{seq}  {name}  [{kind}]")

    if immediates:
        lines.append(f"  immediate constants in the code  ({len(immediates)})")
        for seq in immediates[:12]:
            lines.append(f"      #{seq}  {_text_of(analysis, seq)}")
        if len(immediates) > 12:
            lines.append(f"      ... and {len(immediates) - 12} more")

    for source in sorted(grouped):
        leaves = grouped[source]
        lines.append(f"  {source}  ({len(leaves)})")
        merged = _merge_adjacent(leaves)
        for leaf in merged[:12]:
            lines.append(f"      {leaf.render()}")
        if len(merged) > 12:
            lines.append(f"      ... and {len(merged) - 12} more")
    return "\n".join(lines)


def _text_of(analysis, seq: int) -> str:
    ddg = analysis.ddg
    bundle = analysis.bundle
    block = bundle.blocks.get(ddg.node_block[seq])
    if block is None:
        return ddg.summary_nodes.get(seq, "<summary>")
    raw = block.insns[ddg.node_index[seq]].raw
    mnemonic, op_str = analysis.result.model.disassemble(raw, ddg.node_addr[seq])
    return f"{bundle.rebase(ddg.node_addr[seq])}   {mnemonic} {op_str}".strip()


def _classify_input(analysis, leaf) -> str:
    """Name the origin of a live-in leaf as precisely as the trace allows."""
    from ..ddg import SPACE_MEM

    ddg = analysis.ddg
    bundle = analysis.bundle
    if leaf.space == SPACE_MEM:
        module = bundle.module_for(leaf.loc)
        if module is not None:
            return f"initial image data ({module.name})"
        return "memory not written during the trace (initial state or untraced writer)"
    return "register live-in (set before tracing began)"


def _merge_adjacent(leaves):
    """Coalesce byte-granular leaves into readable ranges."""
    from ..ddg import SPACE_MEM

    ordered = sorted(leaves, key=lambda l: (l.space, l.loc))
    out = []
    for leaf in ordered:
        if (
            out
            and out[-1].space == leaf.space == SPACE_MEM
            and out[-1].loc + out[-1].length == leaf.loc
            and out[-1].used_by == leaf.used_by
        ):
            merged = out[-1]
            out[-1] = type(leaf)(
                merged.space, merged.loc, merged.length + leaf.length,
                merged.used_by, merged.kind,
            )
        else:
            out.append(leaf)
    return out
