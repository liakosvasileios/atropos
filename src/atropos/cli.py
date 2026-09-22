"""Command-line interface.

    atropos info    run.atrace
    atropos slice   run.atrace --at seq=41792 --loc rdx --loc mem=0x7ff6c0001000+16
    atropos verify  run.atrace
    atropos demo    --workflow xor-decoder

The verbs map onto the pipeline stages, and every one of them prints the
precision banner (design v0.2 section 9.6).  That is deliberate: a slice
without its confidence statement is a claim without its evidence, and the
whole point of the integrity work is that the analyst never has to guess how
much to trust what they are reading.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import analyse_path
from .criterion import CriterionError, build_criterion
from .output import (
    ListingOptions,
    render_inputs,
    render_listing,
    to_bridge_json,
    to_dot,
    to_json,
    write_scripts,
)
from .replay import ReplayOptions
from .slicer import MODES, backward_slice, chop, forward_slice


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("bundle", help="path to a .atrace bundle directory")
    parser.add_argument(
        "--expand-rep",
        action="store_true",
        help="record byte-exact provenance through rep-prefixed string ops "
             "instead of the bulk model (design v0.2 section 6.6)",
    )
    parser.add_argument(
        "--allow-suspect",
        action="store_true",
        help="proceed even if the trace failed an integrity check. The results "
             "may describe a different execution than the one that happened.",
    )


def _load(args):
    options = ReplayOptions(expand_rep=getattr(args, "expand_rep", False))
    analysis = analyse_path(
        args.bundle,
        options=options,
        force_control=getattr(args, "force_cd", False),
    )
    if analysis.integrity.n_errors and not getattr(args, "allow_suspect", False):
        print(analysis.integrity.render(), file=sys.stderr)
        print(
            "\nRefusing to slice a suspect trace. A corrupt trace still produces a\n"
            "plausible-looking slice, which is worse than no slice. Re-capture, or\n"
            "pass --allow-suspect if you understand what the findings above mean.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return analysis


# --------------------------------------------------------------------------
# Verbs
# --------------------------------------------------------------------------


def cmd_info(args) -> int:
    analysis = _load(args)
    bundle = analysis.bundle
    ddg = analysis.ddg
    stats = analysis.stats

    print(f"bundle       {Path(args.bundle).resolve()}")
    print(f"arch/os      {bundle.meta.get('arch')} / {bundle.meta.get('os')}")
    print(f"capture      {bundle.meta.get('capture', {})}")
    print()
    print(f"instructions {stats['instructions']:>12,}")
    print(f"blocks       {stats['blocks']:>12,}  ({len(bundle.blocks):,} distinct)")
    print(f"mem accesses {stats['mem_accesses']:>12,}")
    print(f"DDG          {ddg.n_nodes:>12,} nodes, {ddg.n_edges:,} edges, "
          f"~{ddg.approx_bytes() / 1e6:.1f} MB")
    print(f"edge kinds   {ddg.edge_kind_histogram()}")
    print()
    print("modules:")
    for module in bundle.modules:
        print(f"  {module.name:<24s} 0x{module.base:012x} +0x{module.size:x}")
    if ddg.marks:
        print("\nmarks:")
        for mark_id, seq in ddg.marks:
            print(f"  mark={mark_id:<4d} at #{seq}")
    if ddg.version_changes:
        print("\ncode version changes (self-modifying code):")
        for seq, version in ddg.version_changes:
            print(f"  #{seq}: -> v{version}")
    print("\ntimings:")
    for name, seconds in analysis.timings.items():
        print(f"  {name:<14s} {seconds:6.2f}s")
    print()
    for line in analysis.precision_banner():
        print(line)
    return 0


def cmd_verify(args) -> int:
    args.allow_suspect = True
    analysis = _load(args)
    print(analysis.integrity.render(limit=args.limit))
    print()
    for line in analysis.precision_banner():
        print(line)
    return 1 if analysis.integrity.n_errors else 0


def cmd_slice(args) -> int:
    analysis = _load(args)
    try:
        criterion = build_criterion(args.at, args.loc, analysis.result)
    except CriterionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    mode = MODES[args.mode]
    if args.direction == "forward":
        result = forward_slice(analysis.result, criterion, mode, max_nodes=args.max_nodes)
    elif args.direction == "chop":
        if not args.to:
            print("error: --direction chop requires --to", file=sys.stderr)
            return 2
        try:
            sink = build_criterion(args.to, args.loc, analysis.result)
        except CriterionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        result = chop(analysis.result, criterion, sink, mode)
    else:
        result = backward_slice(
            analysis.result,
            criterion,
            mode,
            max_nodes=args.max_nodes,
            max_control_depth=args.max_control_depth,
        )

    options = ListingOptions(
        fold_loops=args.fold_loops,
        max_lines=args.max_lines,
        show_why=not args.no_why,
    )

    if args.format == "listing":
        print(render_listing(analysis, result, options))
        print()
        print(render_inputs(analysis, result))
    elif args.format == "dot":
        print(to_dot(analysis, result, collapse=not args.no_collapse))
    elif args.format == "json":
        print(to_json(analysis, result))
    elif args.format == "bridge":
        print(to_bridge_json(analysis, result))

    if args.write_scripts:
        for path in write_scripts(args.write_scripts):
            print(f"wrote {path}", file=sys.stderr)
    return 0


def cmd_demo(args) -> int:
    """Build a fixture bundle and slice it, with no target process involved.

    Useful as a smoke test after installation and as the shortest possible
    illustration of what the tool does.
    """
    import tempfile

    from .examples import WORKFLOWS

    workflow = WORKFLOWS[args.workflow]
    directory = Path(args.out) if args.out else Path(tempfile.mkdtemp()) / "demo.atrace"
    bundle, criterion_spec, note = workflow(directory)
    print(f"built fixture bundle at {bundle.path}")
    print(note)
    print()

    analysis = analyse_path(bundle.path)
    criterion = build_criterion(criterion_spec[0], criterion_spec[1], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES[args.mode])
    print(render_listing(analysis, result, ListingOptions(fold_loops=True)))
    print()
    print(render_inputs(analysis, result))
    return 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atropos",
        description="Backward dynamic program slicing for Windows x86-64.",
    )
    parser.add_argument("--version", action="version", version=f"atropos {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="summarise a trace bundle")
    _add_common(p_info)
    p_info.set_defaults(func=cmd_info)

    p_verify = sub.add_parser("verify", help="run integrity checks and report")
    _add_common(p_verify)
    p_verify.add_argument("--limit", type=int, default=40)
    p_verify.set_defaults(func=cmd_verify)

    p_slice = sub.add_parser("slice", help="compute and render a slice")
    _add_common(p_slice)
    p_slice.add_argument(
        "--at", required=True,
        help="the point: seq=N | addr=<addr>[@occurrence] | mark=N",
    )
    p_slice.add_argument(
        "--loc", action="append", required=True, metavar="LOCATION",
        help="a location at that point; repeatable. "
             "e.g. rdx, al, zf, rbx[0:3], mem=0x7ff6c0001000+16",
    )
    p_slice.add_argument(
        "--mode", choices=sorted(MODES), default="value",
        help="which edge kinds to follow (design v0.2 section 7.3). "
             "'value' answers 'what arithmetic made this'; add 'addr' for "
             "pointer provenance and 'ctrl' for the branches that got us here.",
    )
    p_slice.add_argument(
        "--direction", choices=("backward", "forward", "chop"), default="backward",
    )
    p_slice.add_argument("--to", help="sink point for --direction chop")
    p_slice.add_argument(
        "--format", choices=("listing", "dot", "json", "bridge"), default="listing",
    )
    p_slice.add_argument("--max-nodes", type=int, default=None)
    p_slice.add_argument("--max-control-depth", type=int, default=None)
    p_slice.add_argument("--max-lines", type=int, default=None)
    p_slice.add_argument("--fold-loops", action="store_true",
                         help="collapse repeated executions of one address")
    p_slice.add_argument("--no-why", action="store_true",
                         help="omit the per-line inclusion reason")
    p_slice.add_argument("--no-collapse", action="store_true",
                         help="for --format dot: keep every instance as its own node")
    p_slice.add_argument("--force-cd", action="store_true",
                         help="emit control edges even in functions detected as "
                              "control-flow flattened (design v0.2 section 7.2)")
    p_slice.add_argument("--write-scripts", metavar="DIR",
                         help="also write the IDA and Ghidra loader scripts there")
    p_slice.set_defaults(func=cmd_slice)

    p_demo = sub.add_parser("demo", help="build and slice a fixture, no target needed")
    p_demo.add_argument("--workflow", default="xor-decoder")
    p_demo.add_argument("--mode", choices=sorted(MODES), default="value")
    p_demo.add_argument("--out", help="where to write the fixture bundle")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
