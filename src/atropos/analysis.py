"""The pipeline: bundle in, sliceable analysis out.

One place that knows the order the passes run in, so the CLI, the tests and any
embedding code all get the same thing:

1. **Replay** — forward pass, shadow state, data edges (:mod:`atropos.replay`).
2. **Continuity** — structural integrity of the trace (:mod:`atropos.integrity`).
3. **Control flow** — CFG recovery, post-dominance, flattening detection, and
   attribution of each instance to its guarding branch (:mod:`atropos.cfg`).

Control-flow analysis runs even when the requested slice mode does not follow
control edges, because it is cheap relative to replay and because the flattening
report belongs in the precision banner whether or not this particular slice used
it.  ``skip_control=True`` is available for the tight loop of the differential
fuzzer, where only data dependence is under test.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .bundle import TraceBundle
from .cfg import ControlFlowAnalysis, analyse_control_flow
from .integrity import check_continuity
from .replay import ReplayOptions, ReplayResult, replay
from .summaries import SummaryTable


@dataclass
class Analysis:
    """Everything downstream needs, and the timings to explain where it went."""

    result: ReplayResult
    control: ControlFlowAnalysis | None = None
    timings: dict[str, float] = field(default_factory=dict)

    # Convenience passthroughs — these are used constantly and the indirection
    # is pure noise at the call sites.
    @property
    def ddg(self):
        return self.result.ddg

    @property
    def bundle(self) -> TraceBundle:
        return self.result.bundle

    @property
    def integrity(self):
        return self.result.integrity

    @property
    def stats(self) -> dict:
        return self.result.stats

    def precision_banner(self) -> list[str]:
        """The confidence statement every report leads with (design v0.2 §9.6).

        An analyst reading a slice has no way to tell, from the slice alone,
        whether the tool was sure.  Saying so explicitly is not politeness; it
        is the difference between "the key comes from the volume serial" and
        "the key comes from the volume serial, and by the way three edges in
        that chain crossed an unmodelled API call".
        """
        lines = [self.integrity.banner()]

        flags = self.ddg.flag_histogram()
        noteworthy = {k: v for k, v in flags.items() if v}
        if noteworthy:
            lines.append(
                "node annotations: "
                + ", ".join(f"{v} {k}" for k, v in sorted(noteworthy.items()))
            )

        if self.control is not None:
            if self.control.flattened_functions:
                lines.append(
                    f"control dependence: unavailable in "
                    f"{len(self.control.flattened_functions)} function(s) "
                    "(control-flow flattening detected)"
                )
                lines.extend("  " + note for note in self.control.notes)
            else:
                lines.append(
                    f"control dependence: {len(self.control.functions)} function(s) "
                    "analysed, no flattening detected"
                )

        if self.stats.get("rep_bulk"):
            lines.append(
                f"{self.stats['rep_bulk']} rep-prefixed instruction(s) modelled in "
                "bulk; byte-exact provenance through them needs --expand-rep"
            )
        if self.stats.get("shift_zero_count"):
            lines.append(
                f"{self.stats['shift_zero_count']} variable shift(s) had a zero "
                "count and correctly defined nothing"
            )
        return lines


def analyse(
    bundle: TraceBundle,
    options: ReplayOptions | None = None,
    summaries: SummaryTable | None = None,
    skip_control: bool = False,
    force_control: bool = False,
) -> Analysis:
    timings: dict[str, float] = {}

    started = time.perf_counter()
    result = replay(bundle, options=options, summaries=summaries)
    timings["replay"] = time.perf_counter() - started

    started = time.perf_counter()
    check_continuity(result)
    timings["continuity"] = time.perf_counter() - started

    control = None
    if not skip_control:
        started = time.perf_counter()
        control = analyse_control_flow(result, force=force_control)
        timings["control_flow"] = time.perf_counter() - started

    return Analysis(result=result, control=control, timings=timings)


def analyse_path(path, **kwargs) -> Analysis:
    return analyse(TraceBundle(path), **kwargs)
