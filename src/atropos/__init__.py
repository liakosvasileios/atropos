"""Atropos — a backward dynamic program slicer for Windows x86-64.

    "For this value, at this point in the run, which instructions actually
     contributed to producing it — and which inputs did it ultimately depend on?"

Atropos answers that question about one concrete execution.  Capture runs inside
the target under Frida's Stalker; everything else runs offline over a recorded
trace bundle.  See ``docs/design-v0.2.md`` for the full design and
``docs/architecture-review.md`` for the analysis of why it is built this way.

Typical use::

    from atropos import analyse_path, build_criterion, backward_slice, MODES

    analysis = analyse_path("run.atrace")
    criterion = build_criterion("mark=1", ["mem=0x7ff6c0001000+16"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
"""

from .analysis import Analysis, analyse, analyse_path
from .bundle import BlockDescriptor, BundleWriter, Module, TraceBundle
from .criterion import Criterion, CriterionError, Location, build_criterion
from .ddg import DDG, Edge
from .replay import ReplayOptions, ReplayResult, replay
from .slicer import (
    MODES,
    InputLeaf,
    SliceMode,
    SliceResult,
    backward_slice,
    chop,
    forward_slice,
)
from .summaries import Summary, SummaryTable

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Analysis",
    "analyse",
    "analyse_path",
    "TraceBundle",
    "BundleWriter",
    "BlockDescriptor",
    "Module",
    "Criterion",
    "CriterionError",
    "Location",
    "build_criterion",
    "DDG",
    "Edge",
    "ReplayOptions",
    "ReplayResult",
    "replay",
    "MODES",
    "SliceMode",
    "SliceResult",
    "InputLeaf",
    "backward_slice",
    "forward_slice",
    "chop",
    "Summary",
    "SummaryTable",
]
