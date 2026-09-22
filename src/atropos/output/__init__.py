"""Output backends.

Five views of the same slice, because "the slice" is not one artifact:

* :mod:`~atropos.output.listing` — the annotated linear listing and the input
  report.  The thing an analyst reads.
* :mod:`~atropos.output.graph` — DOT and JSON exports of the dependence graph.
  The thing an analyst looks at when the question is "what depends on what".
* :mod:`~atropos.output.bridge` — IDA and Ghidra loaders.  The thing an analyst
  actually works in.
"""

from .bridge import GHIDRA_SCRIPT, IDA_SCRIPT, to_bridge_json, write_scripts
from .graph import to_dot, to_json
from .listing import ListingOptions, render_inputs, render_listing

__all__ = [
    "ListingOptions",
    "render_listing",
    "render_inputs",
    "to_dot",
    "to_json",
    "to_bridge_json",
    "write_scripts",
    "IDA_SCRIPT",
    "GHIDRA_SCRIPT",
]
