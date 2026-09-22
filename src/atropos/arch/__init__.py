"""Architecture-specific modelling.

Only x86-64 is implemented.  The split between :mod:`atropos.arch.lanes` (what
storage exists) and :mod:`atropos.arch.effects` (what instructions do to it) is
the seam another architecture would be added at: the replay engine, the DDG and
the slicer are all defined over abstract storage locations and never mention an
x86 register by name.
"""

from . import effects, lanes  # noqa: F401

__all__ = ["lanes", "effects"]
