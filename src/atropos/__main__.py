"""Allow ``python -m atropos ...`` alongside the installed ``atropos`` script.

Without this, the hint printed at the end of a capture (``atropos info ...``)
only works for an installed package, and running it out of a source tree gives
"'atropos' is a package and cannot be directly executed".
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
