"""Where the test corpora live.

The regression suite needs real prefetch files, and real prefetch files contain the account
names and installed software of whoever's machine they came from. So the corpora are **not in
this repository** and their location is configuration, not a hardcoded path - which also means
anyone can point the suite at their own collection.

    export PREFETCH_CORPUS_WIN10=/path/to/a/Win10/Prefetch
    export PREFETCH_CORPUS_WIN11=/path/to/a/Win11/Prefetch
    export PECMD_CSV=/path/to/PECmd_Output.csv     # only for diff_against_pecmd.py

`reference/pf-corpus/` is different: it is the upstream project's published test corpus, which
is synthetic sample data rather than anyone's machine, so it ships with the repository.

A suite whose corpus is missing says so and skips, rather than passing vacuously - "no files
found, therefore no mismatches" is the worst possible green.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Shipped with the repo: the upstream project's published test files, all versions.
VENDORED = os.path.join(HERE, "pf-corpus")

WIN10 = os.environ.get("PREFETCH_CORPUS_WIN10", "")
WIN11 = os.environ.get("PREFETCH_CORPUS_WIN11", "")
PECMD_CSV = os.environ.get("PECMD_CSV", "")


def require(*paths):
    """Exit with a clear message if a needed corpus is not configured."""
    missing = [p for p in paths if not p or not os.path.exists(p)]
    if missing:
        print("This suite needs a prefetch corpus that is not in the repository.\n"
              "Set PREFETCH_CORPUS_WIN10 / PREFETCH_CORPUS_WIN11 (and PECMD_CSV for the\n"
              "PECmd differential) to folders on your machine. See reference/corpus.py.",
              file=sys.stderr)
        return False
    return True
