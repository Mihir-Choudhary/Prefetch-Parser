"""What the regression suite needs from this machine, and where to find it.

The suite needs real prefetch files, and real prefetch files contain the account names and
installed software of whoever's machine they came from. So the corpora are **not in this
repository** and their location is configuration, not a hardcoded path - which also means
anyone can point the suite at their own collection.

Configure them in the environment:

    export PREFETCH_CORPUS_WIN10=/path/to/a/Win10/Prefetch
    export PREFETCH_CORPUS_WIN11=/path/to/a/Win11/Prefetch
    export PECMD_CSV=/path/to/PECmd_Output.csv     # only for diff_against_pecmd.py
    export PREFETCH_SAMPLES=/path/to/external-samples   # third-party corpora, see its MANIFEST
    export PREFETCH_PYLIBS=/path/to/pip-target-dir      # where PySide6 lives, if not installed
                                                        # system-wide (see require_qt below)

...or, so the configuration outlives the shell that set it, in a `corpus-paths.env` file at
the repository root - `KEY=/path` per line, `#` comments allowed. It is gitignored for the
same reason the corpora are not committed: the paths name someone's machine. The environment
wins over the file, so a one-off run against a different collection needs no edit.

`reference/pf-corpus/` is different: it is the upstream project's published test corpus, which
is synthetic sample data rather than anyone's machine, so it ships with the repository. It is
54 files and covers four of the five format versions; it is not a substitute for the real
corpora and no documented figure in `docs/` is derived from it alone.

**A suite that cannot run must say so and skip - never pass, and never report a finding.**
Both halves of that matter. A suite that quietly runs on a fraction of its inputs and prints
the same PASS is the worst possible green; a suite that prints "docs and measurement disagree"
because it measured nothing has invented a finding out of a missing setting. `require()` below
exits with `SKIP_EXIT`, which `run_tests.sh` reports as SKIP and refuses to count as a pass.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# autotools' convention for "this did not run", deliberately distinct from 0 (passed) and from
# 1 (failed). A skipped suite proves nothing, so run_tests.sh propagates it rather than
# swallowing it.
SKIP_EXIT = 77

# CORPUS_PATHS_FILE overrides it, which is how the skip path itself gets tested: point it at
# /dev/null with the variables unset and the suite is genuinely unconfigured.
PATHS_FILE = os.environ.get("CORPUS_PATHS_FILE") or os.path.join(ROOT, "corpus-paths.env")

SETTINGS = ("PREFETCH_CORPUS_WIN10", "PREFETCH_CORPUS_WIN11", "PECMD_CSV",
            "PREFETCH_SAMPLES", "PREFETCH_PYLIBS")


def _from_file(path=PATHS_FILE):
    """Parse `KEY=value` lines out of corpus-paths.env. Absent file, empty dict."""
    values = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key in SETTINGS:
                    values[key] = os.path.expanduser(value)
    except OSError:
        pass
    return values


_FILE_VALUES = _from_file()


def _setting(name):
    """Environment first, then the file. An empty env var counts as unset, not as ''."""
    return os.environ.get(name) or _FILE_VALUES.get(name, "")


# Shipped with the repo: the upstream project's published test files.
VENDORED = os.path.join(HERE, "pf-corpus")

WIN10 = _setting("PREFETCH_CORPUS_WIN10")
WIN11 = _setting("PREFETCH_CORPUS_WIN11")
PECMD_CSV = _setting("PECMD_CSV")
# Third-party sample corpora downloaded for coverage the two real folders cannot give -
# a Windows 7 SuperFetch database above all. Provenance in that directory's MANIFEST.md.
SAMPLES = _setting("PREFETCH_SAMPLES")
# Where PySide6 lives when it is not installed system-wide. Put on sys.path at import so the
# GUI suites run without every caller having to set PYTHONPATH - the Qt bindings being missing
# is a property of the machine, not of the tool, and one line of configuration fixes it.
PYLIBS = _setting("PREFETCH_PYLIBS")
if PYLIBS and os.path.isdir(PYLIBS) and PYLIBS not in sys.path:
    sys.path.insert(0, PYLIBS)

# Short aliases, so a suite can say what it needs by name and the skip message can name it
# back. Passing the *value* would not work: an unset setting is "" and "" cannot say which
# setting it came from - which is how the first version of this reported every unset variable
# for a suite that needed two of them.
ALIASES = {"WIN10": "PREFETCH_CORPUS_WIN10",
           "WIN11": "PREFETCH_CORPUS_WIN11",
           "PECMD": "PECMD_CSV",
           "SAMPLES": "PREFETCH_SAMPLES",
           "PYLIBS": "PREFETCH_PYLIBS"}

_VALUES = {"PREFETCH_CORPUS_WIN10": WIN10,
           "PREFETCH_CORPUS_WIN11": WIN11,
           "PECMD_CSV": PECMD_CSV,
           "PREFETCH_SAMPLES": SAMPLES,
           "PREFETCH_PYLIBS": PYLIBS}


def skip(reason, hint=""):
    """Exit SKIP_EXIT with a reason. Never call this to report a *result*."""
    print(f"SKIP: {reason}", file=sys.stderr)
    if hint:
        print(hint, file=sys.stderr)
    sys.exit(SKIP_EXIT)


def require(*aliases):
    """Skip unless every corpus this suite needs is configured and present.

    Call it at the top of `main()`, before anything reads a file:

        corpus.require("WIN10", "WIN11")

    Suites used to discover a missing corpus halfway through and report it as drift in the
    documented figures, as a moved corpus, or as a traceback - three different ways of blaming
    the evidence for an unset variable.
    """
    problems = []
    for alias in aliases:
        name = ALIASES[alias]        # a typo here is a bug in the suite, not a skip
        value = _VALUES[name]
        if not value:
            problems.append(f"  {name}: not set")
        elif not os.path.exists(value):
            problems.append(f"  {name}: set to {value} - which does not exist")
    if not problems:
        return True
    where = (f"or in {PATHS_FILE}" if os.path.exists(PATHS_FILE)
             else f"or in a corpus-paths.env at the repository root ({PATHS_FILE})")
    skip("this suite needs a prefetch corpus that is not configured.\n" + "\n".join(problems),
         f"Set it in the environment, {where}. See reference/corpus.py.")


def require_seed(path):
    """Skip unless a specific corpus file a suite is pinned to is actually there.

    Several suites parse one named file and then assert on the result. `parse_file` returns a
    *failed record* for a path that does not exist rather than raising - that is the D10
    contract - so a missing seed does not announce itself: the suite carries on and asserts
    against an empty record.
    """
    if not os.path.exists(path):
        skip(f"the seed file this suite is pinned to is missing: {path}",
             "It should be inside the configured corpus. Check the corpus is the right one.")
    return True


def require_qt():
    """Skip unless PySide6's Qt bindings actually import.

    `import PySide6` succeeding proves nothing: the base package installs without the module
    bindings (on Debian/Ubuntu those are separate `python3-pyside6.qt*` packages), and the
    GUI suites then died with a bare ModuleNotFoundError that reads like a code fault.
    """
    try:
        import PySide6.QtWidgets  # noqa: F401
    except ImportError as exc:
        skip(f"PySide6's Qt bindings are not importable: {exc}",
             "The GUI suites cannot run without them. Either:\n"
             "  sudo apt install python3-pyside6.qtcore python3-pyside6.qtgui "
             "python3-pyside6.qtwidgets\n"
             "    (the `PySide6` base package alone is not enough - the bindings are separate)\n"
             "  or, with no root and no venv:\n"
             "  pip install --break-system-packages --target /some/dir PySide6\n"
             "    then set PREFETCH_PYLIBS=/some/dir in corpus-paths.env, which this module\n"
             "    puts on sys.path for you.")
    return True
