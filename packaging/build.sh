#!/usr/bin/env bash
# Build the distributable, then smoke-test it. A build that produces a binary which cannot
# parse a file is not a successful build, so the test is part of this script rather than a
# separate step someone forgets.
#
# Prerequisite (this machine does not have it):
#     python3 -m venv --system-site-packages .venv-build   # needs the python3-venv package
#     .venv-build/bin/pip install pyinstaller
# or, accepting the risk of touching the system interpreter:
#     pip install --break-system-packages pyinstaller
set -euo pipefail
cd "$(dirname "$0")/.."

PYI="${PYI:-pyinstaller}"
if ! command -v "$PYI" >/dev/null 2>&1; then
    if [ -x .venv-build/bin/pyinstaller ]; then
        PYI=.venv-build/bin/pyinstaller
    else
        echo "pyinstaller not found. See the prerequisite block at the top of this script." >&2
        exit 1
    fi
fi

echo "== running the regression suite first; never ship a red build"
./run_tests.sh

echo
echo "== building"
rm -rf build dist
"$PYI" packaging/prefetch.spec --noconfirm --distpath dist --workpath build

OUT="dist/prefetch-explorer"
echo
echo "== smoke-testing the frozen binaries"
test -x "$OUT/pfcli" || { echo "pfcli missing from the bundle" >&2; exit 1; }
test -x "$OUT/pfgui" || { echo "pfgui missing from the bundle" >&2; exit 1; }

# The pure XPRESS decoder is the thing most likely to be silently dropped by the import graph,
# and its absence only shows on a compressed file - so the smoke test must parse one.
SAMPLE="${SAMPLE:-$(ls reference/pf-corpus/Win10/*.pf 2>/dev/null | head -1)}"
if [ -f "$SAMPLE" ]; then
    "$OUT/pfcli" capabilities
    "$OUT/pfcli" info "$SAMPLE" | head -6
    "$OUT/pfcli" info "$SAMPLE" | grep -qi "\.exe" \
        || { echo "frozen pfcli did not parse a prefetch file" >&2; exit 1; }
    echo "  frozen CLI parses a compressed prefetch file: ok"
else
    echo "  (no sample file at $SAMPLE; skipped the parse check)" >&2
fi

QT_QPA_PLATFORM=offscreen "$OUT/pfgui" --help >/dev/null 2>&1 || true
echo "  frozen GUI binary is executable: ok"

echo
du -sh "$OUT"
echo "built: $OUT"
