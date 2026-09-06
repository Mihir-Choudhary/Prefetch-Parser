#!/usr/bin/env bash
# Build the distributable, then smoke-test it. A build that produces a binary which cannot
# parse a file is not a successful build, so the test is part of this script rather than a
# separate step someone forgets.
#
# Prerequisite. Any of these works; the third needs neither root nor a virtualenv, which is
# what this machine has (no python3.14-venv package, no sudo):
#     python3 -m venv --system-site-packages .venv-build && .venv-build/bin/pip install pyinstaller
#     pip install --break-system-packages pyinstaller
#     pip install --break-system-packages --target /some/dir pyinstaller pyside6
#         then: PYTHONPATH=/some/dir ./packaging/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# A --target install has no console script on PATH, so fall back to `python3 -m PyInstaller`,
# which is the same entry point.
PYI="${PYI:-pyinstaller}"
if ! command -v "$PYI" >/dev/null 2>&1; then
    if [ -x .venv-build/bin/pyinstaller ]; then
        PYI=.venv-build/bin/pyinstaller
    elif python3 -c "import PyInstaller" >/dev/null 2>&1; then
        PYI="python3 -m PyInstaller"
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
# shellcheck disable=SC2086 -- $PYI can be "python3 -m PyInstaller", which must word-split
$PYI packaging/prefetch.spec --noconfirm --distpath dist --workpath build

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

# `|| true` does not protect against a HANG, and this hung: the frozen GUI took --help for a
# path, started the event loop and sat there until the build timed out. --help must answer and
# exit, so a timeout here is a build failure, not a shrug.
if ! timeout 60 env QT_QPA_PLATFORM=offscreen "$OUT/pfgui" --help >/dev/null 2>&1; then
    echo "frozen pfgui did not answer --help within 60s" >&2
    exit 1
fi
echo "  frozen GUI answers --help and exits: ok"

# And it must actually start Qt, which --help deliberately does not do.
if ! timeout 120 env QT_QPA_PLATFORM=offscreen PREFETCH_GUI_SELFTEST=1 \
        "$OUT/pfgui" >/dev/null 2>&1; then
    echo "frozen pfgui could not start Qt" >&2
    exit 1
fi
echo "  frozen GUI starts Qt: ok"

# The bundle carries Qt and PySide6 (both LGPL-3) and CPython. Redistributing them means
# shipping their licence texts; a binary that leaves this machine without them is a compliance
# problem, not a packaging detail. Assembled here rather than by hand, and the build FAILS if
# any of them is missing - the same rule this project applies to everything else it claims.
echo
echo "== collecting the licences the bundle is obliged to carry"
LICENSES="$OUT/licenses"
mkdir -p "$LICENSES"
cp LICENSE "$LICENSES/prefetch-explorer-MIT.txt"
missing=""
copy_first() {           # copy_first <destination> <candidate>...
    dest=$1; shift
    for candidate in "$@"; do
        if [ -f "$candidate" ]; then
            cp "$candidate" "$LICENSES/$dest"
            return 0
        fi
    done
    missing="$missing $dest"
    return 1
}
copy_first "python-LICENSE.txt" \
    /usr/lib/python3.14/LICENSE.txt /usr/lib/python3.13/LICENSE.txt \
    /usr/share/doc/python3.14/copyright
copy_first "qt6-copyright.txt" \
    /usr/share/doc/libqt6core6t64/copyright /usr/share/doc/libqt6core6/copyright
copy_first "pyside6-copyright.txt" \
    /usr/share/doc/libpyside6-py3-6.10/copyright \
    /usr/share/doc/python3-pyside6.qtcore/copyright
copy_first "LGPL-3.txt" /usr/share/common-licenses/LGPL-3
if [ -n "$missing" ]; then
    echo "!! licence text missing for:$missing" >&2
    echo "   The bundle may not be redistributed without it. Install the -doc packages or" >&2
    echo "   point copy_first at the right paths, then build again." >&2
    exit 1
fi
cat > "$LICENSES/README.txt" <<'NOTICE'
This bundle contains, in addition to prefetch-explorer itself (MIT, see
prefetch-explorer-MIT.txt):

  * CPython                    - python-LICENSE.txt
  * Qt 6 (LGPL-3 or GPL-2)     - qt6-copyright.txt, LGPL-3.txt
  * PySide6 (LGPL-3)           - pyside6-copyright.txt, LGPL-3.txt

The Qt and PySide6 libraries are shipped as separate shared objects in this
directory, not statically linked, so they may be replaced with compatible
builds of your own - which is what the LGPL requires the recipient be able
to do. Source for Qt and PySide6 is at https://download.qt.io/.
NOTICE
echo "  licences collected: $(ls "$LICENSES" | tr '\n' ' ')"

echo
du -sh "$OUT"
echo "built: $OUT"
