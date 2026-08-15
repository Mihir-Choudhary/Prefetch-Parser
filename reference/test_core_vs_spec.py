#!/usr/bin/env python3
"""Regression test: prefetch_core must agree with validate_spec.py field-for-field.

`validate_spec.py` is the independent parser written from docs/prefetch-format.md and validated
against the upstream NUnit ground truth. It is the thing that proves the spec. `prefetch_core`
is the real implementation. If they ever disagree, one of them is wrong and the difference must
be explained before shipping.

Covers all three corpora so every row of the version LAYOUT table is exercised - the vendored
set is the only source of v17/v23/v26, and a glob that quietly misses it would leave three
quarters of the table untested.

Run:  python3 test_core_vs_spec.py
"""

import collections
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

import validate_spec as ref  # noqa: E402
from prefetch_core import parse_file  # noqa: E402

CORPORA = [
    os.path.join(HERE, "pf-corpus", "**", "*.pf"),
    os.path.join(corpus.WIN10, "*.pf"),
    os.path.join(corpus.WIN11, "*.pf"),
]
EXPECTED_FILES = 691       # 55 vendored (1 deliberately invalid, rejected) + 184 + 452
EXPECTED_VERSIONS = {17, 23, 26, 30, 31}


def compare(path, mismatches):
    raw = open(path, "rb").read()
    try:
        r = ref.parse(raw)
    except Exception:
        return None            # the deliberately-invalid corpus file; core must reject it too
    m = parse_file(path)
    name = os.path.basename(path)

    def eq(key, got, want):
        if got != want:
            mismatches.append((name, key, got, want))

    eq("version", m.version, r.version)
    eq("exe_name", m.executable_name, r.exe_name)
    eq("hash", m.hash, r.hash)
    eq("run_count", m.run_count, r.run_count)
    eq("run_times", m.run_times, r.run_times)
    eq("filenames", m.filenames, r.filenames)
    eq("metric_names", [x.filename for x in m.metrics], r.filenames_via_metrics)
    eq("n_volumes", len(m.volumes), len(r.volumes))
    for mv, rv in zip(m.volumes, r.volumes):
        eq("vol.device", mv.device_name, rv["device"])
        eq("vol.serial", mv.serial, rv["serial"])
        eq("vol.created", mv.created, rv["created"])
        eq("vol.dirs", mv.directories, rv["dirs"])
        eq("vol.refs", len(mv.file_refs), len([x for x in rv["refs"] if x != (0, None)]))

    stored = r.exec_path_field
    is_path = bool(stored) and stored.upper().startswith(("\\DEVICE\\", "\\VOLUME{"))
    if is_path:
        eq("5a_path", m.executable_path, stored)
    elif stored:
        eq("5a_package", m.hosted_package, stored)
    return m.version


def main():
    mismatches = []
    versions = collections.Counter()
    checked = skipped = 0

    for pattern in CORPORA:
        files = sorted(glob.glob(pattern, recursive=True))
        if not files:
            print(f"!! no files matched {pattern}", file=sys.stderr)
        for p in files:
            v = compare(p, mismatches)
            if v is None:
                skipped += 1
            else:
                checked += 1
                versions[v] += 1

    print(f"compared {checked} files ({skipped} rejected by both parsers)")
    print("  versions: " + ", ".join(f"v{v}x{n}" for v, n in sorted(versions.items())))

    ok = True
    missing = EXPECTED_VERSIONS - set(versions)
    if missing:
        print(f"  !! no coverage for version(s) {sorted(missing)} - LAYOUT rows untested")
        ok = False
    if checked + skipped != EXPECTED_FILES:
        print(f"  !! saw {checked + skipped} files, expected {EXPECTED_FILES} - corpus moved?")
        ok = False

    if mismatches:
        ok = False
        print(f"\nMISMATCHES: {len(mismatches)}")
        for key, n in collections.Counter(m[1] for m in mismatches).most_common():
            print(f"   {key}: {n}")
        for m in mismatches[:5]:
            print(f"   {m[0]} {m[1]}\n      core: {str(m[2])[:120]}\n      spec: {str(m[3])[:120]}")
    else:
        print("  no field mismatches")

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
