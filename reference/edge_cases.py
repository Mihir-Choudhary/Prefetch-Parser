#!/usr/bin/env python3
"""Measure the edge cases documented in docs/edge-cases.md, and fail if any drift.

These numbers back design decisions - LastRun must be max() not slot[0], the multi-hash flag
must compare paths not hashes, the parser must not filter on '.exe'. Keeping them checkable
stops the doc from quietly becoming folklore.

Run:  python3 edge_cases.py
"""

import collections
import datetime
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import corpus  # noqa: E402
from validate_spec import parse  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prefetch_core import container  # noqa: E402

CORPORA = [
    corpus.WIN10,
    corpus.WIN11,
]

# The header's size field is the UNCOMPRESSED length and agrees with the actual decompressed
# byte count on every corpus file. That makes a disagreement a genuine integrity signal, the
# same way the \VOLUME{...} name encodes its own creation time and serial.
EXPECTED = {
    "header_size_mismatch": 0,
    "total": 636,
    "slot0_not_newest": 6,
    "any_inversion": 27,
    "duplicate_runtimes": 4,
    "truncated_names": 57,
    "non_exe": 9,          # .TMP x8 + SOFFICE.BIN; excludes truncated names
    "vol2": 10,
    "vol3": 1,
    "op_files": 2,
    "zero_runtimes": 0,
    "runcount_zero": 0,
    "future_runtime": 0,
    "run_before_volume": 0,
    "runcount_mismatch_under_cap": 0,
}


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    got = collections.Counter()
    worst = []

    for d in CORPORA:
        for p in sorted(glob.glob(os.path.join(d, "*.pf"))):
            b = os.path.basename(p)
            pf = parse(open(p, "rb").read())
            got["total"] += 1

            if b.upper().startswith("OP-"):
                got["op_files"] += 1

            rt = pf.run_times
            if not rt:
                got["zero_runtimes"] += 1
            else:
                if rt[0] != max(rt):
                    got["slot0_not_newest"] += 1
                    worst.append(((max(rt) - rt[0]).total_seconds(), b))
                if any(rt[i] < rt[i + 1] for i in range(len(rt) - 1)):
                    got["any_inversion"] += 1
                if len(set(rt)) != len(rt):
                    got["duplicate_runtimes"] += 1
                if max(rt) > now:
                    got["future_runtime"] += 1
                if pf.volumes and min(rt) < min(v["created"] for v in pf.volumes):
                    got["run_before_volume"] += 1

            if pf.run_count == 0:
                got["runcount_zero"] += 1
            body = container.load(open(p, "rb").read())
            if pf.file_size != len(body):
                got["header_size_mismatch"] += 1
            # Below the 8-slot retention cap the two must agree; this validates the
            # "RunCount = section end - 96" rule without reference to PECmd.
            if pf.run_count <= 8 and pf.run_count != len(rt):
                got["runcount_mismatch_under_cap"] += 1

            name = pf.exe_name.upper()
            if len(pf.exe_name) == 29:
                got["truncated_names"] += 1
            elif not name.endswith(".EXE") and not name.startswith("OP-"):
                got["non_exe"] += 1

            n = len(pf.volumes)
            if n == 2:
                got["vol2"] += 1
            elif n >= 3:
                got["vol3"] += 1

    ok = True
    for k in EXPECTED:
        flag = "" if got[k] == EXPECTED[k] else f"   << docs say {EXPECTED[k]}"
        ok &= got[k] == EXPECTED[k]
        print(f"  {k:32} {got[k]:>4}{flag}")

    worst.sort(reverse=True)
    print("\n  largest 'LastRun' error if slot[0] were trusted:")
    for secs, name in worst[:5]:
        print(f"     {secs:8.3f}s  {name}")

    print("\nMATCHES DOCUMENTED RESULT" if ok else "\nDRIFT - docs and measurement disagree")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
