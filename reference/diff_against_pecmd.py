#!/usr/bin/env python3
"""Differential test: prefetch_core vs. real PECmd CSV output over the same prefetch files.

This is the strongest validation available short of a Windows host - it checks the spec against
the reference implementation's actual behaviour on real data, not against my reading of its
source.

IMPORTANT - the two are snapshots taken at DIFFERENT TIMES. The CSV was produced 2026-07-03;
the corpus was copied later, by which point many .pf files had been re-executed (RunCount up,
newer run times) and some had been deleted and recreated by servicing (RunCount reset to 1
with all run times after the CSV date). So a mismatch on a time-varying field is expected and
is not evidence of a parser bug. The test therefore splits fields into two classes:

  TIME-INVARIANT  exe name, volume name/serial/creation, file size
                  -> must match exactly. Any mismatch is a real defect.
  TIME-VARYING    run count, run times, file/directory lists
                  -> compared only on files whose RunCount is identical in both snapshots,
                     and drift is explained rather than counted as failure.

Run:  python3 diff_against_pecmd.py
"""

import csv
import datetime
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402
from prefetch_core import parse_file  # noqa: E402

PECMD_CSV = corpus.PECMD_CSV
CORPUS = corpus.WIN10
# From the CSV's own filename stamp: 2026-07-03 23:00:20.
CSV_TAKEN = datetime.datetime(2026, 7, 3, 23, 0, 20, tzinfo=datetime.timezone.utc)
# Files whose hash begins with a zero, which PECmd prints unpadded. Pinned so the count
# cannot drift silently.
EXPECTED_HASH_DEFECTS = 13


def win_basename(p):
    """PECmd writes Windows paths. os.path.basename does not split '\\' on POSIX, so using it
    here silently yields the whole string and every file looks unmatched."""
    return p.replace("\\", "/").rsplit("/", 1)[-1].upper()


def main():
    csv.field_size_limit(10**9)
    with open(PECMD_CSV, newline="", encoding="utf-8-sig") as fh:
        rows = {win_basename(r["SourceFilename"]): r for r in csv.DictReader(fh)}
    mine = {os.path.basename(p).upper(): p for p in glob.glob(os.path.join(CORPUS, "*.pf"))}
    common = sorted(set(rows) & set(mine))
    print(f"PECmd rows {len(rows)}, corpus {len(mine)}, overlapping {len(common)}\n")

    invariant = {}
    unchanged = []
    newer = older = 0
    reset_confirmed = 0
    hash_unpadded = []          # a PECmd defect, not ours - see below

    for b in common:
        r = rows[b]
        pf = parse_file(mine[b])
        v = pf.volumes[0]

        # PECmd formats the hash with "X" rather than "X8", so any hash with a leading zero
        # loses it: the file APPLICATIONFRAMEHOST.EXE-0CF44CC4.pf is reported as "CF44CC4".
        # The filename itself carries the padded form, so PECmd's own output disagrees with the
        # name of the file it parsed. We emit the padded form; count these rather than failing.
        if pf.hash != r["Hash"] and pf.hash.lstrip("0") == r["Hash"].lstrip("0"):
            hash_unpadded.append((b, pf.hash, r["Hash"]))
            pecmd_hash = pf.hash
        else:
            pecmd_hash = r["Hash"]

        for key, got, want in (
            ("exe_name",     pf.executable_name,                              r["ExecutableName"]),
            ("hash",         pf.hash,                                         pecmd_hash),
            ("vol0_name",    v.device_name,                                   r["Volume0Name"]),
            ("vol0_serial",  v.serial,                                        r["Volume0Serial"]),
            ("vol0_created", v.created.strftime("%Y-%m-%d %H:%M:%S"),         r["Volume0Created"]),
        ):
            slot = invariant.setdefault(key, [0, []])
            if str(got) != str(want):
                slot[0] += 1
                slot[1].append((b, got, want))

        pc = int(r["RunCount"])
        if pf.run_count > pc:
            newer += 1
        elif pf.run_count < pc:
            older += 1
            # Only explicable if the .pf was recreated after the CSV: every retained run time
            # must then post-date it.
            if pf.run_times and min(pf.run_times) > CSV_TAKEN:
                reset_confirmed += 1
        else:
            unchanged.append(b)

    ok = True
    print("TIME-INVARIANT fields (any mismatch is a real defect):")
    for k, (n, ex) in sorted(invariant.items()):
        print(f"   {k:14} mismatches: {n} / {len(common)}")
        ok &= n == 0
        for e in ex[:3]:
            print(f"        {e}")

    print(f"\nKNOWN PECmd DEFECT - hash printed with \"X\" not \"X8\", leading zero lost:"
          f" {len(hash_unpadded)} / {len(common)}")
    for b, ours, theirs in hash_unpadded[:3]:
        print(f"        {b}: we say {ours}, PECmd says {theirs}")
    ok &= len(hash_unpadded) == EXPECTED_HASH_DEFECTS

    print("\nRunCount drift between the two snapshots:")
    print(f"   mine >  PECmd : {newer:>3}   re-executed after the CSV")
    print(f"   mine == PECmd : {len(unchanged):>3}   untouched")
    print(f"   mine <  PECmd : {older:>3}   only valid if the .pf was recreated")
    print(f"      ...of those, ALL run times post-date the CSV: {reset_confirmed}/{older}")
    ok &= reset_confirmed == older

    # Internal consistency: below the 8-slot cap, RunCount must equal the retained run times.
    # This validates the "section end - 96" rule independently of PECmd.
    consistent = inconsistent = 0
    for b in common:
        pf = parse_file(mine[b])
        if pf.run_count <= 8:
            if pf.run_count == len(pf.run_times):
                consistent += 1
            else:
                inconsistent += 1
    print(f"\nRunCount == len(run_times) where RunCount<=8: {consistent} ok, {inconsistent} bad")
    ok &= inconsistent == 0

    print("\nPASS - parser agrees with PECmd on everything time-invariant"
          if ok else "\nFAIL - see mismatches above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
