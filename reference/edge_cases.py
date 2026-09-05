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
    corpus.require("WIN10", "WIN11")
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

    # A prefetch filename is derived from the executable name and a hash of its path, and the
    # header holds both independently. Nothing in the tool compared them until Round 45, so a
    # renamed or planted file - the cheapest anti-forensic move there is - said nothing
    # (AUDIT BUG 75). On the corpora the two agree everywhere, which is what makes a
    # disagreement worth reporting.
    print("\n  the filename against the record's own header:")
    import shutil as _shutil                                          # noqa: PLC0415
    import tempfile as _tempfile                                      # noqa: PLC0415

    from prefetch_core import parse_file as _parse_file               # noqa: PLC0415

    agree = disagree = not_applicable = 0
    corpus_files = [p for d in CORPORA for p in sorted(glob.glob(os.path.join(d, "*.pf")))]
    for path in corpus_files:
        rec = _parse_file(path)
        if rec.filename_hash_match is None and rec.filename_name_match is None:
            not_applicable += 1
        elif rec.filename_hash_match is False or rec.filename_name_match is False:
            disagree += 1
            print(f"     mismatch: {os.path.basename(path)}")
        else:
            agree += 1
    print(f"     agree {agree}, disagree {disagree}, not applicable {not_applicable}")
    if disagree:
        print("     !! a corpus file disagrees with its own header - investigate before "
              "trusting this run")
        ok = False

    # And the detection must actually fire. Renaming a real file is the whole scenario.
    workdir = _tempfile.mkdtemp()
    planted = os.path.join(workdir, "NOTEPAD.EXE-DEADBEEF.pf")
    _shutil.copyfile(corpus_files[0], planted)
    forged = _parse_file(planted)
    original = _parse_file(corpus_files[0])
    fires = (forged.filename_hash_match is False and forged.filename_name_match is False
             and any("renamed" in str(p) for p in forged.problems))
    print(f"     a renamed copy is detected and says why: {fires}")
    # ...and everything else about the record must be unchanged by the rename.
    same = (forged.executable_name == original.executable_name
            and forged.hash == original.hash
            and forged.run_times == original.run_times)
    print(f"     the rename changes nothing else about the record: {same}")
    ok &= fires and same

    # Round 46: the same rename with an upper-case extension. Windows filenames are
    # case-insensitive and `pfcli` discovers `.PF` as readily as `.pf`, but the pattern was
    # case-sensitive - so `NOTEPAD.EXE-DEADBEEF.PF` matched nothing, both fields stayed
    # "not applicable", and the detection said nothing at all. Defeated by the shift key
    # (AUDIT BUG 95).
    shouted = os.path.join(workdir, "NOTEPAD.EXE-DEADBEEF.PF")
    _shutil.copyfile(corpus_files[0], shouted)
    loud = _parse_file(shouted)
    loud_fires = (loud.filename_hash_match is False
                  and any("renamed" in str(p) for p in loud.problems))
    print(f"     an upper-case .PF rename is detected too: {loud_fires}")
    # And an Op-*.pf, which genuinely does not follow the convention, still reports n/a rather
    # than a mismatch - "not applicable" and "does not match" are different answers.
    op = os.path.join(workdir, "Op-Something.pf")
    _shutil.copyfile(corpus_files[0], op)
    op_rec = _parse_file(op)
    op_quiet = (op_rec.filename_hash_match is None and op_rec.filename_name_match is None)
    print(f"     a name outside the convention still reports n/a: {op_quiet}")
    ok &= loud_fires and op_quiet

    if ok:
        print("\nMATCHES DOCUMENTED RESULT")
        return 0
    # "Drift" means these files changed meaning. A different file COUNT means these are not
    # those files, and every documented number will differ for that reason alone - so say which
    # of the two it is rather than accusing the docs.
    if got["total"] != EXPECTED["total"]:
        print(f"\nDIFFERENT CORPUS - measured {got['total']} files, the documented figures are"
              f" from {EXPECTED['total']}.\nEvery count above differs for that reason alone."
              " Point PREFETCH_CORPUS_WIN10/WIN11 at the corpus\nthe docs were measured on, or"
              " re-measure the docs against this one.")
    else:
        print("\nDRIFT - same corpus size, different counts: docs and measurement disagree")
    return 1


if __name__ == "__main__":
    sys.exit(main())
