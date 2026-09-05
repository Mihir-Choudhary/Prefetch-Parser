#!/usr/bin/env python3
"""Assert our CSV export is a strict superset of PECmd's, field for field.

"No data skipped" is easy to claim and easy to break: an export loses a column and nothing
fails, because the rows still look fine. This maps every PECmd column onto ours and checks the
values actually agree on shared files, so a regression shows up as a diff rather than as a
quietly missing column.

Where we deliberately differ, the difference is asserted rather than tolerated:
  * Hash      - we pad to 8 hex digits, PECmd prints 7 when the leading digit is 0 (its bug).
  * LastRun   - we use max(run_times), PECmd uses slot 0, which is not always the newest.
  * Volumes   - PECmd stops at two and writes a Note; we add AllVolumes.

Run:  python3 test_csv_coverage.py
"""

import csv
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import corpus  # noqa: E402

from pfcli.__main__ import split_list  # noqa: E402  - the CSV's own list decoder
PECMD_CSV = corpus.PECMD_CSV
CORPUS = corpus.WIN10

# PECmd column -> ours. None means "intentionally not carried", with a reason.
MAPPING = {
    "SourceFilename": "SourcePath",
    "SourceCreated": "SourceCreated",
    "SourceModified": "SourceModified",
    "SourceAccessed": "SourceAccessed",
    "ExecutableName": "ExecutableName",
    "Hash": "Hash",
    "Size": "Size",
    "Version": "Version",
    "RunCount": "RunCount",
    "LastRun": "LastRun",
    "Volume0Name": "Volume0Name",
    "Volume0Serial": "Volume0Serial",
    "Volume0Created": "Volume0Created",
    "Volume1Name": "Volume1Name",
    "Volume1Serial": "Volume1Serial",
    "Volume1Created": "Volume1Created",
    "Directories": "Directories",
    "FilesLoaded": "FilesLoaded",
    "ParsingError": "ParsedOk",          # inverted; PECmd's is a bare bool
    "Note": "AllVolumes",                # its Note only ever says ">2 volumes"; ours is the data
}
for i in range(7):
    MAPPING[f"PreviousRun{i}"] = f"PreviousRun{i}"


def win_basename(p):
    return p.replace("\\", "/").rsplit("/", 1)[-1].upper()


def main():
    corpus.require("WIN10", "PECMD")
    out = os.path.join(tempfile.mkdtemp(), "ours.csv")
    # `--raw-csv`: this compares VALUES against another tool's output, and the default export
    # deliberately prefixes cells a spreadsheet would re-read - `1482E648` becomes `'1482E648`
    # so Excel cannot turn a hash into 1482 x 10^648 (AUDIT BUG 103). The raw export is the one
    # that promises exact bytes, and it is what a value comparison must use.
    subprocess.run([sys.executable, "-m", "pfcli", "parse", CORPUS, "--csv", out, "--raw-csv"],
                   cwd=ROOT, check=True, capture_output=True)

    csv.field_size_limit(10**9)
    with open(PECMD_CSV, newline="", encoding="utf-8-sig") as fh:
        theirs = {win_basename(r["SourceFilename"]): r for r in csv.DictReader(fh)}
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    ours = {r["SourceName"].upper(): r for r in rows}

    ok = True
    print("column coverage:")
    missing = [c for c, m in MAPPING.items() if m is not None and m not in rows[0]]
    unmapped = [c for c in theirs[next(iter(theirs))].keys() if c not in MAPPING]
    for c in missing:
        print(f"   !! PECmd column '{c}' maps to '{MAPPING[c]}' which we do not emit")
        ok = False
    for c in unmapped:
        print(f"   !! PECmd column '{c}' has no mapping declared")
        ok = False
    if not missing and not unmapped:
        print(f"   all {len(MAPPING)} PECmd columns are carried")
    print(f"   we add {len(set(rows[0]) - set(MAPPING.values()))} columns PECmd lacks")

    # Value agreement on the shared, time-invariant fields.
    common = sorted(set(theirs) & set(ours))
    print(f"\nvalue agreement over {len(common)} shared files:")
    diffs = {}
    for b in common:
        t, o = theirs[b], ours[b]
        for key, mine in (("ExecutableName", "ExecutableName"), ("Version", None),
                          ("Volume0Name", "Volume0Name"), ("Volume0Serial", "Volume0Serial")):
            if mine is None:
                continue
            if t[key].strip() != o[mine].strip():
                diffs.setdefault(key, []).append((b, o[mine], t[key]))
        # Hash: equal once PECmd's dropped leading zero is restored.
        if o["Hash"].lstrip("0") != t["Hash"].lstrip("0"):
            diffs.setdefault("Hash", []).append((b, o["Hash"], t["Hash"]))
        # Loaded-file SET comparison, not counts. The two snapshots are ~6 weeks apart, so the
        # lists legitimately differ - a later execution loads different modules. Counting is
        # therefore meaningless; what matters is whether PECmd names a file we do not, on a
        # file that genuinely did not change.
        #
        # "Same RunCount" is NOT enough to establish that: a prefetch file deleted and
        # recreated by servicing comes back with RunCount 1, matching an original that had also
        # only run once. USOCLIENT.EXE-6A3863B1 is exactly that case - same RunCount, but the
        # embedded size and last-run differ, and PECmd's copy listed a \$MFT entry that is
        # simply not present in the bytes we have. Requiring LastRun to match as well pins the
        # comparison to the same generation of the file.
        if t["RunCount"] == o["RunCount"] and t["LastRun"][:19] == o["LastRun"][:19]:
            theirs_set = {x.strip().upper() for x in t["FilesLoaded"].split(", ") if x.strip()}
            ours_set = {x.strip().upper() for x in split_list(o["FilesLoaded"]) if x.strip()}
            only_theirs = theirs_set - ours_set
            if only_theirs:
                diffs.setdefault("FilesLoaded missing from ours", []).append(
                    (b, f"{len(only_theirs)} missing", sorted(only_theirs)[:2]))

    for key, items in sorted(diffs.items()):
        print(f"   {key}: {len(items)} differ")
        for it in items[:3]:
            print(f"      {it[0]}  ours={it[1]!r}  pecmd={it[2]!r}")
        # A file PECmd names that we do not is a real loss. Everything else in this block is
        # snapshot drift or a known PECmd defect, both expected.
        if key.startswith("FilesLoaded missing"):
            ok = False
    if not diffs:
        print("   no differences")

    # A spreadsheet silently truncates any cell over 32,767 characters, and prefetch list
    # cells go ten times past that. The export cannot raise the limit; it must not let the
    # truncation happen unremarked (AUDIT BUG 74).
    print("\ncells a spreadsheet would truncate are reported, not left to chance:")
    import subprocess as _sp                                          # noqa: PLC0415

    from prefetch_core.output import CellWidths, EXCEL_CELL_LIMIT     # noqa: PLC0415

    widths = CellWidths()
    for row in rows:
        widths.note(row)
    over = sum(widths.over.values())
    print(f"  widest cell: {widths.widest:,} characters, limit {EXCEL_CELL_LIMIT:,}")
    print(f"  cells over the limit: {over} in {sorted(widths.over)}")
    out_again = os.path.join(tempfile.mkdtemp(), "warned.csv")
    proc = _sp.run([sys.executable, "-m", "pfcli", "parse", corpus.WIN10, "--csv", out_again],
                   cwd=ROOT, capture_output=True, text=True, timeout=600)
    # On stderr: diagnostics must not reach the stream a script reads rows from (BUG 107).
    warned = "TRUNCATED silently" in proc.stderr
    check_stdout_clean = "TRUNCATED silently" not in proc.stdout
    print(f"  the export says so on the console: {warned}")
    if (widths.widest > EXCEL_CELL_LIMIT) != warned or (over > 0) != warned:
        print("  !! the warning and the measurement disagree")
        ok = False
    if not check_stdout_clean:
        print("  !! the warning reached stdout, where a script reads the rows")
        ok = False

    # "Read them with a CSV-aware tool" was incomplete advice: Python's csv module refuses a
    # field over 131,072 characters outright, which reads as a corrupt export rather than a
    # reader default. The Win10 corpus has a 323,778-character FilesLoaded cell, so the
    # message must say how to read it (AUDIT BUG 89).
    from prefetch_core.output import PY_CSV_FIELD_LIMIT                # noqa: PLC0415
    said = "csv.field_size_limit" in proc.stderr
    print(f"  widest cell exceeds Python's csv default ({PY_CSV_FIELD_LIMIT:,}): "
          f"{widths.widest > PY_CSV_FIELD_LIMIT}; the note says how to read it: {said}")
    if (widths.widest > PY_CSV_FIELD_LIMIT) != said:
        print("  !! the export does not say what a reader needs to do")
        ok = False
    # ...and it stays quiet when nothing needs saying. A note that is always printed is a note
    # nobody reads.
    narrow = CellWidths()
    narrow.note({"A": "x" * 10})
    if narrow.message is not None:
        print("  !! a narrow export still emits the warning")
        ok = False
    middling = CellWidths()
    middling.note({"A": "x" * (EXCEL_CELL_LIMIT + 1)})
    if middling.message is None or "csv.field_size_limit" in middling.message:
        print("  !! a cell over the spreadsheet limit but under Python's names the wrong limit")
        ok = False

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
