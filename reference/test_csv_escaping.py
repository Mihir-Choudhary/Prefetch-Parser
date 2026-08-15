#!/usr/bin/env python3
"""List-cell escaping must survive a CSV round-trip, including hostile filenames.

CSV quoting protects the *field*. It does not protect the list packed inside a field: an
element containing the separator silently becomes two elements. Prefetch records paths from the
kernel namespace, which permits characters Win32 forbids, so a filename carrying " | " is
creatable via native APIs. In a forensic export that is row injection - an attacker chooses how
many entries an analyst's spreadsheet appears to contain.

No path in the 107,064 strings across both corpora contains one. That is why this needs a test
rather than a corpus check: the corpus cannot exercise it.

Run:  python3 test_csv_escaping.py
"""

import csv
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from pfcli.__main__ import (  # noqa: E402
    CSV_COLUMNS, FORMULA_TRIGGERS, join_list, row_for, sanitize_cell, split_list)
from prefetch_core import parse_file  # noqa: E402

SEED = "" + corpus.WIN10 + "/7ZFM.EXE-7C92DCA0.pf"

HOSTILE = [
    "\\DEVICE\\HARDDISKVOLUME1\\NORMAL.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\HAS | SEPARATOR.DLL",   # the injection case
    "\\DEVICE\\HARDDISKVOLUME1\\ENDS|PIPE.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\BAR|BAR|BAR.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\HAS,COMMA.DLL",         # CSV's own delimiter
    '\\DEVICE\\HARDDISKVOLUME1\\HAS"QUOTE.DLL',         # CSV quoting
    "\\DEVICE\\HARDDISKVOLUME1\\BACK\\\\SLASH.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\ESCAPED\\|LOOKALIKE.DLL",  # already looks backslash-escaped
    "\\DEVICE\\HARDDISKVOLUME1\\CARET^HAT.DLL",             # the escape char itself
    "\\DEVICE\\HARDDISKVOLUME1\\CARET^^DOUBLE.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\LOOKS^pLIKE_ESCAPE.DLL",    # collides with the pipe escape
    "\\DEVICE\\HARDDISKVOLUME1\\UNICODEé中م.DLL",
    "\\DEVICE\\HARDDISKVOLUME1\\   SPACES   .DLL",
    "",                                                  # empty element
]

failures = []


def check(label, got, want):
    ok = got == want
    print(f"  {label:52} {'ok' if ok else 'FAIL'}")
    if not ok:
        failures.append(f"{label}: got {got!r} want {want!r}")


def main():
    print("join/split round-trip in isolation:")
    check("hostile list survives join->split", split_list(join_list(HOSTILE)), HOSTILE)
    check("single element", split_list(join_list(["a|b"])), ["a|b"])
    check("empty list", split_list(join_list([])), [])
    check("element that is only a separator", split_list(join_list([" | "])), [" | "])
    check("element of only backslashes", split_list(join_list(["\\\\\\"])), ["\\\\\\"])

    print("\nthrough a real CSV writer/reader:")
    pf = parse_file(SEED)
    pf.filenames = list(HOSTILE)
    row = row_for(pf)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    w.writeheader()
    w.writerow(row)
    buf.seek(0)
    csv.field_size_limit(10**9)
    back = next(csv.DictReader(buf))

    check("FilesLoaded round-trips exactly", split_list(back["FilesLoaded"]), HOSTILE)
    check("element count preserved", len(split_list(back["FilesLoaded"])), len(HOSTILE))
    check("FileCount matches the list", int(back["FileCount"]), len(HOSTILE))
    # The count column and the list must agree; a mismatch is how injection would show up.
    check("no phantom rows introduced",
          len(split_list(back["FilesLoaded"])), int(back["FileCount"]))

    print("\nother list columns use the same escaping:")
    for column in ("Directories", "AllVolumes", "AllRunTimes", "Problems"):
        cell = back[column]
        # Re-splitting must not error and must not produce empty phantom entries mid-list.
        parts = split_list(cell) if cell else []
        check(f"{column} splits cleanly", all(p == p for p in parts), True)

    print("\nspreadsheet formula injection:")
    # A path named `=cmd|'/c calc'!A1` is executed by Excel when the CSV is opened. Forensic
    # CSVs are opened in Excel constantly and the filename is attacker-chosen.
    for trigger in FORMULA_TRIGGERS:
        payload = trigger + "cmd|'/c calc'!A1"
        check(f"{trigger!r} is neutralised", sanitize_cell(payload).startswith("'"), True)
        check(f"{trigger!r} value is otherwise intact", sanitize_cell(payload)[1:], payload)
    check("ordinary text is untouched", sanitize_cell("NOTEPAD.EXE"), "NOTEPAD.EXE")
    check("empty cell is untouched", sanitize_cell(""), "")
    check("None becomes empty", sanitize_cell(None), "")
    check("--raw-csv leaves the payload exact", sanitize_cell("=EVIL", False), "=EVIL")

    # A leading "-" is both a formula trigger and the start of every negative number. Prefixing
    # numbers turned -1 into the string '-1 - a spreadsheet renders it as text and a
    # programmatic reader gets a stray apostrophe. Real negatives occur: v17 stores
    # TotalDirectoryCount as -1, and a corrupt file can yield negative counts.
    for number in ("-1", "-1155", "-1.5", "0", "42", "1e5"):
        check(f"numeric {number!r} is left exact", sanitize_cell(number), number)
    check("a negative-looking formula is still caught",
          sanitize_cell("-cmd|'/c calc'!A1").startswith("'"), True)
    check("'+1' is a number, not a formula", sanitize_cell("+1"), "+1")

    print("\nPASS" if not failures else "\nFAIL:")
    for f in failures:
        print(f"   {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
