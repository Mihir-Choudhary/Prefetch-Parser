"""Writing the folder's non-.pf artifacts to files.

Lives in the core rather than in the CLI because both surfaces need it: an investigator working
in the GUI needs the same export an investigator working in a shell gets, and two
implementations of one export is how they end up disagreeing.

Nothing here formats for display or decides policy - it writes what the artifacts state.
"""

from __future__ import annotations

import csv
import os
import re

from . import winpath
from .output import CellWidths, atomic_write_pair


LIST_SEP = " | "
ESCAPE = "^"


def join_list(values):
    """Join list-valued CSV cells, escaping any literal separator inside an element.

    CSV quoting protects the *field*, not the list inside it: an element containing " | "
    silently becomes two elements when anyone splits the cell back apart. No path in the
    107,064 strings across both corpora contains one - but Win32 forbidding `|` in filenames
    does not bind the kernel namespace that prefetch records, so a file can be created with
    native APIs whose name carries the separator. That turns a display convention into a way to
    inject extra rows into forensic output, which is worth closing even at zero observed
    occurrences.

    The escape character is `^`, not backslash. Backslash is the obvious choice and it is wrong
    here: every element is a Windows path, so escaping backslashes would double them throughout
    and wreck readability, while escaping *only* `\\|` is not self-inverse - a path that already
    contains `\\|` then decodes differently from how it was encoded. `^` is legal in filenames
    so it still has to be escaped, but it is rare enough that real output is unaffected.

        ^  ->  ^^        |  ->  ^p
    """
    return LIST_SEP.join(
        str(v).replace(ESCAPE, ESCAPE * 2).replace("|", ESCAPE + "p") for v in values)


def split_list(cell):
    """Inverse of `join_list`, for anything reading our CSV back."""
    parts, current, i = [], [], 0
    while i < len(cell):
        if cell.startswith(ESCAPE * 2, i):
            current.append(ESCAPE)
            i += 2
        elif cell.startswith(ESCAPE + "p", i):
            current.append("|")
            i += 2
        elif cell.startswith(LIST_SEP, i):
            parts.append("".join(current))
            current = []
            i += len(LIST_SEP)
        else:
            current.append(cell[i])
            i += 1
    if current or parts:
        parts.append("".join(current))
    return parts


FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


# What a spreadsheet silently re-reads as something other than the text in the file:
#   1482E648   -> scientific notation, becoming a number that is not the hash
#   03583356   -> the leading zero is dropped
#   3-15, 1/2  -> a date
#   17 digits  -> a float, losing the low digits of an MFT reference
_COERCED_BY_SPREADSHEET = re.compile(
    r"^(?:[+-]?\d+[Ee][+-]?\d+|0\d+|\d{1,2}[-/]\d{1,2}|\d{16,})$")


def sanitize_cell(value, enabled=True):
    """Neutralise spreadsheet formula triggers by prefixing the cell with an apostrophe.

    Excel treats a leading `'` as "this is text" and does not display it. Other readers see it
    as part of the value, which is why `--raw-csv` exists: fidelity for programmatic consumers,
    safety by default for the spreadsheet that will actually open this.

    The SQLite store is never sanitised - it is the source of truth and holds exact bytes.

    Zero of the 108,972 strings in both corpora begin with a trigger, so this changes nothing
    about real output.
    """
    text = "" if value is None else str(value)
    # A cell can carry a name that is not valid text - NTFS allows unpaired surrogates, and a
    # folder copied out of an image keeps whatever bytes the name held. Rendered as escapes
    # here so the CSV spells the name exactly as the database does, rather than dying while it
    # is written or diverging from the other export (AUDIT BUG 102). Before the formula guard,
    # which only inspects the first character.
    text = winpath.readable_text(text)
    # A spreadsheet corrupts more than formulas. Excel reads `1482E648` - a real prefetch hash,
    # 5 of the 452 in the Win11 corpus match this shape - as 1482 x 10^648, and shows the
    # analyst a number where a hash was; it drops the leading zero from `03583356`; it turns
    # `3-15` into a date; and it loses precision past 15 digits. Every one of those is silent,
    # and every one of them changes an identifier that ties a prefetch file to what ran.
    #
    # The same remedy the formula guard already uses: a leading apostrophe, which Excel treats
    # as "this is text" and does not display, and which `--raw-csv` turns off for programmatic
    # consumers. Deliberately shaped so it cannot fire on a QUANTITY - a plain count like `12`
    # or `0` matches none of these - only on identifiers (AUDIT BUG 103).
    if enabled and _COERCED_BY_SPREADSHEET.match(text):
        return "'" + text
    if not enabled or text[:1] not in FORMULA_TRIGGERS:
        return text
    # A leading "-" is a formula trigger AND the start of every negative number. Prefixing
    # those turns -1 into the string '-1: a spreadsheet shows it as text and a programmatic
    # reader gets a stray apostrophe. Real negatives occur - v17 stores TotalDirectoryCount as
    # -1, and a corrupt file can yield negative counts - so a value that is simply a number is
    # left exactly as it is. It cannot be a formula.
    try:
        float(text)
        return text
    except ValueError:
        return "'" + text


# One row per path, and a companion file with one row per artifact. Two files rather than one
# because repeating an artifact's facts on each of its 10,118 path rows is not an export, it is
# a spreadsheet nobody can read - and dropping the facts instead would lose the record counts,
# the volume identity and the hash-verification totals (AUDIT BUG 80).
ARTIFACT_PATH_COLUMNS = ["SourceName", "SourcePath", "Kind", "Modified", "PathOrdinal",
                         "Path", "Detail"]
ARTIFACT_SUMMARY_COLUMNS = ["SourceName", "SourcePath", "Kind", "Size", "Modified", "PathCount",
                            "Facts", "Volumes", "Problems"]


def summary_path_for(csv_path: str) -> str:
    base, ext = os.path.splitext(csv_path)
    return f"{base}-summary{ext or '.csv'}"


def write_artifact_csv(found, csv_path, safe=True, sanitize=None, join=None):
    """Write the path rows to `csv_path` and the per-artifact rows beside it.

    Returns `(path_rows_written, summary_path, note)`, where `note` names any cells too wide
    for a spreadsheet to hold, or is None.

    `sanitize` and `join` default to this module's own formula-injection guard and list
    encoding, and stay injectable for a caller with different rules.
    """
    sanitize = sanitize or sanitize_cell
    join = join or join_list

    summary = summary_path_for(csv_path)
    widths = CellWidths()
    rows = 0
    # The pair is published together: a summary that does not match the paths beside it is
    # worse than no summary at all.
    with atomic_write_pair(csv_path, summary) as (fh, summary_fh):
        w = csv.DictWriter(fh, fieldnames=ARTIFACT_PATH_COLUMNS)
        w.writeheader()
        for art in found:
            stamp = art.modified.isoformat(sep=" ") if art.modified else ""
            detail = {p: f"reads={reads} bytes={nbytes}" for p, reads, nbytes in art.io_by_path}
            listed = list(art.paths) + [p for p, _r, _b in art.io_by_path
                                        if p not in set(art.paths)]
            for i, path in enumerate(listed):
                cells = {"SourceName": art.name, "SourcePath": art.path, "Kind": art.kind,
                         "Modified": stamp, "PathOrdinal": i, "Path": path,
                         "Detail": detail.get(path, "")}
                cells = {k: sanitize(v, safe) for k, v in cells.items()}
                widths.note(cells)
                w.writerow(cells)
                rows += 1

        w = csv.DictWriter(summary_fh, fieldnames=ARTIFACT_SUMMARY_COLUMNS)
        w.writeheader()
        for art in found:
            cells = {
                "SourceName": art.name, "SourcePath": art.path, "Kind": art.kind,
                "Size": art.size,
                "Modified": art.modified.isoformat(sep=" ") if art.modified else "",
                "PathCount": len(art.paths),
                "Facts": join(f"{k}={v}" for k, v in art.facts.items() if k != "paths"),
                "Volumes": join("; ".join(f"{k}={v}" for k, v in vol.items())
                                for vol in art.volumes),
                "Problems": join(str(p) for p in art.problems),
            }
            cells = {k: sanitize(v, safe) for k, v in cells.items()}
            widths.note(cells)
            w.writerow(cells)
    return rows, summary, widths.message
