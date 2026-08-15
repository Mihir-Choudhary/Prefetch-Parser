"""Command-line interface. A consumer of prefetch_core - all formatting lives here.

Deliberate differences from PECmd, each one a defect it has:

  * the hash is printed 8 hex digits wide (it prints 7 when the leading digit is zero);
  * `LastRun` is the newest run time, not whatever landed in slot 0;
  * the executable path is resolved once in the core, so every output agrees;
  * every input produces a row, including files that failed to parse;
  * all volumes are reported, not the first two.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

# Allow running from a source checkout without installing. Skipped when frozen: PyInstaller
# sets sys.frozen and puts everything on the bundle's own path, and injecting a directory
# derived from __file__ there points outside the bundle.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefetch_core import available_decompressors, parse_file  # noqa: E402
from prefetch_core.store import Store, StoreError  # noqa: E402

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


# Superset of PECmd's columns. Every column it emits has an equivalent here, plus the fields
# it drops. Two of its shapes are deliberately not copied:
#   * Volume0*/Volume1* only, with a Note when a third exists -> we keep those two for
#     familiarity AND add AllVolumes, which is complete.
#   * Directories concatenated across volumes with no separator -> ours are volume-tagged.
CSV_COLUMNS = [
    "SourceName", "SourcePath", "SourceCreated", "SourceModified", "SourceAccessed",
    "Version", "ExecutableName", "Hash", "Size", "RunCount",
    "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3",
    "PreviousRun4", "PreviousRun5", "PreviousRun6", "AllRunTimes",
    "ExecutablePath", "PathSource", "ExecutablePathAlt", "HostedPackage",
    "VolumeCount", "Volume0Name", "Volume0Serial", "Volume0Created",
    "Volume1Name", "Volume1Serial", "Volume1Created", "AllVolumes",
    "Directories", "DirectoryCount", "FilesLoaded", "FileCount", "TraceChains",
    "NameTruncated", "IsOpFile", "DeceptiveChars", "ParsedOk", "FailedStage", "Problems",
]


def discover(paths, recurse=True):
    """Yield .pf files, each exactly once.

    Recurses by default - ReadyBoot lives in a subdirectory, and a flat glob silently misses an
    entire artifact class.

    **Deduplicated by resolved real path.** Overlapping arguments are easy to produce by
    accident (`parse Prefetch Prefetch/ReadyBoot`, a folder plus a file inside it, a shell glob
    that repeats) and without this every affected row appeared twice in the CSV and the console
    count. The SQLite store happens to survive it because ingest is idempotent per source path,
    but only for literally identical paths - `dir/x.pf` and `dir/./x.pf` slipped through even
    there, which is why the store now normalises too.
    """
    seen = set()
    for path in _walk(paths, recurse):
        key = os.path.realpath(path)
        if key in seen:
            continue
        seen.add(key)
        yield path


def _walk(paths, recurse):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            if not recurse:
                for n in sorted(os.listdir(p)):
                    full = os.path.join(p, n)
                    if os.path.isfile(full) and n.lower().endswith(".pf"):
                        yield full
            else:
                for root, _dirs, names in os.walk(p):
                    for n in sorted(names):
                        if n.lower().endswith(".pf"):
                            yield os.path.join(root, n)
        else:
            print(f"!! not found: {p}", file=sys.stderr)


# Characters that make a spreadsheet treat a cell as a formula rather than text. A path named
# `=cmd|'/c calc'!A1` is executed by Excel on open - the classic DDE/CSV-injection payload.
# Forensic CSVs are opened in Excel more or less always, and the filename is attacker-chosen.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


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


def _ts(dt):
    return dt.isoformat(sep=" ") if dt else ""


def row_for(pf):
    # LastRun is the newest, then the remainder newest-first. PECmd puts slot 0 in LastRun,
    # which is not always the newest - see docs/edge-cases.md 1.
    ordered = sorted(pf.run_times, reverse=True)
    previous = ordered[1:] if ordered else []

    row = {
        "SourceName": os.path.basename(pf.source_path),
        "SourcePath": pf.source_path,
        "SourceCreated": _ts(pf.source_created),
        "SourceModified": _ts(pf.source_modified),
        "SourceAccessed": _ts(pf.source_accessed),
        "Version": pf.version or "",
        "ExecutableName": pf.executable_name,
        "Hash": pf.hash,
        "Size": pf.file_size,
        "RunCount": pf.run_count,
        "LastRun": _ts(ordered[0]) if ordered else "",
        # Every run time in the file's own stored order, so nothing is lost even if a future
        # version retains more than 8 and the fixed PreviousRunN columns overflow.
        "AllRunTimes": join_list(_ts(t) for t in pf.run_times),
        "ExecutablePath": pf.executable_path or "",
        "PathSource": pf.path_source.value,
        "ExecutablePathAlt": pf.executable_path_alt or "",
        "HostedPackage": pf.hosted_package or "",
        "VolumeCount": len(pf.volumes),
        "AllVolumes": join_list(
            f"{v.device_name} serial={v.serial} created={_ts(v.created)}" for v in pf.volumes),
        "Directories": join_list(
            f"[vol{j}] {d}" for j, v in enumerate(pf.volumes) for d in v.directories),
        "DirectoryCount": sum(len(v.directories) for v in pf.volumes),
        "FilesLoaded": join_list(pf.filenames),
        "FileCount": len(pf.filenames),
        "TraceChains": pf.trace_chain_count,
        "NameTruncated": int(pf.name_truncated),
        "IsOpFile": int(pf.is_op_file),
        "DeceptiveChars": int(pf.deceptive_characters),
        "ParsedOk": int(pf.parsed_ok),
        "FailedStage": pf.failed_stage or "",
        "Problems": join_list(str(p) for p in pf.problems),
    }
    for i in range(7):
        row[f"PreviousRun{i}"] = _ts(previous[i]) if i < len(previous) else ""
    for j in range(2):
        v = pf.volumes[j] if j < len(pf.volumes) else None
        row[f"Volume{j}Name"] = v.device_name if v else ""
        row[f"Volume{j}Serial"] = v.serial if v else ""
        row[f"Volume{j}Created"] = _ts(v.created) if v else ""
    return row


def cmd_parse(args):
    files = list(discover(args.paths, recurse=not args.no_recurse))
    if not files:
        print("no .pf files found", file=sys.stderr)
        # Saying only "no .pf files" when Layout.ini and the SuperFetch databases are sitting
        # right there reads as "nothing here". They are a different command, so point at it.
        from prefetch_core.artifacts import scan_folder
        others = []
        for path in args.paths:
            if os.path.isdir(path):
                try:
                    others.extend(scan_folder(path))
                except OSError:
                    pass
        if others:
            kinds = sorted({a.kind for a in others})
            print(f"note: {len(others)} other Prefetch-folder artifact(s) present "
                  f"({', '.join(kinds)}) - run `pfcli artifacts` to report them",
                  file=sys.stderr)
        return 1

    records = []
    failures = 0
    for f in files:
        pf = parse_file(f, prefer_decompressor=args.decompressor)
        records.append(pf)
        if not pf.parsed_ok:
            failures += 1

    # Parsing a large folder takes real time. If one output destination is unwritable, report
    # it plainly and still attempt the other, rather than discarding the whole run behind a
    # traceback because of a permissions typo.
    write_errors = 0

    if args.db:
        try:
            with Store(args.db) as s:
                s.add_all(records)
            print(f"wrote {len(records)} records to {args.db}")
        except (StoreError, OSError) as exc:
            print(f"!! could not write database: {exc}", file=sys.stderr)
            write_errors += 1

    if args.csv:
        try:
            safe = not args.raw_csv
            with open(args.csv, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
                w.writeheader()
                for pf in records:
                    # Sanitised at write time rather than inside row_for, so every column is
                    # covered automatically instead of only the ones anyone remembered.
                    w.writerow({k: sanitize_cell(v, safe) for k, v in row_for(pf).items()})
            print(f"wrote {len(records)} rows to {args.csv}")
        except OSError as exc:
            print(f"!! could not write CSV {args.csv!r}: {exc}", file=sys.stderr)
            write_errors += 1

    if not args.db and not args.csv:
        for pf in records:
            if not pf.parsed_ok:
                # A failed record has no executable name or hash, so printing the normal
                # columns yields a blank line and the analyst cannot tell which file broke.
                reason = pf.problems[-1].message if pf.problems else "unknown"
                print(f"{'FAILED':<8}  {os.path.basename(pf.source_path):<44} "
                      f"[{pf.failed_stage}] {reason}")
                continue
            path = pf.executable_path or f"<{pf.path_source.value}>"
            last = pf.last_run.isoformat(sep=" ", timespec="seconds") if pf.last_run else "-"
            print(f"{pf.hash}  {last}  x{pf.run_count:<5} {pf.executable_name:<32} {path}")

    print(f"\n{len(records)} file(s), {failures} failed to parse", file=sys.stderr)
    # Report the host's lack of birth-time support once, not once per record.
    if records and all(r.source_created is None for r in records):
        print("note: this filesystem reports no creation time, so SourceCreated is empty and "
              "first-run estimates are unavailable", file=sys.stderr)
    # Non-zero when an output could not be written, so a script does not treat a run that
    # produced no file as success.
    return 1 if write_errors else 0


def cmd_info(args):
    pf = parse_file(args.path, prefer_decompressor=args.decompressor)
    print(f"source          : {pf.source_path}")
    # Lead with the verdict. Everything below a failure was read from bytes that never passed
    # validation - the version in particular is taken before the signature is checked, so a
    # file that is not prefetch at all still shows a plausible-looking number. Printing that
    # first and the failure last invites reading it as fact.
    if pf.failed_stage:
        print(f"*** PARSE FAILED at stage '{pf.failed_stage}' - "
              f"fields below are unvalidated and may be meaningless")
    print(f"version         : {pf.version}")
    print(f"executable      : {pf.executable_name}"
          + ("  (name truncated at 29 chars)" if pf.name_truncated else ""))
    print(f"hash            : {pf.hash}")
    print(f"run count       : {pf.run_count}")
    print(f"path            : {pf.executable_path}   [{pf.path_source.value}]")
    if pf.executable_path_alt:
        print(f"  conflicting   : {pf.executable_path_alt}")
    if pf.hosted_package:
        print(f"hosted package  : {pf.hosted_package}")
    newest = pf.last_run
    print(f"run times       : {len(pf.run_times)} retained (stored order; * = newest)")
    for i, t in enumerate(pf.run_times):
        print(f"   slot {i}: {t}{'  *' if t == newest else ''}")
    for j, v in enumerate(pf.volumes):
        print(f"volume {j}        : {v.device_name}")
        print(f"   serial {v.serial}  created {v.created}  name-check {v.name_self_check}")
        print(f"   {len(v.directories)} directories, {len(v.file_refs)} MFT references")
    print(f"loaded files    : {len(pf.filenames)}")
    if pf.problems:
        print("problems:")
        for p in pf.problems:
            print(f"   {p}")
    # Non-zero when the file did not parse, so `pfcli info x.pf && ...` behaves sensibly.
    return 1 if pf.failed_stage else 0


def cmd_ads(args):
    """Recover prefetch hidden in NTFS alternate data streams."""
    from prefetch_core import ads

    try:
        findings = ads.scan_tree(args.folder, include_directories=not args.files_only)
    except ads.AdsUnavailable as exc:
        # Never print "0 found" here. "Could not look" and "looked and found nothing" are
        # different answers and only one of them is evidence.
        print(f"!! alternate data streams cannot be enumerated: {exc}", file=sys.stderr)
        print("   Run this on Windows, or supply a raw NTFS image.", file=sys.stderr)
        return 2

    if not findings:
        print(f"scanned {args.folder}: no prefetch found in any alternate data stream")
        return 0

    records = ads.parse_findings(findings, prefer_decompressor=args.decompressor)
    for finding, pf in zip(findings, records):
        print(f"\n=== {finding.stream.open_path}")
        print(f"    carrier          : {finding.stream.carrier_path}")
        print(f"    stream           : {finding.stream.short_name}  "
              f"({finding.stream.size:,} bytes)")
        print(f"    carrier primary  : {finding.carrier_primary_size:,} bytes")
        print(f"    executable       : {pf.executable_name or '(unparsed)'}")
        print(f"    path             : {pf.executable_path or '-'}")
        print(f"    run count        : {pf.run_count}")
        print(f"    last run         : {pf.last_run or '-'}")
        print(f"    timestamp source : {pf.timestamp_source}")
        print(f"    carrier modified : {pf.carrier_modified or '-'}")
        if finding.outside_prefetch_folder:
            print("    ** recovered from OUTSIDE the Prefetch folder **")
        for problem in pf.problems:
            print(f"    ! {problem}")

    if args.db:
        try:
            with Store(args.db) as s:
                s.add_all(records)
            print(f"\nwrote {len(records)} record(s) to {args.db}")
        except (StoreError, OSError) as exc:
            print(f"!! could not write database: {exc}", file=sys.stderr)
            return 1

    print(f"\n{len(findings)} prefetch file(s) recovered from alternate data streams.")
    print("Timestamps shown are the CARRIER's - a stream has none of its own, so "
          "first-run estimates are unavailable for these records.")
    return 0


def cmd_artifacts(args):
    from prefetch_core.artifacts import scan_folder

    found = scan_folder(args.folder)
    if not found:
        print("no non-.pf artifacts found")
        return 0
    for a in found:
        stamp = a.modified.strftime("%Y-%m-%d %H:%M") if a.modified else "-"
        print(f"\n{a.name}   [{a.kind}]   {a.size:,} bytes   modified {stamp}")
        for k, v in a.facts.items():
            print(f"    {k:22} {v}")
        if a.paths:
            # ReadyBoot yields path *components* (`Windows`, `System32`), not whole paths -
            # the record tree that would join them is not decoded. Labelling them "paths"
            # would invite an analyst to read a bare component as a location on disk.
            label = "name components" if a.kind == "readyboot" else "paths"
            print(f"    {label:22} {len(a.paths)}")
            for p in (a.paths if args.paths else a.paths[:3]):
                print(f"        {p}")
            if not args.paths and len(a.paths) > 3:
                print(f"        … {len(a.paths) - 3} more (--paths to list all)")
        for problem in a.problems:
            print(f"    ! {problem}")
    # These are access/priority artifacts. Saying so once, plainly, is cheaper than an analyst
    # reading a Layout.ini path as evidence that something executed.
    print(f"\n{len(found)} artifact(s). None of these record execution: they show files the "
          f"system treated as hot, with no run times.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pfcli", description="Windows Prefetch parser")
    ap.add_argument("--decompressor", choices=["ntdll", "pure"],
                    help="force a decompressor; default probes for ntdll and falls back")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("parse", help="parse files or directories")
    p.add_argument("paths", nargs="+")
    p.add_argument("--db", help="write a SQLite database (the primary artifact)")
    p.add_argument("--csv", help="write a flat CSV export")
    p.add_argument("--no-recurse", action="store_true", help="do not descend into subdirectories")
    p.add_argument("--raw-csv", action="store_true",
                   help="do not neutralise spreadsheet formula triggers in CSV cells; exact "
                        "bytes, for programmatic consumers rather than Excel")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("info", help="dump one prefetch file in full")
    p.add_argument("path")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("ads", help="recover prefetch hidden in NTFS alternate data streams")
    p.add_argument("folder")
    p.add_argument("--db", help="write recovered records to a SQLite database")
    p.add_argument("--files-only", action="store_true",
                   help="skip directories; NTFS directory objects can carry streams too")
    p.set_defaults(func=cmd_ads)

    p = sub.add_parser("artifacts", help="report non-.pf files in a Prefetch folder")
    p.add_argument("folder")
    p.add_argument("--paths", action="store_true", help="also list every path each one holds")
    p.set_defaults(func=cmd_artifacts)

    sub.add_parser("capabilities", help="show available decompressors").set_defaults(
        func=lambda a: (print("decompressors:", ", ".join(available_decompressors())), 0)[1])

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
