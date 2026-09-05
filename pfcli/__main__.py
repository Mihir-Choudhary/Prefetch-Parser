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
import sqlite3
import sys

# Allow running from a source checkout without installing. Skipped when frozen: PyInstaller
# sets sys.frozen and puts everything on the bundle's own path, and injecting a directory
# derived from __file__ there points outside the bundle.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefetch_core import available_decompressors, parse_file, winpath  # noqa: E402
# The list encoding, the formula guard and the artifact writer live in the core: the GUI
# needs them too, and two implementations of one export is how they come to disagree.
from prefetch_core.export import (  # noqa: E402
    ESCAPE, FORMULA_TRIGGERS, LIST_SEP, join_list, sanitize_cell, split_list,
    write_artifact_csv)
from prefetch_core.output import CellWidths, atomic_write, make_stdio_safe  # noqa: E402
from prefetch_core.store import Store, StoreError  # noqa: E402

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
    # The volume self-check verdict, the references the file does not declare, and the
    # directory count the file states beside the one actually recovered. All three were in the
    # database and none of them in the export.
    "FilenameHashMatch", "FilenameNameMatch", "ContainerTrailingBytes", "Decompressor",
    "VolumeNameChecks", "SlackReferences", "SlackReferenceCount", "DeclaredDirectoryCount",
    "DeclaredReferenceCount", "ReferenceCount",
    # Bytes in the file that belong to no field of it - residue of an earlier version of the
    # same record. Summary here; every region is in the `residue` table of the database.
    "ResidueBytes", "ResidueText",
    # Where the record came from when it was not a file in a Prefetch folder, and whose
    # timestamps the row above is carrying (AUDIT BUG 72).
    "FromAds", "CarrierPath", "StreamName", "StreamSize", "TimestampSource",
    "CarrierCreated", "CarrierModified", "CarrierAccessed", "CarrierIsPrefetch",
    "OutsidePrefetchFolder",
    # created - 10s, the documented approximation of the first execution. Shown in the GUI and
    # in `info`; absent from the export until now.
    "FirstRunApprox",
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
def _ts(dt):
    return dt.isoformat(sep=" ") if dt else ""


def _name(path: str) -> str:
    """A file's name as the console should show it - the same rendering the exports use.

    Without this the console printed the code point Python uses for a byte it could not decode
    while the CSV and the database printed the byte itself: one file,
    two spellings, across three surfaces of one tool (AUDIT BUG 102).
    """
    return winpath.readable_text(os.path.basename(path or ""))


def _shown(text: str) -> str:
    """The same rendering for a whole path or any other string headed for the console."""
    return winpath.readable_text(text or "")


def _tri(value):
    """Three states, never two - the same convention the database uses."""
    return "n/a" if value is None else ("ok" if value else "mismatch")


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
        # Volumes state their own creation time and serial inside the \VOLUME{...} name; the
        # parser checks that against the fields and this is the verdict, per volume. It was in
        # the database and in the GUI but not in the export anyone actually reads.
        # Bytes carried after the end of the compressed stream: empty means "not measured".
        "ContainerTrailingBytes": ("" if pf.container_trailing_bytes is None
                                   else pf.container_trailing_bytes),
        "Decompressor": pf.decompressor_used,
        # The filename against the header: renamed or planted files say so here.
        "FilenameHashMatch": _tri(pf.filename_hash_match),
        "FilenameNameMatch": _tri(pf.filename_name_match),
        "VolumeNameChecks": join_list(
            "n/a" if v.name_self_check is None else ("ok" if v.name_self_check else "mismatch")
            for v in pf.volumes),
        # References found in the array past the count the file declares - evidence the file
        # does not claim. In the database since Round 42, in the CSV only now.
        "SlackReferences": join_list(
            f"[vol{j}] {r}" for j, v in enumerate(pf.volumes) for r in v.slack_refs),
        "SlackReferenceCount": sum(len(v.slack_refs) for v in pf.volumes),
        # The count the file declares, beside the number actually recovered above. A
        # disagreement is a finding, and averaging them away would hide it.
        "DeclaredDirectoryCount": "" if pf.total_directory_count is None else pf.total_directory_count,
        # Slots the reference arrays declare, against the ones that actually hold a reference.
        "DeclaredReferenceCount": sum(v.declared_ref_count for v in pf.volumes),
        "ReferenceCount": sum(len(v.file_refs) for v in pf.volumes),
        "ResidueBytes": pf.residue_bytes,
        # Only the fragments that read as text; the raw bytes of every region are in the
        # database, and `pfcli info` shows them per region.
        "ResidueText": join_list(r.text for r in pf.residue if r.text),
        # Provenance for a record recovered from an alternate data stream. Without it the row
        # sits in the same columns as an ordinary one while carrying the CARRIER's timestamps,
        # with nothing to say so (AUDIT BUG 72). Empty for ordinary records: not applicable is
        # not the same as false.
        "FromAds": int(pf.from_ads),
        "CarrierPath": pf.carrier_path or "",
        "StreamName": pf.stream_name or "",
        "StreamSize": pf.stream_size if pf.from_ads else "",
        # Written for EVERY record, not only the ADS ones. The model's default is "stream" -
        # the measured fact that an ordinary file's timestamps are its own - and blanking it
        # replaced that with the convention this codebase uses for *not measured*. An analyst
        # filtering for records whose times can be trusted got nothing at all (AUDIT BUG 106).
        "TimestampSource": pf.timestamp_source,
        "CarrierCreated": _ts(pf.carrier_created),
        "CarrierModified": _ts(pf.carrier_modified),
        "CarrierAccessed": _ts(pf.carrier_accessed),
        "CarrierIsPrefetch": int(pf.carrier_is_prefetch) if pf.from_ads else "",
        "OutsidePrefetchFolder": int(pf.outside_prefetch_folder) if pf.from_ads else "",
        "FirstRunApprox": _ts(pf.first_run_approx),
    }
    for i in range(7):
        row[f"PreviousRun{i}"] = _ts(previous[i]) if i < len(previous) else ""
    for j in range(2):
        v = pf.volumes[j] if j < len(pf.volumes) else None
        row[f"Volume{j}Name"] = v.device_name if v else ""
        row[f"Volume{j}Serial"] = v.serial if v else ""
        row[f"Volume{j}Created"] = _ts(v.created) if v else ""
    # A filename does not have to be valid text, and the two exports must not spell one name
    # two ways: the database renders undecodable bytes through the same function (AUDIT BUG
    # 102). Applied here rather than per column, so a column added later cannot forget.
    return {k: winpath.readable_text(v) if isinstance(v, str) else v for k, v in row.items()}


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
            # Diagnostics go to stderr, always: a script piping stdout for the rows used to
            # get four lines of commentary mixed into its data (AUDIT BUG 107).
            print(f"wrote {len(records)} records to {args.db}", file=sys.stderr)
        # sqlite3.Error as well as StoreError: the store wraps what it can, and this is the
        # last line before a traceback would discard a run that has already been parsed.
        except (StoreError, OSError, sqlite3.Error) as exc:
            print(f"!! could not write database: {exc}", file=sys.stderr)
            write_errors += 1

    if args.csv:
        try:
            safe = not args.raw_csv
            # Atomic: a failure here must not destroy the CSV from the previous run.
            widths = CellWidths()
            guarded = {}
            with atomic_write(args.csv) as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
                w.writeheader()
                for pf in records:
                    # Sanitised at write time rather than inside row_for, so every column is
                    # covered automatically instead of only the ones anyone remembered.
                    raw = row_for(pf)
                    cells = {k: sanitize_cell(v, safe) for k, v in raw.items()}
                    for key, value in cells.items():
                        if isinstance(value, str) and value.startswith("'") \
                                and str(raw[key] or "") != value:
                            guarded[key] = guarded.get(key, 0) + 1
                    widths.note(cells)
                    w.writerow(cells)
            print(f"wrote {len(records)} rows to {args.csv}", file=sys.stderr)
            if widths.message:
                print(widths.message, file=sys.stderr)
            if guarded:
                # An unexplained apostrophe in an export is its own trust problem: say which
                # cells carry one and why, and name the flag that writes exact bytes.
                columns = ", ".join(f"{name} ({count})" for name, count in sorted(guarded.items()))
                print(f"note: {sum(guarded.values())} cell(s) were prefixed with an apostrophe "
                      f"so a spreadsheet cannot re-read them as numbers or dates: {columns}. "
                      f"The value follows the apostrophe unchanged; --raw-csv writes exact "
                      f"bytes.", file=sys.stderr)
        except OSError as exc:
            print(f"!! could not write CSV {args.csv!r}: {exc}", file=sys.stderr)
            write_errors += 1

    # A prefetch filename is derived from the executable name and a path hash, and the header
    # holds both. A disagreement means renamed, copied or planted - too strong a signal to
    # leave only in the CSV's Problems column, where a console user never sees it.
    renamed = [pf for pf in records
               if pf.filename_hash_match is False or pf.filename_name_match is False]
    if renamed:
        print(f"\n!! {len(renamed)} file(s) whose NAME disagrees with their own header "
              f"(renamed, copied, or planted):", file=sys.stderr)
        for pf in renamed[:20]:
            print(f"   {_name(pf.source_path)}  header says "
                  f"{pf.executable_name or '(none)'} / {pf.hash or '(none)'}", file=sys.stderr)
        if len(renamed) > 20:
            print(f"   ... and {len(renamed) - 20} more", file=sys.stderr)

    # With `--csv` or `--db` the per-file table is not printed, and the run summary then said
    # "8 failed to parse" without saying WHICH - the names were in the export and nowhere on
    # the console. A failed record is the one thing an analyst wants to see immediately.
    failed = [pf for pf in records if not pf.parsed_ok]
    if failed and (args.db or args.csv):
        print(f"\n{len(failed)} file(s) failed to parse:", file=sys.stderr)
        for pf in failed[:20]:
            reason = pf.problems[-1].message if pf.problems else "unknown"
            print(f"   {_name(pf.source_path):<44} [{pf.failed_stage}] {reason}",
                  file=sys.stderr)
        if len(failed) > 20:
            print(f"   ... and {len(failed) - 20} more (all of them are in the export)",
                  file=sys.stderr)

    if not args.db and not args.csv:
        for pf in records:
            if not pf.parsed_ok:
                # A failed record has no executable name or hash, so printing the normal
                # columns yields a blank line and the analyst cannot tell which file broke.
                reason = pf.problems[-1].message if pf.problems else "unknown"
                print(f"{'FAILED':<8}  {_name(pf.source_path):<44} "
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
    # 120, not 1. `1` means "nothing was parsed"; this means "the evidence parsed and one of
    # the outputs could not be written", which a script should be able to tell apart - and
    # `artifacts` and `ads` already returned 120 for exactly this, so `parse` returning 1 made
    # the same condition report two different codes depending on the subcommand (AUDIT BUG 82).
    return 120 if write_errors else 0


def cmd_info(args):
    pf = parse_file(args.path, prefer_decompressor=args.decompressor)
    print(f"source          : {_shown(pf.source_path)}")
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
        slack = (f", {len(v.slack_refs)} unclaimed in array slack"
                 if getattr(v, "slack_refs", None) else "")
        print(f"   {len(v.directories)} directories, {len(v.file_refs)} MFT references{slack}")
        for r in getattr(v, "slack_refs", []):
            # Not counted by the file. Shown apart from the declared references so nothing
            # reads them as part of what the record claims.
            print(f"      slack reference: {r}")
    print(f"loaded files    : {len(pf.filenames)}")
    if pf.metrics:
        # Each metric owns a slice of the trace-chain array; the slices tile it exactly. That
        # is what makes "how much block-load work did this file account for" answerable at all.
        print(f"   trace chains   : {pf.trace_chain_count} entries, "
              f"attributed to {len(pf.metrics)} file(s)")
        print("   idx  chains  fetched  flags    file")
        for m in pf.metrics[:20]:
            ref = f"  mft {m.mft_ref}" if m.mft_ref else ""
            subset = "-" if m.chain_subset is None else str(m.chain_subset)
            # `filename[-60:]` cut the path from the LEFT, silently: the corpus printed
            # `UME{01d8559f...}\WINDOWS\SYSTEM32\IMAGERES.DLL` - a path missing its first four
            # characters, with nothing to say so, in the command whose whole purpose is to be
            # complete. A truncated path in a report is a path that does not exist (AUDIT BUG
            # 108). Printed whole; a long line wraps, which costs nothing an analyst minds.
            print(f"   {m.index:>4}  {m.chain_count:>6}  {subset:>7}  "
                  f"0x{m.flags:04x}  {_shown(m.filename)}{ref}")
        if len(pf.metrics) > 20:
            print(f"   … {len(pf.metrics) - 20} more (--db writes every one)")
    if pf.residue:
        print(f"residue         : {pf.residue_bytes} byte(s) in {len(pf.residue)} region(s) "
              f"that belong to no field of this file")
        for r in pf.residue:
            shown = repr(r.text) if r.text else r.data[:24].hex(" ")
            print(f"   +{r.offset:<8} {r.size:>4} bytes  {shown}")

    undecoded = undecoded_fileinfo(pf)
    if undecoded:
        # Printed because they exist, not because they mean anything. Ten dwords of the
        # file-information section are documented by nobody and are populated on real files;
        # a tool that silently drops them is deciding on the analyst's behalf that they do not
        # matter. Offsets are relative to the section start (absolute 84).
        nonzero = [(off, val) for off, val in undecoded if val]
        print(f"undecoded fields: {len(undecoded)} dword(s) in the file-information section "
              f"that no published description names; {len(nonzero)} non-zero")
        for off, val in nonzero:
            print(f"   +{off:<4} 0x{val:08x}  {val}")
    if pf.problems:
        print("problems:")
        for p in pf.problems:
            print(f"   {p}")
    # Non-zero when the file did not parse, so `pfcli info x.pf && ...` behaves sensibly.
    return 1 if pf.failed_stage else 0


def undecoded_fileinfo(pf):
    """The dwords of the file-information section this parser can name nothing about.

    Everything the format documentation describes is read into fields; this is the remainder,
    returned as `(offset from section start, value)`. It exists so "we read the whole file" is
    a checkable claim rather than a promise.
    """
    import struct as _struct

    from prefetch_core.scca import LAYOUT

    raw = getattr(pf, "fileinfo_raw", b"")
    layout = LAYOUT.get(pf.version)
    if not raw or layout is None:
        return []
    known = set(range(0, 32, 4))                       # the eight offset/count pairs
    if layout.dir_count_offset is not None:
        known.add(layout.dir_count_offset)
    for i in range(layout.runtime_slots * 2):          # 8-byte FILETIMEs
        known.add(layout.runtime_offset + i * 4)
    runcount = layout.runcount_offset
    if runcount is None:
        runcount = len(raw) - 96
    known.add(runcount)
    out = []
    for off in range(0, len(raw) - 3, 4):
        if off in known:
            continue
        out.append((off, _struct.unpack_from("<I", raw, off)[0]))
    return out


def cmd_ads(args):
    """Recover prefetch hidden in NTFS alternate data streams."""
    from prefetch_core import ads

    skipped = []
    try:
        findings = ads.scan_tree(args.folder, include_directories=not args.files_only,
                                 on_error=lambda p, exc: skipped.append((p, exc)))
    except ads.AdsUnavailable as exc:
        # Never print "0 found" here. "Could not look" and "looked and found nothing" are
        # different answers and only one of them is evidence.
        print(f"!! alternate data streams cannot be enumerated: {exc}", file=sys.stderr)
        print("   Run this on Windows, or supply a raw NTFS image.", file=sys.stderr)
        return 2
    except NotADirectoryError:
        print(f"not a directory: {args.folder}\n"
              "`ads` walks a folder - pass the folder, not a file in it.", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as exc:
        # Same reason as above: a path that was never scanned must not read as a clean scan.
        print(f"!! cannot scan {args.folder}: {exc}", file=sys.stderr)
        return 1

    def report_skipped():
        """Entries that refused enumeration are not entries that came back clean."""
        if not skipped:
            return
        print(f"\n!! {len(skipped)} entr(ies) could not be examined - "
              f"this scan is INCOMPLETE:", file=sys.stderr)
        for target, exc in skipped[:10]:
            print(f"   {target}: {exc}", file=sys.stderr)
        if len(skipped) > 10:
            print(f"   … and {len(skipped) - 10} more", file=sys.stderr)

    if not findings:
        print(f"scanned {args.folder}: no prefetch found in any alternate data stream")
        report_skipped()
        return 1 if skipped else 0

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

    write_errors = 0
    if args.db:
        try:
            with Store(args.db) as s:
                s.add_all(records)
            print(f"\nwrote {len(records)} record(s) to {args.db}", file=sys.stderr)
        except (StoreError, OSError, sqlite3.Error) as exc:
            print(f"!! could not write database: {exc}", file=sys.stderr)
            write_errors += 1

    # The CSV carries the carrier path, the stream name and whose timestamps the row holds, so
    # an ADS finding can now be exported without losing the provenance that makes it evidence.
    if args.csv:
        try:
            safe = not args.raw_csv
            widths = CellWidths()
            with atomic_write(args.csv) as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
                w.writeheader()
                for pf in records:
                    cells = {k: sanitize_cell(v, safe) for k, v in row_for(pf).items()}
                    widths.note(cells)
                    w.writerow(cells)
            print(f"wrote {len(records)} row(s) to {args.csv}", file=sys.stderr)
            if widths.message:
                print(widths.message, file=sys.stderr)
        except OSError as exc:
            print(f"!! could not write CSV {args.csv!r}: {exc}", file=sys.stderr)
            write_errors += 1

    print(f"\n{len(findings)} prefetch file(s) recovered from alternate data streams.")
    print("Timestamps shown are the CARRIER's - a stream has none of its own, so "
          "first-run estimates are unavailable for these records.")
    report_skipped()
    if write_errors:
        return 120
    return 1 if skipped else 0


def cmd_artifacts(args):
    from prefetch_core.artifacts import scan_folder

    # A bad path and a clean folder used to print the same line and both exit 0, so
    # `pfcli artifacts "$DIR" && echo clean` reported clean for a typo or an unmounted share.
    # "scanned and found nothing" is evidence; "never scanned" is not.
    try:
        found = scan_folder(args.folder)
    except NotADirectoryError:
        print(f"not a directory: {args.folder}\n"
              "`artifacts` scans a Prefetch folder - pass the folder, not a file in it.",
              file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as exc:
        print(f"cannot scan {args.folder}: {exc}", file=sys.stderr)
        return 1
    if not found:
        print(f"scanned {args.folder}: no non-.pf artifacts found")
        return 0
    for a in found:
        stamp = a.modified.strftime("%Y-%m-%d %H:%M") if a.modified else "-"
        print(f"\n{_shown(a.name)}   [{a.kind}]   {a.size:,} bytes   modified {stamp}")
        for k, v in a.facts.items():
            print(f"    {k:22} {v}")
        if a.paths:
            print(f"    {'paths':22} {len(a.paths)}")
            for p in (a.paths if args.paths else a.paths[:3]):
                print(f"        {p}")
            if not args.paths and len(a.paths) > 3:
                print(f"        … {len(a.paths) - 3} more (--paths to list all)")
        if a.io_by_path:
            # Heaviest first: on a boot trace the top few reads are the whole story, and the
            # tail is thousands of 4 KB reads nobody scrolls through.
            print(f"    {'heaviest reads':22} {len(a.io_by_path)} files")
            for path, count, nbytes in (a.io_by_path if args.paths else a.io_by_path[:5]):
                print(f"        {nbytes / 1048576:9,.1f} MB in {count:>6,} reads  {path}")
            if not args.paths and len(a.io_by_path) > 5:
                print(f"        … {len(a.io_by_path) - 5} more (--paths to list all)")
        for problem in a.problems:
            print(f"    ! {problem}")

    # `\Device\HarddiskVolumeN` is what prefetch records; `C:` is what an analyst needs. This
    # is the one place in a collected folder where the two can be tied together.
    from prefetch_core.artifacts import correlate_volumes, describe_identities
    # Rendered by prefetch_core, not here: the CLI and the GUI each had their own copy of this
    # block and each printed a stated SuperFetch record as an inference (AUDIT BUG 88).
    withheld = []
    lines = describe_identities(correlate_volumes(found, withheld), withheld)
    if lines:
        print()
        for line in lines:
            print(line)

    write_errors = 0
    if args.db:
        try:
            with Store(args.db) as s:
                s.add_artifacts(found)
            print(f"\nwrote {len(found)} artifact(s) to {args.db}", file=sys.stderr)
        except (StoreError, OSError, sqlite3.Error) as exc:
            print(f"!! could not write database: {exc}", file=sys.stderr)
            write_errors += 1

    if args.csv:
        try:
            paths_written, summary_path, note = write_artifact_csv(
                found, args.csv, safe=not args.raw_csv)
            print(f"wrote {paths_written:,} path row(s) to {args.csv}", file=sys.stderr)
            print(f"wrote {len(found)} artifact summary row(s) to {summary_path}",
                  file=sys.stderr)
            if note:
                print(note, file=sys.stderr)
        except OSError as exc:
            print(f"!! could not write CSV {args.csv!r}: {exc}", file=sys.stderr)
            write_errors += 1

    # These are access/priority artifacts. Saying so once, plainly, is cheaper than an analyst
    # reading a Layout.ini path as evidence that something executed.
    print(f"\n{len(found)} artifact(s). None of these record execution: they show files the "
          f"system treated as hot, with no run times.")
    return 120 if write_errors else 0


def main(argv=None):
    # Before anything can print: on Windows a redirected stdout is the ANSI code page, and one
    # Cyrillic filename in the folder ends the run with a UnicodeEncodeError traceback and no
    # report (AUDIT BUG 97).
    make_stdio_safe()
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
    p.add_argument("--csv", help="write recovered records to a CSV, provenance included")
    p.add_argument("--raw-csv", action="store_true",
                   help="do not prefix formula-trigger cells with an apostrophe")
    p.add_argument("--files-only", action="store_true",
                   help="skip directories; NTFS directory objects can carry streams too")
    p.set_defaults(func=cmd_ads)

    p = sub.add_parser("artifacts", help="report non-.pf files in a Prefetch folder")
    p.add_argument("folder")
    p.add_argument("--paths", action="store_true", help="also list every path each one holds")
    p.add_argument("--db", help="write the artifacts to a SQLite database (separate tables "
                                "from .pf records - these are access, not execution)")
    p.add_argument("--csv", help="write one row per path, plus a -summary.csv beside it")
    p.add_argument("--raw-csv", action="store_true",
                   help="do not prefix formula-trigger cells with an apostrophe")
    p.set_defaults(func=cmd_artifacts)

    sub.add_parser("capabilities", help="show available decompressors").set_defaults(
        func=lambda a: (print("decompressors:", ", ".join(available_decompressors())), 0)[1])

    args = ap.parse_args(argv)

    # A forced decompressor that does not exist on this host is an environment failure, not a
    # property of the evidence. Without this check, `--decompressor ntdll` on Linux parsed the
    # whole folder, failed every single file at the container stage, and exited **0** - so a
    # script driving the tool recorded a successful run with no findings (AUDIT BUG 79).
    if getattr(args, "decompressor", None):
        available = available_decompressors()
        if args.decompressor not in available:
            print(f"!! the {args.decompressor!r} decompressor is not available on this host "
                  f"(available: {', '.join(available)}).\n"
                  f"   'ntdll' is the Windows OS decompressor; on any other system use "
                  f"--decompressor pure, which is the default.", file=sys.stderr)
            return 2

    # Two outputs pointed at one path meant the second write silently destroyed the first,
    # while the console reported both: "wrote 6 records to X" (the database) followed by
    # "wrote 6 rows to X" (the CSV, over the top of it), exit 0, and the truncation note
    # helpfully explaining that the full values are "in the database" - which no longer
    # existed. An analyst is left holding one artifact and a console that says two
    # (AUDIT BUG 90).
    outputs = []
    for flag in ("db", "csv"):
        value = getattr(args, flag, None)
        if value:
            outputs.append((f"--{flag}", value))
    # `artifacts --csv` writes a second file beside the one it is given.
    if getattr(args, "func", None) is cmd_artifacts and getattr(args, "csv", None):
        from prefetch_core.export import summary_path_for
        outputs.append(("--csv (its -summary.csv)", summary_path_for(args.csv)))
    seen: dict[str, str] = {}
    for flag, value in outputs:
        key = os.path.realpath(os.path.abspath(value))
        if key in seen:
            print(f"!! {seen[key]} and {flag} both write {value!r}. One would silently "
                  f"overwrite the other and the run would report writing both.",
                  file=sys.stderr)
            return 2
        seen[key] = flag
    # Distinct names can still be one file: a hard link, or two paths through a symlink that
    # realpath cannot resolve identically.
    for i, (flag_a, a) in enumerate(outputs):
        for flag_b, b in outputs[i + 1:]:
            try:
                if os.path.exists(a) and os.path.exists(b) and os.path.samefile(a, b):
                    print(f"!! {flag_a} ({a!r}) and {flag_b} ({b!r}) are the same file. One "
                          f"would silently overwrite the other.", file=sys.stderr)
                    return 2
            except OSError:
                pass
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
