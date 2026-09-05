#!/usr/bin/env python3
"""End-to-end value fidelity: nothing is altered on the way out.

Every other suite checks that the parser reads the right values. This one checks that those
values survive to every place an analyst can read them - the CSV, the SQLite database, the
grid, and the detail panes - **unchanged, element for element**.

That is the property a forensic tool actually has to hold. A wrong path in a report is not
distinguishable from a wrong path in the file, and an analyst has no way to audit the
difference. So the parsed record is treated as ground truth and every output surface is
compared against it for the whole corpus, including the one-to-many lists where a single
off-by-one would silently drop or duplicate an entry.

Two display transforms are expected and asserted rather than ignored:
  * the grid escapes bidi/zero-width characters, so a spoofed name renders as what it is;
  * the grid prints timestamps without the "+00:00" suffix, since the header says UTC.
Both are applied to the *display* only - the CSV and the database carry the raw value.

Run:  python3 test_output_fidelity.py
"""

import csv
import glob
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
os.environ["APPDATA"] = os.environ["XDG_CONFIG_HOME"]

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import corpus  # noqa: E402

corpus.require_qt()      # before the imports below; see test_gui_logic.py

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfcli.__main__ import sanitize_cell, split_list  # noqa: E402
from prefetch_core import parse_file  # noqa: E402
from prefetch_core.store import Store  # noqa: E402
from prefetch_core.winpath import escape_deceptive  # noqa: E402

CORPUS = corpus.WIN10

mismatches = []


def differ(name, field, got, want):
    if str(got) != str(want):
        mismatches.append((name, field, got, want))


def check_csv(records):
    """Compare the CSV against the parsed record, field by field.

    Compared against the **`--raw-csv`** export, which is the one that promises exact bytes.
    The default export deliberately differs on cells a spreadsheet would silently re-read - a
    hash like `1482E648` becomes `\'1482E648` so Excel cannot turn it into 1482 x 10^648
    (AUDIT BUG 103). That difference is checked below rather than ignored: safe output must
    equal raw output except for a leading apostrophe, and nothing else may move.
    """
    workdir = tempfile.mkdtemp()
    out = os.path.join(workdir, "o.csv")
    safe_out = os.path.join(workdir, "safe.csv")
    subprocess.run([sys.executable, "-m", "pfcli", "parse", CORPUS, "--csv", out, "--raw-csv"],
                   cwd=ROOT, capture_output=True, check=True)
    subprocess.run([sys.executable, "-m", "pfcli", "parse", CORPUS, "--csv", safe_out],
                   cwd=ROOT, capture_output=True, check=True)
    csv.field_size_limit(10**9)
    with open(out, newline="", encoding="utf-8") as fh:
        rows = {r["SourcePath"]: r for r in csv.DictReader(fh)}
    with open(safe_out, newline="", encoding="utf-8") as fh:
        safe_rows = {r["SourcePath"]: r for r in csv.DictReader(fh)}

    # The safe export differs from the raw one only by that prefix, and only where the guard
    # says it should. Anything else moving between the two is a defect in the guard itself.
    guarded = 0
    for path, raw_row in rows.items():
        safe_row = safe_rows.get(path)
        if safe_row is None:
            mismatches.append((os.path.basename(path), "missing from the safe CSV", "", ""))
            continue
        for column, raw_value in raw_row.items():
            safe_value = safe_row[column]
            if safe_value == raw_value:
                continue
            if safe_value == "'" + raw_value and sanitize_cell(raw_value) == safe_value:
                guarded += 1
                continue
            mismatches.append((os.path.basename(path), f"{column} moved between raw and safe",
                               safe_value, raw_value))
    print(f"  cells the spreadsheet guard prefixed: {guarded}")

    print(f"  CSV rows: {len(rows)} (records: {len(records)})")
    if len(rows) != len(records):
        mismatches.append(("<csv>", "row count", len(rows), len(records)))

    for path, pf in records.items():
        row = rows.get(path)
        name = os.path.basename(path)
        if row is None:
            mismatches.append((name, "missing from CSV", "", ""))
            continue
        differ(name, "ExecutableName", row["ExecutableName"], pf.executable_name)
        differ(name, "Hash", row["Hash"], pf.hash)
        differ(name, "Version", row["Version"], pf.version)
        differ(name, "Size", row["Size"], pf.file_size)
        differ(name, "RunCount", row["RunCount"], pf.run_count)
        differ(name, "LastRun", row["LastRun"],
               pf.last_run.isoformat(sep=" ") if pf.last_run else "")
        differ(name, "ExecutablePath", row["ExecutablePath"], pf.executable_path or "")
        differ(name, "PathSource", row["PathSource"], pf.path_source.value)
        differ(name, "HostedPackage", row["HostedPackage"], pf.hosted_package or "")
        differ(name, "VolumeCount", row["VolumeCount"], len(pf.volumes))
        differ(name, "FileCount", row["FileCount"], len(pf.filenames))
        # The list cells must round-trip element for element - this is where an escaping bug
        # silently splits or merges entries.
        differ(name, "FilesLoaded", split_list(row["FilesLoaded"]), pf.filenames)
        differ(name, "Directories", split_list(row["Directories"]),
               [f"[vol{j}] {d}" for j, v in enumerate(pf.volumes) for d in v.directories])
        differ(name, "AllRunTimes",
               split_list(row["AllRunTimes"]) if row["AllRunTimes"] else [],
               [t.isoformat(sep=" ") for t in pf.run_times])
        for j in range(min(2, len(pf.volumes))):
            differ(name, f"Volume{j}Name", row[f"Volume{j}Name"], pf.volumes[j].device_name)
            differ(name, f"Volume{j}Serial", row[f"Volume{j}Serial"], pf.volumes[j].serial)
        # Residue is raw file bytes reaching a spreadsheet column; the count must be the true
        # total and the text must round-trip element for element like any other list cell.
        differ(name, "ResidueBytes", row["ResidueBytes"], pf.residue_bytes)
        differ(name, "ResidueText",
               split_list(row["ResidueText"]) if row["ResidueText"] else [],
               [r.text for r in pf.residue if r.text])
        # Columns added in Round 45. Each carries evidence that was in the database and not in
        # the export anyone opens, so each is checked against the record like everything else.
        differ(name, "VolumeNameChecks",
               split_list(row["VolumeNameChecks"]) if row["VolumeNameChecks"] else [],
               ["n/a" if v.name_self_check is None
                else ("ok" if v.name_self_check else "mismatch") for v in pf.volumes])
        differ(name, "SlackReferenceCount", row["SlackReferenceCount"],
               sum(len(v.slack_refs) for v in pf.volumes))
        differ(name, "SlackReferences",
               split_list(row["SlackReferences"]) if row["SlackReferences"] else [],
               [f"[vol{j}] {r}" for j, v in enumerate(pf.volumes) for r in v.slack_refs])
        differ(name, "DeclaredDirectoryCount", row["DeclaredDirectoryCount"],
               "" if pf.total_directory_count is None else pf.total_directory_count)
        differ(name, "FirstRunApprox", row["FirstRunApprox"],
               pf.first_run_approx.isoformat(sep=" ") if pf.first_run_approx else "")
        differ(name, "FromAds", row["FromAds"], int(pf.from_ads))
        differ(name, "ContainerTrailingBytes", row["ContainerTrailingBytes"],
               "" if pf.container_trailing_bytes is None else pf.container_trailing_bytes)
        differ(name, "Decompressor", row["Decompressor"], pf.decompressor_used)


def check_store(records):
    db = os.path.join(tempfile.mkdtemp(), "v.db")
    with Store(db) as store:
        store.add_all(records.values())
        for path, pf in records.items():
            name = os.path.basename(path)
            rows = store.rows("SELECT * FROM prefetch WHERE source_path = ?", (path,))
            if len(rows) != 1:
                mismatches.append((name, "prefetch row count", len(rows), 1))
                continue
            r = rows[0]
            differ(name, "db.executable_name", r["executable_name"], pf.executable_name)
            differ(name, "db.hash", r["hash"], pf.hash)
            differ(name, "db.run_count", r["run_count"], pf.run_count)
            differ(name, "db.executable_path", r["executable_path"], pf.executable_path)
            differ(name, "db.path_source", r["path_source"], pf.path_source.value)
            differ(name, "db.last_run_ticks", r["last_run_ticks"],
                   max(pf.run_times_ticks) if pf.run_times_ticks else None)
            # Raw FILETIME ticks are the lossless copy; datetime cannot hold the 100-ns digit.
            ticks = [x["ticks"] for x in store.rows(
                "SELECT ticks FROM run_time WHERE prefetch_id = ? ORDER BY slot", (r["id"],))]
            differ(name, "db.run_ticks", ticks, pf.run_times_ticks)
            loaded = [x["path"] for x in store.rows(
                "SELECT path FROM loaded_file WHERE prefetch_id = ? ORDER BY ordinal",
                (r["id"],))]
            differ(name, "db.loaded_files", loaded,
                   [m.filename for m in pf.metrics] + pf.filenames[len(pf.metrics):])
            # The trace-chain slice per loaded file, and the metric flags. Fields no other
            # prefetch tool writes, so nothing else would catch them going wrong.
            metric_rows = store.rows(
                "SELECT chain_start, chain_count, chain_subset, metric_flags FROM loaded_file "
                "WHERE prefetch_id = ? ORDER BY ordinal LIMIT ?", (r["id"], len(pf.metrics)))
            differ(name, "db.chain_slices",
                   [(x["chain_start"], x["chain_count"], x["chain_subset"], x["metric_flags"])
                    for x in metric_rows],
                   [(m.chain_start, m.chain_count, m.chain_subset, m.flags)
                    for m in pf.metrics])
            residue = store.rows(
                "SELECT offset, size, text, bytes FROM residue WHERE prefetch_id = ? "
                "ORDER BY offset", (r["id"],))
            differ(name, "db.residue",
                   [(x["offset"], x["size"], x["text"], bytes(x["bytes"])) for x in residue],
                   [(x.offset, x.size, x.text, x.data) for x in pf.residue])
            # Added in Round 45: the record's own filesystem times, and the undecoded regions
            # that until then existed only in memory and in `pfcli info` output.
            differ(name, "db.source_modified", r["source_modified"],
                   pf.source_modified.isoformat(sep=" ") if pf.source_modified else None)
            differ(name, "db.source_accessed", r["source_accessed"],
                   pf.source_accessed.isoformat(sep=" ") if pf.source_accessed else None)
            differ(name, "db.source_created", r["source_created"],
                   pf.source_created.isoformat(sep=" ") if pf.source_created else None)
            differ(name, "db.source_size", r["source_size"], pf.source_size or None)
            differ(name, "db.first_run_estimate", r["source_created_est"],
                   pf.first_run_approx.isoformat(sep=" ") if pf.first_run_approx else None)
            differ(name, "db.header_raw",
                   bytes(r["header_raw"]) if r["header_raw"] else b"", pf.header_raw)
            differ(name, "db.fileinfo_raw",
                   bytes(r["fileinfo_raw"]) if r["fileinfo_raw"] else b"", pf.fileinfo_raw)
            differ(name, "db.fileinfo_offset", r["fileinfo_offset"], pf.fileinfo_offset or None)
            # An ordinary record must say "not from a stream" by holding NULL, not by holding
            # a default that reads like a measurement.
            differ(name, "db.from_ads", r["from_ads"], int(pf.from_ads))
            # ...but WHOSE timestamps these are is a measured fact even for an ordinary file -
            # "stream", meaning the file's own - and blanking it replaced a measurement with
            # this codebase's convention for "not measured" (AUDIT BUG 106). Compared against
            # the record now, rather than against a hardcoded None, which made this a constant
            # rather than a fidelity check.
            differ(name, "db.timestamp_source", r["timestamp_source"], pf.timestamp_source)
            differ(name, "db.carrier_path", r["carrier_path"], None)
            volumes = store.rows(
                "SELECT * FROM volume WHERE prefetch_id = ? ORDER BY ordinal", (r["id"],))
            differ(name, "db.volume_count", len(volumes), len(pf.volumes))
            for v, pv in zip(volumes, pf.volumes):
                differ(name, "db.vol.device", v["device_name"], pv.device_name)
                differ(name, "db.vol.serial", v["serial"], pv.serial)
                differ(name, "db.vol.created_ticks", v["created_ticks"], pv.created_ticks)
                differ(name, "db.vol.raw_tail",
                       bytes(v["raw_tail"]) if v["raw_tail"] else b"", pv.raw_tail)
                differ(name, "db.vol.ref_array_version", v["ref_array_version"],
                       pv.ref_array_version)
                dirs = [x["path"] for x in store.rows(
                    "SELECT path FROM directory WHERE volume_id = ? ORDER BY ordinal",
                    (v["id"],))]
                differ(name, "db.vol.dirs", dirs, pv.directories)
                # Declared and slack references share the table and are told apart by
                # `source`. They must stay apart here too: a slack value is not part of what
                # the record claims, and comparing the mixed list against `file_refs` would
                # either fail (as it did) or, if the record were widened, quietly bless
                # unclaimed data as declared.
                refs = [(x["mft_entry"], x["mft_sequence"]) for x in store.rows(
                    "SELECT mft_entry, mft_sequence FROM file_ref WHERE volume_id = ? "
                    "AND source = 'declared' ORDER BY ordinal", (v["id"],))]
                differ(name, "db.vol.refs", refs,
                       [(m.entry, m.sequence) for m in pv.file_refs])
                slack = [(x["mft_entry"], x["mft_sequence"]) for x in store.rows(
                    "SELECT mft_entry, mft_sequence FROM file_ref WHERE volume_id = ? "
                    "AND source = 'slack' ORDER BY ordinal", (v["id"],))]
                differ(name, "db.vol.slack_refs", slack,
                       [(m.entry, m.sequence) for m in pv.slack_refs])
            differ(name, "db.chain_blob", bytes(r["trace_chain_raw"] or b""),
                   pf.trace_chain_raw)


def check_gui():
    from pfgui.__main__ import MainWindow
    from pfgui.model import COLUMNS

    win = MainWindow()
    win.show()
    win.load([CORPUS])
    column = {key: i for i, (_label, key) in enumerate(COLUMNS)}

    for r in range(win.model.rowCount()):
        pf = win.model.rows[r]["_pf"]
        name = os.path.basename(pf.source_path)

        def cell(key):
            return win.model.data(win.model.index(r, column[key]), Qt.DisplayRole)

        # Read through data(), not the row dict - this is what the grid actually paints.
        differ(name, "grid.executable", cell("executable_name"),
               escape_deceptive(pf.executable_name))
        differ(name, "grid.hash", cell("hash"), pf.hash)
        differ(name, "grid.runs", cell("run_count"), pf.run_count)
        differ(name, "grid.path", cell("executable_path"),
               escape_deceptive(pf.executable_path or ""))
        differ(name, "grid.path_source", cell("path_source"), pf.path_source.value)
        differ(name, "grid.last_run", cell("last_run"),
               pf.last_run.strftime("%Y-%m-%d %H:%M:%S") if pf.last_run else "")
        differ(name, "grid.volumes", cell("volume_count"), len(pf.volumes))
        differ(name, "grid.files", cell("file_count"), len(pf.filenames))

    for pr in range(win.proxy.rowCount()):
        win._show_detail(win.proxy.index(pr, 0))
        pf = win.model.rows[win.proxy.mapToSource(win.proxy.index(pr, 0)).row()]["_pf"]
        name = os.path.basename(pf.source_path)
        differ(name, "detail.run rows", win.detail_runs.table.rowCount(), len(pf.run_times))
        differ(name, "detail.file rows", win.detail_files.table.rowCount(), len(pf.filenames))
        for i, t in enumerate(pf.run_times):
            differ(name, f"detail.run[{i}]", win.detail_runs.table.item(i, 1).text(),
                   t.strftime("%Y-%m-%d %H:%M:%S.%f"))
        for i, filename in enumerate(pf.filenames):
            if win.detail_files.table.item(i, 1).text() != filename:
                mismatches.append((name, f"detail.file[{i}]",
                                   win.detail_files.table.item(i, 1).text(), filename))
                break
        # Columns added in Round 42: the file's trace-chain slice, the subset, and the flags.
        # A value that reaches the CSV and the database but renders wrong in the pane is the
        # exact failure this suite exists for.
        for i, metric in enumerate(pf.metrics):
            got = (win.detail_files.table.item(i, 4).text(),
                   win.detail_files.table.item(i, 5).text(),
                   win.detail_files.table.item(i, 6).text())
            want = (str(metric.chain_count),
                    "" if metric.chain_subset is None else str(metric.chain_subset),
                    f"0x{metric.flags:04x}")
            if got != want:
                mismatches.append((name, f"detail.chains[{i}]", got, want))
                break
    return win.model.rowCount()


# Every field the parser fills must reach an export, or be listed here with the reason it does
# not. Written as a map rather than a count so that adding a field to the model without
# exporting it fails this suite instead of quietly costing an investigator the data - which is
# how the record's own filesystem timestamps, the ADS provenance and the retained undecoded
# regions all came to exist on the record and in no export at all (AUDIT BUG 71, 72, 73).
EXPORTED = {
    "Prefetch": {
        "source_path": "prefetch.source_path", "version": "prefetch.version",
        "executable_name": "prefetch.executable_name", "hash": "prefetch.hash",
        "file_size": "prefetch.file_size", "run_count": "prefetch.run_count",
        "run_times": "run_time.run_time", "run_times_ticks": "run_time.ticks",
        "executable_path": "prefetch.executable_path",
        "executable_path_alt": "prefetch.executable_path_alt",
        "path_source": "prefetch.path_source",
        "hosted_package": "prefetch.hosted_package",
        "filenames": "loaded_file.path", "metrics": "loaded_file",
        "fileinfo_raw": "prefetch.fileinfo_raw", "fileinfo_offset": "prefetch.fileinfo_offset",
        "header_raw": "prefetch.header_raw", "residue": "residue",
        "volumes": "volume", "total_directory_count": "prefetch.total_dir_count",
        "trace_chain_count": "prefetch.trace_chain_count",
        "trace_chain_raw": "prefetch.trace_chain_raw",
        "trace_chain_entry_size": "prefetch.trace_chain_width",
        "source_created": "prefetch.source_created",
        "source_modified": "prefetch.source_modified",
        "source_accessed": "prefetch.source_accessed",
        "source_size": "prefetch.source_size",
        "from_ads": "prefetch.from_ads", "carrier_path": "prefetch.carrier_path",
        "stream_name": "prefetch.stream_name", "stream_size": "prefetch.stream_size",
        "timestamp_source": "prefetch.timestamp_source",
        "carrier_primary_size": "prefetch.carrier_primary_size",
        "carrier_is_prefetch": "prefetch.carrier_is_prefetch",
        "outside_prefetch_folder": "prefetch.outside_prefetch_folder",
        "carrier_created": "prefetch.carrier_created",
        "carrier_modified": "prefetch.carrier_modified",
        "carrier_accessed": "prefetch.carrier_accessed",
        "container_trailing_bytes": "prefetch.container_trailing_bytes",
        "decompressor_used": "prefetch.decompressor_used",
        "filename_hash_match": "prefetch.filename_hash_match",
        "filename_name_match": "prefetch.filename_name_match",
        "is_op_file": "prefetch.is_op_file",
        "deceptive_characters": "prefetch.deceptive_chars",
        "name_truncated": "prefetch.name_truncated",
        "problems": "problem", "failed_stage": "prefetch.failed_stage",
        # Deliberately not exported: the alternative paths are summarised by
        # executable_path / executable_path_alt / path_source, and every candidate is shown by
        # `pfcli info`. Exporting all of them would put a parser-internal list in evidence.
        "path_candidates": None,
    },
    "Volume": {
        "device_name": "volume.device_name", "serial": "volume.serial",
        "created": "volume.created", "created_ticks": "volume.created_ticks",
        "directories": "directory.path", "file_refs": "file_ref (source='declared')",
        "name_self_check": "volume.name_check", "raw_tail": "volume.raw_tail",
        "ref_array_version": "volume.ref_array_version",
        "declared_ref_count": "volume.declared_ref_count", "ref_slots": "file_ref.slot",
        "slack_refs": "file_ref (source='slack')",
    },
    "FileMetric": {
        "index": "loaded_file.ordinal", "filename": "loaded_file.path",
        "mft_ref": "loaded_file.mft_entry + mft_sequence",
        "chain_start": "loaded_file.chain_start", "chain_count": "loaded_file.chain_count",
        "chain_subset": "loaded_file.chain_subset", "flags": "loaded_file.metric_flags",
        # Offsets INTO the string block, not data: the string they point at is exported as
        # `path`, and the offsets are meaningless outside the file they came from.
        "name_offset": None, "name_size": None,
    },
    "Residue": {
        "offset": "residue.offset", "size": "residue.size", "data": "residue.bytes",
        "text": "residue.text",
    },
}


def check_completeness():
    """Fields on the record that reach neither the database nor the CSV, and are not excused."""
    import dataclasses                                                # noqa: PLC0415
    import sqlite3 as _sqlite3                                        # noqa: PLC0415

    from prefetch_core import model as _model                         # noqa: PLC0415
    from prefetch_core.store import SCHEMA                            # noqa: PLC0415

    mem = _sqlite3.connect(":memory:")
    mem.executescript(SCHEMA)
    real = {t: {r[1] for r in mem.execute(f"PRAGMA table_info({t})")}
            for (t,) in mem.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    unaccounted = []
    for cls in (_model.Prefetch, _model.Volume, _model.FileMetric, _model.Residue):
        known = EXPORTED[cls.__name__]
        for field in dataclasses.fields(cls):
            if field.name not in known:
                unaccounted.append(f"{cls.__name__}.{field.name} is in no export and has no "
                                   f"recorded reason")
                continue
            where = known[field.name]
            if where is None or "." not in where.split(" ")[0]:
                continue                       # excused, or a whole table
            table, column = where.split(" ")[0].split(".")
            if column not in real.get(table, set()):
                unaccounted.append(f"{cls.__name__}.{field.name} claims {where}, "
                                   f"which does not exist")
    for problem in unaccounted:
        mismatches.append(("completeness", problem, "", ""))
    return len(unaccounted)


def check_cli_round_trip():
    """Run the CLI the way an analyst does, then read back what it actually wrote.

    Everything above compares in-process objects. This compares the FILES: the CSV and the
    SQLite database produced by `pfcli parse`, against the parsed record, on the vendored
    corpus - which is always present, holds the same file name in two directories, and holds
    a file that fails to parse, so the failed-record path is compared rather than assumed.
    """
    import csv as _csv                                                # noqa: PLC0415
    import sqlite3 as _sqlite3                                        # noqa: PLC0415
    import subprocess as _sp                                          # noqa: PLC0415
    _csv.field_size_limit(1 << 30)     # the tool writes cells wider than the module default

    folder = corpus.VENDORED
    files = sorted(glob.glob(os.path.join(folder, "**", "*.pf"), recursive=True))
    work = tempfile.mkdtemp()
    csv_path, db_path = os.path.join(work, "e2e.csv"), os.path.join(work, "e2e.db")
    proc = _sp.run([sys.executable, "-m", "pfcli", "parse", folder, "--csv", csv_path,
                    "--db", db_path], cwd=ROOT, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        mismatches.append(("cli", "exit code", proc.returncode, 0))
        return 0
    by_path = {r["SourcePath"]: r for r in _csv.DictReader(open(csv_path, encoding="utf-8"))}
    con = _sqlite3.connect(db_path)
    con.row_factory = _sqlite3.Row
    db_rows = {r["source_path"]: r for r in con.execute("SELECT * FROM prefetch")}
    failed_seen = 0
    for path in files:
        pf = parse_file(path)
        failed_seen += 1 if pf.failed_stage else 0
        key = os.path.abspath(path)
        c, d = by_path.get(key) or by_path.get(path), db_rows.get(key) or db_rows.get(path)
        if c is None or d is None:
            mismatches.append((os.path.basename(path), "row present in both exports",
                               (c is not None, d is not None), (True, True)))
            continue
        for label, record, in_csv, in_db in (
                ("ExecutableName", pf.executable_name, c["ExecutableName"], d["executable_name"]),
                ("Hash", pf.hash, c["Hash"], d["hash"]),
                ("Version", pf.version, c["Version"], d["version"]),
                ("RunCount", pf.run_count, c["RunCount"], d["run_count"]),
                ("ExecutablePath", pf.executable_path or "", c["ExecutablePath"],
                 d["executable_path"] or ""),
                ("VolumeCount", len(pf.volumes), c["VolumeCount"], d["volume_count"]),
                ("FileCount", len(pf.filenames), c["FileCount"], d["file_count"])):
            # The CSV is the SAFE export here - what `pfcli parse --csv` actually writes - so
            # a cell a spreadsheet would re-read carries the guard's apostrophe (AUDIT BUG
            # 103). Compared through the same function rather than exempted: the guard must
            # produce exactly this and nothing else.
            if sanitize_cell(str(record)) != str(in_csv) or str(record) != str(in_db):
                mismatches.append((os.path.basename(path), label + " (CSV/DB/record)",
                                   (in_csv, in_db), record))
        newest = max(pf.run_times) if pf.run_times else None
        want = newest.strftime("%Y-%m-%d %H:%M:%S") if newest else ""
        if not (c["LastRun"] or "").startswith(want) or not str(d["last_run"] or "").startswith(want):
            mismatches.append((os.path.basename(path), "LastRun (CSV/DB/record)",
                               (c["LastRun"], d["last_run"]), want))
        if bool(pf.failed_stage) == bool(c["ParsedOk"] and c["ParsedOk"] != "0"):
            mismatches.append((os.path.basename(path), "ParsedOk against failed_stage",
                               c["ParsedOk"], pf.failed_stage))
    con.close()
    # A comparison that never meets a failed record proves nothing about failed records.
    if not failed_seen:
        mismatches.append(("cli", "the corpus exercises the failed-record path", 0, ">0"))
    return len(files)


def main():
    corpus.require("WIN10")
    QApplication([])
    files = sorted(glob.glob(os.path.join(CORPUS, "*.pf")))
    if not files:
        print("!! no corpus files", file=sys.stderr)
        return 1
    records = {f: parse_file(f) for f in files}
    print(f"ground truth: {len(records)} parsed records\n")

    print("CSV export:")
    check_csv(records)
    csv_bad = len(mismatches)
    print(f"  mismatches: {csv_bad}")

    print("\nSQLite store:")
    check_store(records)
    store_bad = len(mismatches) - csv_bad
    print(f"  mismatches: {store_bad}")

    print("\nnothing the parser recovers is missing from BOTH exports:")
    completeness = check_completeness()
    print(f"  fields unaccounted for: {completeness}")

    print("\nthe CLI's own files, read back (vendored corpus, includes a file that fails):")
    before_cli = len(mismatches)
    compared = check_cli_round_trip()
    print(f"  files compared through the written CSV and database: {compared}")
    print(f"  mismatches: {len(mismatches) - before_cli}")
    after_cli = len(mismatches)

    print("\nGUI grid and detail panes:")
    shown = check_gui()
    gui_bad = len(mismatches) - after_cli
    print(f"  rows displayed: {shown}")
    print(f"  mismatches: {gui_bad}")

    if mismatches:
        print(f"\n{len(mismatches)} VALUE MISMATCHES:")
        for name, field, got, want in mismatches[:10]:
            print(f"   {name} {field}\n      output: {str(got)[:100]}"
                  f"\n      record: {str(want)[:100]}")

    print("\nPASS - every output surface matches the parsed record exactly"
          if not mismatches else "\nFAIL")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
