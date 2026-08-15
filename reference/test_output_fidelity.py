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

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfcli.__main__ import split_list  # noqa: E402
from prefetch_core import parse_file  # noqa: E402
from prefetch_core.store import Store  # noqa: E402
from prefetch_core.winpath import escape_deceptive  # noqa: E402

CORPUS = corpus.WIN10

mismatches = []


def differ(name, field, got, want):
    if str(got) != str(want):
        mismatches.append((name, field, got, want))


def check_csv(records):
    workdir = tempfile.mkdtemp()
    out = os.path.join(workdir, "o.csv")
    subprocess.run([sys.executable, "-m", "pfcli", "parse", CORPUS, "--csv", out],
                   cwd=ROOT, capture_output=True, check=True)
    csv.field_size_limit(10**9)
    with open(out, newline="", encoding="utf-8") as fh:
        rows = {r["SourcePath"]: r for r in csv.DictReader(fh)}

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
            volumes = store.rows(
                "SELECT * FROM volume WHERE prefetch_id = ? ORDER BY ordinal", (r["id"],))
            differ(name, "db.volume_count", len(volumes), len(pf.volumes))
            for v, pv in zip(volumes, pf.volumes):
                differ(name, "db.vol.device", v["device_name"], pv.device_name)
                differ(name, "db.vol.serial", v["serial"], pv.serial)
                differ(name, "db.vol.created_ticks", v["created_ticks"], pv.created_ticks)
                dirs = [x["path"] for x in store.rows(
                    "SELECT path FROM directory WHERE volume_id = ? ORDER BY ordinal",
                    (v["id"],))]
                differ(name, "db.vol.dirs", dirs, pv.directories)
                refs = [(x["mft_entry"], x["mft_sequence"]) for x in store.rows(
                    "SELECT mft_entry, mft_sequence FROM file_ref WHERE volume_id = ? "
                    "ORDER BY ordinal", (v["id"],))]
                differ(name, "db.vol.refs", refs,
                       [(m.entry, m.sequence) for m in pv.file_refs])
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
    return win.model.rowCount()


def main():
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

    print("\nGUI grid and detail panes:")
    shown = check_gui()
    gui_bad = len(mismatches) - csv_bad - store_bad
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
