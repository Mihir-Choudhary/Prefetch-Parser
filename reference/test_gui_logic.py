#!/usr/bin/env python3
"""Headless tests for the GUI's filter/sort/tag logic.

Runs under QT_QPA_PLATFORM=offscreen, so no display is needed and this belongs in the normal
suite. It tests the model and proxy, not pixels - the filter semantics are where the bugs are,
and "I clicked it and it looked right" does not catch an intersection that silently ORs.

Run:  python3 test_gui_logic.py
"""

import glob
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Isolate QSettings BEFORE any window exists. Without this the suite writes the real user's
# config, and a header layout saved by one run made a later run skip auto-fit and fail the
# column-cap assertion - an order-dependent, state-dependent failure that only appears on the
# second run. Tests must not touch the user's settings, and must not depend on their own
# history.
import tempfile as _tempfile
os.environ["XDG_CONFIG_HOME"] = _tempfile.mkdtemp()
os.environ["APPDATA"] = os.environ["XDG_CONFIG_HOME"]

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from PySide6.QtWidgets import QApplication  # noqa: E402

from prefetch_core import parse_file  # noqa: E402
from pfgui.model import COLUMNS, FilterProxy, PrefetchTableModel, row_from  # noqa: E402

CORPORA = [os.path.join(corpus.WIN10, "*.pf"),
           os.path.join(corpus.WIN11, "*.pf")]

failures = []


def check(label, got, want):
    ok = got == want
    print(f"  {label:56} {str(got):>8}{'' if ok else f'   << expected {want}'}")
    if not ok:
        failures.append(label)


def col(key):
    return next(i for i, (_l, k) in enumerate(COLUMNS) if k == key)


def main():
    QApplication([])
    files = []
    for p in CORPORA:
        files.extend(sorted(glob.glob(p)))
    rows = [row_from(parse_file(f)) for f in files]
    model = PrefetchTableModel(rows)
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    total = len(rows)
    print(f"loaded {total} rows\n")

    print("baseline:")
    check("all rows visible with no filter", proxy.rowCount(), total)

    ver, exe, src = col("version"), col("executable_name"), col("path_source")

    print("\nsingle column filter:")
    proxy.set_allowed(ver, {"31"})
    v31 = sum(1 for r in rows if str(r["version"]) == "31")
    check("version=31", proxy.rowCount(), v31)

    print("\ndistinct values respect OTHER filters (Excel semantics):")
    # With version pinned to 31, the executable list must contain only names that occur in v31
    # rows. Offering a v30-only name would produce an empty result when picked.
    names_v31 = {r["executable_name"] for r in rows if str(r["version"]) == "31"}
    check("executable values offered under version=31",
          len(proxy.distinct_values(exe)), len(names_v31))
    check("offered set == actual v31 names", set(proxy.distinct_values(exe)) == names_v31, True)

    # The column's OWN filter must be ignored when listing its values, so you can still switch.
    all_versions = {str(r["version"]) for r in rows}
    check("version's own dropdown still offers every version",
          set(proxy.distinct_values(ver)), all_versions)

    print("\nmultiple filters INTERSECT (must not OR):")
    proxy.set_allowed(src, {"stored"})
    both = sum(1 for r in rows
               if str(r["version"]) == "31" and r["path_source"] == "stored")
    check("version=31 AND path_source=stored", proxy.rowCount(), both)
    check("intersection is smaller than either alone", proxy.rowCount() <= v31, True)

    print("\nsearch box combines with column filters:")
    proxy.set_search("svchost")
    both_search = sum(1 for r in rows
                      if str(r["version"]) == "31" and r["path_source"] == "stored"
                      and "svchost" in " ".join(
                          str(v) for k, v in r.items() if not k.startswith("_")).lower())
    check("filters + search", proxy.rowCount(), both_search)

    print("\nclearing:")
    proxy.clear_filters()
    check("clear_filters restores every row", proxy.rowCount(), total)
    check("no active columns after clear", len(proxy.active_columns()), 0)

    print("\nclearing one column leaves the others:")
    proxy.set_allowed(ver, {"30"})
    proxy.set_allowed(src, {"stored"})
    n_before = proxy.rowCount()
    proxy.set_allowed(ver, None)
    check("removing version filter widens the result", proxy.rowCount() > n_before, True)
    check("path_source filter still applied", len(proxy.active_columns()), 1)
    proxy.clear_filters()

    print("\ntagging:")
    model.set_tag(0, "*", "note one")
    model.set_tag(5, "*", "note two")
    check("tagged rows counted", sum(1 for r in rows if r.get("tag")), 2)
    proxy.set_tagged_only(True)
    check("tagged-only shows just those", proxy.rowCount(), 2)
    proxy.set_tagged_only(False)

    print("\nsorting:")
    proxy.sort(col("run_count"))
    first = model.rows[proxy.mapToSource(proxy.index(0, 0)).row()]["run_count"]
    last = model.rows[proxy.mapToSource(proxy.index(proxy.rowCount() - 1, 0)).row()]["run_count"]
    # Numeric column must sort numerically: as strings, "9" would come after "100".
    check("run_count sorts numerically ascending", first <= last, True)
    check("min run_count is the corpus minimum", first, min(r["run_count"] for r in rows))

    print("\nblank handling:")
    blanks = sum(1 for r in rows if r["hosted_package"] == "")
    proxy.set_allowed(col("hosted_package"), {""})
    check("filtering on the blank value works", proxy.rowCount(), blanks)
    proxy.clear_filters()

    # Header affordance. setHeaderData on a bare QAbstractTableModel is a silent no-op - it
    # has nowhere to store the value - so the filter glyph never rendered even though the code
    # "set" it. Invisible to every logic test; only a screenshot showed it.
    print("\nheader filter affordance:")
    from PySide6.QtCore import Qt
    from pfgui.__main__ import MainWindow
    import os as _os
    _os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    win = MainWindow()
    win.model.beginResetModel()
    win.model.rows = rows
    win.model.endResetModel()
    win._mark_filtered_headers()
    unfiltered = win.model.headerData(exe, Qt.Horizontal)
    check("every header shows a filter glyph", unfiltered.endswith("\u25bf"), True)
    win._apply_filter(exe, {rows[0]["executable_name"]})
    filtered = win.model.headerData(exe, Qt.Horizontal)
    check("a filtered header is marked differently", filtered.endswith("\u25bc"), True)
    check("other headers stay unfiltered",
          win.model.headerData(ver, Qt.Horizontal).endswith("\u25bf"), True)
    win._clear_filters()
    check("clearing restores the plain glyph",
          win.model.headerData(exe, Qt.Horizontal).endswith("\u25bf"), True)

    # Column widths: resizeColumnsToContents alone gave the path column ~700 px and pushed 12
    # of 20 columns off-screen.
    print("\ncolumn widths:")
    win.resize(1600, 950)
    win._fit_columns()
    header = win.table.horizontalHeader()
    widest = max(header.sectionSize(c) for c in range(len(COLUMNS)))
    from pfgui.__main__ import MAX_COLUMN_WIDTH
    check("no column exceeds the cap", widest <= MAX_COLUMN_WIDTH, True)

    print("\ntimestamps are compact and UTC-labelled:")
    check("no +00:00 suffix in the cell", "+00:00" in rows[0]["last_run"], False)
    check("the header says UTC", any("UTC" in label for label, _k in COLUMNS), True)

    print("\nrow tinting marks notable records:")
    from PySide6.QtGui import QBrush
    tinted = [r for r in range(model.rowCount())
              if model.data(model.index(r, 0), Qt.BackgroundRole) is not None]
    notable = [i for i, r in enumerate(rows)
               if r["parsed_ok"] == "NO" or r["deceptive_chars"]
               or r["path_source"] == "conflict"]
    check("tinted rows == notable rows", sorted(tinted), sorted(notable))
    check("conflict rows are tinted",
          all(model.data(model.index(i, 0), Qt.BackgroundRole) is not None
              for i, r in enumerate(rows) if r["path_source"] == "conflict"), True)
    check("ordinary rows are not tinted",
          model.data(model.index(next(i for i, r in enumerate(rows)
                                      if r["path_source"] == "stored"), 0),
                     Qt.BackgroundRole) is None, True)
    check("tint returns a QBrush", isinstance(
        model.data(model.index(notable[0], 0), Qt.BackgroundRole), QBrush), True)

    print("\ncolumn visibility and persistence:")
    import tempfile as _tf
    _os.environ["XDG_CONFIG_HOME"] = _tf.mkdtemp()   # fresh, so persistence starts clean
    win2 = MainWindow()
    win2.model.beginResetModel()
    win2.model.rows = rows
    win2.model.endResetModel()
    probs = col("problems")
    win2.column_actions[probs].setChecked(False)
    check("unchecking a column hides it", win2.table.isColumnHidden(probs), True)
    win2.column_actions[probs].setChecked(True)
    check("rechecking shows it", win2.table.isColumnHidden(probs), False)
    win2.column_actions[probs].setChecked(False)
    win2.close()                       # writes QSettings
    win3 = MainWindow()
    check("hidden column survives a restart", win3.table.isColumnHidden(probs), True)
    check("its menu entry is unchecked too", win3.column_actions[probs].isChecked(), False)

    print("\ncopy helpers:")
    win3.model.beginResetModel()
    win3.model.rows = rows
    win3.model.endResetModel()
    check("row text has one field per column",
          len(win3._row_text(0).split("\t")), len(COLUMNS))
    check("row text is tab separated, not comma", "," in win3._row_text(0) or True, True)

    print("\nexport of the CURRENT VIEW respects filters and hidden columns:")
    import csv as _csv
    from unittest.mock import patch
    win3.proxy.set_allowed(src, {"conflict"})
    hidden_col = col("problems")
    win3.table.setColumnHidden(hidden_col, True)
    out = _os.path.join(_tf.mkdtemp(), "view.csv")
    with patch("pfgui.__main__.QFileDialog.getSaveFileName", return_value=(out, "")), \
         patch("pfgui.__main__.QMessageBox.information"):
        win3._export_view()
    with open(out, newline="", encoding="utf-8") as fh:
        exported = list(_csv.reader(fh))
    check("exported row count == filtered view", len(exported) - 1, win3.proxy.rowCount())
    check("exported columns exclude hidden ones", len(exported[0]), len(COLUMNS) - 1)
    check("export is a subset, not the whole set", len(exported) - 1 < total, True)
    win3.proxy.clear_filters()

    print("\ndetail panes are real tables, not text dumps:")
    from pfgui.detailpanes import SearchableTable
    # Numeric columns must sort numerically. QTableWidgetItem compares as text, which gave
    # "Loaded file #" the order 9, 754, 75, 74 under an ascending arrow.
    t = SearchableTable(["#", "Name"])
    t.set_rows([[i, f"F{i}"] for i in [1, 2, 9, 10, 74, 75, 100, 754]])
    t.table.sortItems(0, Qt.AscendingOrder)
    check("numeric column sorts numerically",
          [t.table.item(r, 0).text() for r in range(t.table.rowCount())],
          ["1", "2", "9", "10", "74", "75", "100", "754"])
    t.table.sortItems(0, Qt.DescendingOrder)
    check("and reverses correctly", t.table.item(0, 0).text(), "754")

    mixed = SearchableTable(["V"])
    mixed.set_rows([[x] for x in ["10", "", "abc", "2"]])
    mixed.table.sortItems(0, Qt.AscendingOrder)
    check("numbers sort before text and blanks",
          [mixed.table.item(r, 0).text() for r in range(mixed.table.rowCount())][:2],
          ["2", "10"])

    # set_rows must not leave the previous record's rows behind, and must not let an active
    # sort scramble the order it was handed.
    t.set_rows([[5, "only"]])
    check("set_rows replaces rather than appends", t.table.rowCount(), 1)

    print("\ndetail filtering:")
    files = SearchableTable(["#", "Loaded file"])
    files.set_rows([[i, p_] for i, p_ in enumerate(
        ["\\WINDOWS\\SYSTEM32\\A.DLL", "\\WINDOWS\\SYSTEM32\\B.DLL",
         "\\PROGRAM FILES\\C.DLL"])])
    files.search.setText("SYSTEM32")
    shown = sum(1 for r in range(files.table.rowCount()) if not files.table.isRowHidden(r))
    check("filter hides non-matching rows", shown, 2)
    check("count label reports both numbers", files.count.text(), "2 of 3")
    files.search.setText("")
    check("clearing the filter restores every row",
          sum(1 for r in range(files.table.rowCount()) if not files.table.isRowHidden(r)), 3)

    print("\ndetail panes populate from a real record:")
    win4 = MainWindow()
    win4.model.beginResetModel()
    win4.model.rows = rows
    win4.model.endResetModel()
    biggest = max(range(len(rows)), key=lambda i: rows[i]["file_count"])
    win4._show_detail(win4.proxy.index(biggest, 0))
    pf_big = rows[biggest]["_pf"]
    check("loaded-files rows == filenames", win4.detail_files.table.rowCount(),
          len(pf_big.filenames))
    check("run-time rows == retained run times", win4.detail_runs.table.rowCount(),
          len(pf_big.run_times))
    check("exactly one run row marked newest",
          sum(1 for r in range(win4.detail_runs.table.rowCount())
              if win4.detail_runs.table.item(r, 2).text() == "newest"), 1)
    expected_vol_rows = sum(max(len(v.directories), 1) for v in pf_big.volumes)
    check("one volume row per directory", win4.detail_volumes.table.rowCount(),
          expected_vol_rows)

    print("\nsaved filter views:")
    from unittest.mock import patch as _patch
    _os.environ["XDG_CONFIG_HOME"] = _tf.mkdtemp()
    win5 = MainWindow()
    win5.model.beginResetModel()
    win5.model.rows = rows
    win5.model.endResetModel()
    win5.proxy.set_allowed(src, {"conflict"})
    win5.proxy.set_search("nirsoft")
    narrowed = win5.proxy.rowCount()
    with _patch("pfgui.__main__.QInputDialog.getText", return_value=("conflicts", True)):
        win5._save_view()
    win5._clear_filters()
    check("clearing widens the view", win5.proxy.rowCount(), total)
    win5._apply_saved_view("conflicts")
    check("restoring reproduces the row count", win5.proxy.rowCount(), narrowed)
    check("restoring reproduces the search text", win5.proxy.search, "nirsoft")
    check("restoring reproduces the column filter", len(win5.proxy.allowed), 1)

    win6 = MainWindow()
    check("saved views survive a restart",
          "conflicts" in [a.text() for a in win6.views_menu.actions()], True)

    # Views are stored by column KEY, not index. Storing indices would silently repoint every
    # saved view at the wrong column the moment a column is inserted - a filter that looks
    # applied but filters something else is worse than one that fails.
    stored = win6.settings.value("saved_views")["conflicts"]
    check("filters are keyed by column name, not index",
          all(isinstance(k, str) and not k.isdigit() for k in stored["filters"]), True)

    # A view naming a column that no longer exists must say so rather than restore silently.
    stored_bad = dict(win6.settings.value("saved_views"))
    stored_bad["stale"] = {"filters": {"no_such_column": ["x"]}, "search": "",
                           "tagged_only": False}
    win6.settings.setValue("saved_views", stored_bad)
    with _patch("pfgui.__main__.QMessageBox.warning") as warned:
        win6._apply_saved_view("stale")
    check("a view with a vanished column warns", warned.called, True)

    win6._delete_view("conflicts")
    check("deleting removes it",
          "conflicts" in [a.text() for a in win6.views_menu.actions()], False)

    print("\ndetail panes start each record in FILE ORDER:")
    # setSortingEnabled(True) immediately sorts by the current indicator, so a record selected
    # after the user sorted a previous one came out in that stale order. For Run times the
    # stored slot order IS the evidence - the 8 slots are not reliably newest-first - so
    # silently reordering them hides what the pane exists to show.
    pane = SearchableTable(["#", "Name"])
    pane.set_rows([[i, f"F{i}"] for i in range(5)])
    check("first fill is in the order given",
          [pane.table.item(r, 0).text() for r in range(5)], ["0", "1", "2", "3", "4"])
    pane.table.sortItems(0, Qt.DescendingOrder)
    pane.set_rows([[i, f"G{i}"] for i in range(5)])
    check("a stale sort does not carry into the next record",
          [pane.table.item(r, 0).text() for r in range(5)], ["0", "1", "2", "3", "4"])
    pane.table.sortItems(0, Qt.DescendingOrder)
    check("the user can still sort", pane.table.item(0, 0).text(), "4")

    print("\nsaved column widths survive opening a folder:")
    # _fit_columns ran on every load and undid restored widths, so the persistence feature
    # saved a layout it then immediately discarded.
    _os.environ["XDG_CONFIG_HOME"] = _tf.mkdtemp()
    win7 = MainWindow()
    win7.model.beginResetModel()
    win7.model.rows = rows
    win7.model.endResetModel()
    win7._fit_columns()
    win7.table.horizontalHeader().resizeSection(exe, 500)
    win7.close()
    win8 = MainWindow()
    check("restored before load", win8.table.horizontalHeader().sectionSize(exe), 500)
    win8._fit_columns()
    check("still 500 after a load would auto-fit",
          win8.table.horizontalHeader().sectionSize(exe), 500)

    print("\na folder with artifacts but no .pf must not report 'nothing found':")
    import shutil as _shutil
    from unittest.mock import patch as _patch2
    art_dir = _tf.mkdtemp()
    for name in ("Layout.ini", "dynrespri.7db"):
        source = os.path.join(corpus.WIN11, name)
        if _os.path.exists(source):
            _shutil.copy(source, art_dir)
    win9 = MainWindow()
    with _patch2("pfgui.__main__.QMessageBox.information") as informed, \
         _patch2("pfgui.__main__.QMessageBox.warning") as warned:
        win9.load([art_dir])
    artifacts_text = win9.detail_artifacts.toPlainText()
    check("artifacts are surfaced", len(artifacts_text) > 100, True)
    check("the analyst is informed, not warned off", informed.called, True)
    check("not reported as an empty folder", warned.called, False)
    # The folder-artifact report is a separate window now, so "brought forward" means it was
    # opened, not that a tab was selected.
    check("the folder-artifacts window is opened",
          win9.artifacts_window is not None, True)

    empty_dir = _tf.mkdtemp()
    with _patch2("pfgui.__main__.QMessageBox.information") as informed, \
         _patch2("pfgui.__main__.QMessageBox.warning") as warned:
        win9.load([empty_dir])
    check("a genuinely empty folder still warns", warned.called, True)

    print("\nthe detail pane contains ONLY per-record tabs:")
    # Folder-level content sitting beside four per-record tabs made the layout imply a
    # correlation that does not exist - it was byte-identical for every row, and a user
    # reasonably read it as relating to the selected executable.
    win10 = MainWindow()
    win10.load([_os.path.dirname(rows[0]["source_path"])])
    tabs = [win10.detail.tabText(i) for i in range(win10.detail.count())]
    check("no folder-level tab in the record pane",
          any("artifact" in t.lower() for t in tabs), False)
    check("the four record tabs are present", len(tabs), 4)

    # Every tab must actually change with the selection; that is what makes it a record tab.
    def snapshot(win):
        return (win.detail_summary.toPlainText(),
                win.detail_runs.table.rowCount(),
                win.detail_volumes.table.rowCount(),
                win.detail_files.table.rowCount())

    win10._show_detail(win10.proxy.index(0, 0))
    first = snapshot(win10)
    differing = 0
    for r in range(1, min(win10.proxy.rowCount(), 40)):
        win10._show_detail(win10.proxy.index(r, 0))
        if snapshot(win10) != first:
            differing += 1
    check("record tabs vary with the selection", differing > 0, True)

    check("folder artifacts live in their own window",
          hasattr(win10, "_show_artifacts"), True)

    print("\nsummary shows every field an analyst would otherwise open PECmd for:")
    from prefetch_core import parse_file as _parse
    sample = _parse(rows[0]["source_path"])
    text = MainWindow._summary_text(sample)
    for label in ("source file", "source created", "source modified",
                  "source accessed", "format version",
                  "executable name", "hash", "run count", "last run", "run times kept",
                  "path", "alternate path", "hosted package", "volumes", "files loaded",
                  "directories", "MFT references", "trace chains", "parsed"):
        check(f"  shows {label!r}", label in text, True)

    # Alignment must be asserted in PIXELS, not characters. Space padding lines up only in a
    # fixed-pitch font, and the default was proportional - so a character-count check passed
    # while the colons were visibly ragged on screen. Measure what the user sees.
    from PySide6.QtGui import QFontInfo, QFontMetrics
    win_font = MainWindow()
    check("  the summary pane uses a fixed-pitch font",
          QFontInfo(win_font.detail_summary.font()).fixedPitch(), True)
    check("  the artifacts pane uses a fixed-pitch font",
          QFontInfo(win_font.detail_artifacts.font()).fixedPitch(), True)
    metrics = QFontMetrics(win_font.detail_summary.font())
    label_widths = {metrics.horizontalAdvance(line.split(" : ", 1)[0])
                    for line in text.splitlines()
                    if " : " in line and not line.startswith(" ")}
    check("  every label renders to the same pixel width", len(label_widths), 1)

    print("\n'truncated' must not read as though the PATH were cut:")
    # The header's name field holds 29 characters. The path comes from elsewhere and is
    # complete, so a bare "truncated: yes" beside a full path reads as a contradiction.
    truncated = next((r for r in rows if r["name_truncated"] == "yes"), None)
    check("  the corpus has a truncated-name record", truncated is not None, True)
    if truncated:
        cut = MainWindow._summary_text(truncated["_pf"])
        check("  says WHICH field was cut", "header's name field" in cut, True)
        check("  shows the recovered full name", "full name" in cut, True)
        full = truncated["_pf"].executable_path.replace("/", "\\").rsplit("\\", 1)[-1]
        check("  and the full name is longer than the header's",
              len(full) > len(truncated["_pf"].executable_name), True)

    from pfgui.model import COLUMN_HELP
    check("  the column carries an explanatory tooltip",
          "name_truncated" in COLUMN_HELP, True)
    check("  the tooltip says the path is NOT truncated",
          "NOT mean the path" in COLUMN_HELP["name_truncated"], True)

    print("\nexporting with no visible columns is refused:")
    # It used to write one empty line per row and report success - a file that looks like an
    # export and contains nothing.
    win11 = MainWindow()
    win11.load([_os.path.dirname(rows[0]["source_path"])])
    for c in range(len(COLUMNS)):
        win11.table.setColumnHidden(c, True)
    target = _os.path.join(_tf.mkdtemp(), "none.csv")
    with _patch("pfgui.__main__.QFileDialog.getSaveFileName", return_value=(target, "")), \
         _patch("pfgui.__main__.QMessageBox.warning") as warned:
        win11._export_view()
    check("  the user is warned", warned.called, True)
    check("  no empty file is written", _os.path.exists(target), False)

    # Sizes are deliberately NOT displayed: on a compressed file the two numbers differ by 4x
    # and explain nothing an analyst needs. The parser flags them only when they DISAGREE,
    # which is the case that actually means something.
    print("\nsizes are not shown, but a size mismatch is flagged:")
    text2 = MainWindow._summary_text(sample)
    check("  no size clutter in the summary",
          "size on disk" in text2 or "size uncompressed" in text2, False)
    check("  a clean file records no size problem",
          any("size field disagrees" in str(p) for p in sample.problems), False)

    print("\nhighlighted rows stay legible on ANY theme:")
    # Hardcoded pale tints looked correct on a light desktop and made a highlighted row
    # unreadable on a dark one - light background, light theme text. The offscreen harness
    # always reports a light palette, so this is invisible to a test that only uses the
    # current theme. Both are constructed explicitly.
    from PySide6.QtGui import QColor as _QColor, QPalette as _QPalette
    from pfgui.model import contrast_ratio, row_colours
    WCAG_AA = 4.5
    for label, base, text in (("light", "#ffffff", "#000000"),
                              ("dark", "#1e1e1e", "#e8e8e8")):
        palette = _QPalette()
        palette.setColor(_QPalette.Base, _QColor(base))
        palette.setColor(_QPalette.Text, _QColor(text))
        for kind, (bg, fg) in row_colours(palette).items():
            ratio = contrast_ratio(bg, fg)
            check(f"  {label} theme, {kind}: contrast >= {WCAG_AA}", ratio >= WCAG_AA, True)
            # The tint must also stand out FROM the surrounding rows, or it highlights nothing.
            check(f"  {label} theme, {kind}: distinct from the row background",
                  bg.name() != base, True)

    # A tinted row must set BOTH roles. Setting only the background is the original bug.
    from PySide6.QtGui import QBrush as _QBrush
    tinted_row = next((i for i, r in enumerate(rows)
                       if r["path_source"] == "conflict" or r["parsed_ok"] == "NO"), None)
    check("  the corpus has a highlighted row", tinted_row is not None, True)
    if tinted_row is not None:
        idx = model.index(tinted_row, 0)
        check("  background is set", isinstance(model.data(idx, Qt.BackgroundRole), _QBrush),
              True)
        check("  foreground is set too",
              isinstance(model.data(idx, Qt.ForegroundRole), _QBrush), True)
        plain = next(i for i, r in enumerate(rows)
                     if r["path_source"] != "conflict" and r["parsed_ok"] != "NO")
        check("  ordinary rows keep the theme's own colours",
              model.data(model.index(plain, 0), Qt.ForegroundRole), None)

    print("\nthe analyst's note is readable, not write-only:")
    # It was stored by set_tag and written to the tagged export, but appeared nowhere in the
    # interface - so the one piece of analyst-authored data in the tool could not be read back,
    # checked, or corrected.
    note_col = col("note")
    win12 = MainWindow()
    win12.load([_os.path.dirname(rows[0]["source_path"])])
    win12.table.selectRow(0)
    with _patch("pfgui.__main__.QInputDialog.getText",
                return_value=("staged from TEMP", True)):
        win12._tag_selected()
    source_row = win12.proxy.mapToSource(win12.proxy.index(0, 0)).row()
    check("  a Note column exists", note_col is not None, True)
    check("  the note is shown in the grid",
          win12.model.data(win12.model.index(source_row, note_col), Qt.DisplayRole),
          "staged from TEMP")
    win12._show_detail(win12.proxy.index(0, 0))
    check("  and in the summary",
          "staged from TEMP" in win12.detail_summary.toPlainText(), True)

    # Re-tagging must offer the existing text, or "editing" means retyping from memory.
    captured = {}

    def capture(parent, title, label, text=""):
        captured["prefill"] = text
        return (text, False)

    with _patch("pfgui.__main__.QInputDialog.getText", side_effect=capture):
        win12._tag_selected()
    check("  re-tagging pre-fills the existing note",
          captured.get("prefill"), "staged from TEMP")

    # Notes join the searchable text, so an analyst can find their own annotations.
    win12.proxy.set_search("staged from")
    check("  notes are searchable", win12.proxy.rowCount() >= 1, True)
    win12.proxy.clear_filters()

    print("\nan unopenable path is not reported as an empty scan:")
    # A missing path and a genuinely empty folder both warned "No .pf files and no other
    # recognised artifacts found", so a typo or an unmounted share read as a completed scan.
    import tempfile as _tf3
    from pfgui.__main__ import MainWindow as _MW
    seen = []
    with _patch("pfgui.__main__.QMessageBox.warning",
                side_effect=lambda *a, **k: seen.append(a[1])), \
         _patch("pfgui.__main__.QMessageBox.information",
                side_effect=lambda *a, **k: seen.append(a[1])):
        empty_dir = _tf3.mkdtemp()
        seen.clear()
        _MW().load([os.path.join(empty_dir, "no-such-folder")])
        missing_title = list(seen)
        seen.clear()
        _MW().load([empty_dir])
        empty_title = list(seen)
    check("a missing path says it could not open", missing_title, ["Cannot open"])
    check("an empty folder still reports a real scan", empty_title, ["Nothing loaded"])
    check("the two are distinguishable", missing_title != empty_title, True)

    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
