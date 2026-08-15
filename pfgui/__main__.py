"""GUI. A consumer of prefetch_core - it displays records, it does not parse.

Layout: a filterable grid on top, a detail pane below showing everything the grid cannot fit
(all run times in stored order, every volume, the loaded-file list, parse problems).
"""

from __future__ import annotations

import csv
import os
import sys

# Allow running from a source checkout without installing. Skipped when frozen: PyInstaller
# sets sys.frozen and puts everything on the bundle's own path, and injecting a directory
# derived from __file__ there points outside the bundle.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QProgressDialog, QPushButton, QSplitter, QTableView,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget, QMenu, QDialog,
)

from prefetch_core import parse_file  # noqa: E402
from pfgui.detailpanes import SearchableTable  # noqa: E402
from pfgui.filterpopup import FilterPopup  # noqa: E402
from pfgui.model import COLUMNS, FilterProxy, PrefetchTableModel, row_from  # noqa: E402

MAX_COLUMN_WIDTH = 320       # px; see _fit_columns


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Prefetch Explorer")
        self.resize(1500, 900)
        self.model = PrefetchTableModel([])
        self.proxy = FilterProxy()
        self.proxy.setSourceModel(self.model)

        # Column widths, which columns are hidden, and the window geometry are worth keeping:
        # an analyst who hides twelve columns to make the grid readable should not redo it
        # every launch.
        self.settings = QSettings("prefetch-explorer", "pfgui")

        self._build_ui()
        self._build_menu()
        self._mark_filtered_headers()
        self._restore_state()

    # -- construction ------------------------------------------------------
    def _build_ui(self):
        top = QWidget()
        bar = QHBoxLayout(top)
        bar.setContentsMargins(6, 6, 6, 0)

        self.search = QLineEdit(placeholderText="Search all columns…")
        self.search.textChanged.connect(self.proxy.set_search)
        bar.addWidget(self.search, 3)

        bar.addWidget(QLabel("<i>right-click a column header to filter</i>"))
        self.tagged_only = QCheckBox("Tagged only")
        self.tagged_only.toggled.connect(self.proxy.set_tagged_only)
        bar.addWidget(self.tagged_only)

        for label, slot in (("Clear filters", self._clear_filters),
                            ("Tag selected…", self._tag_selected),
                            ("Export tagged…", self._export_tagged),
                            ("Folder artifacts…", self._show_artifacts)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            bar.addWidget(b)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionsClickable(True)
        # Left-click sorts (Qt's default); the filter dropdown is on right-click, so both are
        # reachable on one header without a modifier.
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_filter)
        # Copying a cell or a whole row is basic table behaviour; without it the only way to
        # get a path out of the grid is to retype it.
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._cell_menu)
        self.table.clicked.connect(self._show_detail)

        self.detail = QTabWidget()
        self.detail_summary = QTextEdit(readOnly=True)
        # Run times, volumes and loaded files are lists to interrogate, not prose. A single
        # prefetch can list 759 loaded files; finding one in a QTextEdit means scrolling.
        self.detail_runs = SearchableTable(
            ["Slot", "Run time (UTC)", "Newest", "FILETIME ticks"], "Filter run times…")
        self.detail_volumes = SearchableTable(
            ["Vol", "Device", "Serial", "Created (UTC)", "Name check", "Directory"],
            "Filter volumes and directories…")
        self.detail_files = SearchableTable(
            ["#", "Loaded file", "MFT entry", "MFT seq"], "Filter loaded files…")
        # Folder-level artifacts do NOT belong in here. Every other tab in this pane describes
        # the selected record; this one described the whole folder and was byte-identical for
        # every row. Sitting alongside four per-record tabs, the layout itself implied a
        # correlation that does not exist - and a user reasonably read it as "these artifacts
        # relate to this executable". It lives in its own window now, opened deliberately.
        self.detail_artifacts = QTextEdit(readOnly=True)
        self.detail_artifacts.setLineWrapMode(QTextEdit.NoWrap)
        self.artifacts_window = None
        self.detail_summary.setLineWrapMode(QTextEdit.NoWrap)
        # Both panes lay values out in columns using space padding, which only lines up in a
        # fixed-pitch font. The default here is proportional Sans Serif: four labels padded to
        # an identical 17 characters render at 76, 88, 91 and 66 px, so the colons come out
        # ragged even though the text is exactly aligned.
        fixed = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        self.detail_summary.setFont(fixed)
        self.detail_artifacts.setFont(fixed)
        for widget, name in ((self.detail_summary, "Summary"), (self.detail_runs, "Run times"),
                             (self.detail_volumes, "Volumes"),
                             (self.detail_files, "Loaded files")):
            self.detail.addTab(widget, name)

        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setSizes([600, 280])

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(top)
        layout.addWidget(split)
        self.setCentralWidget(central)

        self.status = QLabel()
        self.statusBar().addWidget(self.status)
        self.proxy.rowsInserted.connect(self._update_status)
        self.proxy.rowsRemoved.connect(self._update_status)
        self.proxy.layoutChanged.connect(self._update_status)

    def _build_menu(self):
        m = self.menuBar().addMenu("&File")
        for label, slot, shortcut in (("Open folder…", self._open_folder, "Ctrl+O"),
                                      ("Export tagged…", self._export_tagged, "Ctrl+E"),
                                      ("Export current view…", self._export_view, "Ctrl+Shift+E"),
                                      ("Folder artifacts…", self._show_artifacts, "Ctrl+R"),
                                      ("Quit", self.close, "Ctrl+Q")):
            a = QAction(label, self)
            a.triggered.connect(slot)
            a.setShortcut(shortcut)
            m.addAction(a)

        # Twenty columns do not fit on any screen. Hiding the ones this case does not need is
        # the difference between a readable grid and a horizontal scrollbar.
        self.columns_menu = self.menuBar().addMenu("&Columns")
        self.column_actions = []
        for c, (label, _key) in enumerate(COLUMNS):
            a = QAction(label, self, checkable=True, checked=True)
            a.toggled.connect(lambda on, col=c: self._set_column_visible(col, on))
            self.columns_menu.addAction(a)
            self.column_actions.append(a)
        self.columns_menu.addSeparator()
        show_all = QAction("Show all", self)
        show_all.triggered.connect(lambda: [a.setChecked(True) for a in self.column_actions])
        self.columns_menu.addAction(show_all)

        self._build_views_menu()

    def _show_artifacts(self):
        """Open the folder-level artifact report in its own window.

        Separate from the record detail pane on purpose: this describes the *folder*, not the
        selected row, and nothing here records an execution.
        """
        if not self.detail_artifacts.toPlainText():
            QMessageBox.information(self, "Folder artifacts",
                                    "No folder loaded yet, or no non-.pf artifacts found.")
            return
        if self.artifacts_window is None:
            self.artifacts_window = QDialog(self)
            self.artifacts_window.setWindowTitle("Folder artifacts (not per-record)")
            self.artifacts_window.resize(1000, 700)
            layout = QVBoxLayout(self.artifacts_window)
            banner = QLabel(
                "<b>These describe the whole folder, not the selected row.</b><br>"
                "They record file ACCESS and prefetcher priority, not execution, "
                "and carry no run times.")
            banner.setWordWrap(True)
            layout.addWidget(banner)
            layout.addWidget(self.detail_artifacts)
        self.artifacts_window.show()
        self.artifacts_window.raise_()

    def _set_column_visible(self, column, visible):
        self.table.setColumnHidden(column, not visible)

    # -- saved filter sets -------------------------------------------------
    # An analyst reconstructs the same view repeatedly - "conflicts and failures", "svchost
    # only", "this volume". Rebuilding it by hand each session is the tax this removes. Stored
    # by column KEY, not index, so adding a column later does not silently repoint every saved
    # set at the wrong data.
    def _build_views_menu(self):
        self.views_menu = self.menuBar().addMenu("&Views")
        self._refresh_views_menu()

    def _refresh_views_menu(self):
        self.views_menu.clear()
        save = QAction("Save current filters as…", self)
        save.triggered.connect(self._save_view)
        self.views_menu.addAction(save)
        saved = self.settings.value("saved_views") or {}
        if saved:
            self.views_menu.addSeparator()
            for name in sorted(saved):
                a = QAction(name, self)
                a.triggered.connect(lambda _=False, n=name: self._apply_saved_view(n))
                self.views_menu.addAction(a)
            self.views_menu.addSeparator()
            delete = self.views_menu.addMenu("Delete")
            for name in sorted(saved):
                a = QAction(name, self)
                a.triggered.connect(lambda _=False, n=name: self._delete_view(n))
                delete.addAction(a)

    def _save_view(self):
        if not self.proxy.allowed and not self.proxy.search:
            QMessageBox.information(self, "Save view",
                                    "Nothing to save - no filters or search are active.")
            return
        name, ok = QInputDialog.getText(self, "Save view", "Name:")
        if not ok or not name.strip():
            return
        saved = dict(self.settings.value("saved_views") or {})
        saved[name.strip()] = {
            "filters": {COLUMNS[c][1]: sorted(v) for c, v in self.proxy.allowed.items()},
            "search": self.proxy.search,
            "tagged_only": self.proxy.tagged_only,
        }
        self.settings.setValue("saved_views", saved)
        self._refresh_views_menu()

    def _apply_saved_view(self, name):
        saved = (self.settings.value("saved_views") or {}).get(name)
        if not saved:
            return
        by_key = {key: c for c, (_label, key) in enumerate(COLUMNS)}
        self.proxy.clear_filters()
        missing = []
        for key, values in (saved.get("filters") or {}).items():
            if key in by_key:
                self.proxy.set_allowed(by_key[key], set(values))
            else:
                missing.append(key)
        self.search.setText(saved.get("search") or "")
        self.tagged_only.setChecked(bool(saved.get("tagged_only")))
        self._mark_filtered_headers()
        self._update_status()
        if missing:
            # Silently dropping a filter would misrepresent the view as fully restored.
            QMessageBox.warning(self, "View partly restored",
                                "These columns no longer exist and were skipped:\n  "
                                + "\n  ".join(missing))

    def _delete_view(self, name):
        saved = dict(self.settings.value("saved_views") or {})
        saved.pop(name, None)
        self.settings.setValue("saved_views", saved)
        self._refresh_views_menu()

    # -- persistence -------------------------------------------------------
    def _restore_state(self):
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        state = self.settings.value("header")
        # Remember whether a saved layout was applied. Auto-fitting on every load would undo
        # it, which made the persistence feature save widths it then immediately discarded.
        self.header_restored = bool(state)
        if state:
            self.table.horizontalHeader().restoreState(state)
        hidden = self.settings.value("hidden_columns") or []
        for c in (int(x) for x in hidden):
            if 0 <= c < len(COLUMNS):
                self.table.setColumnHidden(c, True)
                self.column_actions[c].setChecked(False)

    def closeEvent(self, event):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("header", self.table.horizontalHeader().saveState())
        self.settings.setValue("hidden_columns",
                               [c for c in range(len(COLUMNS))
                                if self.table.isColumnHidden(c)])
        super().closeEvent(event)

    # -- copying -----------------------------------------------------------
    def _cell_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        menu = QMenu(self)
        copy_cell = menu.addAction("Copy cell")
        copy_row = menu.addAction("Copy row")
        copy_rows = menu.addAction("Copy selected rows (TSV)")
        menu.addSeparator()
        tag = menu.addAction("Tag selected…")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is copy_cell:
            QGuiApplication.clipboard().setText(str(index.data() or ""))
        elif chosen is copy_row:
            QGuiApplication.clipboard().setText(self._row_text(index.row()))
        elif chosen is copy_rows:
            selected = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
            header = "\t".join(label for label, _k in COLUMNS)
            QGuiApplication.clipboard().setText(
                "\n".join([header] + [self._row_text(r) for r in selected]))
        elif chosen is tag:
            self._tag_selected()

    def _row_text(self, proxy_row):
        return "\t".join(
            str(self.proxy.index(proxy_row, c).data() or "") for c in range(len(COLUMNS)))

    # -- data --------------------------------------------------------------
    def load(self, paths):
        files = []
        for p in paths:
            if os.path.isdir(p):
                for root, _d, names in os.walk(p):      # recurse: ReadyBoot is a subdirectory
                    files += [os.path.join(root, n) for n in sorted(names)
                              if n.lower().endswith(".pf")]
            elif p.lower().endswith(".pf"):
                files.append(p)
        # A folder can hold artifacts and no prefetch at all - a partial collection, or a
        # ReadyBoot subfolder. Returning here left the artifacts tab empty and told the analyst
        # "nothing found" while Layout.ini and the SuperFetch databases sat right there.
        if not files:
            self.model.beginResetModel()
            self.model.rows = []
            self.model.endResetModel()
            self._load_artifacts(paths)
            self._update_status()
            others = self.detail_artifacts.toPlainText()
            if others and not others.startswith("No non-.pf"):
                self._show_artifacts()
                QMessageBox.information(
                    self, "No prefetch files",
                    "No .pf files here, but other Prefetch-folder artifacts were found.\n"
                    "They are shown in the 'Folder artifacts' window.")
            else:
                QMessageBox.warning(self, "Nothing loaded",
                                    "No .pf files and no other recognised artifacts found.")
            return
        # Parsing a full folder takes ~30 s. Without feedback the window simply stops
        # responding and reads as a hang, which is the point at which people kill the process.
        progress = QProgressDialog("Parsing prefetch files…", "Cancel", 0, len(files), self)
        progress.setWindowTitle("Loading")
        progress.setMinimumDuration(300)      # no flicker for a small folder
        progress.setWindowModality(Qt.WindowModal)
        rows = []
        for i, f in enumerate(files):
            if progress.wasCanceled():
                break
            # Updating every file would spend more time repainting than parsing.
            if i % 25 == 0:
                progress.setValue(i)
                progress.setLabelText(f"Parsing {os.path.basename(f)}\n{i} of {len(files)}")
                QApplication.processEvents()
            rows.append(row_from(parse_file(f)))
        progress.setValue(len(files))
        if not rows:
            return
        self.model.beginResetModel()
        self.model.rows = rows
        self.model.endResetModel()
        self.proxy.clear_filters()
        self._fit_columns()
        QApplication.processEvents()
        self._load_artifacts(paths)
        self._update_status()

    def _fit_columns(self):
        """Size columns to content, but cap them.

        `resizeColumnsToContents` alone gives the Executable Path column ~700 px - a single
        WindowsApps path - which pushes twelve of twenty columns off-screen behind a horizontal
        scrollbar. Columns the analyst never sees are columns that do not exist.
        """
        if getattr(self, "header_restored", False):
            return          # the analyst's own layout wins over an automatic fit
        self.table.resizeColumnsToContents()
        header = self.table.horizontalHeader()
        for c in range(len(COLUMNS)):
            if header.sectionSize(c) > MAX_COLUMN_WIDTH:
                header.resizeSection(c, MAX_COLUMN_WIDTH)

    def _load_artifacts(self, paths):
        from prefetch_core.artifacts import scan_folder

        found = []
        for p in paths:
            if os.path.isdir(p):
                found += scan_folder(p)
        if not found:
            self.detail_artifacts.setPlainText("No non-.pf artifacts found in the folder(s).")
            return
        blocks = ["These record file ACCESS and prefetcher priority, not execution. "
                  "They carry no run times.\n"]
        for a in found:
            stamp = a.modified.strftime("%Y-%m-%d %H:%M") if a.modified else "-"
            block = [f"{a.name}   [{a.kind}]   {a.size:,} bytes   modified {stamp}"]
            block += [f"    {k:22} {v}" for k, v in a.facts.items()]
            if a.paths:
                block.append(f"    {'paths':22} {len(a.paths)}")
                block += [f"        {p}" for p in a.paths[:200]]
                if len(a.paths) > 200:
                    block.append(f"        … {len(a.paths) - 200} more")
            block += [f"    ! {p}" for p in a.problems]
            blocks.append("\n".join(block))
        self.detail_artifacts.setPlainText("\n\n".join(blocks))

    def _open_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select a Prefetch folder")
        if d:
            self.load([d])

    def _update_status(self, *_):
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        tagged = sum(1 for r in self.model.rows if r.get("tag"))
        failed = sum(1 for r in self.model.rows if r.get("parsed_ok") == "NO")
        bits = [f"{shown} of {total} rows"]
        if tagged:
            bits.append(f"{tagged} tagged")
        if failed:
            bits.append(f"{failed} failed to parse")
        if self.proxy.active_columns():
            bits.append(f"{len(self.proxy.active_columns())} column filter(s) active")
        self.status.setText("   ·   ".join(bits))

    # -- filtering ---------------------------------------------------------
    def _show_filter(self, pos):
        header = self.table.horizontalHeader()
        column = header.logicalIndexAt(pos)
        if column < 0:
            return
        popup = FilterPopup(COLUMNS[column][0],
                            self.proxy.distinct_values(column),
                            self.proxy.allowed.get(column),
                            self)
        popup.applied.connect(lambda values, c=column: self._apply_filter(c, values))
        popup.move(header.mapToGlobal(pos))
        popup.show()

    def _apply_filter(self, column, values):
        self.proxy.set_allowed(column, values)
        self._mark_filtered_headers()
        self._update_status()

    def _mark_filtered_headers(self):
        """Every header carries a filter glyph; an active filter is marked distinctly.

        Without a glyph on every column there is nothing to suggest filtering exists - it is on
        right-click, which nobody discovers by accident. Excel and Timeline Explorer both show
        the affordance on all columns for the same reason.
        """
        active = self.proxy.active_columns()
        for c, (label, _key) in enumerate(COLUMNS):
            self.model.setHeaderData(
                c, Qt.Horizontal, f"{label} ▼" if c in active else f"{label} ▿")

    def _clear_filters(self):
        self.proxy.clear_filters()
        self.search.clear()
        self.tagged_only.setChecked(False)
        self._mark_filtered_headers()
        self._update_status()

    # -- tagging / export --------------------------------------------------
    def _selected_source_rows(self):
        return sorted({self.proxy.mapToSource(i).row()
                       for i in self.table.selectionModel().selectedRows()})

    def _tag_selected(self):
        rows = self._selected_source_rows()
        if not rows:
            QMessageBox.information(self, "Tag", "Select one or more rows first.")
            return
        # Pre-fill with the existing note when one row is selected, so editing does not mean
        # retyping from memory. With several selected there is no single existing note to show.
        existing = self.model.rows[rows[0]].get("note", "") if len(rows) == 1 else ""
        note, ok = QInputDialog.getText(
            self, "Tag rows", f"Note for {len(rows)} row(s):",
            text=existing)
        if not ok:
            return
        for r in rows:
            self.model.set_tag(r, "★", note)
        self._update_status()

    def _export_view(self):
        """Export exactly what the grid currently shows - filters, sort order and all.

        Exporting only tagged rows assumes the analyst tags before exporting. Filtering to
        something interesting and wanting *that* out is at least as common, and retyping the
        filter as a CLI invocation is the workaround this avoids.
        """
        if not self.proxy.rowCount():
            QMessageBox.information(self, "Export", "The current view is empty.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export current view", "view.csv",
                                              "CSV (*.csv)")
        if not path:
            return
        visible = [c for c in range(len(COLUMNS)) if not self.table.isColumnHidden(c)]
        # With everything hidden this wrote one empty line per row and reported success - a
        # file that looks like an export and contains nothing.
        if not visible:
            QMessageBox.warning(
                self, "Nothing to export",
                "Every column is hidden, so the export would contain no data.\n"
                "Show at least one column (Columns menu) and try again.")
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow([COLUMNS[c][0] for c in visible])
                for r in range(self.proxy.rowCount()):
                    w.writerow([str(self.proxy.index(r, c).data() or "") for c in visible])
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self, "Export",
            f"Wrote {self.proxy.rowCount()} row(s) and {len(visible)} column(s)\n"
            f"(the current filtered view, not the whole set).")

    def _export_tagged(self):
        tagged = [r for r in self.model.rows if r.get("tag")]
        if not tagged:
            QMessageBox.information(self, "Export", "No rows are tagged.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export tagged rows", "tagged.csv",
                                              "CSV (*.csv)")
        if not path:
            return
        # Tagged rows are exported COMPLETE - every column plus the analyst's note and the
        # full source path - regardless of what is hidden in the grid. Hiding a column is a
        # viewing choice; tagging a row is a statement that it matters, and an evidence export
        # should not silently inherit a display preference. `Export current view` is the
        # opposite by design: it reproduces exactly what is on screen.
        keys = [k for _label, k in COLUMNS] + ["note", "source_path"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            for r in tagged:
                w.writerow({k: r.get(k, "") for k in keys})
        QMessageBox.information(
            self, "Export",
            f"Wrote {len(tagged)} tagged row(s) with all {len(keys)} columns.\n"
            f"(Tagged exports are complete; hidden columns are still included. "
            f"Use 'Export current view' to export exactly what is on screen.)")

    # -- detail pane -------------------------------------------------------
    @staticmethod
    def _summary_text(pf):
        """Everything about one record, in aligned label/value pairs.

        Deliberately complete: every field PECmd reports plus the ones it does not. An analyst
        should never have to open a second tool to see a timestamp this one already parsed.
        """
        def stamp(value):
            return value.isoformat(sep=" ") if value else "-"

        # Full name recovered from the resolved path. The header's name field caps at 29
        # characters, so "truncated" describes THAT field - not the path, which comes from a
        # different source and is complete. Showing the truncated header name with no
        # explanation next to a full path reads as a contradiction.
        full_name = ""
        if pf.executable_path:
            full_name = pf.executable_path.replace("/", "\\").rsplit("\\", 1)[-1]

        rows = []
        # Lead with the verdict. Everything below a failure was read from bytes that never
        # passed validation - the version in particular is taken before the signature is
        # checked - so putting it first and the failure last invites reading it as fact. The
        # CLI's `info` already did this; the GUI did not.
        if not pf.parsed_ok:
            rows.append(("*** PARSE FAILED",
                         f"at stage '{pf.failed_stage}' - fields below are unvalidated"))
            rows.append((None, None))
        rows += [
            ("source file", pf.source_path),
            ("source created", stamp(pf.source_created)
             if pf.source_created else "(not available on this filesystem)"),
            ("source modified", stamp(pf.source_modified)),
            ("source accessed", stamp(pf.source_accessed)),
            (None, None),
            ("format version", pf.version),
            ("executable name", pf.executable_name),
        ]
        if pf.name_truncated:
            rows.append(("  name truncated",
                         "yes - the header's name field holds only 29 characters"))
            if full_name and full_name.upper() != pf.executable_name.upper():
                rows.append(("  full name", f"{full_name}   (recovered from the path below)"))
        rows += [
            ("hash", pf.hash + "   (from the filename; not recomputable - see docs)"),
            (None, None),
            ("run count", pf.run_count),
            ("last run (UTC)", stamp(pf.last_run)),
            ("run times kept", f"{len(pf.run_times)} of 8 slots"
             + ("   (earlier runs are not retained)" if pf.run_count > len(pf.run_times)
                else "")),
            ("first run approx", ("~" + stamp(pf.first_run_approx))
             if pf.first_run_approx else "-   (needs a creation time)"),
            (None, None),
            ("path", f"{pf.executable_path or '-'}   [{pf.path_source.value}]"),
            ("alternate path", pf.executable_path_alt or "-"),
            ("hosted package", pf.hosted_package or "-"),
            (None, None),
            ("volumes", len(pf.volumes)),
            ("files loaded", len(pf.filenames)),
            ("directories", sum(len(v.directories) for v in pf.volumes)),
            ("MFT references", sum(len(v.file_refs) for v in pf.volumes)),
            ("trace chains", pf.trace_chain_count),
            ("total dir count", pf.total_directory_count
             if pf.total_directory_count >= 0 else "-   (not stored in this version)"),
        ]
        if pf.from_ads:
            rows += [
                (None, None),
                ("recovered from", "an NTFS alternate data stream"),
                ("carrier file", pf.carrier_path),
                ("stream name", pf.stream_name),
                ("timestamps are", pf.timestamp_source + "'s, NOT this prefetch's"),
                ("carrier modified", stamp(pf.carrier_modified)),
            ]
        flags = []
        if pf.is_op_file:
            flags.append("Op-*.pf (not ordinary prefetch)")
        if pf.deceptive_characters:
            flags.append("name/path contains characters that render deceptively")
        if len(pf.volumes) > 1:
            flags.append(f"spans {len(pf.volumes)} volumes")
        rows += [
            (None, None),
            ("flags", ", ".join(flags) if flags else "-"),
            ("parsed", "yes" if pf.parsed_ok else f"NO - failed at '{pf.failed_stage}'"),
        ]

        width = max(len(label) for label, _v in rows if label)
        lines = []
        for label, value in rows:
            if label is None:
                lines.append("")
            else:
                lines.append(f"{label:<{width}} : {value}")
        if pf.problems:
            lines += ["", f"problems ({len(pf.problems)}):"]
            lines += [f"   {p}" for p in pf.problems]
        return "\n".join(lines)

    def _show_detail(self, index):
        row = self.model.rows[self.proxy.mapToSource(index).row()]
        pf = row["_pf"]

        summary = self._summary_text(pf)
        if row.get("note"):
            summary = f"YOUR NOTE      : {row['note']}\n\n" + summary
        self.detail_summary.setPlainText(summary)
        newest_slot = (max(range(len(pf.run_times)), key=lambda i: pf.run_times[i])
                       if pf.run_times else None)
        self.detail_runs.set_rows([
            [i,
             t.strftime("%Y-%m-%d %H:%M:%S.%f"),
             "newest" if i == newest_slot else "",
             pf.run_times_ticks[i] if i < len(pf.run_times_ticks) else ""]
            for i, t in enumerate(pf.run_times)])

        # One row per directory, with the volume repeated. Flat rows are what make the pane
        # sortable and filterable; a nested rendering would not be.
        volume_rows = []
        for j, v in enumerate(pf.volumes):
            created = v.created.strftime("%Y-%m-%d %H:%M:%S") if v.created else ""
            check = {True: "ok", False: "MISMATCH", None: "n/a"}[v.name_self_check]
            if v.directories:
                volume_rows += [[j, v.device_name, v.serial, created, check, d]
                                for d in v.directories]
            else:
                volume_rows.append([j, v.device_name, v.serial, created, check, ""])
        self.detail_volumes.set_rows(volume_rows)

        by_index = {m.index: m for m in pf.metrics}
        self.detail_files.set_rows([
            [i, name,
             by_index[i].mft_ref.entry if i in by_index and by_index[i].mft_ref else "",
             by_index[i].mft_ref.sequence if i in by_index and by_index[i].mft_ref else ""]
            for i, name in enumerate(pf.filenames)])


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv[:1])
    win = MainWindow()
    win.show()
    if len(argv) > 1:
        win.load(argv[1:])
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
