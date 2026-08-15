"""Structured detail panes.

The run-time, loaded-file and directory lists were monospace text dumps. That is fine for
inspecting one record by eye and useless for the thing analysts actually do: a single prefetch
can list **759 loaded files**, and finding one in a `QTextEdit` means Ctrl-F in a widget that
has no Ctrl-F.

Each pane below is a real table - sortable, searchable, and copyable - because these lists are
evidence to be interrogated, not prose to be read.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QLabel, QLineEdit, QMenu, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)


class _Cell(QTableWidgetItem):
    """Table cell that sorts numerically when it holds a number.

    `QTableWidgetItem` compares as text, so a column of indices sorts 1, 10, 100, 2 - and the
    "Loaded file #" column came out 9, 754, 75, 74 while the header showed an ascending arrow.
    Every numeric column here (slot, index, MFT entry, MFT sequence) hits this.
    """

    def __init__(self, value):
        super().__init__(str(value))
        try:
            self._sort_key = (0, float(str(value)))
        except (TypeError, ValueError):
            # Numbers before text, so blanks and labels group together at one end rather than
            # interleaving with the numeric run.
            self._sort_key = (1, str(value).lower())

    def __lt__(self, other):
        if isinstance(other, _Cell):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


class SearchableTable(QWidget):
    """A table with a live filter box and copy support.

    Filtering is on the *whole row* rather than a chosen column: these panes are small and the
    analyst is looking for a substring, not composing a query. The main grid is where the
    per-column filtering lives.
    """

    def __init__(self, headers: list[str], placeholder: str = "Filter…"):
        super().__init__()
        self.headers = headers

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        bar = QHBoxLayout()
        self.search = QLineEdit(placeholderText=placeholder)
        self.search.textChanged.connect(self._apply_filter)
        bar.addWidget(self.search)
        self.count = QLabel()
        bar.addWidget(self.count)
        layout.addLayout(bar)

        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table)

    def set_rows(self, rows: list[list[str]]) -> None:
        """Fill the table, preserving the order given.

        Two Qt behaviours conspire here. Filling with sorting enabled re-sorts on every insert,
        and `setSortingEnabled(True)` immediately sorts by whatever sort indicator is currently
        set - so a record selected after the user sorted a *previous* record came out in that
        old order instead of its own.

        That is not cosmetic for the Run times pane: the stored slot order is itself evidence
        (the 8 slots are not reliably newest-first), so silently re-ordering them hides the
        thing the pane exists to show. The sort indicator is therefore cleared on each fill;
        the user can re-sort, but every new record starts in file order.
        """
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, values in enumerate(rows):
            for c, value in enumerate(values):
                self.table.setItem(r, c, _Cell(value))
        self.table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self.search.clear()
        self._apply_filter("")

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        shown = 0
        for r in range(self.table.rowCount()):
            row_text = " ".join(
                (self.table.item(r, c).text() if self.table.item(r, c) else "")
                for c in range(self.table.columnCount())).lower()
            hidden = bool(needle) and needle not in row_text
            self.table.setRowHidden(r, hidden)
            shown += not hidden
        total = self.table.rowCount()
        self.count.setText(f"{shown} of {total}" if shown != total else f"{total}")

    def _menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        menu = QMenu(self)
        copy_cell = menu.addAction("Copy cell")
        copy_row = menu.addAction("Copy row")
        copy_all = menu.addAction("Copy all visible rows")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        clip = QGuiApplication.clipboard()
        if chosen is copy_cell:
            item = self.table.item(index.row(), index.column())
            clip.setText(item.text() if item else "")
        elif chosen is copy_row:
            clip.setText(self._row_text(index.row()))
        elif chosen is copy_all:
            lines = [self._row_text(r) for r in range(self.table.rowCount())
                     if not self.table.isRowHidden(r)]
            clip.setText("\n".join(["\t".join(self.headers)] + lines))

    def _row_text(self, row: int) -> str:
        return "\t".join(
            (self.table.item(row, c).text() if self.table.item(row, c) else "")
            for c in range(self.table.columnCount()))
