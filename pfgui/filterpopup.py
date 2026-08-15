"""The per-column filter dropdown: search box + distinct-value checklist.

Modelled on Excel's column filter and Timeline Explorer's. The behaviours that make it usable,
each of which is absent from a naive checklist:

  * typing in the search box narrows the *checklist*, and "Select all" then applies to the
    visible subset only - that is how you tick 40 matching values without 40 clicks;
  * the list shows values available under the other columns' filters, so nothing offered here
    can produce an empty result;
  * blank values get an explicit "(blank)" entry rather than an unclickable empty row.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QVBoxLayout, QWidget,
)

BLANK = "(blank)"


class FilterPopup(QWidget):
    """Frameless popup anchored under a column header."""

    applied = Signal(object)      # set[str] of permitted raw values, or None to clear

    def __init__(self, title: str, values: list[str], selected: set[str] | None, parent=None):
        super().__init__(parent, Qt.Popup)
        self.setMinimumWidth(300)
        self.setMaximumHeight(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(QLabel(f"<b>{title}</b>"))

        self.search = QLineEdit(placeholderText="Search values…")
        self.search.textChanged.connect(self._refilter)
        layout.addWidget(self.search)

        self.list = QListWidget()
        self.list.setUniformItemSizes(True)        # keeps long value lists responsive
        for v in values:
            item = QListWidgetItem(v if v != "" else BLANK)
            item.setData(Qt.UserRole, v)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(
                Qt.Checked if (selected is None or v in selected) else Qt.Unchecked)
            self.list.addItem(item)
        layout.addWidget(self.list)

        self.count = QLabel()
        layout.addWidget(self.count)

        buttons = QHBoxLayout()
        for label, slot in (("All", lambda: self._set_visible(True)),
                            ("None", lambda: self._set_visible(False)),
                            ("Invert", self._invert)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        buttons.addStretch()
        layout.addLayout(buttons)

        actions = QHBoxLayout()
        clear = QPushButton("Clear filter")
        clear.clicked.connect(self._clear)
        apply = QPushButton("Apply")
        apply.setDefault(True)
        apply.clicked.connect(self._apply)
        actions.addWidget(clear)
        actions.addStretch()
        actions.addWidget(apply)
        layout.addLayout(actions)

        self.search.setFocus()
        self._update_count()

    # -- helpers -----------------------------------------------------------
    def _visible_items(self):
        for i in range(self.list.count()):
            item = self.list.item(i)
            if not item.isHidden():
                yield item

    def _refilter(self, text):
        needle = text.strip().lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(bool(needle) and needle not in item.text().lower())
        self._update_count()

    def _set_visible(self, checked):
        # Applies to the search-narrowed subset, not the whole list. Ticking 40 filtered values
        # in one click is the entire point of having a search box here.
        for item in self._visible_items():
            item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        self._update_count()

    def _invert(self):
        for item in self._visible_items():
            item.setCheckState(
                Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked)
        self._update_count()

    def _update_count(self):
        total = self.list.count()
        checked = sum(1 for i in range(total)
                      if self.list.item(i).checkState() == Qt.Checked)
        shown = sum(1 for _ in self._visible_items())
        suffix = f", {shown} shown" if shown != total else ""
        self.count.setText(f"{checked} of {total} selected{suffix}")

    def _clear(self):
        self.applied.emit(None)
        self.close()

    def _apply(self):
        chosen = {self.list.item(i).data(Qt.UserRole)
                  for i in range(self.list.count())
                  if self.list.item(i).checkState() == Qt.Checked}
        # Everything ticked is the same as no filter; emitting None keeps the header
        # indicator honest instead of showing a filter that excludes nothing.
        self.applied.emit(None if len(chosen) == self.list.count() else chosen)
        self.close()
