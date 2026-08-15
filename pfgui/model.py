"""Table model and the Excel-style column filter.

The filter behaviour that matters and is easy to get wrong: the value checklist for column X
must list the values available in the rows that pass **every other column's filter**, not the
values in the whole table. Excel and Timeline Explorer both do this, and it is what makes
successive filtering feel sane - after filtering Version to 31, the ExecutableName list should
only offer names that actually occur in v31 rows.

Computing it from the unfiltered table instead offers values that yield zero rows when picked,
which reads as a broken filter.
"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPalette

from prefetch_core.winpath import escape_deceptive

COLUMNS = [
    ("Tag", "tag"),
    # The analyst's own note. It was stored and exported but shown nowhere, so the one piece
    # of analyst-authored data in the tool was write-only - you could not read back what you
    # had written, or spot which rows carried which note.
    ("Note", "note"),
    ("Source", "source_name"),
    ("Executable", "executable_name"),
    ("Hash", "hash"),
    ("Ver", "version"),
    ("Runs", "run_count"),
    ("Last Run (UTC)", "last_run"),
    ("Executable Path", "executable_path"),
    ("Path Source", "path_source"),
    ("Hosted Package", "hosted_package"),
    ("Alt Path", "executable_path_alt"),
    ("Vols", "volume_count"),
    ("Files", "file_count"),
    ("Dirs", "dir_count"),
    ("Name Cut", "name_truncated"),
    ("Op File", "is_op_file"),
    ("Deceptive", "deceptive_chars"),
    ("Parsed", "parsed_ok"),
    ("Failed Stage", "failed_stage"),
    ("Problems", "problems"),
]

NUMERIC = {"version", "run_count", "volume_count", "file_count", "dir_count"}

# Rows the analyst should not have to hunt for: a parse that failed, two sources disagreeing
# about where a binary ran from, a name that renders differently than it is stored. Each marks
# a *fact about the evidence*, never a guess about badness.
#
# Colours are derived from the LIVE PALETTE, not hardcoded. Hardcoded pale tints looked fine on
# a light desktop and rendered a highlighted row unreadable on a dark one - light background,
# light theme text, nothing visible. The developer's theme is not the analyst's, and an
# offscreen test harness reports a light palette regardless, so this cannot be caught by
# looking at it here.
#
# Both a background AND a foreground are always set. Setting only the background leaves the
# text at whatever the theme chose, which is the failure above.
_TINT_HUES = {
    "failed": 0,        # red
    "deceptive": 0,
    "conflict": 35,     # amber
}


def _tint_pair(hue, palette):
    """Return (background, foreground) that contrast, for this palette's light or dark theme."""
    base = palette.color(QPalette.Base)
    dark = base.lightness() < 128
    if dark:
        background = QColor.fromHsl(hue, 140, 58)     # muted, sits on a dark surface
        foreground = QColor("#ffffff")
    else:
        background = QColor.fromHsl(hue, 255, 240)    # pale, sits on a light surface
        foreground = QColor("#1a1a1a")
    return background, foreground


def row_colours(palette):
    """Tint table for the current palette. Recomputed on load so a theme change is picked up."""
    return {key: _tint_pair(hue, palette) for key, hue in _TINT_HUES.items()}


def contrast_ratio(a, b):
    """WCAG contrast ratio. Used by the tests to prove the pairs are legible, not assumed."""
    def channel(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    def luminance(c):
        return (0.2126 * channel(c.red()) + 0.7152 * channel(c.green())
                + 0.0722 * channel(c.blue()))

    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


# Shown as a cell tooltip. Only for columns whose meaning is genuinely not obvious from the
# header - a tooltip on every column trains people to ignore tooltips.
COLUMN_HELP = {
    "name_truncated":
        "The prefetch HEADER stores the executable name in a 29-character field. 'yes' means "
        "that field was full, so the name in it is cut short.\n"
        "It does NOT mean the path is truncated - the path comes from a different part of the "
        "file and is complete, which is how the full name is recovered.",
    "path_source":
        "How the path was determined.\n"
        "stored = read directly from the undocumented path field (most reliable)\n"
        "resolved = matched against the file list\n"
        "conflict = the two sources disagree; see Alt Path\n"
        "ambiguous = several candidates, none decisive\n"
        "unresolved = no path from any source",
    "hosted_package":
        "For generic hosts (DLLHOST, RUNTIMEBROKER, BACKGROUNDTASKHOST) this names the UWP "
        "package they were running - which the executable name alone does not tell you.",
    "executable_path_alt":
        "The other source's answer when the two disagree. Same file name, different directory, "
        "within one execution - consistent with the binary having moved.",
    "deceptive_chars":
        "The name or path contains characters that make it DISPLAY differently from how it is "
        "stored - right-to-left overrides, zero-width or control characters.",
    "is_op_file":
        "An Op-*.pf file. These are not ordinary prefetch: no embedded path field, and they do "
        "not list their own executable.",
    "hash": "From the filename. It is NOT recomputable from the path - see docs.",
    "note": "Your own note, attached when you tagged the row. Tag the row again to edit it.",
}


class Row(dict):
    """One prefetch, flattened for display. `tag` and `note` are analyst state, not parsed."""

    @property
    def tag(self) -> str:
        return self.get("tag", "")


def row_from(pf) -> Row:
    return Row(
        tag="",
        note="",
        source_name=pf.source_path.replace("\\", "/").rsplit("/", 1)[-1],
        source_path=pf.source_path,
        # Escaped for display: a name carrying an RTL override would otherwise render in the
        # grid as something other than what it is.
        executable_name=escape_deceptive(pf.executable_name),
        hash=pf.hash,
        version=pf.version,
        run_count=pf.run_count,
        # Every timestamp is UTC (asserted by the test suite), so repeating "+00:00" on
        # 452 rows costs width and tells the analyst nothing the header does not.
        last_run=pf.last_run.strftime("%Y-%m-%d %H:%M:%S") if pf.last_run else "",
        executable_path=escape_deceptive(pf.executable_path or ""),
        path_source=pf.path_source.value,
        hosted_package=pf.hosted_package or "",
        executable_path_alt=pf.executable_path_alt or "",
        volume_count=len(pf.volumes),
        file_count=len(pf.filenames),
        dir_count=sum(len(v.directories) for v in pf.volumes),
        name_truncated="yes" if pf.name_truncated else "",
        is_op_file="yes" if pf.is_op_file else "",
        deceptive_chars="YES" if pf.deceptive_characters else "",
        parsed_ok="yes" if pf.parsed_ok else "NO",
        failed_stage=pf.failed_stage or "",
        problems=" | ".join(str(p) for p in pf.problems),
        _pf=pf,
    )


class PrefetchTableModel(QAbstractTableModel):
    def __init__(self, rows: list[Row], palette=None):
        super().__init__()
        self.rows = rows
        from PySide6.QtWidgets import QApplication
        self.colours = row_colours(palette or QApplication.palette())
        # Header labels can be overridden to show filter state. Without this store the base
        # QAbstractTableModel.setHeaderData is a silent no-op - it has nowhere to put the
        # value - and headerData below kept returning the static label, so the filter glyph
        # never appeared at all. Only visible in a screenshot; no logic test would catch it.
        self._header_labels: dict[int, str] = {}

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._header_labels.get(section, COLUMNS[section][0])
        return section + 1

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        key = COLUMNS[index.column()][1]
        if role in (Qt.DisplayRole, Qt.EditRole):
            return str(row.get(key, ""))
        if role == Qt.ToolTipRole:
            # Column-level explanations for the ones whose meaning is not self-evident. "Name
            # Cut" in particular reads as though the path were truncated; it describes the
            # 29-character header field, and the path is complete.
            hint = COLUMN_HELP.get(key)
            value = str(row.get(key, ""))
            if hint:
                return f"{hint}\n\n{value}" if value else hint
            return value if len(value) > 40 else None
        kind = self._tint_kind(row)
        if role == Qt.BackgroundRole and kind:
            return QBrush(self.colours[kind][0])
        # The foreground must be set too. Leaving it to the theme is what made a tinted row
        # invisible on a dark desktop.
        if role == Qt.ForegroundRole and kind:
            return QBrush(self.colours[kind][1])
        if role == Qt.FontRole and kind:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.UserRole:
            return row
        return None

    @staticmethod
    def _tint_kind(row):
        if row.get("parsed_ok") == "NO":
            return "failed"
        if row.get("deceptive_chars"):
            return "deceptive"
        if row.get("path_source") == "conflict":
            return "conflict"
        return None

    def setHeaderData(self, section, orientation, value, role=Qt.EditRole) -> bool:
        if orientation != Qt.Horizontal or not 0 <= section < len(COLUMNS):
            return False
        self._header_labels[section] = str(value)
        self.headerDataChanged.emit(orientation, section, section)
        return True

    def value_at(self, row_index: int, key: str) -> str:
        return str(self.rows[row_index].get(key, ""))

    def set_tag(self, row_index: int, tag: str, note: str = "") -> None:
        self.rows[row_index]["tag"] = tag
        if note:
            self.rows[row_index]["note"] = note
        top = self.index(row_index, 0)
        self.dataChanged.emit(top, self.index(row_index, len(COLUMNS) - 1))


class FilterProxy(QSortFilterProxyModel):
    """Per-column allowed-value sets plus a global search box."""

    def __init__(self):
        super().__init__()
        self.allowed: dict[int, set[str]] = {}    # column -> permitted values
        self.search = ""
        self.tagged_only = False

    # -- filter state ------------------------------------------------------
    def set_allowed(self, column: int, values: set[str] | None) -> None:
        if values is None:
            self.allowed.pop(column, None)
        else:
            self.allowed[column] = values
        self.invalidateFilter()

    def clear_filters(self) -> None:
        self.allowed.clear()
        self.search = ""
        self.tagged_only = False
        self.invalidateFilter()

    def set_search(self, text: str) -> None:
        self.search = text.strip().lower()
        self.invalidateFilter()

    def set_tagged_only(self, on: bool) -> None:
        self.tagged_only = on
        self.invalidateFilter()

    def active_columns(self) -> set[int]:
        return set(self.allowed)

    # -- filtering ---------------------------------------------------------
    def _passes(self, source_row: int, skip_column: int | None = None) -> bool:
        model = self.sourceModel()
        row = model.rows[source_row]
        if self.tagged_only and not row.get("tag"):
            return False
        for col, values in self.allowed.items():
            if col == skip_column:
                continue
            if str(row.get(COLUMNS[col][1], "")) not in values:
                return False
        if self.search:
            haystack = " ".join(str(v) for k, v in row.items() if not k.startswith("_")).lower()
            if self.search not in haystack:
                return False
        return True

    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        return self._passes(source_row)

    def distinct_values(self, column: int) -> list[str]:
        """Values available for `column` given every OTHER active filter.

        Deliberately excludes `column`'s own filter, so opening the dropdown on an
        already-filtered column still shows the alternatives you could switch to rather than
        only the ones currently ticked.
        """
        model = self.sourceModel()
        key = COLUMNS[column][1]
        seen = set()
        for r in range(model.rowCount()):
            if self._passes(r, skip_column=column):
                seen.add(str(model.rows[r].get(key, "")))
        numeric = COLUMNS[column][1] in NUMERIC
        return sorted(seen, key=lambda s: (int(s) if numeric and s.isdigit() else 0, s))

    def lessThan(self, left, right) -> bool:
        key = COLUMNS[left.column()][1]
        a = self.sourceModel().rows[left.row()].get(key, "")
        b = self.sourceModel().rows[right.row()].get(key, "")
        if key in NUMERIC:
            return (a or 0) < (b or 0)
        return str(a).lower() < str(b).lower()
