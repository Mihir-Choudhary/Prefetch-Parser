"""Writing output files without destroying the previous one.

`open(path, "w")` truncates immediately. If the write then fails - a full disk, a disconnected
share, a permissions change, a crash - what is left on disk is a *truncated* file with no
indication that it is truncated, and the complete export that was there before is gone. A
185-row CSV became a 7-row CSV with a message on stderr the analyst may never read
(AUDIT BUG 66).

Everything here writes to a temporary file beside the target and renames it into place only
once the write has completed. `os.replace` is atomic on POSIX and on Windows, so a reader
either sees the old file or the new one, never a half-written one.
"""

from __future__ import annotations

import contextlib
import os
import tempfile

from . import winpath


# What `mkstemp` appends beyond the prefix: a path separator, eight random characters, and
# ".partial". The temp file is what has to fit under MAX_PATH, not the directory holding it.
_TEMP_NAME_ROOM = 1 + 8 + len(".partial")


@contextlib.contextmanager
def atomic_write(path: str, encoding: str = "utf-8", newline: str = "",
                 errors: str = "backslashreplace"):
    """Yield a writable text file that replaces `path` only if the block completes.

    The temporary file is created in the same directory, because `os.replace` across
    filesystems is not atomic - and `/tmp` is very often a different filesystem from the
    evidence directory.
    """
    prefix = "." + os.path.basename(path) + "."
    directory = winpath.long_path(os.path.dirname(os.path.abspath(path)),
                                  extra=_TEMP_NAME_ROOM + len(prefix))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=".partial")
    try:
        # `errors` is not "strict": a filename that is not valid UTF-8 - NTFS allows it, and a
        # folder copied out of an image carries it - would otherwise raise while the row is
        # written, losing the whole export (AUDIT BUG 102). An escape keeps the bytes visible;
        # nothing else in a normal export is ever unencodable.
        with os.fdopen(fd, "w", encoding=encoding, newline=newline, errors=errors) as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())      # the rename must not outrun the bytes
        os.replace(tmp, winpath.long_path(path))
        tmp = None
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


@contextlib.contextmanager
def atomic_write_pair(first: str, second: str, encoding: str = "utf-8", newline: str = "",
                      errors: str = "backslashreplace"):
    """Write two files that only make sense together, and publish them together.

    The artifact export is a paths file and a summary file. Writing them with two separate
    `atomic_write` blocks renames the first into place before the second is written, so a
    failure in between leaves a fresh paths file beside a STALE summary from an earlier run,
    with nothing to say they disagree - BUG 66 again, one level up. Both temporaries are
    written first and renamed only once both are complete.
    """
    handles, temps = [], []
    try:
        for path in (first, second):
            prefix = "." + os.path.basename(path) + "."
            directory = winpath.long_path(os.path.dirname(os.path.abspath(path)),
                                          extra=_TEMP_NAME_ROOM + len(prefix))
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=".partial")
            temps.append(tmp)
            handles.append(os.fdopen(fd, "w", encoding=encoding, newline=newline,
                                     errors=errors))
        yield handles[0], handles[1]
        for handle in handles:
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        handles.clear()
        # Both renames now, back to back. A crash between them is possible in principle; a
        # failed *write* - the case that actually happens - can no longer publish half a pair.
        for tmp, path in zip(temps, (first, second)):
            os.replace(tmp, winpath.long_path(path))
        temps.clear()
    finally:
        for handle in handles:
            with contextlib.suppress(OSError):
                handle.close()
        for tmp in temps:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def make_stdio_safe(streams=None) -> None:
    """Stop a filename the console cannot spell from killing the run.

    Windows picks the encoding for `sys.stdout` from the environment, and it is only UTF-8 when
    the stream is a real console. **Redirect the output** - `pfcli parse ... > report.txt`, a
    pipe into `findstr`, or any script that captures it - and the stream becomes the ANSI code
    page: cp1252 in Western Europe, cp932 in Japan. Printing a Cyrillic, CJK or emoji filename
    to that stream raises `UnicodeEncodeError`, which is not caught anywhere, so the process
    dies with a traceback and produces **no report at all** (AUDIT BUG 97).

    That is the same failure as BUG 96: the run ceases to exist rather than reporting what it
    found. And it fires on exactly the evidence an examiner most needs to see - a non-English
    system, or a name chosen precisely because tools mishandle it.

    Two changes, and no others:

      * `errors="backslashreplace"`, so a character the destination cannot represent is written
        as an escape instead of raising. Never `"replace"`: a `?` destroys the one thing the
        analyst needed to read, and this file forbids silent loss everywhere else.
      * for a **redirected** stream only, `encoding="utf-8"`, so a captured report is UTF-8
        rather than the local code page. A real console keeps its own encoding, because writing
        UTF-8 bytes at a cp1252 console renders mojibake - trading a crash for corruption.

    Console encoding is a property of the machine, so this cannot be probed for on Linux
    either; forcing `PYTHONIOENCODING=cp1252` reproduces it exactly, which is how it was found.
    """
    import sys                                                        # noqa: PLC0415

    if streams is None:
        # A PyInstaller **windowed** build on Windows - which is what `pfgui.exe` is - runs with
        # `sys.stdout` and `sys.stderr` set to **None**. Measured, not assumed: on Python 3.14
        # `print()` and argparse both tolerate that and discard the text, so nothing here
        # crashes today. Anything calling `.write()` on the stream directly would, and the two
        # halves of this program should not behave differently because of how they were frozen,
        # so a discarding sink is substituted. A hardening, not a fixed defect - and the reason
        # `pfgui.exe --help` prints nothing on Windows is this, not a failure: `pfcli.exe` is
        # the console half, and is what an analyst pipes.
        for name in ("stdout", "stderr"):
            if getattr(sys, name, None) is None:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
        streams = (sys.stdout, sys.stderr)

    for stream in streams:
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue                       # already wrapped by something else; leave it alone
        try:
            redirected = not stream.isatty()
        except (OSError, ValueError):
            redirected = True
        try:
            if redirected:
                reconfigure(encoding="utf-8", errors="backslashreplace")
            else:
                reconfigure(errors="backslashreplace")
        except (OSError, ValueError, LookupError):
            # A stream that refuses to be reconfigured is not a reason to refuse the run.
            pass


# Excel (and LibreOffice, and Google Sheets) refuse to hold more than 32,767 characters in one
# cell, and they do it SILENTLY: the cell is truncated on import with no warning anywhere.
# Prefetch list cells go well past that - the widest in the Windows 10 corpus is 323,778
# characters, ten times the limit - so a spreadsheet shows a plausible, complete-looking list
# that is missing most of its entries. The export cannot fix the limit, but it must not let it
# pass unremarked (AUDIT BUG 74).
EXCEL_CELL_LIMIT = 32767
# Python's csv module refuses a field wider than this by default (_csv.Error: field larger than
# field limit). It is not a limit this tool imposes; it is the one the most common reader has.
PY_CSV_FIELD_LIMIT = 131072


class CellWidths:
    """Counts cells too wide for a spreadsheet, per column, while an export is written."""

    def __init__(self, limit: int = EXCEL_CELL_LIMIT):
        self.limit = limit
        self.over: dict[str, int] = {}
        self.widest = 0

    def note(self, row) -> None:
        items = row.items() if isinstance(row, dict) else enumerate(row)
        for key, value in items:
            width = len(value) if isinstance(value, str) else len(str(value or ""))
            self.widest = max(self.widest, width)
            if width > self.limit:
                self.over[str(key)] = self.over.get(str(key), 0) + 1

    @property
    def message(self) -> str | None:
        """One line naming what a spreadsheet will quietly cut, or None when nothing will be."""
        if not self.over:
            return None
        columns = ", ".join(f"{name} ({count} row(s))"
                            for name, count in sorted(self.over.items(),
                                                      key=lambda kv: -kv[1]))
        note = (f"note: {sum(self.over.values())} cell(s) exceed the {self.limit:,}-character "
                f"limit a spreadsheet imposes and will be TRUNCATED silently if this file is "
                f"opened in one: {columns}. The values are complete in the file itself and in "
                f"the database; read them with a CSV-aware tool.")
        # "Read them with a CSV-aware tool" is incomplete advice for the tool an analyst is
        # most likely to reach for: Python's own csv module refuses a field over 131,072
        # characters with `_csv.Error: field larger than field limit`, which reads as a corrupt
        # export rather than a reader default. A 323,778-character FilesLoaded cell in the Win10
        # corpus does exactly that, so the message says how to read it (AUDIT BUG 89).
        if self.widest > PY_CSV_FIELD_LIMIT:
            note += (f" The widest is {self.widest:,} characters, which also exceeds Python's "
                     f"csv module default of {PY_CSV_FIELD_LIMIT:,}: raise it with "
                     f"csv.field_size_limit() or the read fails outright.")
        return note
