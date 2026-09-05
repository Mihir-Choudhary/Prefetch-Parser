"""Windows path handling for paths that came out of a prefetch file.

**Never use `os.path` on parsed content.** Prefetch stores Windows paths; this tool runs on
Linux and macOS too, where `os.path.basename` does not treat `\\` as a separator and silently
returns the whole string. That exact bug made a differential test report "0 of 160 files
matched" during development (see docs/edge-cases.md and the 2026-08-13 session log).

`os.path` is still correct for real filesystem paths on the host. These helpers are for
strings *read out of an artifact*.
"""

from __future__ import annotations

import os

# Both notations appear, and they are two spellings of the same volume:
#   \DEVICE\HARDDISKVOLUME3\...     - used by the 5a executable-path field
#   \VOLUME{01d6d2b9...-cc31b5d5}\  - used by filename-list entries and volume records
_VOLUME_PREFIXES = ("\\DEVICE\\", "\\VOLUME{")


def basename(path: str) -> str:
    """Last component of a Windows path. Splits on '\\' regardless of host OS."""
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def dirname(path: str) -> str:
    p = path.replace("/", "\\")
    return p.rsplit("\\", 1)[0] if "\\" in p else ""


def is_device_path(path: str | None) -> bool:
    """True if the string is a volume-rooted path rather than, say, a package identity."""
    return bool(path) and path.upper().startswith(_VOLUME_PREFIXES)


def strip_volume(path: str) -> str:
    """Drop the leading volume component so the two notations can be compared.

    Comparing raw strings reports total disagreement between a `\\DEVICE\\HARDDISKVOLUME1\\...`
    path and a `\\VOLUME{...}\\...` one even when they name the same file.
    """
    upper = path.upper()
    for prefix in _VOLUME_PREFIXES:
        if upper.startswith(prefix):
            sep = upper.find("\\", len(prefix))
            return upper[sep:] if sep >= 0 else upper
    return upper


def same_file(a: str, b: str) -> bool:
    """Case-insensitive comparison ignoring which volume notation each side used."""
    return strip_volume(a) == strip_volume(b)


# Characters that make a string *render* differently from what it contains. Not a heuristic
# about badness - a factual property of the text.
#
#   U+202E RIGHT-TO-LEFT OVERRIDE and friends reverse the display order, so a file stored as
#   "RTL‮gnp.exe" appears in any UI as "RTL exe.png" - the long-standing extension-spoof
#   trick. Zero-width and control characters hide content outright.
#
# Zero occurrences in 87,456 strings across both corpora, so this never fires on normal data.
# It is here because a viewer that silently renders a spoofed name is worse than one that does
# not display the field at all: the analyst reads a filename that is not the filename.
_BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩‎‏"
_ZERO_WIDTH = "​‌‍﻿"


def readable_text(text: str) -> str:
    """Render a string that carries undecodable bytes without losing them, and without raising.

    A filename does not have to be valid text. NTFS allows unpaired UTF-16 surrogates, and a
    Prefetch folder copied out of an image onto Linux carries whatever bytes the name held -
    `os.walk` hands those back as lone surrogates (`\\udcff`), which is Python telling the truth
    about a name that is not valid UTF-8.

    Every text output then refuses them: SQLite raises `UnicodeEncodeError` while binding the
    parameter, and so does the CSV writer. Neither is caught anywhere, so a single such file
    ended the whole run with a traceback and **no report at all** - the same failure as a device
    node in the folder, from a name (AUDIT BUG 102).

    The byte is what an examiner needs, so it is what is shown: the string is encoded back to
    the bytes it came from and re-decoded with escapes, giving `CALC.EXE-3FBEF7FD\\xff.pf`.
    Where that is impossible - a genuine unpaired surrogate from a UTF-16 name, which no byte
    sequence produced - the escape names the code point instead. Lossless either way, and never
    fatal.
    """
    if not text or not any("\ud800" <= ch <= "\udfff" for ch in text):
        return text
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def has_undecodable_bytes(text: str) -> bool:
    """True if `text` came from a name that is not valid UTF-8 (or not valid UTF-16)."""
    return bool(text) and any("\ud800" <= ch <= "\udfff" for ch in text)


def has_deceptive_characters(text: str) -> bool:
    """True if `text` contains characters that make it display differently than it is stored."""
    if not text:
        return False
    return any(c in _BIDI_CONTROLS or c in _ZERO_WIDTH or (ord(c) < 32) for c in text)


def escape_deceptive(text: str) -> str:
    """Render deceptive characters visibly as \\uXXXX so the displayed string is the real one."""
    # An undecodable byte is the same category of problem as a right-to-left override: a string
    # that cannot be shown as it is. Rendered first, so every surface that escapes for display
    # also survives a name that is not valid text (AUDIT BUG 102).
    text = readable_text(text)
    out = []
    for c in text:
        if c in _BIDI_CONTROLS or c in _ZERO_WIDTH or ord(c) < 32:
            out.append(f"\\u{ord(c):04X}")
        else:
            out.append(c)
    return "".join(out)


# MAX_PATH is 260 characters, and the Win32 file APIs enforce it unless the path carries the
# `\\?\` prefix - which turns off all normalisation and lets the wide API address up to 32,767
# characters. Python's `open` and `os.stat` inherit the limit, so a case folder nested deeply
# enough ("C:\Cases\2026-0043\Evidence\HOST-01\C\Windows\Prefetch\...", plus a triage
# tool's own timestamped directories) makes EVERY file in it unreadable, with an error that
# names the file rather than the real cause. 248 rather than 260 because a directory path must
# leave room for an 8.3 name, which is the threshold Windows itself documents.
_MAX_PATH_SAFE = 248


def _long_path_nt(path: str, extra: int = 0) -> str:
    """The transformation itself, in Windows path semantics, callable on any host.

    Split out from `long_path` so it can be tested off Windows: `ntpath` applies Windows rules
    everywhere, while the platform check below cannot be exercised anywhere but Windows. A
    transformation that only runs on the machine nobody can test is a transformation nobody has
    ever checked.
    """
    import ntpath                                                     # noqa: PLC0415

    if not path or path.startswith("\\\\?\\") or path.startswith("\\\\.\\"):
        return path                        # already device-namespace; leave it exactly as given
    absolute = ntpath.abspath(path)
    # `extra` is what the caller will append before using this path. A temporary file is longer
    # than the directory that holds it by its prefix, mkstemp's random characters and a suffix,
    # so a directory comfortably under the limit can still produce a temp path over it - and
    # the create fails for a target the rename would have handled (AUDIT BUG 99, second half).
    if len(absolute) + extra < _MAX_PATH_SAFE:
        return path
    if absolute.startswith("\\\\"):        # UNC: \\server\share -> \\?\UNC\server\share
        return "\\\\?\\UNC" + absolute[1:]
    return "\\\\?\\" + absolute


def long_path(path: str, extra: int = 0) -> str:
    """Return `path` in a form the Win32 file APIs will accept, however long it is.

    A no-op everywhere but Windows, and a no-op on Windows for ordinary lengths - the prefix
    disables path normalisation, so it is applied only where it is needed. Never store the
    result: it is an argument for `open`/`os.stat`, not the path to report to an analyst
    (AUDIT BUG 99).
    """
    import sys                                                        # noqa: PLC0415

    return _long_path_nt(path, extra) if sys.platform == "win32" else path


def creation_time(stat_result):
    """Return a file's creation time, or None if this platform cannot supply one.

    `st_birthtime` is the right answer where it exists - macOS/BSD always, and Windows from
    Python 3.12. Below that, **Windows reports creation time in `st_ctime`**, while on Linux
    the same field is inode-change time and must never be used for this.

    Reading only `st_birthtime` therefore silently returned None on Windows + Python < 3.12,
    which is the platform this tool targets - so `source_created` was empty and the
    "approximate first run" estimate quietly did nothing on the one OS it was built for.

    This is a genuine platform branch, not a capability probe: `st_ctime` exists everywhere and
    *means something different* depending on the OS. Nothing can be probed for that.
    """
    import datetime
    import sys

    birth = getattr(stat_result, "st_birthtime", None)
    if birth is None and sys.platform == "win32":
        birth = stat_result.st_ctime
    if birth is None:
        return None
    return datetime.datetime.fromtimestamp(birth, datetime.timezone.utc)
