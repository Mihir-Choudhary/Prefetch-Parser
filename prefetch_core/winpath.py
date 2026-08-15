"""Windows path handling for paths that came out of a prefetch file.

**Never use `os.path` on parsed content.** Prefetch stores Windows paths; this tool runs on
Linux and macOS too, where `os.path.basename` does not treat `\\` as a separator and silently
returns the whole string. That exact bug made a differential test report "0 of 160 files
matched" during development (see docs/edge-cases.md and the 2026-08-13 session log).

`os.path` is still correct for real filesystem paths on the host. These helpers are for
strings *read out of an artifact*.
"""

from __future__ import annotations

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


def has_deceptive_characters(text: str) -> bool:
    """True if `text` contains characters that make it display differently than it is stored."""
    if not text:
        return False
    return any(c in _BIDI_CONTROLS or c in _ZERO_WIDTH or (ord(c) < 32) for c in text)


def escape_deceptive(text: str) -> str:
    """Render deceptive characters visibly as \\uXXXX so the displayed string is the real one."""
    out = []
    for c in text:
        if c in _BIDI_CONTROLS or c in _ZERO_WIDTH or ord(c) < 32:
            out.append(f"\\u{ord(c):04X}")
        else:
            out.append(c)
    return "".join(out)


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
