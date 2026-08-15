"""prefetch_core - Windows Prefetch parsing. Pure logic, no I/O policy, no formatting.

    from prefetch_core import parse_file
    pf = parse_file("NOTEPAD.EXE-D8414F97.pf")
    print(pf.executable_path, pf.last_run)

The CLI and GUI are both just consumers of these records.
"""

from .container import available_decompressors
from .errors import PrefetchError, Problem, Stage
from .model import FileMetric, MftRef, PathSource, Prefetch, Volume
from .scca import parse

__all__ = [
    "parse", "parse_file", "available_decompressors",
    "Prefetch", "Volume", "FileMetric", "MftRef", "PathSource",
    "PrefetchError", "Problem", "Stage",
]


def parse_file(path: str, prefer_decompressor: str | None = None) -> Prefetch:
    """Read and parse one prefetch file. Read errors become a record, not an exception."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        pf = Prefetch(source_path=path)
        pf.failed_stage = Stage.READ.value
        pf.problems.append(Problem(Stage.READ, str(exc), fatal=True))
        return pf
    pf = parse(data, source_path=path, prefer_decompressor=prefer_decompressor)
    _stamp_source(pf, path)
    return pf


def _stamp_source(pf: Prefetch, path: str) -> None:
    """Attach the .pf's own filesystem timestamps.

    Creation time is only set where the OS actually reports a birth time. `st_ctime` is inode
    *change* time on Unix, not creation, and presenting it as creation would silently corrupt
    the "approximate first run" estimate that is derived from this field.
    """
    import datetime
    import os

    from . import winpath

    try:
        st = os.stat(path)
    except OSError:
        return
    utc = datetime.timezone.utc
    pf.source_size = st.st_size
    pf.source_modified = datetime.datetime.fromtimestamp(st.st_mtime, utc)
    pf.source_accessed = datetime.datetime.fromtimestamp(st.st_atime, utc)
    pf.source_created = winpath.creation_time(st)
    # No `Problem` when the birth time is missing. It is a property of the host filesystem, not
    # of this file, so recording it per record would attach an identical note to every one of
    # 636 rows and bury the real problems. `source_created is None` already says it; callers
    # report it once per run - see `filesystem_supports_creation_time()`.
