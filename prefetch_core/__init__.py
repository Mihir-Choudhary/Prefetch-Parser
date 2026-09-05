"""prefetch_core - Windows Prefetch parsing. Pure logic, no I/O policy, no formatting.

    from prefetch_core import parse_file
    pf = parse_file("NOTEPAD.EXE-D8414F97.pf")
    print(pf.executable_path, pf.last_run)

The CLI and GUI are both just consumers of these records.
"""

import os
import stat

from . import limits, winpath
from .container import available_decompressors
from .errors import PrefetchError, Problem, Stage
from .model import FileMetric, MftRef, PathSource, Prefetch, Volume
from .scca import parse

__all__ = [
    "parse", "parse_file", "available_decompressors",
    "Prefetch", "Volume", "FileMetric", "MftRef", "PathSource",
    "PrefetchError", "Problem", "Stage",
]


def _file_kind(mode: int) -> str:
    """Name what a non-regular path is, so the record says why it was not read."""
    for test, name in ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a FIFO"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISSOCK, "a socket"), (stat.S_ISLNK, "a symbolic link")):
        if test(mode):
            return name
    return "not a regular file"


def parse_file(path: str, prefer_decompressor: str | None = None) -> Prefetch:
    """Read and parse one prefetch file. Read errors become a record, not an exception."""
    try:
        # Size first, then read. A prefetch file is a few hundred kilobytes; anything wildly
        # larger is either not prefetch or is meant to exhaust memory, and either way the run
        # must survive it (AUDIT BUG 77).
        # `long_path` only ever reaches the OS call - never `pf.source_path`, which stays the
        # path the analyst gave, however long it is (AUDIT BUG 99).
        st = os.stat(winpath.long_path(path))
        # A FIFO, a device node, a socket or a directory can sit in a collected folder: a raw
        # image mount, a collection script's leftovers, or something planted deliberately.
        # `st_size` lies about every one of them - /dev/zero reports 0 - and the read below
        # used to be unbounded, so the process grew until the OS killed it. That takes the
        # analyst's whole session with it and produces no report at all, which is the worst
        # failure this tool has: no row, no exit code, no evidence (AUDIT BUG 96). Opening a
        # FIFO is worse still - it blocks forever waiting for a writer, and the scan hangs.
        if not stat.S_ISREG(st.st_mode):
            pf = Prefetch(source_path=path)
            pf.failed_stage = Stage.READ.value
            pf.problems.append(Problem(
                Stage.READ, f"not a regular file ({_file_kind(st.st_mode)}); not opened",
                fatal=True))
            return pf
        size = st.st_size
        if size > limits.MAX_PREFETCH_BYTES:
            pf = Prefetch(source_path=path)
            pf.source_size = size
            pf.failed_stage = Stage.READ.value
            pf.problems.append(Problem(
                Stage.READ,
                f"file is {size:,} bytes, above the {limits.MAX_PREFETCH_BYTES:,} byte ceiling "
                f"for a prefetch file; not read", fatal=True))
            _stamp_source(pf, path, st)
            return pf
        with open(winpath.long_path(path), "rb") as fh:
            # One byte past the ceiling, never `read()`. A file can be longer than the size it
            # just reported - it is being appended to, or the size was never true in the first
            # place - and an unbounded read of it is unbounded memory.
            data = fh.read(limits.MAX_PREFETCH_BYTES + 1)
        if len(data) > limits.MAX_PREFETCH_BYTES:
            pf = Prefetch(source_path=path)
            pf.source_size = size
            pf.failed_stage = Stage.READ.value
            pf.problems.append(Problem(
                Stage.READ,
                f"file reported {size:,} bytes but holds more than the "
                f"{limits.MAX_PREFETCH_BYTES:,} byte ceiling; not read", fatal=True))
            _stamp_source(pf, path, st)
            return pf
    # MemoryError as well as OSError: the ceiling above makes it unlikely, but "every input
    # produces a row" is not a rule that may fail on the one machine with less memory than the
    # file in front of it.
    except (OSError, MemoryError) as exc:
        pf = Prefetch(source_path=path)
        pf.failed_stage = Stage.READ.value
        pf.problems.append(Problem(Stage.READ, str(exc) or type(exc).__name__, fatal=True))
        return pf
    pf = parse(data, source_path=path, prefer_decompressor=prefer_decompressor)
    _stamp_source(pf, path, st)
    return pf


def _stamp_source(pf: Prefetch, path: str, st=None) -> None:
    """Attach the .pf's own filesystem timestamps.

    Creation time is only set where the OS actually reports a birth time. `st_ctime` is inode
    *change* time on Unix, not creation, and presenting it as creation would silently corrupt
    the "approximate first run" estimate that is derived from this field.
    """
    import datetime
    import os

    from . import winpath

    # The caller passes the stat it took BEFORE opening the file. Reading a file updates its
    # access time, and stat-ing afterwards reported the tool's OWN read as the evidence's last
    # access - the export was not even byte-identical between two runs a second apart, because
    # SourceAccessed advanced each time (AUDIT BUG 109). A forensic tool must not report a
    # timestamp it caused.
    if st is None:
        try:
            st = os.stat(winpath.long_path(path))
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
