"""NTFS alternate data stream enumeration and prefetch recovery.

Why this exists: an executable launched from an alternate data stream gets a prefetch file
that **itself lives in an alternate data stream**. The carrier's primary stream is typically
0 bytes, so a directory listing shows an empty text file and every prefetch tool that globs
`*.pf` sees nothing at all.

Three things this does that PECmd's `--ads` does not:

  * scans **every file regardless of extension**, and directories too - NTFS directory objects
    carry streams, and both of PECmd's enumeration paths are files-only;
  * detects prefetch by **content**, not by the stream being named `*.pf` - name-based
    detection misses the entire point of hiding it;
  * **models the timestamp problem instead of repairing it** - see below.

**The timestamp problem, stated plainly.** A stream has no timestamps of its own. NTFS keeps
`$STANDARD_INFORMATION` per *file*, not per *stream*, so anything you read for an ADS-hosted
prefetch is the **carrier's** time, not the prefetch's. PECmd papers over this: when the values
come back as year 1601 it re-stats the carrier and presents the result in the ordinary
`SourceCreated/Modified/Accessed` columns, so the reader cannot tell whose timestamps they are.

That matters beyond tidiness. The "approximate first run" estimate is derived from
`SourceCreated`; fed a carrier's creation time it produces a confident-looking timestamp for an
execution that has nothing to do with it. So every record here carries `timestamp_source`, and
carrier times are reported under their own names.

Availability: `FindFirstStreamW`/`FindNextStreamW` on Windows. Off-Windows, `dissect.ntfs`
against a raw image if it is installed. Neither present means enumeration is unavailable and
says so - it never silently reports "no streams found", which is indistinguishable from
"scanned and clean".
"""

from __future__ import annotations

import ctypes
import datetime
import enum
import os
from dataclasses import dataclass, field

from . import winpath
from .errors import Stage
from .limits import MAX_STREAM_BYTES

# FindFirstStreamW info level; 0 == FindStreamInfoStandard.
_FIND_STREAM_INFO_STANDARD = 0
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_ERROR_HANDLE_EOF = 38
# NTFS names the unnamed primary stream "::$DATA"; everything else is an ADS.
_PRIMARY_STREAM = "::$DATA"




class TimestampSource(enum.Enum):
    """Whose timestamps a record's time fields actually describe.

    Three states, never two: 'unavailable' is not 'carrier'. Collapsing them would let a record
    with no timestamp information at all look like one with the carrier's.
    """

    STREAM = "stream"            # an ordinary file: the times are its own
    CARRIER = "carrier"          # ADS-hosted: the times belong to the host file
    UNAVAILABLE = "unavailable"  # nothing could be read


@dataclass
class Stream:
    """One `$DATA` attribute on a file or directory."""

    carrier_path: str
    name: str                    # ":name:$DATA", or "::$DATA" for the primary stream
    size: int

    @property
    def is_primary(self) -> bool:
        return self.name == _PRIMARY_STREAM

    @property
    def short_name(self) -> str:
        """`:foo:$DATA` -> `foo`. The primary stream has no short name."""
        parts = self.name.split(":")
        return parts[1] if len(parts) > 2 else ""

    @property
    def open_path(self) -> str:
        """Win32 opens an ADS as `file:streamname`."""
        return self.carrier_path if self.is_primary \
            else f"{self.carrier_path}:{self.short_name}"


@dataclass
class AdsFinding:
    """A prefetch file recovered from a stream, with its provenance."""

    stream: Stream
    data: bytes
    carrier_is_prefetch: bool          # was the host file itself a .pf?
    carrier_primary_size: int          # 0 is the normal shape for this technique
    outside_prefetch_folder: bool
    timestamp_source: TimestampSource = TimestampSource.CARRIER
    carrier_created: object = None
    carrier_modified: object = None
    carrier_accessed: object = None
    problems: list[str] = field(default_factory=list)


class AdsUnavailable(Exception):
    """Stream enumeration is not possible on this host.

    Raised rather than returning an empty list: "no streams found" and "cannot look for
    streams" must never be confused, because one of them is evidence and the other is not.
    """


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------
class _Win32Backend:
    """`FindFirstStreamW` / `FindNextStreamW` via ctypes."""

    class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * 296)]

    def __init__(self):
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        # Declare both argtypes and restype. Left to ctypes' defaults a HANDLE is marshalled as
        # a C int, which truncates on 64-bit Windows - the classic way this API "works on my
        # machine" and then fails on a real host.
        self.kernel32.FindFirstStreamW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
        self.kernel32.FindFirstStreamW.restype = ctypes.c_void_p
        self.kernel32.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel32.FindNextStreamW.restype = ctypes.c_bool
        self.kernel32.FindClose.argtypes = [ctypes.c_void_p]
        self.kernel32.FindClose.restype = ctypes.c_bool

    def list_streams(self, path: str) -> list[Stream]:
        data = self._WIN32_FIND_STREAM_DATA()
        handle = self.kernel32.FindFirstStreamW(
            ctypes.c_wchar_p(path), _FIND_STREAM_INFO_STANDARD, ctypes.byref(data), 0)
        if handle in (None, _INVALID_HANDLE_VALUE):
            err = ctypes.get_last_error()
            if err == _ERROR_HANDLE_EOF:
                return []
            raise OSError(err, f"FindFirstStreamW failed on {path!r}")
        streams = []
        try:
            while True:
                streams.append(Stream(path, data.cStreamName, data.StreamSize))
                if not self.kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                    break
        finally:
            self.kernel32.FindClose(handle)
        return streams

    @staticmethod
    def read_stream(stream: Stream) -> bytes:
        # Bounded read, one byte past the ceiling so the caller can tell "exactly at the limit"
        # from "over it". The pre-read check uses the size FindFirstStreamW reported, which is
        # metadata: it can be stale, and on a supplied image it can simply be false. An
        # unbounded read here would let a stream that under-declares its size pull the whole
        # file into memory regardless of the ceiling.
        with open(stream.open_path, "rb") as fh:
            return fh.read(MAX_STREAM_BYTES + 1)


class NtfsImageBackend:
    """`dissect.ntfs` over a raw NTFS image, for off-Windows analysis.

    Only reachable when a caller supplies an opened image, since there is nothing to enumerate
    on an ext4 copy of a Prefetch folder - which is exactly why the corpora here cannot
    exercise any of this.
    """

    def __init__(self, ntfs_filesystem):
        self.fs = ntfs_filesystem

    def list_streams(self, path: str) -> list[Stream]:
        entry = self.fs.get(path)
        streams = []
        for attr in entry.attributes.get("$DATA", []):
            name = f":{attr.name}:$DATA" if attr.name else _PRIMARY_STREAM
            streams.append(Stream(path, name, attr.size))
        return streams

    def read_stream(self, stream: Stream) -> bytes:
        # Bounded for the same reason as the Win32 backend, and more sharply: `attr.size` comes
        # from a raw image the analyst did not necessarily produce, so it is attacker-supplied.
        entry = self.fs.get(stream.carrier_path)
        return entry.open(stream.short_name or None).read(MAX_STREAM_BYTES + 1)


# Public alias: the image backend is the only way to use this off Windows, so it must be
# reachable. Construct it with an opened `dissect.ntfs` filesystem and pass it as `backend`.
def default_backend():
    """Return a usable backend, or None. Capability probe, never an OS-name check."""
    try:
        return _Win32Backend()
    except (AttributeError, OSError):
        return None


def backend_available() -> bool:
    return default_backend() is not None


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def looks_like_prefetch(head: bytes) -> bool:
    """Content-based detection. A hidden prefetch will not be named `.pf`."""
    return head[:3] == b"MAM" or head[4:8] == b"SCCA"


def scan_file(path: str, backend=None, prefetch_folder: str | None = None) -> list[AdsFinding]:
    """Enumerate `path`'s streams and return any that hold prefetch data.

    Raises `AdsUnavailable` when no backend exists, so a caller cannot mistake "could not look"
    for "looked and found nothing".
    """
    backend = backend or default_backend()
    if backend is None:
        raise AdsUnavailable(
            "no ADS backend: FindFirstStreamW is unavailable and no NTFS image was supplied")

    streams = backend.list_streams(path)
    primary = next((s for s in streams if s.is_primary), None)
    # A 0-byte primary stream is the *normal* shape for an ADS-hosted payload, not damage.
    # PECmd's --ads skips these outright, which is precisely backwards.
    primary_size = primary.size if primary else 0
    carrier_is_pf = path.lower().endswith(".pf")

    try:
        st = os.stat(path)
        utc = datetime.timezone.utc
        carrier_times = (
            winpath.creation_time(st),
            datetime.datetime.fromtimestamp(st.st_mtime, utc),
            datetime.datetime.fromtimestamp(st.st_atime, utc),
        )
    except OSError:
        carrier_times = (None, None, None)

    findings = []
    for stream in streams:
        if stream.is_primary:
            continue                       # the primary stream is not an ADS
        if stream.size > MAX_STREAM_BYTES:
            finding = _unreadable(stream, primary_size, carrier_is_pf, prefetch_folder,
                                  carrier_times,
                                  f"stream is {stream.size:,} bytes, above the "
                                  f"{MAX_STREAM_BYTES:,} byte ceiling; not read")
            findings.append(finding)
            continue
        try:
            data = backend.read_stream(stream)
        except OSError as exc:
            findings.append(_unreadable(stream, primary_size, carrier_is_pf,
                                        prefetch_folder, carrier_times, str(exc)))
            continue
        # The check above trusted the enumerated size. This one trusts nothing: a stream that
        # under-declares its size passes the first gate and is caught here, and the mismatch is
        # itself worth reporting - metadata disagreeing with content is a finding, not noise.
        if len(data) > MAX_STREAM_BYTES:
            findings.append(_unreadable(
                stream, primary_size, carrier_is_pf, prefetch_folder, carrier_times,
                f"stream declared {stream.size:,} bytes but read past the "
                f"{MAX_STREAM_BYTES:,} byte ceiling; not used"))
            continue
        if not looks_like_prefetch(data[:8]):
            continue
        finding = AdsFinding(
            stream=stream,
            data=data,
            carrier_is_prefetch=carrier_is_pf,
            carrier_primary_size=primary_size,
            outside_prefetch_folder=_is_outside(path, prefetch_folder),
            timestamp_source=TimestampSource.CARRIER,
            carrier_created=carrier_times[0],
            carrier_modified=carrier_times[1],
            carrier_accessed=carrier_times[2],
        )
        # Stated on every record, not inferred by the reader. The whole point of modelling this
        # rather than repairing it is that nobody should have to know the convention.
        finding.problems.append(
            "timestamps below belong to the CARRIER file, not to this stream - NTFS keeps "
            "$STANDARD_INFORMATION per file, not per stream, so no creation time exists for "
            "the prefetch itself and first-run estimates are not available")
        if primary_size == 0:
            finding.problems.append(
                "carrier's primary stream is 0 bytes - the expected shape for an ADS-hosted "
                "payload, not corruption")
        if not carrier_is_pf:
            finding.problems.append(
                f"carrier is not a .pf file ({os.path.basename(path)}) - prefetch hidden on an "
                "unrelated carrier")
        findings.append(finding)
    return findings


def _unreadable(stream, primary_size, carrier_is_pf, folder, times, message):
    finding = AdsFinding(stream=stream, data=b"", carrier_is_prefetch=carrier_is_pf,
                         carrier_primary_size=primary_size,
                         outside_prefetch_folder=_is_outside(stream.carrier_path, folder),
                         timestamp_source=TimestampSource.UNAVAILABLE,
                         carrier_created=times[0], carrier_modified=times[1],
                         carrier_accessed=times[2])
    finding.problems.append(f"stream could not be read: {message}")
    return finding


def _is_outside(path: str, prefetch_folder: str | None) -> bool:
    """A prefetch file recovered from outside \\Windows\\Prefetch is itself a finding."""
    if prefetch_folder:
        try:
            return os.path.commonpath([os.path.abspath(path),
                                       os.path.abspath(prefetch_folder)]) \
                != os.path.abspath(prefetch_folder)
        except ValueError:                 # different drives on Windows
            return True
    return "\\prefetch" not in path.lower().replace("/", "\\")


def scan_tree(root: str, backend=None, include_directories: bool = True) -> list[AdsFinding]:
    """Walk `root` looking for prefetch in any stream on any file - or directory.

    Every file is examined regardless of extension, because a hidden prefetch will not be
    named like one. Directories are examined too: NTFS directory objects carry streams and
    both of PECmd's enumeration paths are files-only, so it cannot see them at all.

    Raises if `root` cannot be walked. `os.walk` yields nothing for a missing path or a file,
    so without this a typo reported "scanned, no prefetch in any stream" - the same answer as a
    genuinely clean folder. That is the failure this module exists to prevent, and it matters
    more here than anywhere else in the tool: this is the search for deliberately hidden
    evidence, so a false clean is the worst possible result.
    """
    backend = backend or default_backend()
    if backend is None:
        raise AdsUnavailable(
            "no ADS backend: FindFirstStreamW is unavailable and no NTFS image was supplied")
    if not os.path.exists(root):
        raise FileNotFoundError(f"no such path: {root}")
    if not os.path.isdir(root):
        raise NotADirectoryError(f"not a directory: {root}")

    findings = []
    for dirpath, _dirnames, filenames in os.walk(root):
        # os.walk yields every directory as `dirpath` exactly once, so scanning `dirpath`
        # covers the whole tree. Also scanning `dirnames` would revisit every subdirectory a
        # second time - once by name from its parent, once as itself - and report every
        # directory-hosted finding twice.
        targets = [dirpath] if include_directories else []
        targets += [os.path.join(dirpath, n) for n in filenames]
        for target in targets:
            try:
                findings.extend(scan_file(target, backend, prefetch_folder=root))
            except (OSError, AdsUnavailable):
                continue                   # unreadable entry; keep walking
    return findings


def parse_findings(findings, prefer_decompressor=None):
    """Parse each finding's bytes into a `Prefetch`, carrying the ADS provenance onto it."""
    from . import scca

    records = []
    for finding in findings:
        pf = scca.parse(finding.data, source_path=finding.stream.open_path,
                        prefer_decompressor=prefer_decompressor)
        pf.from_ads = True
        pf.carrier_path = finding.stream.carrier_path
        pf.stream_name = finding.stream.short_name
        pf.stream_size = finding.stream.size
        pf.timestamp_source = finding.timestamp_source.value
        pf.carrier_primary_size = finding.carrier_primary_size
        pf.carrier_is_prefetch = finding.carrier_is_prefetch
        pf.outside_prefetch_folder = finding.outside_prefetch_folder
        # Carrier times go in their own fields. Deliberately NOT source_created: that field
        # feeds the first-run estimate, and a carrier's creation time would produce a
        # confident-looking timestamp for an execution it has nothing to do with.
        pf.carrier_created = finding.carrier_created
        pf.carrier_modified = finding.carrier_modified
        pf.carrier_accessed = finding.carrier_accessed
        pf.source_created = None
        from .errors import Problem
        for message in finding.problems:
            pf.problems.append(Problem(Stage.READ, message))
        records.append(pf)
    return records
