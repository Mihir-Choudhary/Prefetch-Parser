"""Everything in the Prefetch folder that is not a `.pf`.

A Prefetch folder is not only prefetch. PECmd parses `.pf` and ignores the rest, so an analyst
who collected the folder gets no report on files that do carry evidence - `Layout.ini` in
particular is the only artifact there with a drive letter, and on Win11 it names the user
account and their installed software.

Everything here is **access/priority evidence, not execution evidence**, and carries no run
timestamps. Callers must present it distinctly from `.pf` rows so nobody reads a `Layout.ini`
path as "this program ran".

Byte-level analysis behind all of this: docs/prefetch-artifacts.md.
"""

from __future__ import annotations

import datetime
import os
import re
import stat
import struct
from dataclasses import dataclass, field

from . import agdb, container, winpath
from .limits import MAX_ARTIFACT_BYTES, MAX_DECOMPRESSED_BYTES
from .xpress import InvalidCompressedData, decompress_pfb

# `PfPre_*.mkd` is a fixed ring: 12-byte header + 16384 x 12-byte records = 196,620 bytes.
PFPRE_SLOTS = 16384
PFPRE_RECORD = 12
PFPRE_HEADER = 12
READYBOOT_MAGIC = b"PfB\xe3"


@dataclass
class Artifact:
    """One non-.pf file. `paths` is the evidence; `facts` is everything else, for display."""

    path: str
    kind: str
    size: int = 0
    modified: datetime.datetime | None = None
    paths: list[str] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    # ReadyBoot only: (path, read count, bytes read) per file, heaviest first.
    io_by_path: list[tuple[str, int, int]] = field(default_factory=list)
    # SuperFetch only: one dict per volume record - device, serial, creation time, file count.
    # Structured rather than swept, so correlate_volumes can use it as evidence rather than
    # re-deriving identity from strings.
    volumes: list[dict] = field(default_factory=list)

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


def identify(name: str, head: bytes) -> str | None:
    """Recognise by name and magic. Returns a kind, or None if it is not ours."""
    upper = name.upper()
    if upper.endswith(".PF"):
        return "prefetch"
    if upper == "LAYOUT.INI":
        return "layout"
    if upper.startswith("PFPRE_") and upper.endswith(".MKD"):
        return "pfpre"
    if agdb.is_superfetch(name, head):
        # `.7db`/`.ebd` are Windows 10/11 names; `Ag*.db` is the Vista/7/8 family this tool
        # used to walk straight past. Same format underneath.
        return "superfetch"
    if head[:4] == READYBOOT_MAGIC:
        return "readyboot"
    return None


def parse_layout(path: str, data: bytes) -> Artifact:
    """`Layout.ini` - UTF-16LE INI listing files the prefetcher wants laid out contiguously.

    The only artifact in the folder written with a drive letter. Win10 typically holds only the
    boot set (~90 lines); Win11 continues into user space (~4,300 lines) and exposes the account
    name and installed third-party software.
    """
    art = Artifact(path, "layout")
    text = data.decode("utf-16-le", errors="replace")
    if not text.lstrip("\ufeff").startswith("["):
        art.problems.append("does not begin with an INI section header")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # Drive-letter paths AND UNC paths. Matching only `X:\` silently discarded every
    # \\SERVER\SHARE\... entry - a file the prefetcher considered hot on a network share is
    # at least as interesting as a local one, and dropping it leaves no trace that it existed.
    art.paths = [ln for ln in lines
                 if re.match(r"^[A-Za-z]:\\", ln) or ln.startswith("\\\\")]
    unc = [p for p in art.paths if p.startswith("\\\\")]

    letters = sorted({p[0].upper() for p in art.paths if not p.startswith("\\\\")})
    users = sorted({m.group(1) for p in art.paths
                    if (m := re.match(r"^[A-Za-z]:\\USERS\\([^\\]+)", p, re.I))
                    and m.group(1).upper() not in ("PUBLIC", "DEFAULT", "ALL USERS")})
    system = sum(1 for p in art.paths
                 if re.match(r"^[A-Za-z]:\\(WINDOWS|PROGRAM FILES|PROGRAMDATA)", p, re.I))
    art.facts = {
        "entries": len(art.paths),
        "unc_paths": len(unc),
        "drive_letters": ",".join(letters),
        # From Layout.ini ALONE only the boot volume's letter is knowable, and only when
        # exactly one letter appears. Correlating these paths against ReadyBoot's per-device
        # path lists does establish a real device->letter mapping - see correlate_volumes().
        "boot_volume_letter": letters[0] if len(letters) == 1 else "",
        "user_accounts": ",".join(users),
        "system_paths": system,
        "user_paths": len(art.paths) - system,
        "version": next((ln.split("=", 1)[1] for ln in lines
                         if ln.upper().startswith("VERSION=")), ""),
    }
    return art


def parse_pfpre(path: str, data: bytes) -> Artifact:
    """`PfPre_<8hex>.mkd` - a fixed 16,384-slot event ring buffer.

    Header is version / identifier / cumulative event count. The count is events *ever written*,
    not slots used, so `count > 16384` means the ring wrapped and older events are gone.
    Semantics of the ~12 event types are unknown; the structure is proven.
    """
    art = Artifact(path, "pfpre")
    if len(data) < PFPRE_HEADER:
        art.problems.append("too small to hold a header")
        return art
    version, identifier, count = struct.unpack_from("<3I", data, 0)
    expected = PFPRE_HEADER + PFPRE_SLOTS * PFPRE_RECORD
    if len(data) != expected:
        art.problems.append(f"expected {expected} bytes for a {PFPRE_SLOTS}-slot ring, "
                            f"found {len(data)}")
    usable = (len(data) - PFPRE_HEADER) // PFPRE_RECORD
    populated = 0
    clock: list[int] = []
    for i in range(usable):
        off = PFPRE_HEADER + i * PFPRE_RECORD
        record = data[off:off + PFPRE_RECORD]
        if record == b"\x00" * PFPRE_RECORD:
            continue
        populated += 1
        clock.append(struct.unpack_from("<I", data, off + 8)[0])

    # The third field is a monotonic clock. Reading a ring that has wrapped linearly walks from
    # newer entries into older ones exactly once, so a single backwards step corroborates the
    # wrap independently of the header count - two signals rather than one, which matters
    # because the count is the only thing otherwise vouching for it.
    reversals = sum(1 for i in range(len(clock) - 1) if clock[i + 1] < clock[i])
    art.facts = {
        "format_version": version,
        "identifier": f"0x{identifier:08X}",
        "events_written": count,
        "slots": usable,
        "slots_populated": populated,
        "wrapped": count > usable,
        "events_lost": max(0, count - usable),
        "clock_first": clock[0] if clock else 0,
        "clock_last": clock[-1] if clock else 0,
        "clock_reversals": reversals,
    }
    if (count > usable) != (reversals > 0):
        art.problems.append(
            f"header says wrapped={count > usable} but the clock has {reversals} reversal(s); "
            "the two wrap signals disagree")
    return art


def parse_superfetch(path: str, data: bytes) -> Artifact:
    """SuperFetch databases: `Ag*.db` (Vista/7/8), `*.7db` and `*.ebd` (Windows 10/11).

    All one format under different names and compression wrappers - see `agdb.py`, which does
    the parsing and checks every recovered path against its own stored name hash.

    What this yields that the old string sweep did not: the volume each path belongs to, that
    volume's serial number and **creation time**, the record counts the database declares (so a
    short read is visible), and on Windows 10/11 static databases a per-file timestamp.

    Still not execution evidence. These are files the prefetcher decided were worth keeping
    warm; nothing here says a program ran.
    """
    art = Artifact(path, "superfetch")
    db = agdb.parse(data)
    art.problems.extend(db.problems)
    art.paths = sorted(set(db.paths))

    for volume in db.volumes:
        art.volumes.append({
            "device": volume.device,
            "serial": volume.serial_hex,
            "created": volume.created,
            "created_ticks": volume.created_ticks,
            "files": len(volume.files),
            "declared_files": volume.declared_files,
        })

    # `volumes` stays a comma-joined string for the callers (and the correlation) that have
    # always read it; the structured records live in art.volumes alongside.
    volume_names = ",".join(v["device"] for v in art.volumes) or ",".join(
        sorted({s for s in db.swept_paths if s.upper().startswith("\\VOLUME{")}))
    art.facts.update({
        "compressed": db.compression != "none",
        "compression": db.compression,
        "format_version": db.signature,
        "db_type": db.db_type,
        "declared_size": db.declared_size,
        "size_matches": db.declared_size == db.actual_size,
        "header_size": db.header_size,
        "decompressed_size": db.actual_size,
        "entry_sizes": ",".join(str(x) for x in db.parameters[:3]),
        "parse_method": db.method,
        "volume_records": f"{len(db.volumes)} of {db.declared_volumes} declared",
        "file_records": f"{db.file_count:,} of {db.declared_files:,} declared",
        "name_hashes_verified": db.hash_verified,
        "paths_found": len(art.paths),
        "volumes": volume_names,
    })
    # `paths` is a de-duplicated set; `file_records` counts records. When they differ it is
    # because the same path appears on more than one volume - say so, so nobody reads the
    # smaller number as records having been lost.
    if db.file_count and db.file_count != len(art.paths):
        art.facts["duplicate_paths"] = (
            f"{db.file_count - len(art.paths)} path(s) recorded on more than one volume; "
            f"{db.file_count:,} records, {len(art.paths):,} distinct paths")

    if db.declared_sources or db.sources:
        # Documented to carry process information including prefetch hashes on AgRobust.db.
        # No database seen here declares any, so the count is reported and nothing is claimed.
        art.facts["source_records"] = (
            f"{len(db.sources)} of {db.declared_sources} declared "
            f"(fields undocumented beyond a hash and a count)")
    if db.method in ("sweep", "none"):
        # Never let a fallback read as a full parse: the count means something different.
        art.facts["file_records"] = f"not parsed structurally ({db.method})"
    timestamps = [f.recorded for v in db.volumes for f in v.files if f.recorded]
    if timestamps:
        art.facts["file_timestamps"] = (
            f"{len(timestamps):,} records carry a timestamp, "
            f"{min(timestamps):%Y-%m-%d %H:%M} to {max(timestamps):%Y-%m-%d %H:%M} UTC")
    return art


def parse_readyboot(path: str, data: bytes) -> Artifact:
    """ReadyBoot `Trace*.fx` / `rblayout.xin` - a `PfB\\xe3` chain of XPRESS Huffman chunks.

    The payload decodes to a boot file-access trace: the files the system touched while
    booting, in the same `\\Device\\HarddiskVolumeN\\` notation `.pf` uses, so the volume
    correlation applies unchanged. Each trace's mtime dates one boot.

    Caveat that must survive to the UI: like Layout.ini and SuperFetch, this is an *access*
    artifact, not an execution record, and individual entries carry no timestamps. The file's
    mtime dates the boot; it does not date any one access inside it.

    A decode failure is reported and the header facts are kept - recognising the file and
    dating the boot is worth something even when the payload cannot be read.
    """
    art = Artifact(path, "readyboot")
    if len(data) < 12 or data[:4] != READYBOOT_MAGIC:
        art.problems.append("missing PfB magic")
        return art
    _magic, declared, first_chunk_len = struct.unpack_from("<3I", data, 0)
    art.facts = {
        "declared_size": declared,
        # Not a record count: this is the compressed length of the first chunk. It was
        # mislabelled as a count until the chunk chain was decoded.
        "first_chunk_len": first_chunk_len,
        "compressed_size": len(data),
        "ratio": round(declared / len(data), 2) if len(data) else 0,
        "payload_decoded": False,
    }
    try:
        payload = decompress_pfb(data, max_output=MAX_DECOMPRESSED_BYTES)
    except (InvalidCompressedData, struct.error) as exc:
        art.problems.append(f"payload did not decode: {exc}")
        return art

    art.facts["payload_decoded"] = True
    art.facts["decompressed_size"] = len(payload)
    art.facts["inner_format"] = payload[:4].decode("latin-1") if len(payload) >= 4 else ""

    bounds = _name_table_bounds(payload)
    if bounds is None:
        art.problems.append("payload decoded but its inner format is not recognised; "
                            "no paths recovered")
        return art
    records, stopped_at, replaced = _read_table(payload, *bounds)
    art.facts["name_records"] = len(records)
    if not records:
        art.problems.append("name table located but held no readable records")
        return art
    # Both of these used to be invisible. An early stop means records were discarded, and the
    # counts still agree afterwards, so nothing downstream can notice on the analyst's behalf.
    if stopped_at < bounds[1]:
        art.problems.append(
            f"name table walk stopped {bounds[1] - stopped_at:,} bytes before its end; "
            "records after that point were not read")
    if replaced:
        art.problems.append(
            f"{replaced} name(s) contained characters that are not valid UTF-16 and were "
            "decoded lossily")

    art.paths, broken = _resolve_paths(records)
    art.facts["paths_found"] = len(art.paths)
    art.facts["broken_links"] = broken
    if broken:
        art.problems.append(f"{broken} of {len(records)} records have an unresolvable parent "
                            "link; those paths were dropped rather than guessed")

    # The I/O trace. Summarised rather than stored event by event: a single trace holds ~175,000
    # reads, and an analyst wants "what was read, how much, when" long before they want the
    # individual events. iter_io_events() is public for anyone who does.
    by_name: dict[int, list[int]] = {}
    events = bytes_read = 0
    first = last = None
    try:
        for when, size, _offset, name in iter_io_events(payload, bounds[0]):
            events += 1
            bytes_read += size
            # min/max, NOT first-seen/last-seen. The two sections are consecutive in the file
            # but CONCURRENT in time - section 2 starts before section 1 ends on every trace in
            # the corpus - so the last record read is not the latest event and the first is not
            # the earliest. Taking them in iteration order happens to be right on this corpus
            # and would silently produce a wrong (or negative) span elsewhere.
            first = when if first is None else min(first, when)
            last = when if last is None else max(last, when)
            slot = by_name.get(name)
            if slot is None:
                by_name[name] = [1, size]
            else:
                slot[0] += 1
                slot[1] += size
    except (InvalidCompressedData, struct.error) as exc:
        art.problems.append(f"I/O trace not read: {exc}")
        return art
    if not events:
        return art

    art.facts["io_events"] = events
    art.facts["io_bytes_read"] = bytes_read
    art.facts["io_files_touched"] = len(by_name)
    art.facts["io_first_tick"] = first
    art.facts["io_last_tick"] = last
    span = (last or 0) - (first or 0)
    art.facts["io_span_ticks"] = span
    # The unit is not stated in the file, but two independent constraints pin it at
    # microseconds. Read as us the five corpus traces span 35-81 s at 100-256 MB/s - a normal
    # boot on an SSD. Read as ms they would be 10-22 HOUR traces averaging 0.1 MB/s, which no
    # boot and no disk does. Derived, not read, so it is named as an inference.
    art.facts["io_seconds_assuming_us"] = round(span / 1_000_000, 1)
    art.io_by_path = sorted(
        ((_path_for(records, off), n, b) for off, (n, b) in by_name.items()),
        key=lambda row: row[2], reverse=True)
    # Reads the tracer could not tie to a file. These are not decode failures - they resolve
    # perfectly, to a marker name the tracer itself writes - and they dominate early boot,
    # before the filesystem is available. Counting unresolvable offsets instead would report 0
    # and tell an analyst nothing.
    #
    # Exact match, not endswith: the marker is a ROOT record, so its whole path is
    # "\FI_UNKNOWN". A suffix test also swallows a real file named MY_FI_UNKNOWN, or any file
    # called FI_UNKNOWN sitting on a device, and inflates the unattributed count with reads
    # that were in fact attributed.
    art.facts["io_unattributed"] = sum(
        n for path, n, _b in art.io_by_path if path == _UNATTRIBUTED)
    return art


def _path_for(records: dict[int, tuple[str, int]], offset: int) -> str:
    """Whole path for one name-table offset, or a marker when the link cannot be followed."""
    parts: list[str] = []
    seen: set[int] = set()
    cursor = offset
    while cursor != _NO_PARENT and cursor in records and cursor not in seen \
            and len(parts) < _MAX_DEPTH:
        seen.add(cursor)
        name, parent = records[cursor]
        parts.append(name)
        cursor = parent
    if not parts:
        return f"<unresolved:{offset}>"
    return "\\" + "\\".join(reversed(parts))


# The decompressed payload ends (or, for rblayout, begins) with a **name table**: a directory
# tree stored as back-to-back records, each naming one path component and pointing at its
# parent.
#
#     u32  parent's offset within the table, or 0xFFFFFFFF for a root
#     u16  character count
#          that many UTF-16LE characters
#
# Walking it yields whole paths in `\Device\HarddiskVolumeN\...` notation - the same notation
# `.pf` uses, so the volume correlation applies unchanged.
_REC_HEADER = 6
_MAX_NAME_CHARS = 512
_NO_PARENT = 0xFFFFFFFF

# Two different inner formats travel inside the same PfB container, and they put the name table
# in opposite places - so the table cannot be found by one rule, or by scanning.
_XFCE_MAGIC = 0x45634678      # 'xFcE' - the boot traces, table LAST, size at offset 16
_RDLI_MAGIC = 0x52644C69      # 'RdLi' - rblayout.xin, table FIRST at offset 16, size at 8

# A path nested deeper than this is a corrupt or hostile link chain, not a real path.
_MAX_DEPTH = 128


def _name_table_bounds(payload: bytes) -> tuple[int, int] | None:
    """Locate the name table from the inner header. Returns (start, end) or None."""
    if len(payload) < 20:
        return None
    magic = struct.unpack_from("<I", payload, 0)[0]
    if magic == _XFCE_MAGIC:
        size = struct.unpack_from("<I", payload, 16)[0]
        if not 0 < size <= len(payload) - 20:
            return None
        return len(payload) - size, len(payload)
    if magic == _RDLI_MAGIC:
        size = struct.unpack_from("<I", payload, 8)[0]
        if not 0 < size <= len(payload) - 16:
            return None
        return 16, 16 + size
    return None


def _read_table(payload: bytes, start: int,
                end: int) -> tuple[dict[int, tuple[str, int]], int, int]:
    """Parse the name table. Returns (records, byte the walk stopped at, names substituted).

    The walk is bounded by `end`, so it always terminates; the checks below decide where the
    real table ends rather than whether the loop can run away.

    A name that will not decode is **not** treated as the end of the table. NTFS filenames are
    UTF-16 and Windows does not reject unpaired surrogates, so one legal-but-odd name - or one
    corrupt byte - used to stop the walk and silently discard every record after it. Losing
    thousands of paths that way is invisible: the record count and the path count still agree,
    so the result looks clean. Such a name is decoded lossily and counted instead, and the
    caller reports both the substitution and any early stop.
    """
    records: dict[int, tuple[str, int]] = {}
    replaced = 0
    pos = start
    while pos + _REC_HEADER <= end:
        parent, count = struct.unpack_from("<IH", payload, pos)
        if not 1 <= count <= _MAX_NAME_CHARS:
            break
        stop = pos + _REC_HEADER + count * 2
        if stop > end:
            break
        raw = payload[pos + _REC_HEADER:stop]
        try:
            name = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            # "replace", not "surrogatepass": a lone surrogate in a str raises when it is
            # printed or written out, which would move the failure to the reporting surface.
            name = raw.decode("utf-16-le", errors="replace")
            replaced += 1
        # Real components are printable and single-line; a control character means the walk has
        # left the table and is reading binary. This is the genuine end-of-table signal.
        if any(ch < " " for ch in name):
            break
        records[pos - start] = (name, parent)
        pos = stop
    return records, pos, replaced


# The `xFcE` payload in front of the name table is the I/O trace itself: one 40-byte record per
# read the system performed while booting.
#
#     u32  flags                       7 distinct values
#     u32  flags                       almost always 0
#     u64  byte offset of the read     within the file, or on the volume when unattributed
#     u32  name-table offset  <-- WHICH FILE. Resolves for 100% of records on every trace.
#     u32  unidentified                constant 402 across every record seen
#     u32  I/O size in bytes           4096, 65536, 1048576, ...
#     u32  timestamp                   monotonic tick since boot
#     u32  sequence within the block
#     u32  unidentified
#
# Records are grouped into blocks of 1024 followed by an 8-byte trailer. The trailer is NOT a
# usable live count - it reads 0 on a block holding 63 real records - so the authority for how
# many records exist is the pair of counts in the `xFcE` header at offsets 8 and 12. They are
# two consecutive sections laid out in the same blocks, and they sum exactly to the number of
# non-empty records (105,535 + 67,874 = 173,409 on Trace2.fx). A section that does not fill its
# last block leaves the remainder zeroed and the next section starts at the next block.
_IO_RECORD = 40
_IO_PER_BLOCK = 1024
_IO_BLOCK = _IO_PER_BLOCK * _IO_RECORD + 8
# The tracer's own marker for a read it could not attribute to a file. A root record, so its
# whole path is exactly this.
_UNATTRIBUTED = "\\FI_UNKNOWN"

# One trace holds ~175k events; a crafted header could claim far more. This bounds the work
# without ever firing on real evidence.
_MAX_IO_EVENTS = 4_000_000


def io_array_start(payload: bytes) -> int | None:
    """Byte offset of the first I/O record, derived from the header rather than assumed.

    The `xFcE` header ends with a length-prefixed `DMIO:ID:` + disk GUID: a u16 count at offset
    20, then that many bytes from offset 22. Hardcoding the resulting 46 would misalign the
    entire record array on any machine that writes a different-length string, and a misaligned
    array does not fail - it decodes into plausible nonsense.
    """
    if len(payload) < 22:
        return None
    start = 22 + struct.unpack_from("<H", payload, 20)[0]
    if start > len(payload):
        return None
    return start


def iter_io_events(payload: bytes, table_start: int):
    """Yield (timestamp, size, offset, name_offset) for each recorded read, in file order.

    Only the `xFcE` traces carry this; `iLdR` (rblayout) is a layout list with no I/O section.

    Raises InvalidCompressedData when the header describes an array that cannot be read, so the
    caller can report it. Yielding nothing on a malformed trace is indistinguishable from a
    trace that genuinely recorded nothing, and this parser must never make that ambiguous.
    """
    if len(payload) < 20 or struct.unpack_from("<I", payload, 0)[0] != _XFCE_MAGIC:
        return
    sections = struct.unpack_from("<2I", payload, 8)
    if sum(sections) > _MAX_IO_EVENTS:
        raise InvalidCompressedData(
            f"header claims {sum(sections):,} I/O events, above the "
            f"{_MAX_IO_EVENTS:,} ceiling")
    start = io_array_start(payload)
    if start is None:
        raise InvalidCompressedData("header is truncated before the I/O array")
    block = 0
    for count in sections:
        emitted = 0
        while emitted < count:
            base = start + block * _IO_BLOCK
            if base + _IO_BLOCK > table_start:
                raise InvalidCompressedData(
                    f"I/O array runs past the name table after {block} blocks; "
                    f"the header's event counts and the file do not agree")
            take = min(_IO_PER_BLOCK, count - emitted)
            for i in range(take):
                _f0, _f1, lo, hi, name, _c, size, when, _seq, _x = struct.unpack_from(
                    "<10I", payload, base + i * _IO_RECORD)
                yield when, size, (hi << 32) | lo, name
            emitted += take
            block += 1


def _resolve_paths(records: dict[int, tuple[str, int]]) -> tuple[list[str], int]:
    """Join records into whole paths. Returns (paths, count of unresolvable links).

    Cycle-safe: a crafted table can point a record at itself or form a loop, which would hang
    a naive parent walk. Depth is capped and visited offsets are tracked per path.
    """
    paths: list[str] = []
    broken = 0
    for offset in sorted(records):
        parts: list[str] = []
        seen: set[int] = set()
        cursor = offset
        ok = True
        while cursor != _NO_PARENT:
            if cursor in seen or len(parts) >= _MAX_DEPTH or cursor not in records:
                ok = cursor == _NO_PARENT
                break
            seen.add(cursor)
            name, parent = records[cursor]
            parts.append(name)
            cursor = parent
        if not ok:
            broken += 1
            continue
        paths.append("\\" + "\\".join(reversed(parts)))
    return paths, broken


PARSERS = {
    "layout": parse_layout,
    "pfpre": parse_pfpre,
    "superfetch": parse_superfetch,
    "readyboot": parse_readyboot,
}


def _file_kind(mode: int) -> str:
    """Name what a non-regular path is, so the report says why it was not opened."""
    for test, name in ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a FIFO"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISSOCK, "a socket"), (stat.S_ISLNK, "a symbolic link")):
        if test(mode):
            return name
    return "not a regular file"


def parse_artifact(path: str) -> Artifact | None:
    """Identify and parse one non-.pf file. Returns None if it is not a known artifact."""
    try:
        st = os.stat(winpath.long_path(path))
        # A FIFO, a device node or a socket in the collected folder: `st_size` lies about all
        # of them (/dev/zero reports 0), so the ceiling below passed and the unbounded read
        # that followed grew until the OS killed the process - no report, no exit code, the
        # analyst's session gone with it. Opening a FIFO does not even get that far: it blocks
        # forever waiting for a writer (AUDIT BUG 96). Reported without being opened.
        if not stat.S_ISREG(st.st_mode):
            # A `.pf` belongs to the prefetch path either way - the same rule as a readable one
            # below - and it reports the same refusal there. Claiming it here as well would put
            # one file in two reports.
            if os.path.basename(path).upper().endswith(".PF"):
                return None
            art = Artifact(path, "unreadable")
            art.problems.append(f"not a regular file ({_file_kind(st.st_mode)}); not opened")
            return art
        size = st.st_size
        with open(winpath.long_path(path), "rb") as fh:
            # Identify from the first bytes only. Deciding whether a file is too large must not
            # itself read it - an earlier version read one byte past the ceiling to detect
            # oversize and so allocated the whole ceiling to refuse it.
            head = fh.read(16)
            data = b""
            if size <= MAX_ARTIFACT_BYTES:
                fh.seek(0)
                # One byte past the ceiling, never `read()`: a file can hold more than the size
                # it reported, and an unbounded read of it is unbounded memory.
                data = fh.read(MAX_ARTIFACT_BYTES + 1)
                if len(data) > MAX_ARTIFACT_BYTES:
                    art = Artifact(path, identify(os.path.basename(path), head) or "unrecognised")
                    art.size = size
                    art.problems.append(
                        f"file reported {size:,} bytes but holds more than the "
                        f"{MAX_ARTIFACT_BYTES:,} byte ceiling; not parsed")
                    return art
    except OSError as exc:
        art = Artifact(path, "unreadable")
        art.problems.append(str(exc))
        return art

    kind = identify(os.path.basename(path), head)
    if kind == "prefetch":
        return None                      # parsed as a record, not as an artifact
    if kind is None:
        # A file in the Prefetch folder that we do not recognise is still a fact about the
        # folder. Dropping it silently is how a 2 MB SuperFetch database sat in a collection
        # while the tool printed "no non-.pf artifacts found" - the same false-clean this
        # codebase forbids everywhere else. Report it with its size, magic and mtime; that is
        # enough for an analyst to decide whether it matters.
        art = Artifact(path, "unrecognised")
        art.size = size
        art.facts["first_bytes"] = head[:8].hex(" ")
        art.problems.append("not a recognised Prefetch-folder artifact; reported, not parsed")
        try:
            art.modified = datetime.datetime.fromtimestamp(
                os.stat(path).st_mtime, datetime.timezone.utc)
        except OSError:
            pass
        return art
    if size > MAX_ARTIFACT_BYTES:
        art = Artifact(path, kind)
        art.size = size
        art.problems.append(
            f"file is {size:,} bytes, above the {MAX_ARTIFACT_BYTES:,} byte ceiling; "
            f"not parsed")
        return art
    parser = PARSERS.get(kind)
    if parser is None:
        # `identify` gaining a kind that no parser handles is a programming error, but it must
        # not reach the user as a KeyError from inside a folder scan: report the file as
        # recognised-and-unparsed, which is true, and keep the rest of the scan.
        art = Artifact(path, kind)
        art.size = size
        art.problems.append(f"recognised as {kind!r} but this build has no parser for it")
        return art
    art = parser(path, data)
    art.size = len(data)
    try:
        art.modified = datetime.datetime.fromtimestamp(
            os.stat(path).st_mtime, datetime.timezone.utc)
    except OSError:
        pass
    return art


def scan_folder(root: str, progress=None) -> list[Artifact]:
    """Walk a Prefetch folder for non-.pf artifacts.

    Recurses: ReadyBoot lives in a `ReadyBoot/` subdirectory, and its absence is normal (Win10
    has none), so neither recursion nor a missing subtree is an error.

    `progress(name)` is called before each file is parsed. A single ReadyBoot trace takes over
    a second - decompressing 8 MB and resolving ~200,000 I/O events - so a folder with five of
    them blocks for several seconds. A caller with a UI needs to be able to say so rather than
    appear to hang.

    Raises if `root` is not a readable directory. `os.walk` yields nothing for a missing or
    non-directory path, which would make "this folder holds no artifacts" - real evidence -
    indistinguishable from "this path was never scanned". The same distinction `AdsUnavailable`
    exists to preserve.
    """
    if not os.path.exists(root):
        raise FileNotFoundError(f"no such path: {root}")
    if not os.path.isdir(root):
        raise NotADirectoryError(f"not a directory: {root}")
    found = []
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            if progress is not None:
                progress(n)
            art = parse_artifact(os.path.join(dirpath, n))
            if art is not None:
                found.append(art)
    return found


# --- Cross-artifact correlation -------------------------------------------------------------
#
# `\Device\HarddiskVolumeN` is what prefetch records; `C:` is what an analyst needs. The mapping
# is not in any .pf file, and design notes here previously said it could not be recovered at all
# beyond guessing the boot volume from Layout.ini's single drive letter.
#
# Decoding ReadyBoot changed that. ReadyBoot names tens of thousands of files *per device*, and
# Layout.ini names thousands *per drive letter*. Where the two sets overlap, the device and the
# letter are the same volume. On the corpus the discrimination is absolute - 99.3% of Layout.ini's
# C: paths appear under HarddiskVolume3 and 0.0% under any other device - which is what makes
# this a match rather than a correlation.

# A letter is only claimed when one device explains most of its paths AND every other device
# explains essentially none. Anything less is reported as no answer: a wrong drive letter in a
# forensic report is worse than a missing one.
_VOL_MATCH_MIN = 0.50
_VOL_REJECT_MAX = 0.02
# A percentage alone is not evidence: one shared path is "100%". The real match in the corpus
# rests on 4,239 shared paths, so a floor this low cannot lose a genuine mapping while it
# refuses letters backed by a handful of coincidences.
_VOL_MIN_SHARED = 20
# ...and at least this many of those shared paths must be ones a stock Windows would NOT have.
#
# `\WINDOWS\SYSTEM32\NTOSKRNL.EXE` is on every Windows installation ever made, so a match built
# only from system paths says "both of these are Windows", not "both of these are THIS machine".
# Measured: pointing this at a folder assembled from two different computers - one machine's
# Layout.ini beside another's ReadyBoot traces - produced `C: = \Device\HarddiskVolume3` at
# **88.8%**, a confident mapping between a letter on one disk and a device on another. Triage
# collections get merged, folders get copied into one place, and nothing in the artifacts says
# which machine they came from (AUDIT BUG 105).
#
# The same argument the `$Mft` filter already makes, one level up: paths that exist on every
# installation identify no particular installation. On the real folder 1,402 of the 4,238 shared
# paths are machine-specific (Program Files, user profiles, installed software); across the two
# machines, **zero** of the 79 are. A floor of five separates those by three orders of magnitude
# while costing nothing on real evidence.
_VOL_MIN_MACHINE_SPECIFIC = 5

# What every Windows installation has at the top of its system drive. A path whose first
# component is one of these, with nothing under it, is not evidence about *which* machine.
_STOCK_WINDOWS_ROOTS = frozenset({
    "WINDOWS", "PROGRAM FILES", "PROGRAM FILES (X86)", "PROGRAMDATA", "USERS",
    "PERFLOGS", "$WINDOWS.~BT", "$WINREAGENT",
})
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# NTFS puts these on *every* volume, so they say nothing about which volume this is. Left in,
# a drive letter whose only known paths are `\$Mft` and `\System Volume Information` matches
# any device at 100% and gets confidently mapped to the wrong one.
_VOLUME_GENERIC = frozenset({
    "SYSTEM VOLUME INFORMATION", "$RECYCLE.BIN", "RECYCLER", "$EXTEND",
})


def _normalise(path: str) -> str:
    return path.upper().rstrip("\\")


def _machine_specific(path: str) -> bool:
    """True if this path is one a *stock* Windows installation would not have.

    A path under the Windows directory is excluded outright, and a bare top-level folder every
    Windows creates (Program Files, Users) carries no more information than its own existence. What is
    left - installed software, user profiles, anything the owner put there - is what makes one
    disk distinguishable from another.
    """
    parts = [part for part in path.upper().split("\\") if part]
    if not parts or parts[0] == "WINDOWS":
        return False
    return len(parts) > 1 or parts[0] not in _STOCK_WINDOWS_ROOTS


def _discriminating(path: str) -> bool:
    """False for paths that exist on every NTFS volume and so identify none of them."""
    # Upper-cased before the comparison. The trace and Layout.ini spell these folders however
    # Windows wrote them, and `\System Volume Information` in mixed case slipped straight past
    # a set held in upper case - defeating the one filter that stops a drive letter being
    # mapped onto a device by paths that identify no volume at all (AUDIT BUG 84).
    first = path.lstrip("\\").split("\\", 1)[0].upper()
    return bool(first) and not first.startswith("$") and first not in _VOLUME_GENERIC


def correlate_volumes(artifacts: list[Artifact], notes: list | None = None) -> list[dict]:
    """Tie together what each artifact knows about the same volume.

    Returns one row per volume the folder can identify. A row is either **stated** - a
    SuperFetch volume record that names \\Device\\HarddiskVolumeN outright - or **inferred**,
    a drive letter tied to a device by path overlap. `basis` says which, every time, and the
    measurement columns of a stated row are None rather than 0: nothing was measured to
    produce it, and a stated fact must not be dressed up as a 100% match (AUDIT BUG 87).
    """
    by_device: dict[str, set[str]] = {}
    # Devices are grouped case-insensitively. The input test accepts any casing, so a trace
    # that spelled one device two ways split it into two competitors - and the rule below that
    # rejects a contested device then suppressed the true mapping entirely (AUDIT BUG 85). The
    # first spelling seen is kept for display, so the row still reads as the trace wrote it.
    spelling: dict[str, str] = {}
    for art in artifacts:
        if art.kind != "readyboot":
            continue
        for path in art.paths:
            if not path.upper().startswith("\\DEVICE\\"):
                continue
            rest = path[len("\\Device\\"):]
            device, _, tail = rest.partition("\\")
            if tail and _discriminating(tail):
                key = device.upper()
                spelling.setdefault(key, device)
                by_device.setdefault(key, set()).add(_normalise("\\" + tail))

    by_letter: dict[str, set[str]] = {}
    for art in artifacts:
        if art.kind != "layout":
            continue
        for path in art.paths:
            if len(path) > 2 and path[1] == ":" and _discriminating(path[2:]):
                by_letter.setdefault(path[0].upper(), set()).add(_normalise(path[2:]))

    # Serial and creation time come from the SuperFetch \VOLUME{creation-serial} names, which
    # are the only place in the folder that carries a volume's creation time.
    volumes: list[tuple[str, datetime.datetime | None]] = []
    stated: list[dict] = []
    seen: set[tuple] = set()
    for art in artifacts:
        if art.kind != "superfetch":
            continue
        for record in art.volumes:
            # A SuperFetch volume record names the device itself. Where it does, the identity
            # needs no correlation at all - the database states which serial and creation time
            # belong to \Device\HarddiskVolumeN. That is stronger evidence than a path-overlap
            # match and is reported separately, as fact rather than inference.
            device = str(record.get("device", "")).upper()
            if device.startswith("\\DEVICE\\"):
                # A folder holds several SuperFetch databases and they describe the same
                # volumes, so the same record arrives more than once. Left duplicated, the two
                # copies cancelled each other out under the contested-device rule below and
                # the folder's strongest evidence vanished (AUDIT BUG 86).
                key = (device, record.get("serial"), record.get("created"))
                if key not in seen:
                    seen.add(key)
                    stated.append(record)
            # The ResPri* static databases describe no real volume: device "Volume Serial
            # Number : 1", serial 1, no creation time. Counting them as a volume made the
            # folder look like it held two, which suppressed the serial binding below - the
            # rule that refuses to guess when more than one volume is present.
            if not (device.startswith("\\DEVICE\\") or device.startswith("\\VOLUME{")):
                continue
            if record.get("serial") and record["serial"] != "00000000":
                volumes.append((record["serial"].upper(), record.get("created")))
        if art.volumes:
            continue
        for name in str(art.facts.get("volumes", "")).split(","):
            m = re.match(r"\\VOLUME\{([0-9a-fA-F]+)-([0-9a-fA-F]+)\}", name.strip())
            if not m:
                continue
            # Integer division: FILETIME ticks exceed float64's exact range, and dividing in
            # float silently corrupts the low digits of every timestamp.
            created = _FILETIME_EPOCH + datetime.timedelta(
                microseconds=int(m.group(1), 16) // 10)
            volumes.append((m.group(2).upper(), created))

    inferred: list[dict] = []
    for letter, letter_paths in sorted(by_letter.items()):
        if not letter_paths:
            continue
        scores = {dev: len(letter_paths & paths) / len(letter_paths)
                  for dev, paths in by_device.items()}
        if not scores:
            continue
        best = max(scores, key=scores.get)
        others = [s for dev, s in scores.items() if dev != best]
        shared_paths = letter_paths & by_device[best]
        shared = len(shared_paths)
        if scores[best] < _VOL_MATCH_MIN or any(s > _VOL_REJECT_MAX for s in others):
            continue
        if shared < _VOL_MIN_SHARED:
            continue
        # A match built only from stock Windows paths says "both of these are Windows", not
        # "both of these are this machine" - and a folder assembled from two computers is
        # exactly what that looks like (AUDIT BUG 105). Refused, and the refusal is reported:
        # the analyst must be able to tell "no evidence" from "evidence that proves nothing".
        specific = sum(1 for path in shared_paths if _machine_specific(path))
        if specific < _VOL_MIN_MACHINE_SPECIFIC:
            if notes is not None:
                notes.append(
                    f"{letter}: matched \\Device\\{spelling[best]} on {shared:,} shared "
                    f"path(s), but only {specific} of them are paths a stock Windows would not "
                    f"have. Every Windows installation shares its system files, so this cannot "
                    f"show the two artifacts describe the SAME machine - withheld.")
            continue
        inferred.append({
            "drive_letter": f"{letter}:",
            "device": f"\\Device\\{spelling[best]}",
            "device_key": best,
            "shared_paths": shared,
            "match": round(scores[best] * 100, 1),
            "next_best": round(max(others) * 100, 1) if others else 0.0,
            "basis": "ReadyBoot paths matched against Layout.ini (inferred)",
        })

    # One device cannot be two drive letters. When two letters both best-match the same device
    # the evidence cannot tell them apart - and with only one device present there is no
    # competing device for the rejection rule above to catch it, so every letter matches. Drop
    # the whole contested set rather than pick a winner. Only the inferred rows are counted
    # here: a stated record claims no letter, so it can never be the second claimant, and
    # counting it made evidence and inference annihilate each other (AUDIT BUG 86).
    claimed: dict[str, int] = {}
    for row in inferred:
        claimed[row["device_key"]] = claimed.get(row["device_key"], 0) + 1
    inferred = [row for row in inferred if claimed[row["device_key"]] == 1]

    # Where the database states the identity of a device an overlap match also found, the two
    # describe one volume: the letter stays inferred, the serial and creation time become
    # stated fact. Only when exactly one record names that device - two conflicting records
    # are reported as they are rather than resolved by guess.
    # Keyed on the bare device name, upper-cased: that is what by_device keys on. Keeping the
    # `\Device\` prefix here made every lookup miss, so the merge below never fired and the
    # stated record and the inferred letter stayed two rows describing one volume.
    records_for: dict[str, list[dict]] = {}
    for record in stated:
        name = str(record["device"]).upper()[len("\\DEVICE\\"):]
        records_for.setdefault(name, []).append(record)
    consumed: set[int] = set()
    for row in inferred:
        matches = records_for.get(row["device_key"], [])
        if len(matches) != 1:
            continue
        record = matches[0]
        row["volume_serial"] = record.get("serial", "")
        row["volume_created"] = record.get("created")
        row["basis"] = ("letter inferred from ReadyBoot paths matched against Layout.ini; "
                        "serial and creation time stated by the SuperFetch database")
        consumed.add(id(record))

    unclaimed = [record for record in stated if id(record) not in consumed]
    rows: list[dict] = []
    for record in unclaimed:
        rows.append({
            "drive_letter": "",
            "device": record["device"],
            # Nothing was measured: no letter was matched to this device. Writing 0 shared
            # paths and a 100% match printed a self-contradiction under a stated fact.
            "shared_paths": None,
            "match": None,
            "next_best": None,
            "volume_serial": record["serial"],
            "volume_created": record.get("created"),
            "basis": "SuperFetch volume record (stated in the database, not inferred)",
        })
    rows += inferred

    # Bind the serial only when there is exactly one volume AND exactly one mapped letter.
    # With one volume and two letters there is nothing to say which letter it belongs to, and
    # attaching it to both states as fact that C: and D: are the same volume - a claim that is
    # necessarily false and would go into a report unchallenged. A stated record left over
    # blocks the binding too: that record already claims the folder's one volume for a device
    # the letter did not match, so binding it to the letter would attach another device's
    # serial.
    if len(volumes) == 1 and len(inferred) == 1 and not unclaimed \
            and not inferred[0].get("volume_serial"):
        inferred[0]["volume_serial"] = volumes[0][0]
        inferred[0]["volume_created"] = volumes[0][1]
        # Said out loud in the row: the letter came from the path overlap, the serial did not.
        # It is attached because the folder describes exactly one volume, which is a second
        # and weaker inference, and a reader who is not told will read it as part of the match.
        inferred[0]["basis"] += ("; serial and creation time from the folder's only SuperFetch "
                                 "volume record, bound because it is the only one")
    for row in rows:
        row.pop("device_key", None)
    return rows


def describe_identities(rows: list[dict], notes: list | None = None) -> list[str]:
    """Render correlate_volumes() rows for a human.

    Shared by the CLI and the GUI. Both wrote their own copy of this, both printed a stated
    record as `` = \\DEVICE\\HARDDISKVOLUME2`` with an empty letter and "0 shared paths -
    100.0%", and both ended the block with "Derived by correlation, not read from any file."
    - which is the opposite of true for a record the database states outright (AUDIT BUG 88).
    """
    if not rows and not notes:
        return []
    lines = ["Volume identity (correlated across the folder's artifacts):"]
    for row in rows:
        if row["drive_letter"]:
            lines.append(f"    {row['drive_letter']} = {row['device']}")
            lines.append(f"        {row['shared_paths']:,} shared paths — {row['match']}% of "
                         f"{row['drive_letter']} paths, next best device {row['next_best']}%")
        else:
            lines.append(f"    {row['device']}   (no drive letter established)")
        if row.get("volume_serial"):
            created = row.get("volume_created")
            lines.append(f"        serial {row['volume_serial']}"
                         + (f", volume created {created:%Y-%m-%d %H:%M:%S} UTC"
                            if created else ""))
        lines.append(f"        basis: {row['basis']}")
    if any(row["drive_letter"] for row in rows):
        lines.append("    A drive letter is derived by correlation, not read from any file.")
        lines.append("    Devices with no matching evidence are omitted rather than guessed.")
    for note in notes or []:
        # A letter that was matched and then refused is worth more to an analyst than silence:
        # it says the folder holds evidence that looks like a mapping and is not one.
        lines.append("    NOT claimed - " + note)
    return lines
