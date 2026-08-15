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
import struct
from dataclasses import dataclass, field

from . import container
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
    if upper.endswith(".7DB") or upper.endswith(".EBD"):
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
    """`*.7db` (plain) and `*.ebd` (MAM-compressed) - one container once decompressed.

    Self-validating: the size field equals the decompressed length. Holds UTF-16 paths in
    prefetch's own `\\VOLUME{serial}` notation, so the serials correlate with .pf volume records.
    """
    art = Artifact(path, "superfetch")
    body = data
    if container.is_container(data):
        try:
            body = container.load(data)
            art.facts["compressed"] = True
        except Exception as exc:
            art.problems.append(f"decompression failed: {exc}")
            return art
    if len(body) < 32:
        art.problems.append("too small to hold a header")
        return art

    version, total_size, header_size, kind = struct.unpack_from("<4I", body, 0)
    record_size = struct.unpack_from("<I", body, 20)[0]
    if total_size != len(body):
        art.problems.append(f"size field {total_size} != actual {len(body)}")

    # Extract UTF-16LE strings from the raw bytes rather than decoding the whole buffer and
    # regexing the text: the buffer is mostly binary records, so a whole-buffer decode splices
    # unrelated bytes into apparent strings and a path-shaped regex then matches almost nothing
    # (or the wrong things). Scanning for runs of printable UTF-16 code units is what the
    # manual analysis did, and it finds the 559 paths in dynrespri.7db that the regex missed.
    strings = [m.group(0).decode("utf-16-le", errors="replace")
               for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", body)]
    art.paths = sorted({s for s in strings if "\\" in s})
    volumes = sorted({s for s in strings if s.upper().startswith("\\VOLUME{")})
    art.facts.update({
        "format_version": version,
        "declared_size": total_size,
        "size_matches": total_size == len(body),
        "header_size": header_size,
        "db_type": kind,
        "record_size": record_size,
        "decompressed_size": len(body),
        "paths_found": len(art.paths),
        "volumes": ",".join(volumes),
    })
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
    records = _read_table(payload, *bounds)
    art.facts["name_records"] = len(records)
    if not records:
        art.problems.append("name table located but held no readable records")
        return art

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


def _read_table(payload: bytes, start: int, end: int) -> dict[int, tuple[str, int]]:
    """Parse the name table into {offset within table: (name, parent offset)}."""
    records: dict[int, tuple[str, int]] = {}
    pos = start
    while pos + _REC_HEADER <= end:
        parent, count = struct.unpack_from("<IH", payload, pos)
        if not 1 <= count <= _MAX_NAME_CHARS:
            break
        stop = pos + _REC_HEADER + count * 2
        if stop > end:
            break
        try:
            name = payload[pos + _REC_HEADER:stop].decode("utf-16-le")
        except UnicodeDecodeError:
            break
        # Real components are printable and single-line; a control character means the walk has
        # left the table and is reading binary.
        if any(ch < " " for ch in name):
            break
        records[pos - start] = (name, parent)
        pos = stop
    return records


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


def parse_artifact(path: str) -> Artifact | None:
    """Identify and parse one non-.pf file. Returns None if it is not a known artifact."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            # Identify from the first bytes only. Deciding whether a file is too large must not
            # itself read it - an earlier version read one byte past the ceiling to detect
            # oversize and so allocated the whole ceiling to refuse it.
            head = fh.read(16)
            data = b""
            if size <= MAX_ARTIFACT_BYTES:
                fh.seek(0)
                data = fh.read()
    except OSError as exc:
        art = Artifact(path, "unreadable")
        art.problems.append(str(exc))
        return art

    kind = identify(os.path.basename(path), head)
    if kind in (None, "prefetch"):
        return None
    if size > MAX_ARTIFACT_BYTES:
        art = Artifact(path, kind)
        art.size = size
        art.problems.append(
            f"file is {size:,} bytes, above the {MAX_ARTIFACT_BYTES:,} byte ceiling; "
            f"not parsed")
        return art
    art = PARSERS[kind](path, data)
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
    """
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
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _normalise(path: str) -> str:
    return path.upper().rstrip("\\")


def correlate_volumes(artifacts: list[Artifact]) -> list[dict]:
    """Tie together what each artifact knows about the same volume.

    Returns one row per device for which a drive letter could be established, carrying the
    letter, the shared-path evidence, and - when the folder offers exactly one candidate - the
    volume serial and creation time. Everything here is **inferred from correlation**, so each
    row says what it was derived from.
    """
    by_device: dict[str, set[str]] = {}
    for art in artifacts:
        if art.kind != "readyboot":
            continue
        for path in art.paths:
            if not path.upper().startswith("\\DEVICE\\"):
                continue
            rest = path[len("\\Device\\"):]
            device, _, tail = rest.partition("\\")
            if tail:
                by_device.setdefault(device, set()).add(_normalise("\\" + tail))

    by_letter: dict[str, set[str]] = {}
    for art in artifacts:
        if art.kind != "layout":
            continue
        for path in art.paths:
            if len(path) > 2 and path[1] == ":":
                by_letter.setdefault(path[0].upper(), set()).add(_normalise(path[2:]))

    # Serial and creation time come from the SuperFetch \VOLUME{creation-serial} names, which
    # are the only place in the folder that carries a volume's creation time.
    volumes: list[tuple[str, datetime.datetime | None]] = []
    for art in artifacts:
        if art.kind != "superfetch":
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

    rows = []
    for letter, letter_paths in sorted(by_letter.items()):
        if not letter_paths:
            continue
        scores = {dev: len(letter_paths & paths) / len(letter_paths)
                  for dev, paths in by_device.items()}
        if not scores:
            continue
        best = max(scores, key=scores.get)
        others = [s for dev, s in scores.items() if dev != best]
        if scores[best] < _VOL_MATCH_MIN or any(s > _VOL_REJECT_MAX for s in others):
            continue
        rows.append({
            "drive_letter": f"{letter}:",
            "device": f"\\Device\\{best}",
            "shared_paths": len(letter_paths & by_device[best]),
            "match": round(scores[best] * 100, 1),
            "next_best": round(max(others) * 100, 1) if others else 0.0,
            "basis": "ReadyBoot paths matched against Layout.ini (inferred)",
        })

    # Bind the serial only when there is exactly one volume AND exactly one mapped letter.
    # With one volume and two letters there is nothing to say which letter it belongs to, and
    # attaching it to both states as fact that C: and D: are the same volume - a claim that is
    # necessarily false and would go into a report unchallenged.
    if len(volumes) == 1 and len(rows) == 1:
        rows[0]["volume_serial"] = volumes[0][0]
        rows[0]["volume_created"] = volumes[0][1]
    return rows
