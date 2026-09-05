"""Windows SuperFetch databases - `Ag*.db`, `*.7db`, `*.ebd`.

The Prefetch folder holds more than prefetch. Alongside the `.pf` files sits SuperFetch's own
record of **what the system read and when it read it**: tens of thousands of file paths per
volume, each carrying the volume's serial number and creation time, and on some variants a
per-file timestamp. None of it is execution evidence - it is access and priority evidence - but
it names files no `.pf` mentions, including user-profile paths, browser cache, and temporary
files that have long since been deleted from disk.

This tool used to ignore the entire `Ag*.db` family: `identify()` matched `.7db` and `.ebd`
only, so a Windows Vista/7/8 Prefetch folder - where the databases are named `AgGlGlobalHistory.db`,
`AgAppLaunch.db`, `AgRobust.db` and so on - reported "no non-.pf artifacts found" while sitting
on megabytes of file-access history. And the `.7db`/`.ebd` files it did recognise were only
swept for strings, so their volume identity, per-file hashes and record counts never surfaced.

## The format, and how much of it we trust

Structure from libyal's `Windows SuperFetch (DB) format.asciidoc`, which is the only public
description. Two corrections were needed against real files, both recorded in
`docs/superfetch-format.md`:

  * the nine database parameters start at **+4** of the database header, not +12;
  * the path is written **immediately after the fixed-size entry**, with the sub-entry array
    *after* the path - the document lists the path last, which reads the other way round.

**Every path is checked against its own stored name hash** (libagdb's documented function).
That is what makes this parser safe on layouts nobody has documented: a wrong offset produces a
wrong hash, so a mis-parse announces itself instead of yielding plausible nonsense. Six real
files verify at 100% - **12,316 paths in total**, the largest being 10,118/10,118 in the
Windows 7 `AgGlGlobalHistory.db`.

It is also what lets an *undocumented* entry size be handled: `_probe_file_layout` tries the
layouts that are documented and accepts one only if its hashes verify. A wrong layout cannot
pass that test, so the probe either finds the real one or reports that it found none.

Three strategies are tried in order, and the record says which one produced the result:

  1. **structural** - walk the documented layout for this entry size. Accepted only if every
     entry's hash verifies and the walk ends inside the buffer.
  2. **scan** - for layouts whose sub-entry sizing is not documented, step forward and accept an
     offset only when the hash of the following path matches the hash stored there. A 32-bit
     hash over the exact path bytes is not something arbitrary data satisfies by accident.
  3. **sweep** - failing both, the UTF-16 string sweep the `.7db` parser has always used, so a
     format we cannot walk still yields its paths rather than nothing.

A database we cannot parse at all is reported as such. It is never reported as empty.
"""

from __future__ import annotations

import datetime
import re
import struct
from dataclasses import dataclass, field

from . import container
from .errors import PrefetchError
from .limits import MAX_DECOMPRESSED_BYTES
from .xpress import InvalidCompressedData, decompress as xpress_decompress

# Compressed wrappers. MAM is the same container `.pf` uses and is handled by container.py.
MEM0 = b"MEM0"          # Windows 7:    XPRESS Huffman, 64 KiB blocks
MEMB0 = b"MEM\xb0"      # Windows 8-11: XPRESS Huffman, block size varies by release
MEMO = b"MEMO"          # Windows Vista: LZNT1
# An uncompressed database starts with its own signature dword rather than a magic string.
UNCOMPRESSED_SIGNATURES = {0x03, 0x05, 0x0E, 0x0F}

# MEM\xb0 block sizes, largest first: Windows 11, Windows 10, Windows 8.x. The header does not
# say which, so the right one is the one that consumes the input exactly.
MEMB0_BLOCK_SIZES = (0x160000, 0x20000, 0x10000)

# Windows Vista/7 and Windows 8+ share entry sizes with different field offsets, so the layout
# is keyed by (entry size, database-header family) rather than size alone.
VISTA7 = "vista7"
WIN8 = "win8"

# Volume information entry: where to find the fields inside the fixed part.
# (number of files, creation FILETIME, serial, device-path character count)
VOLUME_LAYOUTS = {
    (56, VISTA7): (8, 24, 32, 44),
    (72, VISTA7): (16, 32, 40, 56),
    (72, WIN8): (8, 24, 32, 44),
    (96, WIN8): (16, 32, 40, 56),
}

# File information entry: (name-hash offset, hash width, path-character-count offset,
#                          sub-entry-count offset or None, flags offset or None,
#                          FILETIME offset or None)
FILE_LAYOUTS = {
    (36, VISTA7): (4, 4, 28, 8, 12, None),
    (52, VISTA7): (4, 4, 28, 8, 12, None),
    (72, VISTA7): (4, 4, 28, 8, 12, None),
    (64, VISTA7): (8, 8, 48, 16, 20, None),
    (88, VISTA7): (8, 8, 48, 16, 20, None),
    (48, WIN8): (4, 4, 8, None, None, None),
    (56, WIN8): (8, 8, 16, 32, None, None),
    (64, WIN8): (8, 8, 16, None, None, 56),
    (80, WIN8): (8, 8, 16, 76, None, None),
}

# Source information entry: (name-hash offset, hash width, number-of-entries offset).
# 32-bit entries put the hash at +4 and the count at +8; 64-bit at +8 and +16.
SOURCE_LAYOUTS = {
    60: (4, 4, 8), 68: (4, 4, 8), 100: (4, 4, 8),
    88: (8, 8, 16), 96: (8, 8, 16), 144: (8, 8, 16),
}

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_MAX_PATH_CHARS = 4096          # a path longer than this is a mis-parse, not a long name
_SCAN_WINDOW = 65536            # how far the scan looks for the next verifiable entry
_STRING_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass
class AgdbFile:
    """One file the database records, and whether its own hash vouches for the path."""

    path: str
    name_hash: int
    hash_ok: bool
    flags: int | None = None
    recorded: datetime.datetime | None = None
    recorded_ticks: int = 0


@dataclass
class AgdbVolume:
    """One volume, named the way prefetch names volumes, with its identity attached."""

    device: str
    serial: int
    created: datetime.datetime | None
    created_ticks: int
    declared_files: int
    files: list[AgdbFile] = field(default_factory=list)

    @property
    def serial_hex(self) -> str:
        return f"{self.serial:08X}"


@dataclass(slots=True)
class AgdbSource:
    """A source information entry.

    Only two fields are documented: a name hash and an entry count. libyal notes that
    `AgRobust.db`'s sources carry *process information including prefetch hashes*, which would
    tie a SuperFetch record to a `.pf` file directly - but **no sample with sources exists**:
    every database this tool has seen declares zero. Parsed, reported, and explicitly not
    interpreted.
    """

    index: int
    name_hash: int
    entries: int


@dataclass
class SuperFetchDb:
    """A parsed SuperFetch database. `method` says how much of it is structure vs. recovery."""

    signature: int = 0
    db_type: int = 0
    parameters: tuple[int, ...] = ()
    declared_size: int = 0
    actual_size: int = 0
    header_size: int = 0
    declared_volumes: int = 0
    declared_files: int = 0
    declared_sources: int = 0
    compression: str = "none"
    family: str = ""
    method: str = "none"
    volumes: list[AgdbVolume] = field(default_factory=list)
    sources: list[AgdbSource] = field(default_factory=list)
    swept_paths: list[str] = field(default_factory=list)
    # Paths visible in the raw bytes that no parsed record accounts for. Never dropped: a
    # structural parse that quietly covers less than the string sweep did would be a
    # regression disguised as an upgrade.
    unaccounted_paths: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def paths(self) -> list[str]:
        out = [f.path for v in self.volumes for f in v.files]
        return (out + list(self.unaccounted_paths)) if out else list(self.swept_paths)

    @property
    def hash_verified(self) -> int:
        return sum(1 for v in self.volumes for f in v.files if f.hash_ok)

    @property
    def file_count(self) -> int:
        return sum(len(v.files) for v in self.volumes)


def name_hash(raw: bytes) -> int:
    """libagdb's documented hash over the UTF-16LE path bytes, without the end-of-string.

    This is the parser's oracle. It is why a layout can be trusted on a file nobody has ever
    documented: a mis-read path or a mis-placed offset changes the hash, and the entry is then
    reported as unverified instead of being presented as a fact.
    """
    mask = 0xFFFFFFFF
    value = 0x4CB2F
    offset = 0
    size = len(raw)
    while offset + 8 < size:
        acc = raw[offset + 1]
        for k in (2, 3, 4, 5, 6):
            acc = (acc * 0x25 + raw[offset + k]) & mask
        acc = (acc * 0x25) & mask
        acc = (acc + 0x1A617D0D * raw[offset]) & mask
        value = (acc - (0x2FE8ED1F * value) + raw[offset + 7]) & mask
        offset += 8
    while offset < size:
        value = (value * 0x25 + raw[offset]) & mask
        offset += 1
    return value


def is_superfetch(name: str, head: bytes) -> bool:
    """Recognise by magic first, then by the naming SuperFetch actually uses.

    Magic first because the name is the weaker signal: `Ag*.db` is a convention, and a file
    copied out of a Prefetch folder can arrive under any name at all.
    """
    if head[:4] in (MEM0, MEMB0, MEMO):
        return True
    upper = name.upper()
    if upper.endswith(".7DB") or upper.endswith(".EBD"):
        return True
    if upper.endswith(".DB") or upper.endswith(".DB.TRX"):
        # Vista/7/8 names: AgGlGlobalHistory.db, AgRobust.db, AgCx_SC1.db, AgGlUAD_<SID>.db,
        # and the `.trx` transaction logs beside them.
        if upper.startswith("AG"):
            return True
        if len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] in UNCOMPRESSED_SIGNATURES:
            return True
    return False


def _lznt1(data: bytes, expected: int) -> bytes:
    """LZNT1, for Windows Vista's MEMO databases.

    Written from the MS-XCA description because no Vista sample could be found to test against
    - `docs/superfetch-format.md` records that, and the parser reports `compression=MEMO
    (untested)` so nothing downstream mistakes it for a verified path.
    """
    out = bytearray()
    pos = 0
    while pos + 2 <= len(data) and len(out) < expected:
        header = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if header == 0:
            break
        size = (header & 0x0FFF) + 1
        chunk = data[pos:pos + size]
        pos += size
        if not header & 0x8000:                     # stored, not compressed
            out += chunk
            continue
        start = len(out)
        cursor = 0
        while cursor < len(chunk) and len(out) - start < 4096:
            flags = chunk[cursor]
            cursor += 1
            for bit in range(8):
                if cursor >= len(chunk):
                    break
                if not flags & (1 << bit):
                    out.append(chunk[cursor])
                    cursor += 1
                    continue
                if cursor + 2 > len(chunk):
                    break
                pair = struct.unpack_from("<H", chunk, cursor)[0]
                cursor += 2
                # The split between offset bits and length bits moves as the chunk fills.
                # The boundary is on `written - 1 >= 16`, not `written >= 16`: at exactly 16
                # bytes written the shift is still 12. Getting this off by one mis-decodes any
                # chunk whose first back-reference lands on that boundary, which is precisely
                # the kind of error a format with no checksum would never announce.
                written = len(out) - start
                shift = 12
                iterator = written - 1
                while iterator >= 0x10:
                    shift -= 1
                    iterator >>= 1
                length = (pair & ((1 << shift) - 1)) + 3
                offset = (pair >> shift) + 1
                if offset > len(out) - start:
                    raise InvalidCompressedData("LZNT1 back-reference before the chunk start")
                for _ in range(length):
                    out.append(out[len(out) - offset])
    return bytes(out)


def _blocked(raw: bytes, header_size: int, block_size: int | None) -> bytes:
    """MEM0 / MEM\xb0: a declared total, then `[u32 compressed size][XPRESS Huffman data]`."""
    total = struct.unpack_from("<I", raw, 4)[0]
    if total > MAX_DECOMPRESSED_BYTES:
        raise InvalidCompressedData(
            f"declares {total:,} bytes, above the {MAX_DECOMPRESSED_BYTES:,} byte ceiling")
    sizes = (block_size,) if block_size else MEMB0_BLOCK_SIZES
    last_error = None
    for size in sizes:
        out = bytearray()
        pos = header_size
        try:
            while pos + 4 <= len(raw) and len(out) < total:
                compressed = struct.unpack_from("<I", raw, pos)[0]
                pos += 4
                if compressed == 0 or pos + compressed > len(raw):
                    raise InvalidCompressedData(
                        f"block at {pos - 4} declares {compressed} bytes, past the end")
                want = min(size, total - len(out))
                out += xpress_decompress(raw[pos:pos + compressed], want)
                pos += compressed
        except (InvalidCompressedData, ValueError, struct.error) as exc:
            last_error = exc
            continue
        if len(out) == total:
            return bytes(out)
        last_error = InvalidCompressedData(
            f"decompressed {len(out):,} bytes, header declares {total:,}")
    raise InvalidCompressedData(str(last_error) if last_error else "no block size fits")


def decompress(raw: bytes) -> tuple[bytes, str]:
    """Return `(payload, compression name)`. Uncompressed input is returned unchanged."""
    if raw[:4] == MEM0:
        return _blocked(raw, 8, 0x10000), "MEM0"
    if raw[:4] == MEMB0:
        return _blocked(raw, 12, None), "MEM\\xb0"
    if raw[:4] == MEMO:
        total = struct.unpack_from("<I", raw, 4)[0]
        out = _lznt1(raw[8:], total)
        if len(out) != total:
            raise InvalidCompressedData(
                f"MEMO/LZNT1 produced {len(out):,} bytes, header declares {total:,}")
        return out, "MEMO (LZNT1, untested - no sample)"
    if container.is_container(raw):
        return container.load(raw), "MAM"
    return raw, "none"


def _filetime(raw: int) -> datetime.datetime | None:
    """Integer division only: FILETIME values exceed float64's exact-integer range."""
    if raw <= 0:
        return None
    try:
        return _EPOCH + datetime.timedelta(microseconds=raw // 10)
    except (OverflowError, OSError):
        return None


def _align(offset: int, boundary: int) -> int:
    return (offset + boundary - 1) // boundary * boundary


def _family(db_type: int, header_size: int) -> str:
    """Vista/7 and Win8+ reuse entry sizes with different offsets; the type separates them."""
    return WIN8 if db_type >= 15 else VISTA7


def _read_file_entry(data: bytes, offset: int, entry_size: int, layout) -> AgdbFile | None:
    hash_off, hash_width, chars_off, _sub_off, flags_off, time_off = layout
    if offset + entry_size + 2 > len(data):
        return None
    raw_chars = struct.unpack_from("<I", data, offset + chars_off)[0]
    chars = raw_chars >> 2                      # the low 2 bits are undocumented
    if not 1 <= chars <= _MAX_PATH_CHARS:
        return None
    start = offset + entry_size
    if start + chars * 2 > len(data):
        return None
    path_bytes = data[start:start + chars * 2]
    fmt = "<Q" if hash_width == 8 else "<I"
    stored = struct.unpack_from(fmt, data, offset + hash_off)[0]
    ok = name_hash(path_bytes) == (stored & 0xFFFFFFFF)
    flags = struct.unpack_from("<I", data, offset + flags_off)[0] if flags_off is not None else None
    ticks = struct.unpack_from("<Q", data, offset + time_off)[0] if time_off is not None else 0
    return AgdbFile(
        path=path_bytes.decode("utf-16-le", errors="replace"),
        name_hash=stored,
        hash_ok=ok,
        flags=flags,
        recorded=_filetime(ticks),
        recorded_ticks=ticks,
    )


def _walk_structural(data, db, volume_offset, vol_layout, file_layout):
    """The documented walk. Returns None the moment anything fails to verify."""
    vol_size, file_size = db.parameters[0], db.parameters[1]
    sub_size = db.parameters[3] or 8
    nfiles_off, created_off, serial_off, chars_off = vol_layout
    _, _, _, sub_off, _, _ = file_layout
    if sub_off is None:
        return None, 0                           # sizing unknown; the scan handles these
    volumes = []
    offset = volume_offset
    for _ in range(db.declared_volumes):
        offset = _align(offset, 8)
        if offset + vol_size > len(data):
            return None, 0
        declared, = struct.unpack_from("<I", data, offset + nfiles_off)
        created, = struct.unpack_from("<Q", data, offset + created_off)
        serial, = struct.unpack_from("<I", data, offset + serial_off)
        name_chars, = struct.unpack_from("<H", data, offset + chars_off)
        if offset + vol_size + name_chars * 2 > len(data) or declared > 10_000_000:
            return None, 0
        device = data[offset + vol_size:offset + vol_size + name_chars * 2].decode(
            "utf-16-le", errors="replace")
        volume = AgdbVolume(device=device, serial=serial, created=_filetime(created),
                            created_ticks=created, declared_files=declared)
        offset = _align(offset + vol_size + (name_chars + 1) * 2, 8)
        for _ in range(declared):
            entry = _read_file_entry(data, offset, file_size, file_layout)
            if entry is None or not entry.hash_ok:
                return None, 0
            volume.files.append(entry)
            count, = struct.unpack_from("<I", data, offset + sub_off)
            if count > 1_000_000:
                return None, 0
            chars = struct.unpack_from("<I", data, offset + file_layout[2])[0] >> 2
            offset = _align(offset + file_size + count * sub_size + (chars + 1) * 2, 8)
        volumes.append(volume)
    return volumes, offset


def _scan(data, start, file_size, file_layout, limit) -> tuple[list[AgdbFile], int]:
    """Step forward accepting only offsets whose stored hash matches the path that follows.

    Used where the sub-entry array between records is not documented. The acceptance test is
    the file's own hash over its own path bytes, so this recovers records rather than guessing
    at them: an offset that does not verify is simply not reported.
    """
    found: list[AgdbFile] = []
    offset = start
    while offset + file_size < len(data) and len(found) < limit:
        stop = min(len(data) - file_size, offset + _SCAN_WINDOW)
        hit = None
        for candidate in range(offset, stop, 4):
            entry = _read_file_entry(data, candidate, file_size, file_layout)
            if entry is not None and entry.hash_ok:
                hit = (candidate, entry)
                break
        if hit is None:
            break
        candidate, entry = hit
        found.append(entry)
        chars = len(entry.path)
        offset = _align(candidate + file_size + (chars + 1) * 2, 4)
    return found, offset


def _read_sources(data, db, offset) -> None:
    """Read the source information entries, when a database declares any.

    Two documented fields, a name hash and an entry count, and nothing to verify them against -
    unlike file entries, a source carries no path for its hash to be checked over. So this
    reads what the format describes, stops the moment an entry would run past the buffer, and
    says how many it got. **No database seen by this tool declares a source**, so this path has
    only ever run against a synthetic file built to the documented layout.
    """
    if db.declared_sources <= 0:
        return
    src_size = db.parameters[2]
    layout = SOURCE_LAYOUTS.get(src_size)
    if layout is None:
        db.problems.append(
            f"{db.declared_sources} source record(s) declared, but source entry size "
            f"{src_size} is not documented; not parsed")
        return
    hash_off, hash_width, count_off = layout
    fmt = "<Q" if hash_width == 8 else "<I"
    cursor = _align(offset, 8)
    for index in range(min(db.declared_sources, 100_000)):
        if cursor + src_size > len(data):
            db.problems.append(
                f"source records run past the end of the file: read {len(db.sources)} of "
                f"{db.declared_sources} declared")
            return
        name_hash, = struct.unpack_from(fmt, data, cursor + hash_off)
        entries, = struct.unpack_from("<I", data, cursor + count_off)
        db.sources.append(AgdbSource(index=index, name_hash=name_hash, entries=entries))
        cursor += src_size


def _probe_file_layout(data, db, vol_layout, file_size):
    """Find a documented layout whose name hashes verify against this file's own bytes.

    The hash is what makes this safe. A wrong layout reads a wrong path length at a wrong
    offset, and the 32-bit hash stored beside it will not match - so a probe either finds the
    real layout or finds nothing. It never guesses.
    """
    nfiles_off, _created_off, _serial_off, chars_off = vol_layout
    vol_size = db.parameters[0]
    offset = _align(db.header_size, 8)
    if offset + vol_size > len(data):
        return None
    declared, = struct.unpack_from("<I", data, offset + nfiles_off)
    name_chars, = struct.unpack_from("<H", data, offset + chars_off)
    if name_chars > 512 or offset + vol_size + name_chars * 2 > len(data):
        return None
    first = _align(offset + vol_size + (name_chars + 1) * 2, 8)
    wanted = min(max(declared, 1), 8)            # a handful is already decisive
    for layout in dict.fromkeys(FILE_LAYOUTS.values()):
        verified, _end = _scan(data, first, file_size, layout, wanted)
        if len(verified) == wanted:
            return layout
    return None


def _sweep(data: bytes) -> list[str]:
    """Last resort: runs of printable UTF-16, the same sweep the .7db parser always used."""
    strings = [m.group(0).decode("utf-16-le", errors="replace") for m in _STRING_RUN.finditer(data)]
    return sorted({s for s in strings if "\\" in s})


def _account_for_every_path(data: bytes, db: SuperFetchDb) -> None:
    """Confirm the structured parse covers everything the raw bytes show.

    The string sweep is a lower bound on what is in the file: if it can see a path that no
    parsed record accounts for, the walk missed a record. Rather than trust the walk, the
    difference is reported and the paths are kept - the whole point of parsing structurally is
    to gain volume ownership and hash verification, not to lose coverage.

    Volume device names are excluded: they are in the sweep because they contain a backslash,
    and they are not files. They are already reported as volume records.
    """
    parsed = {f.path for v in db.volumes for f in v.files}
    if not parsed:
        return
    devices = {v.device for v in db.volumes}
    missed = []
    for text in _sweep(data):
        if text in parsed or text in devices:
            continue
        # A record's path can appear inside a longer swept run when two strings sit adjacent.
        if any(text in path for path in parsed):
            continue
        missed.append(text)
    if missed:
        db.unaccounted_paths = sorted(set(missed))
        db.problems.append(
            f"{len(db.unaccounted_paths):,} path(s) appear in the file but belong to no parsed "
            f"record; reported separately rather than dropped")


def parse(raw: bytes) -> SuperFetchDb:
    """Parse a SuperFetch database from its on-disk bytes, compressed or not."""
    db = SuperFetchDb(actual_size=len(raw))
    try:
        data, how = decompress(raw)
    except (InvalidCompressedData, PrefetchError, ValueError, struct.error) as exc:
        # container.load raises PrefetchError, not InvalidCompressedData - a malformed MAM
        # header therefore escaped as an exception until the fuzz harness caught it. A
        # malformed artifact is a finding, never a crash.

        db.problems.append(f"decompression failed: {exc}")
        return db
    db.compression = how
    db.actual_size = len(data)

    if len(data) < 72:
        db.problems.append("too small to hold a database header")
        db.swept_paths = _sweep(data)
        db.method = "sweep" if db.swept_paths else "none"
        return db

    db.signature, db.declared_size, db.header_size = struct.unpack_from("<3I", data, 0)
    if db.declared_size != len(data):
        db.problems.append(
            f"header declares {db.declared_size:,} bytes, payload is {len(data):,}")
    header = 12
    db.db_type = struct.unpack_from("<I", data, header)[0]
    # The nine parameters sit at +4, not +12 as the reference document has it. Measured on
    # AgGlGlobalHistory.db (Windows 7), dynrespri.7db and ResPriStaticDb.ebd (Windows 11).
    db.parameters = struct.unpack_from("<9I", data, header + 4)
    db.declared_volumes, db.declared_files = struct.unpack_from("<2I", data, header + 40)
    db.declared_sources = struct.unpack_from("<I", data, header + 52)[0]
    db.family = _family(db.db_type, db.header_size)

    vol_size, file_size = db.parameters[0], db.parameters[1]
    vol_layout = VOLUME_LAYOUTS.get((vol_size, db.family))
    file_layout = FILE_LAYOUTS.get((file_size, db.family))
    if vol_layout is not None and file_layout is None:
        # An entry size nobody has documented for this family - `AgRobust.db`'s 112-byte
        # 64-bit entry is the known case. Rather than give up, try the layouts that ARE
        # documented and let the name hash decide: a layout that produces paths whose stored
        # hashes verify is the right layout, and one that does not cannot be mistaken for it.
        file_layout = _probe_file_layout(data, db, vol_layout, file_size)
        if file_layout is not None:
            db.problems.append(
                f"file entry size {file_size} is not documented for {db.family} databases; "
                f"a known layout was matched by verifying stored name hashes")
    if vol_layout is None or file_layout is None:
        db.problems.append(
            f"undocumented entry sizes (volume {vol_size}, file {file_size}, "
            f"database type {db.db_type}); recovering paths by string sweep only")
        db.swept_paths = _sweep(data)
        db.method = "sweep" if db.swept_paths else "none"
        return db

    volumes, after_volumes = _walk_structural(data, db, db.header_size, vol_layout, file_layout)
    if volumes is not None and sum(len(v.files) for v in volumes) == db.declared_files:
        db.volumes = volumes
        db.method = "structural"
        _read_sources(data, db, after_volumes)
        _account_for_every_path(data, db)
        return db

    # Structural walk did not hold. Read the volume records - they are simple and verified by
    # their own device name - then recover their files by hash-verified scan.
    offset = _align(db.header_size, 8)
    nfiles_off, created_off, serial_off, chars_off = vol_layout
    recovered = 0
    for _ in range(min(db.declared_volumes, 64)):
        if offset + vol_size > len(data):
            break
        declared, = struct.unpack_from("<I", data, offset + nfiles_off)
        created, = struct.unpack_from("<Q", data, offset + created_off)
        serial, = struct.unpack_from("<I", data, offset + serial_off)
        name_chars, = struct.unpack_from("<H", data, offset + chars_off)
        if name_chars > 512 or offset + vol_size + name_chars * 2 > len(data):
            break
        device = data[offset + vol_size:offset + vol_size + name_chars * 2].decode(
            "utf-16-le", errors="replace")
        volume = AgdbVolume(device=device, serial=serial, created=_filetime(created),
                            created_ticks=created, declared_files=declared)
        first = _align(offset + vol_size + (name_chars + 1) * 2, 8)
        volume.files, offset = _scan(data, first, file_size, file_layout, declared)
        db.volumes.append(volume)
        recovered += len(volume.files)
        if not volume.files:
            break
    if recovered:
        db.method = "scan"
        _read_sources(data, db, offset)
        _account_for_every_path(data, db)
        if recovered != db.declared_files:
            db.problems.append(
                f"recovered {recovered:,} of {db.declared_files:,} declared file records; "
                f"the rest could not be verified against their own name hash")
        return db

    db.swept_paths = _sweep(data)
    db.method = "sweep" if db.swept_paths else "none"
    if not db.swept_paths:
        db.problems.append("no file records and no recoverable paths")
    return db
