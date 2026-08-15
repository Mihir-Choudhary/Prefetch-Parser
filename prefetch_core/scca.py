"""The `.pf` parser. ONE parser driven by a version table, not four near-identical classes.

The reference implementation has a class per version. They drift: that is exactly how its
v30/31 file-metrics bug survived (the fix never got copied across). A table makes the
per-version differences visible in one place and impossible to apply inconsistently.

Everything non-obvious here is measured, not copied. See docs/prefetch-format.md.
"""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass

from . import container, winpath
from .errors import Bounds, PrefetchError, Problem, Stage
from .model import FileMetric, MftRef, PathSource, Prefetch, Volume

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
HEADER_SIZE = 84
NAME_FIELD_CHARS = 29          # the header name field truncates here
RUNTIME_SLOTS_MODERN = 8


@dataclass(frozen=True)
class Layout:
    """Per-version geometry. `fileinfo` of None means the section is self-describing."""

    fileinfo: int | None
    metric: int
    chain: int
    volume: int
    runtime_slots: int
    runtime_offset: int          # from the start of the file-information section
    runcount_offset: int | None  # None -> derive as (section end - 96)
    dir_count_offset: int | None # None -> not stored (v17)


LAYOUT: dict[int, Layout] = {
    17: Layout(fileinfo=68,  metric=20, chain=12, volume=40,
               runtime_slots=1, runtime_offset=36, runcount_offset=60, dir_count_offset=None),
    23: Layout(fileinfo=156, metric=32, chain=12, volume=104,
               runtime_slots=1, runtime_offset=44, runcount_offset=68, dir_count_offset=36),
    # 220, not the 224 the reference uses. Measured: metrics start at 304 on every v26 file.
    26: Layout(fileinfo=220, metric=32, chain=12, volume=104,
               runtime_slots=8, runtime_offset=44, runcount_offset=124, dir_count_offset=36),
    # Self-describing: 220 on 2015-era v30, 212 on modern v30/v31. RunCount is always 96 bytes
    # before the section end, which replaces the reference's "probe +120 else shift back 8".
    30: Layout(fileinfo=None, metric=32, chain=8, volume=96,
               runtime_slots=8, runtime_offset=44, runcount_offset=None, dir_count_offset=36),
    31: Layout(fileinfo=None, metric=32, chain=8, volume=96,
               runtime_slots=8, runtime_offset=44, runcount_offset=None, dir_count_offset=36),
}


def _filetime(raw: int) -> datetime.datetime | None:
    """FILETIME (100-ns ticks since 1601-01-01 UTC) -> datetime, truncating to microseconds.

    Integer division, deliberately. `raw / 10` produces a float, and FILETIME values are around
    1.3e17 - far past float64's 2^53 exact-integer limit - so the float path silently corrupts
    the low digits of every timestamp. It cost an off-by-one-microsecond discrepancy on 720
    fields before being caught.

    Python's datetime tops out at microsecond resolution, so the final 100-ns digit cannot be
    represented at all. It is preserved separately as raw ticks rather than discarded.
    """
    if raw <= 0:
        return None
    try:
        return FILETIME_EPOCH + datetime.timedelta(microseconds=raw // 10)
    except (OverflowError, OSError):
        return None


def _u32(b: Bounds, o: int, what: str) -> int:
    b.check(o, 4, what)
    return struct.unpack_from("<I", b.data, o)[0]


def _i32(b: Bounds, o: int, what: str) -> int:
    b.check(o, 4, what)
    return struct.unpack_from("<i", b.data, o)[0]


def _u16(b: Bounds, o: int, what: str) -> int:
    b.check(o, 2, what)
    return struct.unpack_from("<H", b.data, o)[0]


def _i64(b: Bounds, o: int, what: str) -> int:
    b.check(o, 8, what)
    return struct.unpack_from("<q", b.data, o)[0]


def _utf16(b: Bounds, o: int, nbytes: int, what: str) -> str:
    b.check(o, nbytes, what)
    return b.data[o:o + nbytes].decode("utf-16-le", errors="replace")


def _mft_ref(b: Bounds, o: int, what: str) -> MftRef | None:
    """6-byte entry number + 2-byte sequence number. All-zero means 'no reference'."""
    b.check(o, 8, what)
    raw = b.data[o:o + 8]
    if raw == b"\x00" * 8:
        return None
    entry = int.from_bytes(raw[:6], "little")
    sequence = struct.unpack_from("<H", raw, 6)[0]
    return MftRef(entry, sequence)


def parse(data: bytes, source_path: str = "", prefer_decompressor: str | None = None) -> Prefetch:
    """Parse one prefetch file. Never raises for a malformed file.

    On failure the record carries `failed_stage` plus everything parsed before that point, so a
    truncated or corrupt file still produces a usable row rather than vanishing.
    """
    pf = Prefetch(source_path=source_path)
    pf.is_op_file = winpath.basename(source_path).upper().startswith("OP-")

    try:
        body = container.load(data, prefer_decompressor)
    except PrefetchError as exc:
        pf.failed_stage = exc.stage.value
        pf.problems.append(Problem(exc.stage, exc.message, fatal=True))
        return pf

    b = Bounds(body)
    try:
        _parse_body(b, pf)
    except PrefetchError as exc:
        pf.failed_stage = exc.stage.value
        b.at(exc.stage).note(exc.message)
    pf.problems = b.problems
    return pf


def _parse_body(b: Bounds, pf: Prefetch) -> None:
    # --- signature ---------------------------------------------------------
    b.at(Stage.SIGNATURE)
    pf.version = _i32(b, 0, "version")
    b.check(4, 4, "signature")
    if b.data[4:8] != b"SCCA":
        raise PrefetchError(Stage.SIGNATURE, f"expected 'SCCA', got {b.data[4:8]!r}")
    layout = LAYOUT.get(pf.version)
    if layout is None:
        raise PrefetchError(Stage.SIGNATURE, f"unknown version {pf.version}")

    # --- header, 84 bytes at 0 ---------------------------------------------
    b.at(Stage.HEADER)
    pf.file_size = _i32(b, 0x0C, "file size")
    # The header states the length of the decompressed structure, and it equals the actual
    # decompressed byte count on all 690 corpus files. So the two are a free tamper check:
    # nothing is reported while they agree, and a disagreement is worth an analyst's attention
    # because it means the file was edited without the size field being corrected.
    if pf.file_size != len(b.data):
        b.note(f"header declares {pf.file_size:,} bytes but the file holds "
               f"{len(b.data):,} - the size field disagrees with the actual content")
    raw_name = _utf16(b, 0x10, 60, "executable name")
    if "\0" not in raw_name:
        b.note("executable name is not NUL-terminated within its 60-byte field")
    pf.executable_name = raw_name.split("\0")[0].strip()
    # Exactly 29 characters means the name hit the field limit and is truncated. This breaks
    # basename equality against the filename list, so the resolver needs to know.
    pf.name_truncated = len(pf.executable_name) == NAME_FIELD_CHARS
    pf.hash = "%08X" % _u32(b, 0x4C, "hash")

    # --- file information section at 84 ------------------------------------
    b.at(Stage.FILEINFO)
    fi = HEADER_SIZE
    metrics_offset = _i32(b, fi + 0, "metrics offset")
    metrics_count = _i32(b, fi + 4, "metrics count")
    chains_offset = _i32(b, fi + 8, "trace chains offset")
    pf.trace_chain_count = _i32(b, fi + 12, "trace chains count")
    names_offset = _i32(b, fi + 16, "filename strings offset")
    names_size = _i32(b, fi + 20, "filename strings size")
    vols_offset = _i32(b, fi + 24, "volumes offset")
    vol_count = _i32(b, fi + 28, "volume count")

    if layout.dir_count_offset is not None:
        pf.total_directory_count = _i32(b, fi + layout.dir_count_offset, "total directory count")

    slots = layout.runtime_slots
    for i in range(slots):
        ticks = _i64(b, fi + layout.runtime_offset + 8 * i, f"run time {i}")
        t = _filetime(ticks)
        if t is not None:
            pf.run_times.append(t)
            pf.run_times_ticks.append(ticks)

    if layout.runcount_offset is not None:
        pf.run_count = _i32(b, fi + layout.runcount_offset, "run count")
    else:
        # Self-describing section: metrics start immediately after it, and RunCount always sits
        # 96 bytes before its end. Derived rather than probed - see prefetch-format.md 3.0a.
        fileinfo_size = metrics_offset - HEADER_SIZE
        if fileinfo_size <= 96:
            raise PrefetchError(Stage.FILEINFO,
                                f"implausible file-information size {fileinfo_size}")
        pf.run_count = _i32(b, fi + fileinfo_size - 96, "run count")

    if pf.run_count < 0:
        b.note(f"negative run count {pf.run_count}")
    # Below the retention cap the two must agree; a mismatch means one of them is misread.
    if 0 <= pf.run_count <= slots and pf.run_count != len(pf.run_times):
        b.note(f"run count {pf.run_count} != {len(pf.run_times)} retained run times")

    # --- file metrics -------------------------------------------------------
    b.at(Stage.METRICS)
    v17 = pf.version == 17
    name_off_field, name_size_field = (8, 12) if v17 else (12, 16)
    metrics = []
    for i in range(max(metrics_count, 0)):
        o = metrics_offset + i * layout.metric
        metrics.append((
            _i32(b, o + name_off_field, f"metric {i} name offset"),
            _i32(b, o + name_size_field, f"metric {i} name size"),
            None if v17 else _mft_ref(b, o + 24, f"metric {i} MFT reference"),
        ))

    # --- trace chains -------------------------------------------------------
    # 12-byte entries on v17/23/26, 8 on v30/31. Nothing in the reference implementation reads
    # these, so they have simply been absent from prefetch output; "no data skipped" includes
    # them. Parsed defensively - a bad count here must not lose the rest of the record.
    b.at(Stage.TRACE_CHAINS)
    n_chains = max(pf.trace_chain_count, 0)
    if n_chains:
        # Slice the array out whole and decode lazily (see Prefetch.trace_chains). One bounds
        # check and one slice replaces ~1.3M per-entry calls across 100 files, and avoids
        # materialising up to 15,000 objects per file that almost nothing reads.
        available = max(0, (len(b.data) - chains_offset) // layout.chain)
        usable = min(n_chains, available)
        if usable < n_chains:
            b.note(f"trace chain array declares {n_chains} entries but only {usable} "
                   f"fit before end of file")
        if usable:
            span = usable * layout.chain
            b.check(chains_offset, span, "trace chain array")
            pf.trace_chain_raw = bytes(b.data[chains_offset:chains_offset + span])
            pf.trace_chain_entry_size = layout.chain

    # --- filename strings ---------------------------------------------------
    b.at(Stage.FILENAMES)
    b.check(names_offset, names_size, "filename string block")
    blob = b.data[names_offset:names_offset + names_size]
    pf.filenames = [s for s in blob.decode("utf-16-le", errors="replace").split("\0") if s]
    if metrics_count >= 0 and len(pf.filenames) != metrics_count:
        b.note(f"{len(pf.filenames)} filenames but {metrics_count} file metrics")

    # Pair each metric with its own name. name_offset is a BYTE offset from the block start;
    # name_size is a CHARACTER count excluding the NUL. Established empirically - the reference
    # throws this pairing away by splitting the whole blob on NULs.
    for i, (noff, nsize, ref) in enumerate(metrics):
        try:
            name = _utf16(b, names_offset + noff, nsize * 2, f"metric {i} filename")
        except PrefetchError:
            b.note(f"metric {i} filename offset {noff} is outside the string block")
            name = ""
        pf.metrics.append(FileMetric(i, name, noff, nsize, ref))

    # --- 5a: the undocumented trailing executable-path string ---------------
    b.at(Stage.EXEC_PATH)
    names_end = names_offset + names_size
    if vols_offset > names_end:
        b.check(names_end, vols_offset - names_end, "trailing exec-path string")
        tail = b.data[names_end:vols_offset].decode("utf-16-le", errors="replace").split("\0")[0]
        # Shorter than this is alignment padding, not a string. Pre-modern versions have only
        # 0-6 bytes of padding here and no field at all.
        stored = tail if len(tail) > 8 else None
    else:
        stored = None

    # --- volumes ------------------------------------------------------------
    b.at(Stage.VOLUMES)
    for j in range(max(vol_count, 0)):
        pf.volumes.append(_parse_volume(b, vols_offset + j * layout.volume, vols_offset, j))

    if pf.total_directory_count >= 0:
        total = sum(len(v.directories) for v in pf.volumes)
        if total != pf.total_directory_count:
            b.note(f"stored TotalDirectoryCount {pf.total_directory_count} != {total} parsed")

    _resolve_path(pf, stored)

    pf.deceptive_characters = any(
        winpath.has_deceptive_characters(t)
        for t in [pf.executable_name, pf.executable_path or "", pf.hosted_package or ""]
        + pf.filenames)


def _parse_volume(b: Bounds, vo: int, vols_offset: int, index: int) -> Volume:
    dev_offset = _i32(b, vo + 0, f"volume {index} device offset")
    dev_chars = _i32(b, vo + 4, f"volume {index} device name length")
    created_ticks = _i64(b, vo + 8, f"volume {index} creation time")
    created = _filetime(created_ticks)
    serial = "%08X" % _u32(b, vo + 16, f"volume {index} serial")
    refs_offset = _i32(b, vo + 20, f"volume {index} file-refs offset")
    refs_size = _i32(b, vo + 24, f"volume {index} file-refs size")
    dirs_offset = _i32(b, vo + 28, f"volume {index} dirs offset")
    dirs_count = _i32(b, vo + 32, f"volume {index} dirs count")

    device = _utf16(b, vols_offset + dev_offset, dev_chars * 2, f"volume {index} device name")

    refs: list[MftRef] = []
    ro = vols_offset + refs_offset
    num_refs = _u32(b, ro + 4, f"volume {index} reference count")
    p = ro + 8
    # Count ITERATIONS, not appended refs. Null (all-zero) slots are dropped from the output,
    # so bounding the loop by len(refs) would read one extra entry for every null skipped and
    # walk past the end of the declared array.
    for _ in range(max(num_refs, 0)):
        if p + 8 > ro + refs_size:
            b.note(f"volume {index}: reference array declares {num_refs} refs but only "
                   f"{(p - ro - 8) // 8} fit in {refs_size} bytes")
            break
        ref = _mft_ref(b, p, f"volume {index} file reference")
        if ref is not None:
            refs.append(ref)
        p += 8

    dirs: list[str] = []
    p = vols_offset + dirs_offset
    for _ in range(max(dirs_count, 0)):
        nchars = _u16(b, p, f"volume {index} directory length")
        p += 2
        dirs.append(_utf16(b, p, nchars * 2 + 2, f"volume {index} directory").rstrip("\0"))
        p += nchars * 2 + 2

    vol = Volume(device, serial, created, created_ticks, dirs, refs)
    vol.name_self_check = _check_volume_name(device, serial, created_ticks)
    return vol


def _check_volume_name(device: str, serial: str, created_ticks: int) -> bool | None:
    """`\\VOLUME{<creation FILETIME hex>-<serial hex>}` encodes both parsed fields.

    Free integrity check. Compares raw ticks, not datetimes, so it stays exact rather than
    depending on how the timestamp was truncated to microseconds.

    Returns None for `\\DEVICE\\HARDDISKVOLUMEn`, which encodes nothing - that is 'not
    applicable', never 'failed'. Collapsing the two would fire on most of the older corpus.
    """
    upper = device.upper()
    if not upper.startswith("\\VOLUME{") or "-" not in upper:
        return None
    try:
        inner = upper[len("\\VOLUME{"):].rstrip("}")
        ft_hex, serial_hex = inner.split("-", 1)
        return serial_hex.upper() == serial.upper() and int(ft_hex, 16) == created_ticks
    except (ValueError, TypeError):
        return None


def _resolve_path(pf: Prefetch, stored: str | None) -> None:
    """Decide `executable_path`, `path_source` and `hosted_package`.

    The 5a field is primary where it holds a path. Where it holds a Store/UWP identity that is
    NOT a second spelling of the path - for generic hosts it names the package being hosted -
    so the filename list is still consulted, and both columns populate.
    """
    if stored and not winpath.is_device_path(stored):
        pf.hosted_package = stored
        stored = None

    candidates = _candidates_from_filenames(pf)
    pf.path_candidates = candidates

    if stored:
        pf.executable_path = stored
        if candidates and not any(winpath.same_file(stored, c) for c in candidates):
            # Same executable name, different directory, within one execution. Observed on the
            # Edge updater as DOWNLOAD\{guid} -> INSTALL\{guid}: 5a is where the process
            # launched from, the filename list holds a path it occupied earlier. Report both;
            # the discrepancy is the finding.
            pf.path_source = PathSource.CONFLICT
            pf.executable_path_alt = candidates[0]
        else:
            pf.path_source = PathSource.STORED
        return

    if len(candidates) == 1:
        pf.executable_path = candidates[0]
        pf.path_source = PathSource.RESOLVED
    elif candidates:
        pf.path_source = PathSource.AMBIGUOUS
    else:
        pf.path_source = PathSource.UNRESOLVED


def _candidates_from_filenames(pf: Prefetch) -> list[str]:
    """Filename-list entries whose last component is the executable.

    Equality on the last COMPONENT - not the reference's `EndsWith`, which is a substring test
    and matches `NOTNOTEPAD.EXE` for `NOTEPAD.EXE`.
    """
    target = pf.executable_name.upper()
    if not target:
        return []
    hits = [f for f in pf.filenames if winpath.basename(f).upper() == target]
    if hits or not pf.name_truncated:
        return hits

    # A 29-character name is truncated, so equality can never match it. Prefix-match, then keep
    # only the SHORTEST completion: a bare prefix also catches the executable's satellites
    # (FOO.EXE.CONFIG, FOO.EXE.MUI, FOO.APPDOMAIN.DLL), which are not candidates for what ran.
    hits = [f for f in pf.filenames if winpath.basename(f).upper().startswith(target)]
    if len(hits) > 1:
        shortest = min(len(winpath.basename(h)) for h in hits)
        hits = [h for h in hits if len(winpath.basename(h)) == shortest]
    return hits
