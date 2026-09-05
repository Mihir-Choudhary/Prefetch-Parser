#!/usr/bin/env python3
"""The ReadyBoot `PfB` container: exact decode, and refusal to hang or over-read.

Two separate jobs here.

1. **Correctness on real files.** The decode is verified two independent ways, because either
   one alone can be fooled. The length check alone cannot catch a wrong intermediate chunk
   that happens to sum correctly, so every chunk start is also checked to land on a
   Kraft-complete Huffman table - a 256-byte window is a valid canonical XPRESS table iff
   `sum(2**(15-len)) == 32768` over its 512 nibble code lengths, which arbitrary bytes
   essentially never satisfy.

2. **Robustness on crafted files.** This parser is reachable from `pfcli artifacts` on a
   folder an attacker may have written, and it walks a length-prefixed chunk chain - the
   classic shape for both infinite loops (a zero-length chunk that never advances) and
   over-reads (a chunk claiming more bytes than the file holds). Python's slicing silently
   clamps `raw[pos:pos+n]` at the end of the buffer, so an unguarded version of this loop
   *appears* to work on real files while being wrong; that is exactly how the bogus final
   chunk length went unnoticed at first.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import corpus
from prefetch_core.artifacts import Artifact
from prefetch_core.xpress import PFB_MAGIC, InvalidCompressedData, decompress_pfb

CHUNK = 65536
failures = []


def check(label, ok, detail=""):
    # This file's helper takes a CONDITION; others in this directory take (got, want). Passing
    # a value where a condition belongs inverts the check silently - an empty list reads as a
    # failure, a count of 1 reads as a pass - and it has happened three times while writing
    # these suites. A boolean is now required, so the mistake fails loudly and immediately.
    if not isinstance(ok, bool):
        raise TypeError(f"check({label!r}) needs a condition, got {type(ok).__name__} {ok!r}")
    print(f"  {label:56} {'ok' if ok else 'FAIL'}"
          f"{'  ' + str(detail) if detail and not ok else ''}")
    if not ok:
        failures.append(label)


def kraft_complete(data, off):
    """True if the 256 bytes at `off` form a complete canonical Huffman table."""
    if off + 256 > len(data):
        return False
    total = 0
    for b in data[off:off + 256]:
        for length in (b & 0x0F, b >> 4):
            if length:
                total += 1 << (15 - length)
    return total == 32768


def real_files():
    if not corpus.WIN11:
        return []
    root = os.path.join(corpus.WIN11, "ReadyBoot")
    if not os.path.isdir(root):
        return []
    return [os.path.join(root, n) for n in sorted(os.listdir(root))]


def main():
    corpus.require("WIN11")
    files = real_files()
    if not files:
        corpus.skip("the configured Win11 corpus has no ReadyBoot/ folder: "
                    + os.path.join(corpus.WIN11, "ReadyBoot"),
                    "Win10 folders have none - this suite needs a Win11 collection.")

    print("real ReadyBoot files decode to exactly their declared size:")
    for path in files:
        with open(path, "rb") as fh:
            raw = fh.read()
        name = os.path.basename(path)
        if raw[:4] != PFB_MAGIC:
            check(f"{name}: PfB magic", False, raw[:4].hex())
            continue
        declared = struct.unpack_from("<I", raw, 4)[0]
        out = decompress_pfb(raw)
        check(f"{name}: decompressed == declared {declared:,}",
              len(out) == declared, len(out))

    print("\nevery chunk starts on a complete Huffman table, and there are ceil(size/64K):")
    for path in files:
        with open(path, "rb") as fh:
            raw = fh.read()
        name = os.path.basename(path)
        _magic, total, chunk_len = struct.unpack_from("<3I", raw, 0)
        pos, produced, chunks, bad = 12, 0, 0, 0
        while produced < total:
            if not kraft_complete(raw, pos):
                bad += 1
            avail = len(raw) - pos
            produced += min(CHUNK, total - produced)
            pos += min(chunk_len, avail)
            chunks += 1
            if produced >= total:
                break
            _unknown, chunk_len = struct.unpack_from("<2I", raw, pos)
            pos += 8
        expected = -(-total // CHUNK)
        check(f"{name}: {chunks} chunks, none misaligned",
              bad == 0 and chunks == expected, f"{bad} bad, expected {expected} chunks")

    print("\nthe name table resolves into whole paths, with nothing dropped:")
    from prefetch_core.artifacts import parse_artifact
    for path in files:
        art = parse_artifact(path)
        name = os.path.basename(path)
        records = art.facts.get("name_records") or 0
        found = art.facts.get("paths_found") or 0
        # Every record must produce a path. A partial resolution rate is the symptom of
        # locating the table at the wrong origin - which is exactly what an early attempt did,
        # resolving 23% and reconstructing nonsense.
        check(f"{name}: {records:,} records all resolve",
              records > 0 and found == records and art.facts.get("broken_links") == 0,
              f"{found} paths, {art.facts.get('broken_links')} broken")

    trace = next(p for p in files if os.path.basename(p).startswith("Trace"))
    art = parse_artifact(trace)
    paths = set(art.paths)
    check("paths are whole and rooted at \\Device",
          all(p.startswith("\\") for p in art.paths)
          and any(p.startswith("\\Device\\HarddiskVolume") for p in art.paths))
    # A printable-run scan cannot see where a name ends and swallows the next record's length
    # field, yielding 'EFI6' / 'MicrosoftB'. Whole paths must contain neither.
    check("no scan artefacts in any component",
          not any("EFI6" in p or "MicrosoftB" in p or "BootZ" in p for p in paths))
    check("a known boot path is present",
          any(p.endswith("\\Windows\\System32\\ntoskrnl.exe") for p in paths))

    print("\nthe I/O trace decodes, and its event count matches the header exactly:")
    import struct as _s
    from prefetch_core.xpress import decompress_pfb as _dc
    for path in files:
        name = os.path.basename(path)
        art = parse_artifact(path)
        with open(path, "rb") as fh:
            payload = _dc(fh.read())
        if _s.unpack_from("<I", payload, 0)[0] != 0x45634678:      # 'xFcE'
            check(f"{name}: no I/O section (layout file)", not art.facts.get("io_events"))
            continue
        # The two section counts in the header are the authority; a decoder that walks blocks
        # by any other rule drifts and silently loses or invents events.
        declared = sum(_s.unpack_from("<2I", payload, 8))
        check(f"{name}: {declared:,} events, matching header 8+12",
              art.facts.get("io_events") == declared, art.facts.get("io_events"))
        # Every event names a file. Anything less means the record layout is misaligned.
        unresolved = [p for p, _n, _b in art.io_by_path if p.startswith("<unresolved:")]
        check(f"{name}: every event resolves to a name", not unresolved, unresolved[:3])
        check(f"{name}: clock runs forward",
              (art.facts.get("io_first_tick") or 0) < (art.facts.get("io_last_tick") or 0))

    print("\nthe GUI's folder-artifacts window shows the I/O trace, not just the facts:")
    # The recurring failure mode in this project is a correct value that never reaches a
    # surface. io_by_path is a new field on Artifact; the CLI prints it, and this asserts the
    # GUI does too rather than silently dropping it.
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("  (PySide6 not installed; skipped)")
    else:
        app = QApplication.instance() or QApplication([])
        import pfgui.__main__ as gui
        window = gui.MainWindow()
        window._load_artifacts([corpus.WIN11])
        text = window.detail_artifacts.toPlainText()
        for needle in ("heaviest reads", "io_events", "io_seconds_assuming_us",
                       # The CLI prints this too; both surfaces must agree about what the
                       # tool established, or they answer the same question differently.
                       "Volume identity", "C: = \\Device\\HarddiskVolume3"):
            check(f"folder-artifacts text includes {needle!r}", needle in text)
        check("a real read total is rendered", " MB in " in text)
        app.processEvents()

    print("\nscan_folder reports progress, so a slow folder cannot look like a hang:")
    from prefetch_core.artifacts import scan_folder
    seen = []
    scan_folder(os.path.dirname(files[0]), progress=seen.append)
    check("progress callback fired per file", len(seen) >= len(files), len(seen))
    check("scan_folder still works without a callback",
          len(scan_folder(os.path.dirname(files[0]))) == len(files))

    print("\nbugs found in the 2026-08-15 audit stay fixed:")
    import struct as _st
    from prefetch_core.artifacts import io_array_start, iter_io_events
    from prefetch_core.xpress import decompress_pfb as _dcp
    trace_file = next(p for p in files if os.path.basename(p).startswith("Trace"))
    with open(trace_file, "rb") as fh:
        payload = _dcp(fh.read())
    table_start = len(payload) - _st.unpack_from("<I", payload, 16)[0]

    # 1. The two sections are CONCURRENT in time, not sequential: section 2 begins before
    #    section 1 ends. first/last must therefore be min/max, not first-seen/last-seen.
    sec1, sec2 = _st.unpack_from("<2I", payload, 8)
    ticks = [w for w, _s, _o, _n in iter_io_events(payload, table_start)]
    check("section 2 starts before section 1 ends (the reason min/max is required)",
          ticks[sec1] < ticks[sec1 - 1], f"{ticks[sec1]} vs {ticks[sec1 - 1]}")
    art = parse_artifact(trace_file)
    check("io_first_tick is the minimum, not the first seen",
          art.facts["io_first_tick"] == min(ticks), art.facts["io_first_tick"])
    check("io_last_tick is the maximum, not the last seen",
          art.facts["io_last_tick"] == max(ticks), art.facts["io_last_tick"])
    check("span is never negative", art.facts["io_span_ticks"] >= 0)

    # 2. The I/O array start is derived from the header's length-prefixed DMIO string. Hardcoding
    #    46 misaligns the whole array on any machine writing a different-length string, and a
    #    misaligned array decodes into plausible nonsense rather than failing.
    check("I/O array start is derived from the header", io_array_start(payload) == 46,
          io_array_start(payload))
    shifted = bytearray(payload)
    _st.pack_into("<H", shifted, 20, 40)
    check("a different DMIO length moves the derived start",
          io_array_start(bytes(shifted)) == 62, io_array_start(bytes(shifted)))

    # 3. A malformed I/O header must be REPORTED. Yielding nothing is indistinguishable from a
    #    trace that genuinely recorded nothing, which limits.py forbids.
    for label, mutate in (
        ("absurd event counts", lambda b: _st.pack_into("<2I", b, 8, 10**9, 10**9)),
    ):
        bad = bytearray(payload)
        mutate(bad)
        try:
            list(iter_io_events(bytes(bad), table_start))
            check(f"{label} is reported, not skipped", False, "yielded silently")
        except (InvalidCompressedData, struct.error):
            check(f"{label} is reported, not skipped", True)
    try:
        list(iter_io_events(payload, 100))       # name table before the array can fit
        check("truncated I/O region is reported, not skipped", False, "yielded silently")
    except (InvalidCompressedData, struct.error):
        check("truncated I/O region is reported, not skipped", True)

    # 4. FI_UNKNOWN is a ROOT record, so the marker path is exactly "\FI_UNKNOWN". A suffix
    #    test also swallows a real file called MY_FI_UNKNOWN and inflates the count.
    inflating = [p for p, _n, _b in art.io_by_path
                 if p.endswith("FI_UNKNOWN") and p != "\\FI_UNKNOWN"]
    exact = next((n for p, n, _b in art.io_by_path if p == "\\FI_UNKNOWN"), 0)
    check("unattributed counts only the exact marker",
          art.facts["io_unattributed"] == exact, art.facts["io_unattributed"])
    check("no non-marker path is being counted as unattributed", not inflating, inflating[:3])

    print("\none undecodable name does not discard the rest of the name table:")
    from prefetch_core.artifacts import _read_table, _resolve_paths
    NO_PARENT_ = 0xFFFFFFFF

    def _rec(parent, text, chars):
        return _st.pack("<IH", parent, chars) + text

    table = bytearray()
    table += _rec(NO_PARENT_, "Test".encode("utf-16-le"), 4)
    table += _rec(0, b"\x00\xd8", 1)          # lone high surrogate: legal in an NTFS name
    table += _rec(0, "After".encode("utf-16-le"), 5)
    table += _rec(0, "Later".encode("utf-16-le"), 5)
    recs, stopped, replaced = _read_table(bytes(table), 0, len(table))
    # Strict decoding used to stop here, keeping 1 of 4 and reporting nothing - and the record
    # count matched the path count afterwards, so the loss was invisible.
    check("all four records survive one bad name", len(recs) == 4, len(recs))
    check("the walk reaches the end of the table", stopped == len(table), stopped)
    check("the lossy decode is counted", replaced == 1, replaced)
    names, _broken = _resolve_paths(recs)
    check("recovered names are safe to print", all(isinstance(n, str) for n in names))
    # A lone surrogate would raise on encode; "replace" is what keeps the reporting surface safe.
    check("no lone surrogate reaches the output",
          all(n.encode("utf-8", errors="strict") for n in names))

    # Round 49. The per-file I/O totals are an attribution of the trace's own events, and the
    # trace states how many events it holds. If the two disagree, the attribution is either
    # dropping events or counting some twice - and an analyst reading "this file accounted for
    # 12% of boot I/O" would be reading a number with no denominator. Never checked until now.
    print("\nthe per-file read totals account for every event the trace declares:")
    from prefetch_core.artifacts import scan_folder as _scan_folder    # noqa: PLC0415

    traces = [a for a in _scan_folder(corpus.WIN11) if a.kind == "readyboot" and a.io_by_path]
    check("the folder holds traces to check", len(traces) > 0, True)
    for art in traces:
        declared = art.facts.get("events")
        reads = sum(r for _p, r, _b in art.io_by_path)
        paths = {p for p, _r, _b in art.io_by_path}
        check(f"  {art.name}: reads sum to the declared event count",
              declared is None or int(declared) == reads, f"{reads} vs {declared}")
        check(f"  {art.name}: no path is counted twice",
              len(paths) == len(art.io_by_path), len(art.io_by_path) - len(paths))

    print("\nvolume identity is correlated across artifacts, and withheld when unsupported:")
    from prefetch_core.artifacts import (correlate_volumes, describe_identities,
                                     scan_folder)
    rows = correlate_volumes(scan_folder(corpus.WIN11))
    check("one drive letter established", len(rows) == 1, len(rows))

    # 5. With two letters mapped and one volume on record, there is nothing to say which letter
    #    the serial belongs to. Attaching it to both asserts C: and D: are the same volume.
    def _art(kind, paths, facts=None):
        a = Artifact("synthetic", kind)
        a.paths = paths
        a.facts = facts or {}
        return a
    # Machine-specific paths: a match built only from \WINDOWS\ system files cannot show
    # that two artifacts describe the same machine (AUDIT BUG 105), so a fixture meant to
    # establish a mapping has to look like a disk somebody actually used.
    win = [f"\\PROGRAM FILES\\ACME\\W{i}.DLL" for i in range(40)]
    dat = [f"\\DATA\\D{i}.DAT" for i in range(40)]
    two = correlate_volumes([
        _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in win]
             + [f"\\Device\\HarddiskVolume9{p}" for p in dat]),
        _art("layout", [f"C:{p}" for p in win] + [f"D:{p}" for p in dat]),
        _art("superfetch", [], {"volumes": "\\VOLUME{01d6d2b931a49a11-cc31b5d5}"}),
    ])
    check("two letters map to their own separate devices", len(two) == 2,
          [(r["drive_letter"], r["device"]) for r in two])
    check("one serial is NOT stamped onto two different letters",
          not any("volume_serial" in r for r in two),
          [r.get("volume_serial") for r in two])

    # Three ways to get a confident wrong answer out of a percentage. Each must yield nothing.
    many = [f"\\PROGRAM FILES\\ACME\\F{i}.DLL" for i in range(40)]
    generic = ["\\$MFT", "\\SYSTEM VOLUME INFORMATION", "\\$LOGFILE", "\\$RECYCLE.BIN"]
    cases = [
        # One shared path is "100%". A percentage without a count is not evidence.
        ("a single shared path claims nothing",
         [_art("readyboot", ["\\Device\\HarddiskVolume3\\WINDOWS\\A.DLL"]),
          _art("layout", ["C:\\WINDOWS\\A.DLL"])]),
        # With only one device there is no competing device to reject against, so without an
        # explicit check every letter matches it.
        ("one device cannot be two letters",
         [_art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in many]
               + [f"\\Device\\HarddiskVolume3\\DATA\\D{i}.DAT" for i in range(40)]),
          _art("layout", [f"C:{p}" for p in many]
               + [f"D:\\DATA\\D{i}.DAT" for i in range(40)])]),
        # $Mft and friends exist on every NTFS volume, so they identify none of them.
        ("volume-generic paths claim nothing",
         [_art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in generic + many]),
          _art("layout", [f"D:{p}" for p in generic])]),
    ]
    for label, arts in cases:
        check(label, correlate_volumes(arts) == [], correlate_volumes(arts))

    # Round 48. A folder can be assembled from two machines - triage output gets merged, and
    # folders get copied into one place - and every Windows installation shares its system
    # files. One machine's Layout.ini beside another's ReadyBoot traces produced
    # `C: = \Device\HarddiskVolume3` at **88.8%**: a confident mapping between a letter on one
    # disk and a device on another (AUDIT BUG 105).
    print("\na match built only from stock Windows paths is refused, and says why:")
    stock = [f"\\WINDOWS\\SYSTEM32\\S{i}.DLL" for i in range(60)]
    notes = []
    rows = correlate_volumes([
        _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in stock]),
        _art("layout", [f"C:{p}" for p in stock])], notes)
    check("no letter is claimed from system files alone", rows == [], rows)
    check("...and the refusal is reported rather than silent", bool(notes), True)
    check("...naming what it saw and why it refused",
          bool(notes) and "stock Windows" in notes[0] and "withheld" in notes[0],
          notes[:1])
    rendered = "\n".join(describe_identities(rows, notes))
    check("...and it reaches the report", "NOT claimed" in rendered, rendered[:120])
    # Five machine-specific paths are enough to tell one disk from another; four are not.
    for count, expected in ((5, 1), (4, 0)):
        mixed = stock + [f"\\PROGRAM FILES\\ACME\\M{i}.EXE" for i in range(count)]
        got = correlate_volumes([
            _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in mixed]),
            _art("layout", [f"C:{p}" for p in mixed])])
        check(f"{count} machine-specific path(s) -> {expected} mapping(s)",
              len(got) == expected, len(got))
    # And the real folder is unaffected: 1,401 of its 4,238 shared paths are machine-specific.
    real = correlate_volumes(scan_folder(corpus.WIN11))
    check("the real corpus still maps its letter", len(real) == 1, len(real))

    # Round 46, feature 7 re-audit. Five ways the correlation misreported an identity.
    #
    # BUG 84: the volume-generic filter held its folder names in upper case and compared them
    # against the path as written. Windows writes `System Volume Information` in mixed case,
    # so the one rule that stops a letter being mapped by paths present on every volume did
    # nothing for the spelling that actually occurs.
    mixed = [f"\\System Volume Information\\x{i}" for i in range(40)]
    check("mixed-case volume-generic paths claim nothing",
          correlate_volumes([
              _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in mixed]),
              _art("layout", [f"C:{p}" for p in mixed])]) == [], "mapped on generic paths")

    # BUG 85: devices were accepted in any casing and then grouped case-sensitively, so one
    # device spelled two ways became two competitors - and the rule that rejects a contested
    # device threw the true mapping away.
    half = [f"\\USERS\\BOB\\H{i}.DLL" for i in range(20)]
    rest = [f"\\USERS\\BOB\\R{i}.DLL" for i in range(20)]
    spelled_twice = correlate_volumes([
        _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in half]
             + [f"\\DEVICE\\HARDDISKVOLUME3{p}" for p in rest]),
        _art("layout", [f"C:{p}" for p in half + rest])])
    check("one device spelled two ways is still one device",
          len(spelled_twice) == 1 and spelled_twice[0]["drive_letter"] == "C:", spelled_twice)

    # BUG 86: the "one device cannot be two letters" rule counted stated SuperFetch records as
    # claimants. A folder holding both a database that names \Device\HarddiskVolume3 and the
    # ReadyBoot/Layout.ini pair that maps C: to it reported NOTHING - the more evidence a
    # folder carried, the less the tool said.
    def _sf(device, serial):
        a = Artifact("synthetic", "superfetch")
        a.volumes = [{"device": device, "serial": serial, "created": None}]
        return a
    both = correlate_volumes([
        _art("readyboot", [f"\\Device\\HarddiskVolume3{p}" for p in many]),
        _art("layout", [f"C:{p}" for p in many]),
        _sf("\\Device\\HarddiskVolume3", "AABBCCDD")])
    check("a stated record and an inferred letter do not cancel out", len(both) == 1, both)
    check("the letter is kept and the stated serial attached to it",
          both and both[0]["drive_letter"] == "C:" and both[0]["volume_serial"] == "AABBCCDD",
          both)
    check("and the row says the serial was stated, not matched",
          both and "stated by the SuperFetch database" in both[0]["basis"],
          both and both[0]["basis"])
    # The same record reaches correlation once per database in the folder. Duplicated, the two
    # copies used to annihilate each other under that same rule.
    twice = correlate_volumes([_sf("\\Device\\HarddiskVolume2", "885029E6"),
                               _sf("\\Device\\HarddiskVolume2", "885029E6")])
    check("a device stated by two databases is reported once, not zero times",
          len(twice) == 1 and twice[0]["volume_serial"] == "885029E6", twice)
    # Two databases disagreeing about one device is a conflict to show, not to resolve.
    conflict = correlate_volumes([_sf("\\Device\\HarddiskVolume2", "885029E6"),
                                  _sf("\\Device\\HarddiskVolume2", "11112222")])
    check("conflicting records are both reported", len(conflict) == 2, conflict)

    # BUG 87: a stated row carried shared_paths 0, match 100.0 and next_best 0.0 - numbers no
    # measurement produced, printed as "0 shared paths - 100.0%" under a fact.
    check("a stated row measures nothing and says so",
          twice[0]["shared_paths"] is None and twice[0]["match"] is None
          and twice[0]["next_best"] is None, twice[0])

    # BUG 88: the CLI and the GUI each rendered these rows themselves, and both labelled a
    # stated record "Derived by correlation, not read from any file."
    from prefetch_core.artifacts import describe_identities
    text = "\n".join(describe_identities(twice))
    check("a stated-only report does not claim to be inference",
          "not read from any file" not in text, text)
    check("...and does not print an empty drive letter",
          "no drive letter established" in text and " = " not in text, text)
    letters = "\n".join(describe_identities(both))
    check("an inferred letter still carries its warning",
          "not read from any file" in letters, letters)
    if rows:
        row = rows[0]
        check("C: maps to HarddiskVolume3",
              row["drive_letter"] == "C:" and row["device"].endswith("HarddiskVolume3"), row)
        # The whole basis of the claim: one device explains nearly every path and the rest
        # explain none. A weak margin here would mean the mapping is a coincidence.
        check("the match is unambiguous", row["match"] > 90 and row["next_best"] < 1,
              f"{row['match']}% vs {row['next_best']}%")
        check("volume serial and creation time attached",
              row.get("volume_serial") == "CC31B5D5" and row.get("volume_created") is not None)
        check("creation time survives FILETIME precision",
              row["volume_created"].year == 2020 and row["volume_created"].microsecond == 766196,
              row.get("volume_created"))
    if corpus.WIN10:
        # Win10 has no ReadyBoot at all, so there is nothing to correlate Layout.ini against.
        # Emitting a guess here would be the failure mode this function exists to avoid.
        check("no mapping invented without ReadyBoot",
              correlate_volumes(scan_folder(corpus.WIN10)) == [])

    print("\ncrafted name tables cannot hang the parser:")
    from prefetch_core.artifacts import _resolve_paths
    NO_PARENT = 0xFFFFFFFF
    # A record that is its own parent, and a two-record loop. A naive parent walk never
    # terminates on either.
    self_loop = {0: ("a", 0)}
    two_cycle = {0: ("a", 10), 10: ("b", 0)}
    dangling = {0: ("a", 9999)}
    deep = {i * 10: (f"d{i}", (i - 1) * 10 if i else NO_PARENT) for i in range(500)}
    for label, table, expect_paths in (
        ("self-referencing record", self_loop, 0),
        ("two-record cycle", two_cycle, 0),
        ("link to a non-existent record", dangling, 0),
        ("500-deep chain is capped", deep, None),
    ):
        try:
            out, broken = _resolve_paths(table)
            ok = True if expect_paths is None else len(out) == expect_paths
            check(f"{label}: terminates", ok, f"{len(out)} paths, {broken} broken")
        except RecursionError as exc:
            check(f"{label}: terminates", False, str(exc))

    print("\ncrafted containers are refused, not hung or over-read:")
    good_chunk = None
    with open(files[0], "rb") as fh:
        raw = fh.read()
    first_len = struct.unpack_from("<I", raw, 8)[0]
    good_chunk = raw[12:12 + first_len]

    def hdr(total, clen):
        return PFB_MAGIC + struct.pack("<2I", total, clen)

    cases = [
        ("not a PfB container", b"XXXX" + b"\x00" * 32),
        ("truncated header", PFB_MAGIC + b"\x00\x00"),
        # Would spin forever without the liveness guard: pos never advances.
        ("zero-length chunk", hdr(CHUNK * 4, 0) + good_chunk),
        # Would over-read without the bounds guard; Python slicing hides this.
        ("chunk longer than the file", hdr(CHUNK * 4, 1 << 30) + good_chunk),
        ("trailer past end of file", hdr(CHUNK * 4, first_len) + good_chunk + b"\x01\x02"),
        ("declared size beyond the ceiling", hdr(1 << 30, first_len) + good_chunk),
    ]
    for label, blob in cases:
        try:
            decompress_pfb(blob, max_output=64 * 1024 * 1024)
            check(label, False, "accepted a malformed container")
        except (InvalidCompressedData, struct.error, ValueError):
            check(label, True)
        except Exception as exc:  # noqa: BLE001 - an unexpected type is itself the failure
            check(label, False, f"raised {type(exc).__name__}: {exc}")

    # A parser must never turn a malformed artifact into a crash; it reports a problem instead.
    print("\nthe artifact parser degrades to a problem, never an exception:")
    import tempfile
    for label, blob in cases:
        with tempfile.NamedTemporaryFile(suffix=".fx", delete=False) as fh:
            fh.write(blob if blob[:4] == PFB_MAGIC else PFB_MAGIC + blob[4:])
            tmp = fh.name
        try:
            art = parse_artifact(tmp)
            ok = art is None or not art.facts.get("payload_decoded")
            check(f"{label}: reported, not raised", ok)
        except Exception as exc:  # noqa: BLE001
            check(f"{label}: reported, not raised", False, f"{type(exc).__name__}: {exc}")
        finally:
            os.unlink(tmp)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all ReadyBoot checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
