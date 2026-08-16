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
    files = real_files()
    if not files:
        print("This suite needs a Win11 corpus with a ReadyBoot/ folder.", file=sys.stderr)
        print("Set PREFETCH_CORPUS_WIN11. See reference/corpus.py.", file=sys.stderr)
        return 1

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

    print("\nvolume identity is correlated across artifacts, and withheld when unsupported:")
    from prefetch_core.artifacts import correlate_volumes, scan_folder
    rows = correlate_volumes(scan_folder(corpus.WIN11))
    check("one drive letter established", len(rows) == 1, len(rows))

    # 5. With two letters mapped and one volume on record, there is nothing to say which letter
    #    the serial belongs to. Attaching it to both asserts C: and D: are the same volume.
    def _art(kind, paths, facts=None):
        a = Artifact("synthetic", kind)
        a.paths = paths
        a.facts = facts or {}
        return a
    win = [f"\\WINDOWS\\W{i}.DLL" for i in range(40)]
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
    many = [f"\\WINDOWS\\F{i}.DLL" for i in range(40)]
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
