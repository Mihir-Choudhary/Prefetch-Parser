#!/usr/bin/env python3
"""Pin the non-.pf artifact parsing against the manual byte-level analysis.

Every number here was established by hand in docs/prefetch-artifacts.md before any code
existed. This asserts the parser reproduces that analysis rather than whatever it happens to
produce today.

Run:  python3 test_artifacts.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core.artifacts import scan_folder  # noqa: E402

WIN10 = corpus.WIN10
WIN11 = corpus.WIN11

EXPECT = {
    # name -> (kind, facts that must match)
    ("win10", "Layout.ini"): ("layout", {"entries": 89, "boot_volume_letter": "C",
                                         "user_paths": 0, "unc_paths": 0}),
    # clock_reversals is the second, independent wrap signal: a ring read linearly crosses from
    # newer entries to older ones exactly once. Win10 has not wrapped, so it must be 0.
    ("win10", "PfPre_cb1e3c5c.mkd"): ("pfpre", {"format_version": 5, "events_written": 2603,
                                                "slots": 16384, "slots_populated": 2603,
                                                "wrapped": False, "clock_reversals": 0,
                                                "clock_last": 1503292}),
    # Structural now, not a string sweep: paths_found dropped by one because the volume
    # device name is no longer counted as a file path - it is reported as a volume record.
    ("win10", "cadrespri.7db"): ("superfetch", {"format_version": 3, "size_matches": True,
                                                "db_type": 19, "paths_found": 12,
                                                "parse_method": "structural",
                                                "name_hashes_verified": 12}),
    ("win10", "dynrespri.7db"): ("superfetch", {"db_type": 19, "paths_found": 558,
                                                "parse_method": "structural",
                                                "name_hashes_verified": 558}),
    # MAM\x84: payload at +12, not +8. Decompressing to exactly the declared size is the proof.
    ("win10", "ResPriHMStaticDb.ebd"): ("superfetch", {"compressed": True, "db_type": 22,
                                                       "decompressed_size": 153100,
                                                       "size_matches": True,
                                                       "paths_found": 753,
                                                       "parse_method": "scan",
                                                       "name_hashes_verified": 753}),
    ("win11", "Layout.ini"): ("layout", {"entries": 4268, "user_paths": 357,
                                         "boot_volume_letter": "C"}),
    # Win11's ring HAS wrapped, so the clock must reverse exactly once - not zero (which would
    # mean the wrap signal is imaginary) and not many (which would mean it is not a clock).
    ("win11", "PfPre_490977ab.mkd"): ("pfpre", {"events_written": 17779, "wrapped": True,
                                                "slots_populated": 16384, "events_lost": 1395,
                                                "clock_reversals": 1}),
    ("win11", "dynrespri.7db"): ("superfetch", {"db_type": 19, "paths_found": 530,
                                                "parse_method": "structural",
                                                "name_hashes_verified": 530}),
    ("win11", "ResPriStaticDb.ebd"): ("superfetch", {"compressed": True,
                                                     "decompressed_size": 63932,
                                                     "size_matches": True,
                                                     "parse_method": "scan",
                                                     "name_hashes_verified": 345}),
    ("win11", "Trace2.fx"): ("readyboot", {"declared_size": 7795764, "payload_decoded": True}),
    ("win11", "rblayout.xin"): ("readyboot", {"declared_size": 1583772}),
}
# win10 has no ReadyBoot subdirectory at all. Its three extra artifacts are BLAH.TXT,
# HOST.TXT and PF.zip - files left in the folder by earlier ADS work, which the scanner now
# REPORTS as unrecognised instead of dropping silently. A file present in a collection is a
# fact about the collection whether or not this tool can parse it.
EXPECTED_COUNTS = {"win10": 8, "win11": 10}
EXPECTED_UNRECOGNISED = {"win10": {"BLAH.TXT", "HOST.TXT", "PF.zip"}, "win11": set()}

failures = []


def main():
    corpus.require("WIN10", "WIN11")
    found = {}
    for tag, root in (("win10", WIN10), ("win11", WIN11)):
        arts = scan_folder(root)
        print(f"{tag}: {len(arts)} artifacts")
        if len(arts) != EXPECTED_COUNTS[tag]:
            failures.append(f"{tag}: {len(arts)} artifacts, expected {EXPECTED_COUNTS[tag]}")
        for a in arts:
            found[(tag, a.name)] = a
            print(f"   {a.name:24} {a.kind}")
        unrecognised = {a.name for a in arts if a.kind == "unrecognised"}
        if unrecognised != EXPECTED_UNRECOGNISED[tag]:
            failures.append(f"{tag}: unrecognised {sorted(unrecognised)}, "
                            f"expected {sorted(EXPECTED_UNRECOGNISED[tag])}")
        # Everything the folder holds must be accounted for, one way or another.
        for a in arts:
            if a.kind == "unrecognised" and not a.problems:
                failures.append(f"{tag}/{a.name}: unrecognised but says nothing about why")

    print("\nfacts:")
    for (tag, name), (kind, facts) in EXPECT.items():
        a = found.get((tag, name))
        if a is None:
            failures.append(f"{tag}/{name} not found")
            print(f"   !! {tag}/{name} MISSING")
            continue
        if a.kind != kind:
            failures.append(f"{tag}/{name} kind {a.kind} != {kind}")
        for key, want in facts.items():
            got = a.facts.get(key)
            ok = got == want
            if not ok:
                failures.append(f"{tag}/{name}.{key} = {got!r}, expected {want!r}")
            print(f"   {tag}/{name:24} {key:20} {str(got):>10}"
                  f"{'' if ok else f'   << expected {want}'}")

    # ReadyBoot IS decoded now (docs/readyboot-format.md): a PfB chain of 64 KB XPRESS Huffman
    # chunks. The decode is exact, so assert exactness - a payload that decodes to anything
    # other than its declared size means the chunk chain desynchronised, which is precisely the
    # failure a "did it decode at all" check would wave through.
    for (tag, name), a in found.items():
        if a.kind != "readyboot":
            continue
        if a.problems:
            failures.append(f"{tag}/{name}: readyboot failed to decode: {a.problems}")
            continue
        declared = a.facts.get("declared_size")
        actual = a.facts.get("decompressed_size")
        if actual != declared:
            failures.append(f"{tag}/{name}: decompressed {actual} != declared {declared}")
        if not a.facts.get("paths_found"):
            failures.append(f"{tag}/{name}: decoded but recovered no name components")
        print(f"   {tag}/{name:24} {'decoded':20} {actual:>10,} bytes, "
              f"{a.facts.get('paths_found'):,} names")

    # Synthetic Layout.ini shapes the corpus cannot provide. The UNC case is a real bug that
    # a drive-letter-only regex silently dropped.
    print("\nsynthetic Layout.ini shapes:")
    import codecs
    import tempfile
    from prefetch_core.artifacts import parse_artifact
    workdir = tempfile.mkdtemp()
    shapes = {
        "unc and local":      ("\\\\SERVER\\SHARE\\A.DLL\r\nC:\\B.DLL\r\n", 2, 1, "C"),
        "several drives":     ("C:\\A.DLL\r\nD:\\B.DLL\r\nE:\\C.DLL\r\n", 3, 0, ""),
        "no C: at all":       ("D:\\A.DLL\r\nD:\\B.DLL\r\n", 2, 0, "D"),
        "no path lines":      ("", 0, 0, ""),
    }
    for label, (body, entries, uncs, boot) in shapes.items():
        target = os.path.join(workdir, "Layout.ini")
        text = "[OptimalLayoutFile]\r\nVersion=1\r\n" + body
        with open(target, "wb") as fh:
            fh.write(codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
        a = parse_artifact(target)
        for key, want in (("entries", entries), ("unc_paths", uncs),
                          ("boot_volume_letter", boot)):
            got = a.facts.get(key)
            if got != want:
                failures.append(f"layout[{label}].{key} = {got!r}, expected {want!r}")
            print(f"   {label:18} {key:20} {str(got):>8}"
                  f"{'' if got == want else f'   << expected {want!r}'}")

    # The artifact parsers were never fuzzed - only the .pf parser was. A planted or corrupt
    # Layout.ini / PfPre / .7db / ReadyBoot file must not crash a scan.
    print("\nmalformed artifacts must not crash:")
    import struct as _struct
    import tempfile as _tf
    from prefetch_core.artifacts import parse_artifact
    workdir = _tf.mkdtemp()
    malformed = [
        ("Layout.ini", b""),
        ("Layout.ini", b"\xff\xfe"),
        ("Layout.ini", b"\x00" * 10),
        ("Layout.ini", os.urandom(2000)),
        ("PfPre_deadbeef.mkd", b""),
        ("PfPre_deadbeef.mkd", b"\x00" * 11),
        ("PfPre_deadbeef.mkd", _struct.pack("<3I", 5, 0, 0xFFFFFFFF)),
        ("PfPre_deadbeef.mkd", os.urandom(500)),
        ("x.7db", b""),
        ("x.7db", b"\x00" * 31),
        ("x.7db", _struct.pack("<8I", 3, 0xFFFFFFFF, 80, 19, 96, 56, 80, 8)),
        ("x.7db", os.urandom(3000)),
        ("x.ebd", b"MAM\x04" + _struct.pack("<I", 0xFFFFFFF) + b"\x00" * 20),
        ("x.ebd", b"MAM\x84" + _struct.pack("<I", 10) + b"\x00" * 4),
        ("x.ebd", b"MAM"),
        ("rb.fx", b"PfB\xe3"),
        ("rb.fx", b"PfB\xe3" + _struct.pack("<2I", 0xFFFFFFFF, 0)),
    ]
    crashes = 0
    for name, blob in malformed:
        target = os.path.join(workdir, name)
        with open(target, "wb") as fh:
            fh.write(blob)
        try:
            art = parse_artifact(target)
            if art is not None and not art.problems and art.kind != "prefetch":
                # Not fatal, but a malformed artifact silently reporting no problems means the
                # parser accepted nonsense as valid.
                print(f"   note: {name} ({len(blob)}B) parsed with no problem recorded")
        except Exception as exc:
            crashes += 1
            print(f"   CRASH {name} ({len(blob)}B): {type(exc).__name__}: {exc}")
    if crashes:
        failures.append(f"{crashes} malformed artifacts crashed the parser")
    print(f"   {len(malformed)} malformed inputs, {crashes} crashes")

    # Resource ceilings. Every input here is attacker-influenceable; "scan this folder" must
    # not become an out-of-memory crash because someone planted a huge file or a container
    # that declares a huge expansion.
    print("\nresource ceilings:")
    import resource as _resource
    from prefetch_core import container as _container
    from prefetch_core.limits import MAX_ARTIFACT_BYTES, MAX_DECOMPRESSED_BYTES

    big = os.path.join(workdir, "Layout.ini")
    with open(big, "wb") as fh:
        fh.truncate(MAX_ARTIFACT_BYTES + 4096)        # sparse: costs no disk
    before = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss / 1024
    oversized = parse_artifact(big)
    after = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss / 1024
    grew = after - before
    print(f"   oversized artifact refused, RSS grew {grew:.0f} MB")
    if not oversized.problems or "ceiling" not in oversized.problems[0]:
        failures.append("oversized artifact was not refused with an explanation")
    # Deciding a file is too large must not read it. An earlier fix read one byte past the
    # ceiling and so allocated the whole ceiling in order to refuse it.
    if grew > 32:
        failures.append(f"refusing an oversized artifact allocated {grew:.0f} MB")

    bomb = b"MAM\x04" + _struct.pack("<I", MAX_DECOMPRESSED_BYTES + 1) + b"\x00" * 64
    try:
        _container.load(bomb)
        failures.append("a container declaring an over-ceiling expansion was accepted")
        print("   !! decompression bomb accepted")
    except Exception as exc:
        print(f"   decompression bomb refused: {type(exc).__name__}")

    # Until Round 45 the artifacts reached no machine-readable output at all: an investigator
    # could see 10,118 SuperFetch paths on screen and had no way to get them into a report
    # except by retyping them (AUDIT BUG 80). They are exported to their own tables and their
    # own CSV - separate from `.pf` records, because access is not execution - and what comes
    # out has to equal what was parsed.
    print("\nthe artifacts reach the exports intact:")
    import csv as _csv                                                # noqa: PLC0415
    import sqlite3 as _sqlite3                                        # noqa: PLC0415
    import subprocess as _sp                                          # noqa: PLC0415
    import tempfile as _tempfile                                      # noqa: PLC0415

    from prefetch_core.store import Store as _Store                   # noqa: PLC0415

    def _check(label, got, want):
        flag = "" if got == want else f"   << expected {want}"
        print(f"  {label:<58} {str(got)[:28]}{flag}")
        if got != want:
            failures.append(f"{label}: {got!r} != {want!r}")

    for folder in (corpus.WIN10, corpus.WIN11):
        found = scan_folder(folder)
        expected_paths = sum(len(a.paths) + len([p for p, _r, _b in a.io_by_path
                                                 if p not in set(a.paths)])
                             for a in found)
        workdir = _tempfile.mkdtemp()
        db_path = os.path.join(workdir, "artifacts.db")
        with _Store(db_path) as store:
            store.add_artifacts(found)
            store.add_artifacts(found)          # re-ingest must not double anything
        conn = _sqlite3.connect(db_path)
        label = os.path.basename(os.path.dirname(folder)) or folder
        _check(f"{label}: every artifact is a row",
               conn.execute("SELECT COUNT(*) FROM artifact").fetchone()[0], len(found))
        _check(f"{label}: every path is a row",
               conn.execute("SELECT COUNT(*) FROM artifact_path").fetchone()[0], expected_paths)
        _check(f"{label}: no artifact loses its kind",
               conn.execute("SELECT COUNT(*) FROM artifact WHERE kind IS NULL "
                            "OR kind = ''").fetchone()[0], 0)
        io_rows = sum(len(a.io_by_path) for a in found)
        _check(f"{label}: ReadyBoot's per-file I/O survives",
               conn.execute("SELECT COUNT(*) FROM artifact_path "
                            "WHERE detail LIKE 'reads=%'").fetchone()[0], io_rows)
        problems = sum(len(a.problems) for a in found)
        _check(f"{label}: every problem is kept",
               conn.execute("SELECT COUNT(*) FROM artifact_problem").fetchone()[0], problems)

        csv_path = os.path.join(workdir, "artifacts.csv")
        run = _sp.run([sys.executable, "-m", "pfcli", "artifacts", folder, "--csv", csv_path],
                      cwd=os.path.dirname(HERE), capture_output=True, text=True, timeout=600)
        _check(f"{label}: the CSV command succeeds", run.returncode, 0)
        _csv.field_size_limit(10 ** 9)
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(_csv.DictReader(fh))
        _check(f"{label}: one CSV row per path", len(rows), expected_paths)
        summary = os.path.join(workdir, "artifacts-summary.csv")
        with open(summary, newline="", encoding="utf-8") as fh:
            summary_rows = list(_csv.DictReader(fh))
        _check(f"{label}: one summary row per artifact", len(summary_rows), len(found))
        _check(f"{label}: the summary keeps the facts",
               all(r["Facts"] or not next(a.facts for a in found if a.name == r["SourceName"])
                   for r in summary_rows), True)

    print("\nPASS" if not failures else "\nFAIL:")
    for f in failures:
        print(f"   {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
