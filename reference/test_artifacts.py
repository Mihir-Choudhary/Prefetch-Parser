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
    ("win10", "PfPre_cb1e3c5c.mkd"): ("pfpre", {"format_version": 5, "events_written": 2603,
                                                "slots": 16384, "slots_populated": 2603,
                                                "wrapped": False}),
    ("win10", "cadrespri.7db"): ("superfetch", {"format_version": 3, "size_matches": True,
                                                "db_type": 19, "paths_found": 13}),
    ("win10", "dynrespri.7db"): ("superfetch", {"db_type": 19, "paths_found": 559}),
    # MAM\x84: payload at +12, not +8. Decompressing to exactly the declared size is the proof.
    ("win10", "ResPriHMStaticDb.ebd"): ("superfetch", {"compressed": True, "db_type": 22,
                                                       "decompressed_size": 153100,
                                                       "size_matches": True,
                                                       "paths_found": 753}),
    ("win11", "Layout.ini"): ("layout", {"entries": 4268, "user_paths": 357,
                                         "boot_volume_letter": "C"}),
    ("win11", "PfPre_490977ab.mkd"): ("pfpre", {"events_written": 17779, "wrapped": True,
                                                "slots_populated": 16384, "events_lost": 1395}),
    ("win11", "dynrespri.7db"): ("superfetch", {"db_type": 19, "paths_found": 531}),
    ("win11", "ResPriStaticDb.ebd"): ("superfetch", {"compressed": True,
                                                     "decompressed_size": 63932,
                                                     "size_matches": True}),
    ("win11", "Trace2.fx"): ("readyboot", {"declared_size": 7795764, "payload_decoded": True}),
    ("win11", "rblayout.xin"): ("readyboot", {"declared_size": 1583772}),
}
EXPECTED_COUNTS = {"win10": 5, "win11": 10}      # win10 has no ReadyBoot subdirectory at all

failures = []


def main():
    found = {}
    for tag, root in (("win10", WIN10), ("win11", WIN11)):
        arts = scan_folder(root)
        print(f"{tag}: {len(arts)} artifacts")
        if len(arts) != EXPECTED_COUNTS[tag]:
            failures.append(f"{tag}: {len(arts)} artifacts, expected {EXPECTED_COUNTS[tag]}")
        for a in arts:
            found[(tag, a.name)] = a
            print(f"   {a.name:24} {a.kind}")

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
        if not a.facts.get("component_count"):
            failures.append(f"{tag}/{name}: decoded but recovered no name components")
        print(f"   {tag}/{name:24} {'decoded':20} {actual:>10,} bytes, "
              f"{a.facts.get('component_count'):,} names")

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

    print("\nPASS" if not failures else "\nFAIL:")
    for f in failures:
        print(f"   {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
