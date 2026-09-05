#!/usr/bin/env python3
"""Pin the SuperFetch database parser: `Ag*.db`, `*.7db`, `*.ebd`.

Until 2026-08-27 this tool recognised `.7db` and `.ebd` and nothing else, so a Windows
Vista/7/8 Prefetch folder - where the databases are named `AgGlGlobalHistory.db`,
`AgRobust.db`, `AgCx_SC1.db` - reported **"no non-.pf artifacts found"** while holding
megabytes of file-access history. The gap survived because neither corpus here has one: both
are Windows 10/11 machines with SysMain writing the newer names.

What is asserted:

  * the six real databases parse, with **every path verified against its own stored name
    hash** - the property that makes an undocumented layout safe to walk;
  * the structural walk never covers less than the string sweep it replaced;
  * a database that cannot be parsed says so, and is never reported as empty;
  * a file the scanner does not recognise is still reported, with its size and magic.

Needs PREFETCH_SAMPLES for the Windows 7 database (see that directory's MANIFEST.md).

Run:  python3 test_superfetch.py
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import agdb  # noqa: E402
from prefetch_core.artifacts import correlate_volumes, identify, scan_folder  # noqa: E402

failures = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {label:<58} {'ok' if ok else 'FAIL'}"
          + ("" if ok else f"  got {got!r} want {want!r}"))
    if not ok:
        failures.append(label)


# (file, compression, database type, parse method, volumes, file records, first volume device)
EXPECT = [
    ("samples", "plaso/AgGlGlobalHistory.db", "MEM0", 1, "structural", 2, 10118,
     "\\DEVICE\\HARDDISKVOLUME2"),
    ("win10", "dynrespri.7db", "none", 19, "structural", 1, 558, "\\VOLUME{"),
    ("win10", "cadrespri.7db", "none", 19, "structural", 1, 12, "\\VOLUME{"),
    ("win10", "ResPriHMStaticDb.ebd", "MAM", 22, "scan", 1, 753, "Volume Serial Number"),
    ("win11", "dynrespri.7db", "none", 19, "structural", 1, 530, "\\VOLUME{"),
    ("win11", "ResPriStaticDb.ebd", "MAM", 22, "scan", 1, 345, "Volume Serial Number"),
]

ROOTS = {"win10": corpus.WIN10, "win11": corpus.WIN11, "samples": corpus.SAMPLES}


def _synthetic_agrobust(paths, sources=()):
    """Build a database with AgRobust's documented shape: type 14, 72/112/144 entries.

    Written to the *documented database* layout with an *undocumented file entry size*, which
    is exactly the situation a real `AgRobust.db` presents. Field placement inside the 112-byte
    entry follows the shape libyal documents for the other 64-bit entries (hash at +8, path
    character count at +16); the parser is not told any of that - it has to verify its way in.
    """
    vol_size, file_size, src_size = 72, 112, 144
    device = "\\DEVICE\\HARDDISKVOLUME1"

    def align(value, boundary=8):
        return (value + boundary - 1) // boundary * boundary

    header_size = 12 + 156
    body = bytearray(header_size)
    struct.pack_into("<I", body, 0, 0x0E)                       # Vista/7 signature
    struct.pack_into("<I", body, 8, header_size)
    struct.pack_into("<I", body, 12, 14)                        # database type
    struct.pack_into("<9I", body, 16, vol_size, file_size, src_size, 16, 16, 16, 16, 0, 0)
    struct.pack_into("<2I", body, 12 + 40, 1, len(paths))       # volumes, files
    struct.pack_into("<I", body, 12 + 52, len(sources))

    volume = bytearray(vol_size)
    struct.pack_into("<I", volume, 16, len(paths))              # number of files
    struct.pack_into("<Q", volume, 32, 130835373846718750)      # creation FILETIME
    struct.pack_into("<I", volume, 40, 0x1234ABCD)              # serial
    struct.pack_into("<H", volume, 56, len(device))
    body += volume
    body += device.encode("utf-16-le") + b"\x00\x00"
    body += b"\x00" * (align(len(body)) - len(body))

    for path in paths:
        raw = path.encode("utf-16-le")
        entry = bytearray(file_size)
        struct.pack_into("<Q", entry, 8, agdb.name_hash(raw))   # hash at +8, as documented
        struct.pack_into("<I", entry, 16, len(path) << 2)       # chars << 2, as documented
        body += entry + raw + b"\x00\x00"
        body += b"\x00" * (align(len(body)) - len(body))

    for name_hash, entries in sources:
        source = bytearray(src_size)
        struct.pack_into("<Q", source, 8, name_hash)
        struct.pack_into("<I", source, 16, entries)
        body += source

    struct.pack_into("<I", body, 4, len(body))                  # total size, as the header says
    return bytes(body)


def main():
    corpus.require("WIN10", "WIN11", "SAMPLES")

    print("real databases parse, and every path is vouched for by its own hash:")
    total_files = total_hashes = 0
    for tag, name, compression, db_type, method, volumes, records, device in EXPECT:
        path = os.path.join(ROOTS[tag], name)
        if not os.path.exists(path):
            failures.append(f"{tag}/{name} missing from the corpus")
            print(f"  {tag}/{name:<40} MISSING")
            continue
        db = agdb.parse(open(path, "rb").read())
        label = f"{tag}/{os.path.basename(name)}"
        check(f"{label}: compression", db.compression.split(" ")[0], compression)
        check(f"{label}: database type", db.db_type, db_type)
        check(f"{label}: parse method", db.method, method)
        check(f"{label}: volume records", len(db.volumes), volumes)
        check(f"{label}: file records", db.file_count, records)
        check(f"{label}: matches its own declared count", db.file_count, db.declared_files)
        # The whole point: a path is only reported because its stored hash vouches for it.
        check(f"{label}: every name hash verifies", db.hash_verified, records)
        check(f"{label}: nothing in the bytes is unaccounted for", len(db.unaccounted_paths), 0)
        check(f"{label}: first volume", db.volumes[0].device.upper().startswith(device.upper()),
              True)
        check(f"{label}: header size matches the payload",
              db.declared_size, db.actual_size)
        total_files += db.file_count
        total_hashes += db.hash_verified
    check("every path across every database verified", total_hashes, total_files)
    print(f"    ({total_files:,} file records, {total_hashes:,} hash-verified)")

    print("\nthe Windows 7 database states volume identity outright:")
    win7 = agdb.parse(open(os.path.join(corpus.SAMPLES,
                                        "plaso/AgGlGlobalHistory.db"), "rb").read())
    by_device = {v.device.upper(): v for v in win7.volumes}
    vol2 = by_device.get("\\DEVICE\\HARDDISKVOLUME2")
    check("HarddiskVolume2 is present", vol2 is not None)
    if vol2:
        check("...with its serial", vol2.serial_hex, "885029E6")
        check("...and its creation time", str(vol2.created)[:19], "2015-08-08 19:56:24")
        # FILETIME through a float loses the low digits; the ticks are the lossless copy.
        check("...kept losslessly as ticks", vol2.created_ticks, 130835373846718750)
        check("...with its own file count", len(vol2.files), vol2.declared_files)
    paths = {f.path for v in win7.volumes for f in v.files}
    check("user-profile paths are recovered",
          any(p.upper().startswith("\\USERS\\") for p in paths))
    check("10,118 distinct records", win7.file_count, 10118)

    print("\ncorrelation reports a stated identity as stated, not as inference:")
    art_dir = os.path.join(corpus.SAMPLES, "plaso")
    rows = correlate_volumes(scan_folder(art_dir))
    stated = [r for r in rows if "SuperFetch volume record" in r["basis"]]
    check("both volumes reported", len(stated), 2)
    check("serial carried through", {r["volume_serial"] for r in stated},
          {"885029E6", "204D9F2B"})
    check("and it does not claim a drive letter it cannot know",
          all(r["drive_letter"] == "" for r in stated))
    # Round 46: a stated row used to carry shared_paths 0, match 100.0, next_best 0.0 - three
    # numbers no measurement produced, printed as "0 shared paths - 100.0%" beneath a fact
    # (AUDIT BUG 87). Nothing was measured here, so nothing is reported as measured.
    check("a stated row reports no measurement it did not make",
          [(r["shared_paths"], r["match"], r["next_best"]) for r in stated],
          [(None, None, None)] * len(stated))
    # Both databases in this folder describe the same two volumes. Deduplicated wrongly - or
    # not at all - the folder reported four rows, or under the contested-device rule, none.
    check("two volumes, two rows, however many databases state them", len(rows), 2)

    print("\nrecognition covers the family, and does not overreach:")
    check("AgGlGlobalHistory.db by name", identify("AgGlGlobalHistory.db", b"MEM0\x00\x00\x00\x00"),
          "superfetch")
    check("AgRobust.db by name", identify("AgRobust.db", b"\x0f\x00\x00\x00"), "superfetch")
    check("AgCx_SC1.db by name", identify("AgCx_SC1.db", b"\x03\x00\x00\x00"), "superfetch")
    check("a .db.trx log", identify("AgGlGlobalHistory.db.trx", b"\x03\x00\x00\x00"),
          "superfetch")
    check("MEM0 magic under any name", identify("copied-out.bin", b"MEM0\x00\x00\x00\x00"),
          "superfetch")
    check(".7db still recognised", identify("dynrespri.7db", b"\x03\x00\x00\x00"), "superfetch")
    # Not everything named .db is SuperFetch. A browser history database must not be claimed.
    check("an unrelated .db is not claimed",
          identify("History.db", b"SQLite format 3\x00"), None)
    check("a .pf is still a .pf", identify("CMD.EXE-12345678.pf", b"MAM\x84"), "prefetch")

    print("\nLZNT1 (Windows Vista MEMO databases) decodes the documented vectors:")
    # No Vista sample exists publicly, so this decoder was written from the specification and
    # was untested until these vectors. The first is libyal's own published example; the rest
    # are built from the documented algorithm and exercise the parts it does not cover.

    def lznt1_chunk(body, compressed=True):
        header = (0x8000 if compressed else 0) | 0x3000 | (len(body) - 1)
        return struct.pack("<H", header) + body

    # Published example: tag 0x02 -> one literal space, then tuple 0x0ffc = (offset -1,
    # size 4095). The offset stays fixed at the end of the output, so it yields 4096 spaces.
    spaces = agdb._lznt1(lznt1_chunk(bytes([0x02, 0x20, 0xfc, 0x0f])), 4096)
    check("the published 4096-space example", spaces, b" " * 4096)

    # The other published example, rebuilt with tuples encoded per the documented algorithm.
    # It walks the offset/size split through three widths - 12, 11 and 10 bits - which is the
    # part of LZNT1 that is easy to get wrong and impossible to notice: the format carries no
    # checksum, so a mis-split silently yields plausible bytes.
    text = b"#include <ntfs.h>\n#include <stdio.h>\n"
    body = bytearray()
    body += b"\x00" + text[0:8]
    body += b"\x00" + text[8:16]
    body.append(0b00000100)
    body += text[16:18]
    body += struct.pack("<H", (17 << 11) | (10 - 3))   # (-18, 10) -> "#include <"
    body += b"stdio"
    body.append(0b00000001)
    body += struct.pack("<H", (18 << 10) | (4 - 3))    # (-19, 4)  -> ".h>\n"
    check("a three-width tuple sequence", agdb._lznt1(lznt1_chunk(bytes(body)), len(text)), text)

    # The boundary the specification is explicit about: the split changes when
    # (written - 1) >= 0x10, so at exactly 16 bytes written the shift is still 12. Writing it
    # as `written >= 0x10` decodes this case to the wrong bytes - which is what it did.
    literals = b"ABCDEFGHIJKLMNOP"
    body = bytearray(b"\x00" + literals[:8] + b"\x00" + literals[8:])
    body.append(0b00000001)
    body += struct.pack("<H", (15 << 12) | (4 - 3))    # (-16, 4)
    check("a back-reference at exactly 16 bytes written",
          agdb._lznt1(lznt1_chunk(bytes(body)), 20), literals + literals[:4])

    stored = b"the quick brown fox"
    check("an uncompressed chunk passes through",
          agdb._lznt1(lznt1_chunk(stored, compressed=False), len(stored)), stored)

    # And end to end, as a MEMO file: header, then LZNT1 chunks.
    payload = (b"\x0e\x00\x00\x00" + b"\x00" * 300)
    chunks = b""
    for start in range(0, len(payload), 4096):
        piece = payload[start:start + 4096]
        chunks += lznt1_chunk(piece, compressed=False)
    memo = b"MEMO" + struct.pack("<I", len(payload)) + chunks
    body_out, how = agdb.decompress(memo)
    check("a MEMO container decompresses to its declared size", len(body_out), len(payload))
    check("...and says the path is untested", "untested" in how, True)

    print("\nAgRobust-shaped databases: layouts nobody has documented, and sources:")
    # `AgRobust.db` is the one SuperFetch database documented to carry *process information
    # including prefetch hashes* - it would tie SuperFetch records to `.pf` files directly.
    # No public sample exists (searched: `AgRobust.db`, `AgGlFaultHistory`, `AgCx_SC1` - 92, 55
    # and 3 code hits, every one of them tooling or documentation, never a file). Its 64-bit
    # file entry is 112 bytes, which libyal's document marks TODO.
    #
    # So this is built to the documented *database* shape with an entry size no table covers,
    # and the parser is asked to find its way by verifying stored name hashes. That is a real
    # test of the probe, even though the bytes are synthetic: nothing here tells the parser
    # where the fields are.
    robust = _synthetic_agrobust([
        "\\WINDOWS\\SYSTEM32\\SVCHOST.EXE",
        "\\PROGRAM FILES\\SOMETHING\\APP.EXE",
    ], sources=[(0xDEADBEEF, 3)])
    db = agdb.parse(robust)
    check("an undocumented entry size still parses", db.method in ("structural", "scan"), True)
    check("...by matching a layout against the stored hashes",
          any("verifying stored name hashes" in p for p in db.problems), True)
    check("...and recovers the paths",
          sorted(f.path for v in db.volumes for f in v.files),
          ["\\PROGRAM FILES\\SOMETHING\\APP.EXE", "\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"])
    check("...with every hash verified", db.hash_verified, 2)
    check("source records are read", len(db.sources), 1)
    check("...carrying the hash the format documents", db.sources[0].name_hash, 0xDEADBEEF)
    check("...and its entry count", db.sources[0].entries, 3)

    # A database that declares sources it does not contain must say so, not invent them.
    truncated = robust[:len(robust) - 144]
    db = agdb.parse(truncated)
    check("a truncated source array is reported",
          any("run past the end" in p or "declares" in p for p in db.problems), True)

    print("\nmalformed input is a finding, never a crash:")
    bad = [
        b"", b"MEM0", b"MEM0" + b"\xff" * 8, b"MAM\x84", b"MAM\x84" + b"\x00" * 8,
        b"MEM\xb0" + b"\x00" * 16, b"MEMO" + b"\x00" * 16,
        b"\x03\x00\x00\x00" + b"\x00" * 100, b"\x0e\x00\x00\x00" + b"\xff" * 300,
        os.urandom(512), b"\x03\x00\x00\x00" + os.urandom(2048),
    ]
    crashes = 0
    for raw in bad:
        try:
            db = agdb.parse(raw)
        except Exception as exc:                              # noqa: BLE001 - that is the test
            crashes += 1
            failures.append(f"crash on {raw[:8]!r}: {type(exc).__name__}: {exc}")
            continue
        if db.method == "none" and not db.problems:
            failures.append(f"{raw[:8]!r}: parsed nothing and said nothing")
    check("no crashes across malformed inputs", crashes, 0)
    check("...and none of them reported an empty database silently",
          all(agdb.parse(r).problems or agdb.parse(r).paths for r in bad))

    print("\nmutated real databases: no crash, no hang, no silent empty:")
    # Crafted inputs above cover the shapes I thought of. Mutation covers the ones I did not:
    # these are real databases with bytes flipped in them, which is what a corrupt or planted
    # file looks like. Seeded, so a failure is reproducible.
    import random                                                    # noqa: PLC0415
    import time                                                      # noqa: PLC0415

    rng = random.Random(20260827)
    seeds = []
    for tag, name, *_rest in EXPECT:
        path = os.path.join(ROOTS[tag], name)
        if os.path.exists(path):
            seeds.append((os.path.basename(name), open(path, "rb").read()))
    crashes = slow = silent = 0
    mutations = 0
    for name, blob in seeds:
        for _ in range(40):
            data = bytearray(blob)
            style = rng.randrange(4)
            if style == 0:                                # flip bits anywhere
                for _ in range(rng.randrange(1, 8)):
                    data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            elif style == 1:                              # truncate
                data = data[:rng.randrange(1, len(data))]
            elif style == 2:                              # corrupt the header numbers
                for offset in (4, 8, 12, 16, 20, 52, 56):
                    if offset + 4 <= len(data) and rng.random() < 0.5:
                        struct.pack_into("<I", data, offset, rng.choice(
                            [0, 1, 0xFFFFFFFF, 0x7FFFFFFF, rng.randrange(1 << 32)]))
            else:                                         # splice in random bytes
                at = rng.randrange(max(1, len(data) - 64))
                data[at:at + 64] = os.urandom(64)
            mutations += 1
            started = time.perf_counter()
            try:
                db = agdb.parse(bytes(data))
            except Exception as exc:                      # noqa: BLE001 - that is the test
                crashes += 1
                failures.append(f"{name} mutation crashed: {type(exc).__name__}: {exc}")
                continue
            elapsed = time.perf_counter() - started
            if elapsed > 15:
                slow += 1
                failures.append(f"{name} mutation took {elapsed:.1f}s")
            # A mutated database may legitimately yield nothing - but it must say why.
            if not db.paths and not db.problems:
                silent += 1
                failures.append(f"{name} mutation returned nothing and reported nothing")
    check(f"{mutations} mutations: crashes", crashes, 0)
    check("...hangs", slow, 0)
    check("...silent empties", silent, 0)

    print("\na database that cannot be walked still yields its paths:")
    # A real header whose declared entry sizes are nonsense: the layout tables cannot match,
    # so the parser must fall back to the sweep rather than report nothing.
    body = bytearray(b"\x03\x00\x00\x00" + b"\x00" * 300)
    struct.pack_into("<I", body, 4, len(body))
    struct.pack_into("<I", body, 8, 80)
    struct.pack_into("<9I", body, 16, 999, 999, 999, 8, 8, 8, 8, 0, 0)
    struct.pack_into("<2I", body, 52, 1, 1)
    body += "\\WINDOWS\\SYSTEM32\\EVIL.DLL".encode("utf-16-le")
    struct.pack_into("<I", body, 4, len(body))
    db = agdb.parse(bytes(body))
    check("falls back to the sweep", db.method, "sweep")
    check("says why", any("undocumented entry sizes" in p for p in db.problems))
    check("and the path still reaches the analyst",
          any("EVIL.DLL" in p for p in db.paths))

    print("\nthe path-accounting check is real, not decorative:")
    # Drop a record from a parsed database and confirm the check notices the orphaned path.
    real = os.path.join(corpus.WIN11, "dynrespri.7db")
    data, _ = agdb.decompress(open(real, "rb").read())
    db = agdb.parse(open(real, "rb").read())
    dropped = db.volumes[0].files.pop()
    db.unaccounted_paths = []
    db.problems = []
    agdb._account_for_every_path(data, db)
    check("a dropped record is noticed", dropped.path in db.unaccounted_paths)
    check("and reported as a problem", any("belong to no parsed record" in p
                                           for p in db.problems))

    print("\nthe name hash is the documented one:")
    sample = "\\WINDOWS\\SYSTEM32\\SHLWAPI.DLL".encode("utf-16-le")
    entry = next(f for v in agdb.parse(open(real, "rb").read()).volumes for f in v.files
                 if f.path.upper().endswith("SYSTEM32\\SHLWAPI.DLL"))
    check("hash of a known path matches the file's own",
          agdb.name_hash(sample), entry.name_hash & 0xFFFFFFFF)
    check("a one-character change changes it",
          agdb.name_hash(sample) != agdb.name_hash(
              "\\WINDOWS\\SYSTEM32\\SHLWAPJ.DLL".encode("utf-16-le")))

    print("\nunrecognised files are reported, not dropped:")
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "mystery.bin"), "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        with open(os.path.join(tmp, "Layout.ini"), "wb") as fh:
            fh.write("[Files]\r\nC:\\WINDOWS\\X.DLL\r\n".encode("utf-16-le"))
        arts = scan_folder(tmp)
        kinds = {a.name: a.kind for a in arts}
        check("the unknown file appears", kinds.get("mystery.bin"), "unrecognised")
        check("the known one still parses", kinds.get("Layout.ini"), "layout")
        unknown = next(a for a in arts if a.kind == "unrecognised")
        check("it carries its magic", unknown.facts.get("first_bytes"),
              "89 50 4e 47 0d 0a 1a 0a")
        check("and says it was not parsed", bool(unknown.problems))

    print()
    if failures:
        for f in failures:
            print(f"FAILED: {f}")
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all SuperFetch checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
