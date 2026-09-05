#!/usr/bin/env python3
"""ADS recovery logic, tested against a simulated stream backend.

ext4 has no alternate data streams, so the corpora cannot exercise this and the real
`FindFirstStreamW` path cannot run here. What *can* be verified is everything above the
syscall: stream classification, content-based detection, provenance flags, and - the part that
actually matters - that a carrier's timestamps are never presented as the prefetch's own.

The fake backend reproduces the real technique's shape exactly: a carrier whose primary stream
is **0 bytes** with a genuine prefetch file in a named stream. Real `.pf` bytes are used, so the
recovered records must parse identically to the same file read normally.

**Not covered here, and only a Windows run will cover it:** the ctypes `FindFirstStreamW` /
`FindNextStreamW` calls and the `path:stream` open syntax. That layer is thin and deliberately
isolated in `_Win32Backend` for exactly this reason.

Run:  python3 test_ads.py
"""

import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import ads, parse_file  # noqa: E402

REAL_PF = "" + corpus.WIN10 + "/7ZFM.EXE-7C92DCA0.pf"

failures = []


def check(label, got, want):
    ok = got == want
    print(f"  {label:58} {str(got):>10}{'' if ok else f'   << expected {want}'}")
    if not ok:
        failures.append(f"{label}: {got!r} != {want!r}")


class FakeBackend:
    """Simulates NTFS streams. `layout` maps carrier path -> {stream name: bytes}."""

    def __init__(self, layout):
        self.layout = layout

    def list_streams(self, path):
        if path not in self.layout:
            return []
        streams = []
        for name, blob in self.layout[path].items():
            full = "::$DATA" if name == "" else f":{name}:$DATA"
            streams.append(ads.Stream(path, full, len(blob)))
        return streams

    def read_stream(self, stream):
        return self.layout[stream.carrier_path][stream.short_name]


def main():
    corpus.require("WIN10")
    corpus.require_seed(REAL_PF)
    with open(REAL_PF, "rb") as fh:
        pf_bytes = fh.read()

    # The documented technique: a 0-byte text file carrying prefetch in a named stream.
    layout = {
        "/case/Prefetch/HOST.TXT": {"": b"", "PF.pf": pf_bytes},
        "/case/Prefetch/NORMAL.pf": {"": pf_bytes},                    # ordinary file
        "/case/Prefetch/DECOY.TXT": {"": b"hello", "notes": b"nothing here"},
        "/case/Users/bob/README.md": {"": b"# readme", "hidden": pf_bytes},
    }
    backend = FakeBackend(layout)

    print("stream classification:")
    streams = backend.list_streams("/case/Prefetch/HOST.TXT")
    primary = [s for s in streams if s.is_primary]
    named = [s for s in streams if not s.is_primary]
    check("primary stream identified", len(primary), 1)
    check("named stream identified", len(named), 1)
    check("short name strips the $DATA decoration", named[0].short_name, "PF.pf")
    check("open path uses file:stream syntax", named[0].open_path,
          "/case/Prefetch/HOST.TXT:PF.pf")
    check("primary stream is 0 bytes (the technique's shape)", primary[0].size, 0)

    print("\ncontent-based detection:")
    check("real prefetch bytes recognised", ads.looks_like_prefetch(pf_bytes[:8]), True)
    check("MAM container recognised", ads.looks_like_prefetch(b"MAM\\x04\\x00\\x00\\x00\\x00"), True)
    check("arbitrary text rejected", ads.looks_like_prefetch(b"nothing here"), False)

    print("\nscanning one carrier:")
    found = ads.scan_file("/case/Prefetch/HOST.TXT", backend,
                          prefetch_folder="/case/Prefetch")
    check("one finding from the carrier", len(found), 1)
    check("primary stream is never itself a finding",
          all(not f.stream.is_primary for f in found), True)
    check("0-byte primary noted, not treated as damage",
          any("0 bytes" in p for p in found[0].problems), True)
    check("carrier is not a .pf, and says so",
          any("not a .pf" in p for p in found[0].problems), True)

    print("\nnon-prefetch streams are ignored:")
    check("decoy carrier yields nothing",
          len(ads.scan_file("/case/Prefetch/DECOY.TXT", backend, "/case/Prefetch")), 0)
    check("an ordinary file with only a primary stream yields nothing",
          len(ads.scan_file("/case/Prefetch/NORMAL.pf", backend, "/case/Prefetch")), 0)

    print("\nprovenance - outside the Prefetch folder:")
    outside = ads.scan_file("/case/Users/bob/README.md", backend,
                            prefetch_folder="/case/Prefetch")
    check("prefetch found outside the folder", len(outside), 1)
    check("flagged as outside", outside[0].outside_prefetch_folder, True)
    check("in-folder finding is not flagged", found[0].outside_prefetch_folder, False)

    # Round 46. "Outside the Prefetch folder" is a claim in a report, and both ways of
    # deciding it were wrong. A false OUTSIDE fabricates a finding; a false INSIDE only omits a
    # flag from a record the analyst still reads in full - so where it is uncertain, inside.
    from prefetch_core.ads import _is_outside                          # noqa: PLC0415

    # BUG 93: NTFS is case-insensitive and both paths come off the same volume, but the
    # comparison was literal - so a folder recorded as `Prefetch` and a carrier path spelled
    # `prefetch` reported the file as recovered from OUTSIDE the Prefetch folder. A finding
    # produced by nothing but the spelling of a folder.
    check("a differently-cased folder is still the same folder",
          _is_outside("/case/Windows/prefetch/X.pf", "/case/Windows/Prefetch"), False)
    check("...and a sibling that merely starts the same is not",
          _is_outside("/case/Windows/Prefetch2/X.pf", "/case/Windows/Prefetch"), True)
    # BUG 94: with no folder given the test was `"\\prefetch" in path`, by substring. Any
    # folder called `prefetch` anywhere on the disk counted as THE Prefetch folder and
    # suppressed the flag - which is the one thing that makes an ADS-hosted prefetch
    # interesting in the first place.
    check("a user's own folder named prefetch is not the Prefetch folder",
          _is_outside(r"C:\Users\bob\Desktop\prefetch\evil.exe", None), True)
    check("...nor is PrefetchOld", _is_outside(r"C:\Windows\PrefetchOld\x.pf", None), True)
    check("the real one is recognised in any case",
          _is_outside(r"c:\windows\prefetch\x.pf", None), False)
    check("...through a UNC path", _is_outside(r"\\host\c$\Windows\Prefetch\x.pf", None), False)
    check("...and through a mounted image's path",
          _is_outside("/evidence/C/Windows/Prefetch/X.pf", None), False)

    print("\nTHE TIMESTAMP PROBLEM - the reason this module exists:")
    records = ads.parse_findings(found)
    pf = records[0]
    check("record marked as ADS-sourced", pf.from_ads, True)
    check("timestamp_source says 'carrier'", pf.timestamp_source, "carrier")
    # The critical assertion. A stream has no timestamps; NTFS keeps them per file. Putting the
    # carrier's creation time in source_created would feed the first-run estimate a time that
    # belongs to an unrelated event and print it as fact.
    check("source_created is NOT populated from the carrier", pf.source_created, None)
    check("first-run estimate refuses to guess", pf.first_run_approx, None)
    check("the caveat is stated on the record",
          any("CARRIER" in str(p) for p in pf.problems), True)
    check("carrier path recorded", pf.carrier_path, "/case/Prefetch/HOST.TXT")
    check("stream name recorded", pf.stream_name, "PF.pf")

    # An ADS record only means anything with its provenance attached. Until Round 45 neither
    # export carried any of it: the record landed in the same columns as an ordinary one while
    # holding the CARRIER's timestamps, with nothing to say so (AUDIT BUG 72).
    # One entry that refuses to be examined must cost that entry, not the scan. The Windows
    # backend raises OSError and was handled; the documented off-Windows backend is
    # `dissect.ntfs`, whose errors are its own types - and one of those ended the entire scan
    # with nothing reported at all (AUDIT BUG 81).
    print("\none unreadable entry costs that entry, not the scan:")
    import tempfile as _tf                                            # noqa: PLC0415

    class Rude:
        """Raises something that is not an OSError, the way a raw-image backend does."""

        def __init__(self, victim):
            self.victim = victim

        def list_streams(self, path):
            if os.path.basename(path) == self.victim:
                raise ValueError("corrupt MFT entry")
            return []

        def read_stream(self, stream):
            return b""

    tree = _tf.mkdtemp()
    for name in ("a.txt", "victim.txt", "b.txt"):
        with open(os.path.join(tree, name), "wb") as fh:
            fh.write(b"x")
    seen = []
    result = ads.scan_tree(tree, Rude("victim.txt"),
                           on_error=lambda p, e: seen.append((os.path.basename(p), e)))
    check("the scan completes", isinstance(result, list), True)
    check("the entry that refused is reported", [n for n, _e in seen], ["victim.txt"])
    check("...with the real reason, not a shrug",
          isinstance(seen[0][1], ValueError) if seen else False, True)
    # ...while a missing backend still stops the run: that is a property of the run, not of
    # one file, and swallowing it would be the false-clean this module exists to prevent.
    try:
        ads.scan_tree(tree, None)
        check("a missing backend still stops the run", False, True)
    except ads.AdsUnavailable:
        check("a missing backend still stops the run", True, True)

    print("\nthe provenance survives into both exports:")
    import sqlite3 as _sqlite3                                        # noqa: PLC0415
    import tempfile as _tempfile                                      # noqa: PLC0415
    import csv as _csv                                                # noqa: PLC0415

    from prefetch_core.store import Store as _Store                   # noqa: PLC0415
    from pfcli.__main__ import CSV_COLUMNS, row_for                   # noqa: PLC0415

    workdir = _tempfile.mkdtemp()
    db_path = os.path.join(workdir, "ads.db")
    with _Store(db_path) as st:
        st.add_all([pf, direct_for_export := parse_file(REAL_PF)])
    conn = _sqlite3.connect(db_path)
    conn.row_factory = _sqlite3.Row
    ads_row = conn.execute("SELECT * FROM prefetch WHERE from_ads = 1").fetchone()
    normal_row = conn.execute("SELECT * FROM prefetch WHERE from_ads = 0").fetchone()
    check("the database marks the record as ADS-sourced", ads_row is not None, True)
    check("...with the carrier file", ads_row["carrier_path"], "/case/Prefetch/HOST.TXT")
    check("...the stream name", ads_row["stream_name"], "PF.pf")
    check("...and whose timestamps these are", ads_row["timestamp_source"], "carrier")
    check("the carrier's modified time round-trips under its own name",
          ads_row["carrier_modified"],
          pf.carrier_modified.isoformat(sep=" ") if pf.carrier_modified else None)
    # The simulated carrier is not a real file, so os.stat gave it no times. Prove the column
    # actually carries one rather than passing because both sides are empty.
    stamped = ads.parse_findings(found)[0]
    stamped.carrier_modified = datetime.datetime(2026, 3, 4, 5, 6, 7,
                                                 tzinfo=datetime.timezone.utc)
    stamped_db = os.path.join(workdir, "stamped.db")
    with _Store(stamped_db) as st2:
        st2.add(stamped)
    scon = _sqlite3.connect(stamped_db)
    check("a carrier time that exists is stored",
          scon.execute("SELECT carrier_modified FROM prefetch").fetchone()[0],
          "2026-03-04 05:06:07+00:00")
    check("...and reaches the CSV too",
          row_for(stamped)["CarrierModified"], "2026-03-04 05:06:07+00:00")
    check("...and NOT as the prefetch file's own", ads_row["source_created"], None)
    check("no first-run estimate is invented for it", ads_row["source_created_est"], None)
    # An ordinary record has no carrier and no stream - but it does have an answer to "whose
    # timestamps are these?", and it is "the file's own". Holding NULL there conflated a
    # measured fact with "not measured" (AUDIT BUG 106).
    check("an ordinary record names no carrier", normal_row["carrier_path"], None)
    check("...and says its timestamps are its own",
          normal_row["timestamp_source"], "stream")
    check("...while the ADS record says they are the carrier's",
          ads_row["timestamp_source"], "carrier")

    csv_path = os.path.join(workdir, "ads.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = _csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerow(row_for(pf))
    exported = next(iter(_csv.DictReader(open(csv_path, newline="", encoding="utf-8"))))
    check("the CSV says the row came from a stream", exported["FromAds"], "1")
    check("...names the carrier", exported["CarrierPath"], "/case/Prefetch/HOST.TXT")
    check("...names the stream", exported["StreamName"], "PF.pf")
    check("...says whose timestamps it carries", exported["TimestampSource"], "carrier")
    check("...leaves the prefetch file's own creation empty", exported["SourceCreated"], "")
    check("...and offers no first-run estimate", exported["FirstRunApprox"], "")

    print("\nrecovered record parses identically to the same file read normally:")
    direct = parse_file(REAL_PF)
    check("executable name", pf.executable_name, direct.executable_name)
    check("hash", pf.hash, direct.hash)
    check("run count", pf.run_count, direct.run_count)
    check("run times", pf.run_times, direct.run_times)
    check("executable path", pf.executable_path, direct.executable_path)
    check("loaded file count", len(pf.filenames), len(direct.filenames))

    print("\na normal record still reports its own timestamps:")
    check("normal record is not ADS-sourced", direct.from_ads, False)
    check("normal timestamp_source is 'stream'", direct.timestamp_source, "stream")

    print("\nfirst-run estimate on a normal record with a real birth time:")
    synthetic = parse_file(REAL_PF)
    synthetic.source_created = datetime.datetime(2026, 1, 1, 12, 0, 30,
                                                 tzinfo=datetime.timezone.utc)
    check("estimate subtracts the 10 s write lag", synthetic.first_run_approx,
          datetime.datetime(2026, 1, 1, 12, 0, 20, tzinfo=datetime.timezone.utc))

    print("\nunavailability is reported, never silently empty:")
    # "Cannot look for streams" and "looked and found nothing" are different answers; only one
    # of them is evidence. Returning [] for both is how a tool tells an analyst a machine is
    # clean when it never checked.
    try:
        ads.scan_file("/case/Prefetch/HOST.TXT", backend=None)
        got = "returned normally"
    except ads.AdsUnavailable:
        got = "raised AdsUnavailable"
    except Exception as exc:                      # pragma: no cover
        got = f"raised {type(exc).__name__}"
    # On a Windows host a backend exists, so the call would legitimately succeed.
    check("no backend -> explicit failure",
          got in ("raised AdsUnavailable", "returned normally")
          and (got == "raised AdsUnavailable" or ads.backend_available()), True)

    print("\nunreadable stream still produces a record:")
    class Broken(FakeBackend):
        def read_stream(self, stream):
            raise OSError(5, "Access is denied")

    broken = ads.scan_file("/case/Prefetch/HOST.TXT", Broken(layout), "/case/Prefetch")
    check("a finding is still emitted", len(broken), 1)
    check("timestamp_source is 'unavailable'", broken[0].timestamp_source.value, "unavailable")
    check("the error is recorded",
          any("could not be read" in p for p in broken[0].problems), True)

    print("\nscan_tree visits each entry exactly once:")
    import collections
    import tempfile
    visited = []

    class Spy:
        def list_streams(self, path):
            visited.append(path)
            return []

        def read_stream(self, stream):
            return b""

    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "a", "b"))
    for rel in ("f1.txt", os.path.join("a", "f2.txt")):
        with open(os.path.join(root, rel), "w") as fh:
            fh.write("x")
    ads.scan_tree(root, Spy())
    dupes = {p: c for p, c in collections.Counter(visited).items() if c > 1}
    # os.walk yields every directory as `dirpath` once. Also scanning `dirnames` revisited each
    # subdirectory a second time, so every directory-hosted finding was reported twice.
    check("no path scanned twice", dupes, {})
    check("every directory still covered",
          {os.path.relpath(p, root) for p in visited} >= {".", "a", os.path.join("a", "b")},
          True)
    check("files covered too",
          {os.path.relpath(p, root) for p in visited} >= {"f1.txt", os.path.join("a", "f2.txt")},
          True)

    visited.clear()
    ads.scan_tree(root, Spy(), include_directories=False)
    check("--files-only skips directories",
          any(os.path.isdir(p) for p in visited), False)

    print("\noversized streams are refused, not read:")
    huge = {"/case/BIG.TXT": {"": b"", "payload": b"x"}}

    class LyingSize(FakeBackend):
        def list_streams(self, path):
            return [ads.Stream(path, "::$DATA", 0),
                    ads.Stream(path, ":payload:$DATA", ads.MAX_STREAM_BYTES + 1)]

        def read_stream(self, stream):        # must never be reached
            raise AssertionError("read_stream called on an oversized stream")

    big = ads.scan_file("/case/BIG.TXT", LyingSize(huge), "/case")
    check("a record is still produced", len(big), 1)
    check("it is marked unavailable", big[0].timestamp_source.value, "unavailable")
    check("the ceiling is explained",
          any("ceiling" in p for p in big[0].problems), True)

    # The mirror case, which the size check alone cannot catch: a stream that UNDER-declares
    # its size passes the pre-read gate and then hands back more than the ceiling. On a raw
    # image the declared size is attacker-supplied, so it cannot be the only guard.
    print("\na stream that under-declares its size is caught after the read:")

    class UnderDeclared(FakeBackend):
        def list_streams(self, path):
            return [ads.Stream(path, "::$DATA", 0),
                    ads.Stream(path, ":payload:$DATA", 10)]      # claims 10 bytes

        def read_stream(self, stream):
            return b"MAM\x84" + b"x" * ads.MAX_STREAM_BYTES      # delivers far more

    lied = ads.scan_file("/case/BIG.TXT", UnderDeclared(huge), "/case")
    check("a record is still produced", len(lied), 1)
    check("the oversized read is refused, not parsed",
          any("ceiling" in p for p in lied[0].problems), True)
    check("the declared/actual mismatch is reported",
          any("declared" in p for p in lied[0].problems), True)

    print("\na path that cannot be walked is not reported as a clean scan:")
    # os.walk yields nothing for a missing path or a file, so scan_tree used to return 0
    # findings and the CLI printed "scanned X: no prefetch found in any alternate data stream".
    # Off Windows the missing backend hid this; with a backend present it is reachable, and a
    # false clean is the worst possible answer when hunting deliberately hidden evidence.
    import tempfile as _tf2
    walkable = _tf2.mkdtemp()
    for label, target, expected in (
        ("a missing folder", os.path.join(walkable, "nope"), FileNotFoundError),
        ("a file, not a folder", __file__, NotADirectoryError),
    ):
        try:
            ads.scan_tree(target, FakeBackend({}))
            check(f"{label} raises rather than reporting clean", False, "returned quietly")
        except expected:
            check(f"{label} raises rather than reporting clean", True, True)
        except Exception as exc:  # noqa: BLE001 - wrong type is itself the failure
            check(f"{label} raises rather than reporting clean", False,
                  f"{type(exc).__name__}: {exc}")
    got = ads.scan_tree(walkable, FakeBackend({}))
    check("a real empty folder still scans cleanly", got, [])

    print("\nstream enumeration tells end-of-list apart from a failure:")
    # FindNextStreamW returns FALSE both at the end of the list and on a real error, and the
    # two are only distinguishable by GetLastError. Treating every FALSE as the end silently
    # truncates the stream list - in the routine whose entire job is finding hidden streams.
    import ctypes as _ct
    from unittest.mock import patch as _patch2
    _SD = ads._Win32Backend._WIN32_FIND_STREAM_DATA

    class _StubK32:
        def __init__(self, stop_after):
            self.n = 0
            self.stop_after = stop_after

        def FindFirstStreamW(self, path, level, buf, flags):
            d = _ct.cast(buf, _ct.POINTER(_SD)).contents
            d.StreamSize, d.cStreamName = 0, "::$DATA"
            return 1234

        def FindNextStreamW(self, handle, buf):
            self.n += 1
            if self.n > self.stop_after:
                return False
            d = _ct.cast(buf, _ct.POINTER(_SD)).contents
            d.StreamSize, d.cStreamName = 100, f":hidden{self.n}:$DATA"
            return True

        def FindClose(self, handle):
            return True

    backend32 = object.__new__(ads._Win32Backend)
    backend32.kernel32 = _StubK32(stop_after=2)
    with _patch2.object(ads, "_get_last_error", lambda: 38):        # ERROR_HANDLE_EOF
        got = backend32.list_streams(r"C:\case\HOST.TXT")
    check("a genuine end of list returns every stream", len(got), 3)

    backend32 = object.__new__(ads._Win32Backend)
    backend32.kernel32 = _StubK32(stop_after=2)
    with _patch2.object(ads, "_get_last_error", lambda: 5):         # ERROR_ACCESS_DENIED
        try:
            backend32.list_streams(r"C:\case\HOST.TXT")
            check("a mid-enumeration failure raises", False, "returned a truncated list")
        except OSError as exc:
            # On Windows the four-argument OSError maps winerror onto errno (5 -> EACCES), so
            # the Win32 code lives in `winerror` there and in `errno` here. Assert the one the
            # platform actually carries, or the suite reports a defect on its first Windows run
            # that is nothing but a platform difference.
            check("a mid-enumeration failure raises",
                  getattr(exc, "winerror", None) or exc.errno, 5)

    print("\nentries that refuse enumeration are reported, not silently skipped:")
    # On a live system these are the in-use and ACL-restricted files - exactly where a payload
    # would be hidden. Skipping them quietly turns "could not examine N files" into "clean".
    import tempfile as _tf4
    walk_dir = _tf4.mkdtemp()
    for _n in ("a.txt", "b.txt", "c.txt"):
        with open(os.path.join(walk_dir, _n), "w") as _fh:
            _fh.write("x")

    class _Flaky(FakeBackend):
        def list_streams(self, path):
            if path.endswith("b.txt"):
                raise OSError(5, "Access is denied")
            return []

    noticed = []
    ads.scan_tree(walk_dir, _Flaky({}), on_error=lambda p, e: noticed.append(p))
    check("the unreadable entry is surfaced", len(noticed), 1)
    check("and it is the right one", os.path.basename(noticed[0]) if noticed else "", "b.txt")
    check("the walk still completes past it",
          ads.scan_tree(walk_dir, _Flaky({})), [])

    print("\ncreation time is read correctly per platform:")
    from prefetch_core.winpath import creation_time
    from unittest.mock import patch as _p

    class _Stat:
        st_ctime = 1700000000.0

    class _StatBirth(_Stat):
        st_birthtime = 1700000000.0

    # On Linux st_ctime is inode-change time and must never be used as creation.
    check("linux without birthtime yields None", creation_time(_Stat()), None)
    check("birthtime is used where present", creation_time(_StatBirth()) is not None, True)
    # Windows before Python 3.12 has no st_birthtime; creation time lives in st_ctime. Reading
    # only st_birthtime made source_created None on the target platform, silently disabling
    # the first-run estimate.
    with _p("sys.platform", "win32"):
        check("windows falls back to st_ctime", creation_time(_Stat()) is not None, True)

    print("\nimage backend is reachable for off-Windows analysis:")
    check("NtfsImageBackend is public", hasattr(ads, "NtfsImageBackend"), True)

    print("\nPASS" if not failures else "\nFAIL:")
    for f in failures:
        print(f"   {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
