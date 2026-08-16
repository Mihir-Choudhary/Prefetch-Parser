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
