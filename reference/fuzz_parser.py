#!/usr/bin/env python3
"""Robustness harness: malformed input must never crash and must always yield a record.

The contract `prefetch_core` promises (design doc D10) is that **every input produces a row**.
A parse failure carries the source path, the stage that failed, and whatever was recovered
before it. That is only true if it is tested, because the failure modes that matter are the
ones nobody writes a happy-path test for.

Three ways a parser can be wrong here, in increasing order of nastiness:

  1. crash          - raises out of parse(). Loud, easy to spot, least dangerous.
  2. hang / blowup  - a huge count field makes it allocate forever. Looks like a hang.
  3. silent garbage - returns a confident-looking record built from out-of-bounds reads.
                      This is the one that puts a wrong path in a report.

Every mutation below is checked for all three.

Run:  python3 fuzz_parser.py
"""

import glob
import os
import shutil
import random
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import parse, parse_file  # noqa: E402
from prefetch_core.container import is_container  # noqa: E402
from prefetch_core import container as container_mod  # noqa: E402

SEEDS = [
    os.path.join(HERE, "pf-corpus", "Win10", "*.pf"),
    os.path.join(HERE, "pf-corpus", "Vista", "*.pf"),
    os.path.join(HERE, "pf-corpus", "WinXP", "*.pf"),
    os.path.join(corpus.WIN10, "*.pf"),
]
PER_FILE_TIMEOUT = 5.0          # seconds; anything slower is a pathological-allocation bug


def decompressed_seeds(limit=12):
    """Return decompressed bodies, so mutations hit the SCCA structure not the MAM envelope."""
    out = []
    for pattern in SEEDS:
        for p in sorted(glob.glob(pattern))[:6]:
            raw = open(p, "rb").read()
            try:
                body = container_mod.load(raw) if is_container(raw) else raw
            except Exception:
                continue
            if body[4:8] == b"SCCA":
                out.append((os.path.basename(p), body))
            if len(out) >= limit:
                return out
    return out


def mutations(name, body):
    """Yield (label, bytes). Targeted mutations first, then random corruption."""
    yield "empty", b""
    yield "one_byte", b"\x00"
    yield "header_only", body[:84]
    yield "signature_broken", body[:4] + b"XXXX" + body[8:]
    for v in (0, 1, 16, 18, 24, 27, 29, 32, 99, 0xFFFFFFFF):
        yield f"version_{v}", struct.pack("<I", v) + body[4:]

    # Truncate at every plausible section boundary and a few arbitrary points.
    for frac in (0.05, 0.25, 0.5, 0.75, 0.9, 0.99):
        n = int(len(body) * frac)
        yield f"truncate_{int(frac * 100)}pct", body[:n]
    for n in (84, 85, 88, 296, 304):
        if n < len(body):
            yield f"truncate_at_{n}", body[:n]

    # Poison the file-information section's offsets and counts. These drive every subsequent
    # read, so a missing bounds check shows up here as an out-of-range access or a huge loop.
    fields = {
        0: "metrics_offset", 4: "metrics_count", 8: "chains_offset", 12: "chains_count",
        16: "names_offset", 20: "names_size", 24: "vols_offset", 28: "vol_count",
    }
    for off, label in fields.items():
        for value in (0, 1, 0x7FFFFFFF, 0xFFFFFFFF, len(body) + 1, len(body) * 4):
            m = bytearray(body)
            struct.pack_into("<I", m, 84 + off, value & 0xFFFFFFFF)
            yield f"{label}={value:#x}", bytes(m)

    # Volume records: the second layer of offsets, reached only if the first layer survives.
    for off in (0, 4, 20, 24, 28, 32):
        m = bytearray(body)
        vols_offset = struct.unpack_from("<I", body, 84 + 24)[0]
        if vols_offset + 36 < len(m):
            struct.pack_into("<I", m, vols_offset + off, 0xFFFFFF)
            yield f"volume_field_{off}_huge", bytes(m)

    # MAM envelope lies: wrong declared size, bad flags, truncated payload.
    yield "mam_bogus", b"MAM\x04" + struct.pack("<I", 0x7FFFFFFF) + body[:64]
    yield "mam_zero_size", b"MAM\x04" + struct.pack("<I", 0) + body[:64]
    yield "mam_flag80_short", b"MAM\x84" + struct.pack("<I", 4096) + b"\x00" * 4

    rng = random.Random(0xC0FFEE)      # fixed seed: failures must be reproducible
    for i in range(40):
        m = bytearray(body)
        for _ in range(rng.randint(1, 24)):
            m[rng.randrange(len(m))] = rng.randrange(256)
        yield f"random_{i}", bytes(m)


def main():
    # The vendored files are uncompressed; only the real corpora exercise MAM containers.
    corpus.require("WIN10")
    seeds = decompressed_seeds()
    if not seeds:
        print("!! no seed files found", file=sys.stderr)
        return 1
    print(f"seeds: {len(seeds)}")

    crashes, slow, garbage = [], [], []
    stages_hit = set()
    total = 0

    for name, body in seeds:
        for label, data in mutations(name, body):
            total += 1
            start = time.monotonic()
            try:
                pf = parse(data, source_path=f"{name}#{label}")
            except Exception as exc:            # the contract says this cannot happen
                crashes.append((name, label, f"{type(exc).__name__}: {exc}"))
                continue
            elapsed = time.monotonic() - start
            if elapsed > PER_FILE_TIMEOUT:
                slow.append((name, label, f"{elapsed:.1f}s"))

            if pf.failed_stage:
                stages_hit.add(pf.failed_stage)

            # Silent-garbage checks. A record that claims success must be internally coherent;
            # anything incoherent should have been flagged as a problem or a failed stage.
            if pf.parsed_ok:
                bad = None
                if pf.run_count < 0:
                    bad = f"negative run_count {pf.run_count}"
                elif len(pf.run_times) > 8:
                    bad = f"{len(pf.run_times)} run times (max is 8)"
                elif any(len(v.directories) > 100_000 for v in pf.volumes):
                    bad = "absurd directory count"
                elif len(pf.filenames) > 200_000:
                    bad = f"{len(pf.filenames)} filenames"
                elif pf.executable_path and "\x00" in pf.executable_path:
                    bad = "NUL inside resolved executable path"
                if bad and not pf.problems:
                    garbage.append((name, label, bad))

    print(f"mutations: {total}")
    print(f"  crashes        : {len(crashes)}")
    print(f"  slow (>{PER_FILE_TIMEOUT:g}s)   : {len(slow)}")
    print(f"  silent garbage : {len(garbage)}")
    for title, items in (("CRASH", crashes), ("SLOW", slow), ("GARBAGE", garbage)):
        for it in items[:10]:
            print(f"   {title}: {it[0]} [{it[1]}] {it[2]}")

    # A planted file far larger than any real prefetch must cost one row, not the run. The
    # released build read it whole and died with MemoryError, taking every other record with it
    # (AUDIT BUG 77). The file here is sparse, so it costs 4 KB of disk to test 4 GB of claim.
    print("\na planted oversize file costs one row, not the run:")
    import subprocess as _sp                                          # noqa: PLC0415
    import tempfile as _tempfile                                      # noqa: PLC0415

    from prefetch_core import limits as _limits                       # noqa: PLC0415

    folder = _tempfile.mkdtemp()
    import glob as _glob                                              # noqa: PLC0415
    real = sorted(_glob.glob(os.path.join(corpus.WIN10, "*.pf")))[0]
    shutil.copyfile(real, os.path.join(folder, os.path.basename(real)))
    huge = os.path.join(folder, "HUGE.EXE-DEADBEEF.pf")
    with open(huge, "wb") as fh:
        fh.write(b"\x1e\x00\x00\x00SCCA")
        fh.truncate(_limits.MAX_PREFETCH_BYTES * 4)
    record = parse_file(huge)
    over_ok = (not record.parsed_ok and record.failed_stage == "read"
               and any("ceiling" in str(p) for p in record.problems))
    print(f"  the oversize file becomes a failed record that says why: {over_ok}")
    run = _sp.run([sys.executable, "-m", "pfcli", "parse", folder],
                  cwd=os.path.dirname(HERE), capture_output=True, text=True, timeout=300)
    # The summary line goes to stderr; the rows go to stdout. Check both, and check the run
    # did not die on the way (the released build ended in a MemoryError traceback).
    output = run.stdout + run.stderr
    survived = ("2 file(s), 1 failed to parse" in output and "MemoryError" not in output
                and "Traceback" not in output)
    print(f"  the rest of the folder still parses: {survived}")
    ok_oversize = over_ok and survived

    # Round 46. A collected Prefetch folder does not only contain files. A FIFO left by a
    # collection script, a device node from a mounted image, something planted: `st_size` lies
    # about every one of them - /dev/zero reports 0 - so the ceiling above passed and the read
    # that followed was UNBOUNDED. The process grew until the OS killed it: no row, no exit
    # code, no report, and the analyst's session gone with it (AUDIT BUG 96). Opening a FIFO
    # never gets that far - it blocks forever waiting for a writer, and the scan hangs.
    #
    # Run under a hard 512 MB address-space cap in a subprocess: a regression here must fail
    # this check, not take the machine down with it.
    print("\n  a folder that contains things which are not files:")
    # The hazard is the same on both platforms - a path that is not an ordinary file, whose
    # size says nothing about how much it will read - but nothing about how to *create* one is
    # portable. POSIX: a FIFO and a symlink to /dev/zero. Windows: `os.mkfifo` does not exist,
    # /dev/zero does not exist, and `os.symlink` needs Developer Mode or elevation - but the
    # reserved device names do the job better, because `C:\...\NUL.pf` IS a character device to
    # every Win32 API, needs no privilege, and is exactly what a collected folder can contain.
    # A probe that raises AttributeError on its first Windows run would report a defect that is
    # nothing but a platform difference.
    probe = r"""
import os, sys, tempfile
if os.name != "nt":
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
sys.path.insert(0, %r)
from prefetch_core import parse_file
from prefetch_core.artifacts import scan_folder

work = tempfile.mkdtemp()
if os.name == "nt":
    # A reserved device name resolves to the device wherever it appears, extension and all, so
    # `NUL.pf` needs no privilege to "create" and is exactly what a collected folder can hold.
    pf_path = os.path.join(work, "NUL.pf")
    expected = {"PfPre_CON.mkd": "character device"}
else:
    os.mkfifo(os.path.join(work, "PfPre_fifo.mkd"))
    os.symlink("/dev/zero", os.path.join(work, "Trace9.fx"))
    os.symlink("/dev/zero", os.path.join(work, "ZERO.EXE-DEADBEEF.pf"))
    pf_path = os.path.join(work, "ZERO.EXE-DEADBEEF.pf")
    expected = {"PfPre_fifo.mkd": "FIFO", "Trace9.fx": "character device"}

rec = parse_file(pf_path)
assert not rec.parsed_ok and rec.failed_stage == "read", rec.failed_stage
assert any("not a regular file" in str(p) for p in rec.problems), rec.problems

found = {a.name: [str(p) for p in a.problems] for a in scan_folder(work)}
for name, want in expected.items():
    if os.name == "nt" and name not in found:
        continue          # a device name cannot always be listed as a directory entry
    assert name in found and want in found[name][0], (name, found)
print("OK")
""" % (os.path.dirname(HERE),)
    devnodes = _sp.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120)
    nodes_ok = devnodes.returncode == 0 and "OK" in devnodes.stdout
    print(f"    a FIFO and a device node are reported, not read: {nodes_ok}")
    if not nodes_ok:
        print("    !! " + (devnodes.stderr.strip().splitlines() or ["no output"])[-1][:200])

    # Round 48. `container.decompress()` is public, and for a malformed stream it let the pure
    # decoder's own exception type escape - an exception from an internal module that no
    # documented contract mentions, so a crafted container could reach a caller as something
    # other than the one error type this package promises (AUDIT BUG 104). `parse_file` was
    # never affected: it goes through `load()`, which converted it. The boundary now does.
    print("\n  the public container API raises only PrefetchError:")
    import struct as _struct                                          # noqa: PLC0415

    from prefetch_core import container as _container                 # noqa: PLC0415
    from prefetch_core.errors import PrefetchError as _PrefetchError   # noqa: PLC0415

    mam = None
    import glob as _glob2                                             # noqa: PLC0415
    for candidate in sorted(_glob2.glob(os.path.join(corpus.WIN10, "*.pf"))):
        with open(candidate, "rb") as fh:
            blob = fh.read()
        if blob[:3] == b"MAM":
            mam = blob
            break
    escapes = []
    if mam:
        cases = {"a declared size the stream cannot fill": 64 * 1024 * 1024,
                 "a declared size of zero": 0,
                 "one byte more than the stream holds": None}
        for label, declared in cases.items():
            crafted = bytearray(mam)
            if declared is None:
                declared = _struct.unpack_from("<I", crafted, 4)[0] + 1
            _struct.pack_into("<I", crafted, 4, declared)
            try:
                _container.decompress(bytes(crafted), prefer="pure")
            except _PrefetchError:
                pass
            except Exception as exc:                                  # noqa: BLE001
                escapes.append(f"{label}: {type(exc).__name__}")
        # ...and the same through the wrapper, which callers use.
        for cut in (12, 40, len(mam) // 2):
            try:
                _container.load(mam[:cut], prefer="pure")
            except _PrefetchError:
                pass
            except Exception as exc:                                  # noqa: BLE001
                escapes.append(f"load(truncated at {cut}): {type(exc).__name__}")
    print(f"    exceptions escaping the container API: {escapes or 'none'}")
    container_ok = not escapes and mam is not None

    # A harness that stops reaching the deep stages still reports a clean pass, which is how a
    # regression hides. Assert the mutations actually drive failures through every stage.
    want_stages = {"container", "signature", "fileinfo", "metrics",
                   "filenames", "exec_path", "volumes"}
    missing = want_stages - stages_hit
    print(f"  stages exercised: {len(stages_hit)}/{len(want_stages)}")
    if missing:
        print(f"   !! no mutation reached: {sorted(missing)} - the harness has gone weak")

    ok = (not (crashes or slow or garbage or missing) and ok_oversize and nodes_ok
          and container_ok)
    print("\nPASS - no crashes, no hangs, no unflagged nonsense" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
