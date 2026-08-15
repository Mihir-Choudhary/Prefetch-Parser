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
import random
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import parse  # noqa: E402
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

    # A harness that stops reaching the deep stages still reports a clean pass, which is how a
    # regression hides. Assert the mutations actually drive failures through every stage.
    want_stages = {"container", "signature", "fileinfo", "metrics",
                   "filenames", "exec_path", "volumes"}
    missing = want_stages - stages_hit
    print(f"  stages exercised: {len(stages_hit)}/{len(want_stages)}")
    if missing:
        print(f"   !! no mutation reached: {sorted(missing)} - the harness has gone weak")

    ok = not (crashes or slow or garbage or missing)
    print("\nPASS - no crashes, no hangs, no unflagged nonsense" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
