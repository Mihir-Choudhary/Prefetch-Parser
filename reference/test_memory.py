#!/usr/bin/env python3
"""Memory ceiling: parsing a full Prefetch folder must not need gigabytes.

Windows caps the folder at 1,024 prefetch files. An earlier build materialised every
trace-chain entry as an object - up to ~15,000 per file - which cost 3.1 MB per record and put
a full folder near 3 GB. That is an out-of-memory crash on a modest analyst machine, and the
kind of regression that reappears the moment someone makes `trace_chains` eager again for
convenience.

Run:  python3 test_memory.py
"""

import glob
import os
import resource
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import parse_file  # noqa: E402

CORPUS = os.path.join(corpus.WIN11, "*.pf")
# Measured at 0.15 MB/record after making chain decoding lazy. The ceiling leaves generous
# headroom while still failing loudly if eager materialisation returns.
MAX_MB_PER_RECORD = 0.6


def main():
    corpus.require("WIN11")
    files = sorted(glob.glob(CORPUS))
    if not files:
        print("!! no corpus files", file=sys.stderr)
        return 1

    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    records = [parse_file(f) for f in files]
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    per = (after - before) / len(records)

    print(f"{len(records)} records: peak RSS {before:.0f} -> {after:.0f} MB "
          f"({per:.2f} MB/record, ceiling {MAX_MB_PER_RECORD})")
    projected = per * 1024
    print(f"  projected for a full 1,024-file folder: {projected:.0f} MB")

    ok = per <= MAX_MB_PER_RECORD

    # Lazy decoding must still be correct, not just cheap.
    with_chains = [r for r in records if r.trace_chain_count > 0]
    if with_chains:
        sample = max(with_chains, key=lambda r: r.trace_chain_count)
        decoded = sample.trace_chains
        match = len(decoded) == sample.trace_chain_count
        print(f"  lazy decode of {sample.trace_chain_count} chains correct: {match}")
        ok &= match
        # Decoding twice must give equal results - a cached-wrong or consumed-iterator bug.
        ok &= len(sample.trace_chains) == len(decoded)

    # A record carrying a large residue must cost no more than one carrying none. The residue
    # caps live in scca.py, but the ceiling lives here, and until this check existed the suite
    # that owns the ceiling had never seen a file with more than ~20 bytes of residue in it
    # (BUG 61: the region count was capped and the retained bytes were not).
    print("\na file with a megabyte of residue stays inside the same ceiling:")
    seed = os.path.join(os.path.dirname(HERE), "reference", "pf-corpus", "XPPro",
                        "CALC.EXE-02CD573A.pf")
    with open(seed, "rb") as fh:
        body = fh.read()
    with tempfile.TemporaryDirectory() as tmp:
        crafted = os.path.join(tmp, "RESIDUE.EXE-0BADF00D.pf")
        with open(crafted, "wb") as fh:
            fh.write(body + b"\x41" * (1 << 20))     # a megabyte belonging to no field
        record = parse_file(crafted)
        retained = sum(len(r.data) for r in record.residue)
        print(f"  residue found {record.residue_bytes:,} bytes, retained {retained:,}")
        ok &= record.parsed_ok
        ok &= record.residue_bytes >= (1 << 20)      # the finding is reported in full...
        ok &= retained <= 64 * 1024                  # ...and the copy is bounded
        print(f"  reported in full: {record.residue_bytes >= (1 << 20)}, "
              f"retained bounded: {retained <= 64 * 1024}")

        # ...and it must not reach the database as a megabyte of BLOBs either.
        from prefetch_core import store                                # noqa: PLC0415

        db_path = os.path.join(tmp, "out.db")
        db = store.Store(db_path)
        db.add(record)
        db.close()
        with sqlite3.connect(db_path) as conn:
            rows, blob = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(bytes)), 0) FROM residue").fetchone()
        print(f"  database holds {rows} residue row(s), {blob:,} bytes")
        ok &= blob <= 64 * 1024

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
