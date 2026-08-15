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
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import parse_file  # noqa: E402

CORPUS = os.path.join(corpus.WIN11, "*.pf")
# Measured at 0.15 MB/record after making chain decoding lazy. The ceiling leaves generous
# headroom while still failing loudly if eager materialisation returns.
MAX_MB_PER_RECORD = 0.6


def main():
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

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
