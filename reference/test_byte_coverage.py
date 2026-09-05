#!/usr/bin/env python3
"""Prove the parser reads the file - all of it - rather than the parts it has fields for.

"Nothing an investigator needs is missed" is a claim about *bytes*, and until this suite
existed nothing checked it. Instrumenting the bounds-checked reader answers it directly: every
field read goes through `Bounds.check`, so recording those calls gives the exact set of bytes
the parser looked at, and the complement is what it walked past.

The first run of this instrument found **3-5% of every file unread**, in two patterns:

  * 12 bytes of every 32-byte file-metric entry. Those dwords are called "unknown" by every
    published description. They are not unknown: measured across 284 files spanning all five
    versions, the first two are the file's own slice of the trace-chain array - they sum to the
    chain count and the last slice ends exactly on it, so the slices tile the array with no gap
    and no overlap. That is the only link between a loaded file and the prefetcher's block-load
    bookkeeping, and it was being thrown away.
  * the undocumented tail of the file-information section, of the 84-byte header, and of every
    volume entry - all populated on real files.

Reading them took the unread share from ~3-5% to **under 0.2%**, and what is left is alignment
padding. This suite pins that:

  1. no NON-ZERO byte outside the known padding regions goes unread;
  2. the per-file unread budget stays small, per version;
  3. the trace-chain slices still tile the array exactly, on every corpus file;
  4. the raw regions are retained on the record, so even undecoded bytes remain recoverable;
  5. reference-shaped values in the array slack are recovered and kept separate.

Run:  python3 test_byte_coverage.py
"""

import collections
import glob
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import container, errors, parse_file  # noqa: E402

failures = []

# Per-version ceiling on unread bytes per file, with headroom over what is measured today.
# Alignment padding only: a real field stopping being read blows straight through these.
UNREAD_BUDGET = {17: 64, 23: 192, 26: 128, 30: 128, 31: 128}


def check(label, got, want=True):
    ok = got == want
    print(f"  {label:<58} {'ok' if ok else 'FAIL'}"
          + ("" if ok else f"  got {got!r} want {want!r}"))
    if not ok:
        failures.append(label)


class Recorder:
    """Wraps Bounds.check so every field read is logged as a byte range."""

    def __init__(self):
        self.spans = []
        self._original = errors.Bounds.check

    def __enter__(self):
        spans = self.spans
        original = self._original

        def recording(bounds, offset, length, what):
            original(bounds, offset, length, what)
            if length > 0:
                spans.append((offset, offset + length))

        errors.Bounds.check = recording
        return self

    def __exit__(self, *exc):
        errors.Bounds.check = self._original

    def coverage(self, size):
        seen = bytearray(size)
        for start, end in self.spans:
            for i in range(max(0, start), min(size, end)):
                seen[i] = 1
        return seen


def body(path):
    raw = open(path, "rb").read()
    return container.load(raw) if container.is_container(raw) else raw


def sample_files():
    """A spread across every version, from both real corpora and the vendored samples."""
    picks = []
    for pattern, limit in (
        (os.path.join(corpus.WIN11, "*.pf"), 40),
        (os.path.join(corpus.WIN10, "*.pf"), 25),
        (os.path.join(corpus.SAMPLES, "plaso", "winprefetch", "*.pf"), 20),
        (os.path.join(HERE, "pf-corpus", "**", "*.pf"), 60),
    ):
        picks.extend(sorted(glob.glob(pattern, recursive=True))[:limit])
    return picks


def main():
    # Corpora only. The byte-coverage guarantee is about the corpora; tying it to the
    # downloaded samples would lose the whole sweep on a machine that has the real
    # prefetch but not the download.
    corpus.require("WIN10", "WIN11")
    files = sample_files()
    print(f"instrumenting {len(files)} files\n")

    by_version = collections.Counter()
    unread_by_version = collections.Counter()
    worst = []
    nonzero_unread = []
    chain_mismatch = []
    missing_raw = []

    for path in files:
        try:
            data = body(path)
        except Exception:                                   # noqa: BLE001
            continue
        with Recorder() as rec:
            pf = parse_file(path)
        if not pf.parsed_ok:
            continue
        by_version[pf.version] += 1

        seen = rec.coverage(len(data))
        unread = [i for i, flag in enumerate(seen) if not flag]
        unread_by_version[pf.version] = max(unread_by_version[pf.version], len(unread))
        worst.append((len(unread), os.path.basename(path), pf.version))

        # Padding is zero. A non-zero byte must be either read by a field or reported as
        # residue - "the parser looked at it" and "the analyst is told about it" are the two
        # acceptable outcomes, and silence is not one of them.
        reported = set()
        for region in pf.residue:
            reported.update(range(region.offset, region.offset + region.size))
        stray = [i for i in unread if data[i] and i not in reported]
        if stray:
            nonzero_unread.append((os.path.basename(path), pf.version, len(stray),
                                   data[stray[0]:stray[0] + 8].hex(" ")))

        # The metric slices must still tile the trace-chain array.
        if pf.metrics and pf.trace_chain_count:
            covered = sum(m.chain_count for m in pf.metrics)
            end = pf.metrics[-1].chain_start + pf.metrics[-1].chain_count
            if covered != pf.trace_chain_count or end != pf.trace_chain_count:
                chain_mismatch.append((os.path.basename(path), covered, end,
                                       pf.trace_chain_count))

        if not pf.header_raw or not pf.fileinfo_raw:
            missing_raw.append(os.path.basename(path))
        if pf.version != 17 and pf.volumes and not any(v.raw_tail for v in pf.volumes):
            missing_raw.append(f"{os.path.basename(path)} (volume tail)")

    print("coverage of every version present:")
    for version in sorted(by_version):
        budget = UNREAD_BUDGET[version]
        worst_for_version = max((n for n, _, v in worst if v == version), default=0)
        check(f"v{version}: {by_version[version]} files, worst unread {worst_for_version} bytes",
              worst_for_version <= budget, True)
    check("all five versions exercised", sorted(by_version), [17, 23, 26, 30, 31])

    print("\nno non-zero byte is both unread and unreported:")
    check("files with unaccounted non-zero bytes", len(nonzero_unread), 0)
    for name, version, count, sample in nonzero_unread[:5]:
        print(f"     {name} v{version}: {count} byte(s), first bytes {sample}")

    print("\nresidue is found where the corpus has it:")
    with_residue = 0
    for path in files[:200]:
        try:
            pf = parse_file(path)
        except Exception:                                   # noqa: BLE001
            continue
        if pf.residue:
            with_residue += 1
    check("some files report residue (104 of 698 across the full corpora)",
          with_residue > 0, True)
    print(f"     {with_residue} of the {min(len(files), 200)} sampled files carry residue")

    print("\nthe trace-chain slices tile the array:")
    check("files where the metric slices do not add up", len(chain_mismatch), 0)
    for entry in chain_mismatch[:5]:
        print(f"     {entry}")

    print("\nundecoded regions are retained, not discarded:")
    check("files missing a retained raw region", len(missing_raw), 0)
    for name in missing_raw[:5]:
        print(f"     {name}")

    print("\nthe fields that used to be thrown away carry real values:")
    win11 = sorted(glob.glob(os.path.join(corpus.WIN11, "*.pf")))
    pf = parse_file(win11[0])
    check("metrics carry a chain slice", all(m.chain_count >= 0 for m in pf.metrics))
    check("the first slice starts at zero", pf.metrics[0].chain_start, 0)
    check("slices are consecutive",
          all(pf.metrics[i + 1].chain_start == pf.metrics[i].chain_start + pf.metrics[i].chain_count
              for i in range(len(pf.metrics) - 1)))
    check("the subset never exceeds the slice",
          all(m.chain_subset is None or m.chain_subset <= m.chain_count for m in pf.metrics))
    check("flags are populated", any(m.flags for m in pf.metrics))
    check("the reference array version is read", pf.volumes[0].ref_array_version, 3)

    print("\nunclaimed references in the array slack are recovered:")
    # 24 files in the two corpora carry a reference the header does not count. This one is a
    # Win10 v30 file, so the check needs nothing downloaded.
    logon = parse_file(os.path.join(corpus.WIN10, "LOGONUI.EXE-1BEE4A84.pf"))
    slack = [str(r) for v in logon.volumes for r in v.slack_refs]
    check("LOGONUI.EXE has one unclaimed reference", slack, ["254640-0"])
    check("...kept out of the declared list", len(logon.volumes[0].file_refs), 116)
    check("...and reported as a problem",
          any("slack" in str(p) for p in logon.problems))

    # The v23 sample says the same about a much older layout, when it is configured.
    seed = os.path.join(corpus.SAMPLES or "", "plaso", "winprefetch", "PING.EXE-B29F6629.pf")
    if corpus.SAMPLES and os.path.exists(seed):
        ping = parse_file(seed)
        check("PING.EXE too (v23 sample)",
              [str(r) for v in ping.volumes for r in v.slack_refs], ["2507-1"])
        check("...kept out of the declared list", len(ping.volumes[0].file_refs), 33)
    else:
        print("  - the v23 sample is not configured; its extra checks did not run "
              "(PREFETCH_SAMPLES)")

    # Coverage of the DECOMPRESSED body is not coverage of the file. A MAM container states
    # only its output size, so bytes appended after the compressed stream ride along, decode to
    # nothing, and leave the record looking perfect (AUDIT BUG 78).
    print("\nbytes carried after the end of the compressed stream are counted:")
    import shutil as _shutil                                          # noqa: PLC0415
    import tempfile as _tempfile                                      # noqa: PLC0415

    from prefetch_core import container as _container                 # noqa: PLC0415

    compressed = next(f for f in files
                      if _container.is_container(open(f, "rb").read()[:4]))
    clean = parse_file(compressed)
    check("a real file's padding is measured, not assumed",
          clean.container_trailing_bytes is not None and clean.container_trailing_bytes <= 3)
    check("...and the decoder that measured it is named", clean.decompressor_used, "pure")
    workdir = _tempfile.mkdtemp()
    planted = os.path.join(workdir, os.path.basename(compressed))
    with open(planted, "wb") as fh:
        fh.write(open(compressed, "rb").read() + b"HIDDEN" * 512)
    hidden = parse_file(planted)
    check("3,072 bytes hidden after the stream are counted exactly",
          hidden.container_trailing_bytes, clean.container_trailing_bytes + 3072)
    check("...and reported as a problem",
          any("follow the end of the compressed stream" in str(p) for p in hidden.problems))
    check("...while every parsed value stays identical",
          (hidden.executable_name, hidden.hash, hidden.run_times, hidden.filenames),
          (clean.executable_name, clean.hash, clean.run_times, clean.filenames))

    print("\nresidue reporting is bounded, and says what it dropped:")
    # A crafted file can be an alternation of read fields and non-zero gaps, which would
    # otherwise materialise one object and one database row per gap - the unbounded-allocation
    # shape this project refuses everywhere else.
    from prefetch_core import scca                                   # noqa: PLC0415
    from prefetch_core.errors import Bounds                          # noqa: PLC0415
    from prefetch_core.model import Prefetch                         # noqa: PLC0415

    bounds = Bounds(b"\x41" * 40000)
    for offset in range(0, 40000, 8):
        bounds.check(offset, 4, "probe")
    crafted = Prefetch(source_path="crafted")
    scca._residue(bounds, crafted)
    check("regions are capped", len(crafted.residue), scca._RESIDUE_MAX_REGIONS)
    check("the bytes it could not keep are still counted",
          any("were not retained" in str(p) for p in bounds.problems), True)
    check("the reported total is the true total",
          any("20000 byte(s)" in str(p) for p in bounds.problems), True)

    # The other axis: few regions, each enormous. Capping the region count alone bounded the
    # wrong one - 256 regions of 4 KB apiece is a megabyte of retained bytes per record, well
    # past what the memory suite allows, and a BLOB per region in the database besides.
    big = Bounds(b"\x41" * (4 << 20))
    for offset in range(0, 4 << 20, 512 << 10):
        big.check(offset, 8, "probe")
    huge = Prefetch(source_path="crafted-large")
    scca._residue(big, huge)
    kept = sum(len(r.data) for r in huge.residue)
    check("a few enormous regions are capped by total bytes, not count",
          kept <= scca._RESIDUE_MAX_TOTAL, True)
    check("...well under the per-record memory ceiling", kept <= 64 * 1024, True)
    check("...while the reported total stays exact", huge.residue_bytes, 4194240)

    print("\nwhat is still unread, for the record:")
    worst.sort(reverse=True)
    for count, name, version in worst[:5]:
        print(f"     {name:<44} v{version}  {count} bytes")

    print()
    if failures:
        for f in failures:
            print(f"FAILED: {f}")
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("byte coverage holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
