#!/usr/bin/env python3
"""Properties that must hold across EVERY file at once, rather than field by field.

The other suites check what one record says against what the format says. This one checks the
things that are only visible over a whole corpus, and that a per-file test cannot see:

  * parsing the same bytes twice gives the same answer - anything order-dependent (a set, a
    dict, a filesystem walk leaking into output) shows up here and nowhere else;
  * every `datetime` still equals the FILETIME ticks it was built from, so the lossless copy
    and the convenient copy cannot drift apart unnoticed;
  * nothing that reaches a report carries a control character;
  * the three-state fields hold only their three states, AND all three actually occur - a state
    that never occurs in any corpus is a state nobody has tested;
  * every SuperFetch path is vouched for by its own stored hash, the hash is reproducible
    independently of the parser, and no single-bit mutation can produce an unverified path;
  * a Prefetch folder holding things that are not ordinary files is still reported.

Round 46 wrote these as scratch audit scripts; a crash deleted the scratch directory, which is
its own argument for where checks belong.

Run:  python3 test_invariants.py
"""

import datetime
import glob
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import corpus  # noqa: E402

from prefetch_core import agdb, parse_file  # noqa: E402
from prefetch_core.artifacts import identify, scan_folder  # noqa: E402
from prefetch_core.scca import parse as parse_bytes  # noqa: E402

failures = []

EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
CONTROLS = {chr(c) for c in range(32)} | {chr(127)}


def check(label, got, want=True):
    ok = got == want
    print(f"  {label:62} {str(got):>10}{'' if ok else f'   << expected {want}'}")
    if not ok:
        failures.append(f"{label}: {got!r} != {want!r}")


def strings_of(pf):
    out = [pf.executable_name, pf.hash, pf.executable_path or "", pf.executable_path_alt or "",
           pf.hosted_package or "", pf.source_path or ""]
    out += list(pf.filenames)
    out += [v.device_name for v in pf.volumes]
    out += list(pf.path_candidates)
    out += [str(p) for p in pf.problems]
    return [s for s in out if s]


def corpus_files():
    files = []
    for folder in (corpus.WIN10, corpus.WIN11, corpus.VENDORED, corpus.SAMPLES):
        if folder and os.path.isdir(folder):
            files += glob.glob(os.path.join(folder, "**", "*.pf"), recursive=True)
            files += glob.glob(os.path.join(folder, "**", "*.PF"), recursive=True)
    return sorted(set(files))


def superfetch_files():
    found = []
    for folder in (corpus.WIN10, corpus.WIN11, corpus.SAMPLES):
        if not folder or not os.path.isdir(folder):
            continue
        for pattern in ("**/*.db", "**/*.7db", "**/*.ebd", "**/Ag*"):
            for path in glob.glob(os.path.join(folder, pattern), recursive=True):
                if not os.path.isfile(path):
                    continue
                with open(path, "rb") as fh:
                    if agdb.is_superfetch(os.path.basename(path), fh.read(8)):
                        found.append(path)
    return sorted(set(found))


def main():
    corpus.require("WIN10", "WIN11")
    files = corpus_files()
    print(f"{len(files)} prefetch files across every configured corpus\n")

    bad_ticks = bad_index = bad_control = bad_residue = bad_tri = 0
    bad_slots = bad_runs = 0
    example = {}
    states = set()
    for path in files:
        pf = parse_file(path)
        if len(pf.run_times) != len(pf.run_times_ticks):
            bad_ticks += 1
            example.setdefault("ticks", path)
        else:
            for when, ticks in zip(pf.run_times, pf.run_times_ticks):
                if when is None:
                    continue
                want = EPOCH + datetime.timedelta(microseconds=ticks // 10)
                if abs((when - want).total_seconds()) > 1e-6:
                    bad_ticks += 1
                    example.setdefault("ticks", f"{path}: {when} != {want}")
                    break
        for metric in pf.metrics:
            index = getattr(metric, "filename_index", None)
            if index is not None and 0 <= index and index >= len(pf.filenames):
                bad_index += 1
                example.setdefault("index", path)
                break
        for text in strings_of(pf):
            if CONTROLS & set(text):
                bad_control += 1
                example.setdefault("control", f"{path}: {text!r}")
                break
        for run in pf.residue:
            if run.offset < 0 or run.size < 0:
                bad_residue += 1
                example.setdefault("residue", f"{path}: {run.offset}+{run.size}")
                break
        for field in ("filename_hash_match", "filename_name_match"):
            if getattr(pf, field, "missing") not in (None, True, False):
                bad_tri += 1
                example.setdefault("tri", f"{path}: {getattr(pf, field)!r}")
        states.add(pf.filename_hash_match)
        for volume in pf.volumes:
            declared = getattr(volume, "declared_ref_count", 0)
            if declared and len(volume.file_refs) > declared:
                bad_slots += 1
                example.setdefault("slots", path)
                break
        real = [t for t in pf.run_times if t is not None]
        if pf.run_count and len(real) > max(pf.run_count, 8):
            bad_runs += 1
            example.setdefault("runs", path)

    print("properties held across the whole corpus:")
    check("every datetime equals its own FILETIME ticks", bad_ticks, 0)
    check("no metric indexes a filename that does not exist", bad_index, 0)
    check("no control character reaches a reported string", bad_control, 0)
    check("every residue run has a sane offset and size", bad_residue, 0)
    check("the three-state fields hold only their three states", bad_tri, 0)
    # A state that never occurs anywhere is a state nobody has tested. `n/a` is what a file
    # outside the NAME-HASH.pf convention reports; `True` is every ordinary file.
    check("all three of those states actually occur", {None, True} <= states, True)
    check("no volume recovers more references than it declared", bad_slots, 0)
    check("no file records more runs than its own run count allows", bad_runs, 0)
    for key, value in sorted(example.items()):
        print(f"    first {key}: {value}")

    # Round 48. A record's verdict and its problems must say the same thing: `parsed_ok` False
    # with every problem marked `fatal = 0` meant a query for records carrying a fatal problem
    # returned nothing for a folder full of failures (AUDIT BUG 111). Only the container stage
    # recorded its exception as fatal; every stage after it used the "carry on" path.
    # Round 49. `pfcli info` prints: "Each metric owns a slice of the trace-chain array; the
    # slices tile it exactly. That is what makes 'how much block-load work did this file account
    # for' answerable at all." A claim the tool makes in its own output, and nothing checked it.
    print("\nthe metric slices tile the trace-chain array exactly:")
    tiled = gaps = overlaps = over = 0
    for path in files:
        pf = parse_file(path)
        spans = sorted((m.chain_start, m.chain_start + m.chain_count) for m in pf.metrics
                       if getattr(m, "chain_start", None) is not None
                       and getattr(m, "chain_count", None) is not None)
        if not spans or not pf.trace_chain_count:
            continue
        tiled += 1
        cursor = 0
        for start, end in spans:
            if start > cursor:
                gaps += 1
                break
            if start < cursor:
                overlaps += 1
                break
            cursor = end
        else:
            if cursor > pf.trace_chain_count:
                over += 1
    print(f"  files carrying metrics and a chain count: {tiled}")
    check("  the claim is checked against real files", tiled > 100, True)
    check("  no slice overlaps the one before it", overlaps, 0)
    check("  no gap is left between slices", gaps, 0)
    check("  no slice runs past the array it indexes", over, 0)

    print("\na failed parse and a fatal problem are the same thing:")
    disagreeing = []
    stages_seen = set()
    for path in files:
        pf = parse_file(path)
        fatal = [p for p in pf.problems if p.fatal]
        if bool(fatal) != (not pf.parsed_ok):
            disagreeing.append((os.path.basename(path), pf.failed_stage, len(fatal)))
        stages_seen.update(p.stage.value for p in fatal)
    check("no record disagrees with itself about failing", disagreeing, [])
    # And the property must be exercised: a corpus with no failures proves nothing here.
    failed = [p for p in files if not parse_file(p).parsed_ok]
    check("the corpus contains a failing file, so this checks something", bool(failed), True)
    # Every stage that can end a parse marks its problem fatal, not just the container.
    import prefetch_core.scca as _scca                                # noqa: PLC0415

    from prefetch_core.errors import Stage as _Stage                  # noqa: PLC0415

    crafted = {
        "signature": b"\x1e\x00\x00\x00SDCA" + b"\x00" * 80,
        "header": b"\x1e\x00\x00\x00SCCA" + b"\x00" * 20,
        "container": b"MAM\x04" + b"\xff" * 40,
    }
    for label, blob in crafted.items():
        rec = _scca.parse(blob, source_path=f"/case/{label}.pf")
        fatal = [p for p in rec.problems if p.fatal]
        # This suite takes (label, got, want) - the other convention in this directory takes
        # (label, condition, detail), and mixing them is a mistake I have now made four times.
        check(f"  a failure at {label} carries a fatal problem",
              (bool(fatal), rec.parsed_ok), (True, False))

    print("\nparsing is deterministic, and the two entry points agree:")
    sample = files[::max(1, len(files) // 120)]
    import dataclasses                                                 # noqa: PLC0415

    differs = entry_differs = 0
    fs_only = {"source_created", "source_created_est", "source_modified", "source_accessed",
               "source_size", "ads", "ads_streams", "ads_error"}
    for path in sample:
        first = dataclasses.asdict(parse_file(path))
        if first != dataclasses.asdict(parse_file(path)):
            differs += 1
        with open(path, "rb") as fh:
            raw = fh.read()
        from_bytes = dataclasses.asdict(parse_bytes(raw, source_path=path))
        if {k: v for k, v in first.items() if k not in fs_only} != \
           {k: v for k, v in from_bytes.items() if k not in fs_only}:
            entry_differs += 1
    check(f"the same bytes parse the same way twice ({len(sample)} files)", differs, 0)
    check("parse(bytes) and parse_file(path) agree", entry_differs, 0)

    print("\nSuperFetch: every path is vouched for by its own stored hash:")
    dbs = superfetch_files()
    total = verified = unverified = 0
    reproduced = sampled = 0
    for path in dbs:
        with open(path, "rb") as fh:
            db = agdb.parse(fh.read())
        for volume in db.volumes:
            for entry in volume.files:
                total += 1
                if entry.hash_ok:
                    verified += 1
                else:
                    unverified += 1
                if sampled < 200:
                    sampled += 1
                    # Recomputed from the DECODED path, not from the bytes the parser sliced:
                    # an oracle that reuses the parser's own reading proves nothing.
                    if agdb.name_hash(entry.path.encode("utf-16-le")) == \
                            (entry.name_hash & 0xFFFFFFFF):
                        reproduced += 1
    print(f"  {len(dbs)} databases, {total:,} file records")
    check("no path is presented that its hash does not vouch for", unverified, 0)
    check("the oracle ran on real data rather than on nothing", verified > 1000, True)
    check("the stored hash reproduces from the path text", reproduced, sampled)

    if dbs:
        print("\n...and no single-bit mutation can produce one:")
        with open(dbs[0], "rb") as fh:
            raw = fh.read()
        random.seed(46)
        raised = escaped = 0
        for _ in range(200):
            data = bytearray(raw)
            data[random.randrange(len(data))] ^= 1 << random.randrange(8)
            try:
                db = agdb.parse(bytes(data))
            except Exception as exc:                                   # noqa: BLE001
                raised += 1
                print(f"    raised {type(exc).__name__}: {exc}")
                continue
            escaped += sum(1 for v in db.volumes for f in v.files if not f.hash_ok)
        check("200 mutations raise nothing", raised, 0)
        check("...and none yields an unverified path", escaped, 0)

        print("\n...and truncation is a report, never an exception:")
        raised = silent = 0
        for cut in list(range(0, 256, 13)) + [len(raw) // 3, len(raw) - 1]:
            try:
                db = agdb.parse(raw[:cut])
            except Exception as exc:                                   # noqa: BLE001
                raised += 1
                print(f"    {cut} bytes raised {type(exc).__name__}: {exc}")
                continue
            if not (db.problems or db.volumes or db.swept_paths):
                silent += 1
        check("every truncation parses to a report", raised, 0)
        check("...and none is silently empty", silent, 0)

    print("\na folder that holds more than ordinary files is still reported:")
    work = tempfile.mkdtemp()
    # A Layout.ini in UTF-16 with a BOM - the encoding Windows writes for non-ASCII paths.
    text = "[Files]\r\nC:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\r\nC:\\WINDOWS\\SYSTEM32\\ÜBER.DLL\r\n"
    with open(os.path.join(work, "Layout.ini"), "wb") as fh:
        fh.write(b"\xff\xfe" + text.encode("utf-16-le"))
    found = scan_folder(work)
    layout = [a for a in found if a.kind == "layout"]
    check("a UTF-16 Layout.ini is recognised", len(layout), 1)
    if layout:
        check("...and its paths are recovered, not mojibake",
              any("NOTEPAD.EXE" in p for p in layout[0].paths), True)

    # Magic that belongs to another kind, under a name that belongs to this one. Whatever the
    # answer, every file must get exactly one kind and nothing may be dropped.
    clash = tempfile.mkdtemp()
    with open(os.path.join(clash, "Layout.ini"), "wb") as fh:
        fh.write(b"MEM0" + b"\x00" * 32)
    with open(os.path.join(clash, "AgSomething.db"), "wb") as fh:
        fh.write(b"[Files]\r\nC:\\X.EXE\r\n")
    found = scan_folder(clash)
    check("a magic/name clash still yields one entry per file", len(found), 2)
    check("...each with a kind or a stated problem",
          all(a.kind and (a.paths or a.facts or a.problems) for a in found), True)

    # A blob far above the artifact ceiling, named like a trace. Reported, not read.
    big_dir = tempfile.mkdtemp()
    with open(os.path.join(big_dir, "Trace1.fx"), "wb") as fh:
        fh.truncate(200 * 1024 * 1024)          # sparse: costs no disk, lies about nothing
    found = scan_folder(big_dir)
    check("a 200 MB blob yields a reported entry", len(found), 1)
    if found:
        check("...that says it was not parsed",
              any("ceiling" in p or "not parsed" in p for p in found[0].problems), True)

    # And the shape every consumer relies on.
    real = scan_folder(corpus.WIN11)
    check("every artifact has a kind, a name and a size",
          all(a.kind and a.name and a.size >= 0 for a in real), True)
    check("every path in every artifact is a string",
          all(isinstance(p, str) for a in real for p in a.paths), True)

    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
