#!/usr/bin/env python3
"""CLI must fail usefully: no tracebacks, a stated cause, and never discard the whole run.

Parsing a large folder costs real time. Losing all of it behind a Python traceback because one
output path had the wrong permissions is the difference between a tool an analyst trusts and
one they work around. Every failure mode here must print `!! <what> : <why>`, exit non-zero,
and still write whatever other output was requested.

Run:  python3 test_cli_errors.py
"""

import csv
import time
import glob
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import corpus  # noqa: E402

from prefetch_core import parse_file  # noqa: E402
SEED = "" + corpus.WIN10 + "/7ZFM.EXE-7C92DCA0.pf"

failures = []


csv.field_size_limit(1 << 30)   # this tool writes cells far wider than the module default


def run(*args):
    p = subprocess.run([sys.executable, "-m", "pfcli", *args],
                       cwd=ROOT, capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout, p.stderr


def check(label, ok, detail=""):
    # This helper takes a CONDITION, and passing a value where a condition belongs inverts the
    # check silently - a correct zero reads as a failure. Required to be a boolean so the
    # mistake fails loudly instead (Round 48).
    if not isinstance(ok, bool):
        raise TypeError(f"check({label!r}) needs a condition, got {type(ok).__name__} {ok!r}")
    # str(detail): callers pass counts as well as strings, and a harness that raises TypeError
    # while reporting a failure hides the failure behind a traceback.
    print(f"  {label:52} {'ok' if ok else 'FAIL'}"
          f"{'  ' + str(detail) if detail and not ok else ''}")
    if not ok:
        failures.append(label)


def main():
    corpus.require("WIN10", "WIN11")
    corpus.require_seed(SEED)
    tmp = tempfile.mkdtemp()
    readonly = os.path.join(tmp, "ro")
    os.mkdir(readonly)
    os.chmod(readonly, stat.S_IRUSR | stat.S_IXUSR)
    # `chmod` on Windows only toggles the read-only attribute, and only on files: the directory
    # stays writable, every "unwritable destination" case below then succeeds, and the exit-120
    # rows fail for a reason that has nothing to do with the tool. Prove the premise instead of
    # assuming it - and say so, rather than reporting a defect that is a platform difference.
    try:
        probe = os.path.join(readonly, "probe")
        with open(probe, "w") as fh:
            fh.write("x")
        os.unlink(probe)
        unwritable_works = False
    except OSError:
        unwritable_works = True
    if not unwritable_works:
        print("  note: this platform's chmod cannot make a directory unwritable; the "
              "unwritable-destination checks are reported as skipped, not passed")
    notadb = os.path.join(tmp, "notadb")
    with open(notadb, "w") as fh:
        fh.write("this is not a database")

    cases = [
        ("db in a read-only directory", os.path.join(readonly, "x.db")),
        ("db path is a directory", tmp),
        ("db path is not a database", notadb),
        ("db in a nonexistent directory", os.path.join(tmp, "nope", "x.db")),
    ]
    if not unwritable_works:
        cases = [c for c in cases if "read-only" not in c[0]]
    print("database failures:")
    for label, target in cases:
        code, out, err = run("parse", SEED, "--db", target)
        check(f"{label}: exits non-zero", code != 0, f"exit={code}")
        check(f"{label}: reports the cause", "!! could not write database" in err)
        check(f"{label}: no traceback", "Traceback" not in err and "Traceback" not in out)

    print("\nCSV failures:")
    if unwritable_works:
        code, out, err = run("parse", SEED, "--csv", os.path.join(readonly, "x.csv"))
        check("unwritable CSV: exits non-zero", code != 0)
        check("unwritable CSV: reports the cause", "!! could not write CSV" in err)
        check("unwritable CSV: no traceback", "Traceback" not in err)
    else:
        print("  (skipped: no unwritable directory on this platform)")

    print("\nwork is not discarded when one destination fails:")
    good_csv = os.path.join(tmp, "good.csv")
    # A destination that fails for a reason every platform agrees on, so this check does not
    # depend on chmod: a database path that is a directory can never be opened.
    code, out, err = run("parse", SEED, "--db", tmp, "--csv", good_csv)
    check("CSV still written when the DB fails", os.path.exists(good_csv))
    check("still exits non-zero", code != 0)
    if os.path.exists(good_csv):
        with open(good_csv) as fh:
            check("CSV has a header and a data row", len(fh.readlines()) >= 2)

    print("\ninput failures:")
    code, out, err = run("parse", os.path.join(tmp, "does-not-exist.pf"))
    check("missing input: exits non-zero", code != 0)
    check("missing input: names the path", "not found" in err)
    code, out, err = run("parse", tmp, "--no-recurse")
    check("directory with no .pf: exits non-zero", code != 0)
    check("directory with no .pf: says so", "no .pf files found" in err)

    print("\ninfo subcommand:")
    code, out, err = run("info", os.path.join(HERE, "pf-corpus", "Bad", "notAPrefetch.pf"))
    check("info on an unparseable file exits non-zero", code != 0, f"exit={code}")
    # The version is read before the signature is validated, so a non-prefetch file still
    # shows a plausible number. The verdict has to come first or it reads as fact.
    check("failure verdict precedes the fields",
          out.index("PARSE FAILED") < out.index("version") if "PARSE FAILED" in out else False)
    check("info on a good file exits zero", run("info", SEED)[0] == 0)

    print("\noverlapping arguments do not duplicate rows:")
    # `parse FOLDER FOLDER`, or a folder plus a file inside it, yielded every affected file
    # twice - doubling rows in the CSV and the console count.
    sys.path.insert(0, ROOT)
    from pfcli.__main__ import discover
    folder = os.path.dirname(SEED)
    once = len(list(discover([folder])))
    # Written in the (label, got, want) convention this file does not use, so every one of
    # these passed on the truthiness of a count and tested nothing at all - four vacuous checks
    # in a shipped suite, found by the type guard on `check` above (Round 48).
    twice = len(list(discover([folder, folder])))
    check("folder listed twice", twice == once, f"{twice} vs {once}")
    plus_file = len(list(discover([folder, SEED])))
    check("folder plus a file inside it", plus_file == once, f"{plus_file} vs {once}")
    same = len(list(discover([SEED, SEED])))
    check("same file twice", same == 1, same)
    alias = len(list(discover(
        [SEED, os.path.join(os.path.dirname(SEED), ".", os.path.basename(SEED))])))
    check("a ./ alias of the same file", alias == 1, alias)

    print("\nartifacts-only folder is not reported as empty:")
    import shutil as _shutil
    art_dir = os.path.join(tmp, "artifacts_only")
    os.makedirs(art_dir, exist_ok=True)
    for name in ("Layout.ini", "dynrespri.7db"):
        source = os.path.join(corpus.WIN11, name)
        if os.path.exists(source):
            _shutil.copy(source, art_dir)
    code, out, err = run("parse", art_dir)
    check("still exits non-zero (no prefetch parsed)", code != 0)
    check("names the artifacts that ARE present", "other Prefetch-folder artifact" in err)
    check("points at the command that reports them", "pfcli artifacts" in err)
    code, out, err = run("parse", os.path.join(tmp, "genuinely-empty"))
    check("a genuinely empty path does not invent artifacts",
          "other Prefetch-folder artifact" not in err)

    print("\n`artifacts` separates 'scanned and clean' from 'never scanned':")
    # All three used to print the same line and exit 0, so
    # `pfcli artifacts "$DIR" && echo clean` reported clean for a typo or an unmounted share.
    empty_dir = os.path.join(tmp, "empty-for-artifacts")
    os.makedirs(empty_dir, exist_ok=True)
    code, out, err = run("artifacts", empty_dir)
    check("an empty folder is a clean SCAN, exit 0", code == 0, f"exit={code}")
    check("and says it actually scanned it", "scanned" in out, out.strip()[:60])

    code, out, err = run("artifacts", os.path.join(tmp, "no-such-folder-here"))
    check("a missing path fails, exit 1", code == 1, f"exit={code}")
    check("and does not claim 'no artifacts found'",
          "no non-.pf artifacts found" not in out, out.strip()[:60])

    code, out, err = run("artifacts", SEED)          # a file, not a folder
    check("a file where a folder belongs fails, exit 1", code == 1, f"exit={code}")
    check("and explains what to pass instead", "not a directory" in err, err.strip()[:60])

    # An export that fails must not destroy the export that was already there. `open(path,
    # "w")` truncates before the first byte is written, so a full disk or a dropped share left
    # a truncated CSV where a complete one had been - 185 rows became 7, with the only warning
    # on stderr (AUDIT BUG 66). Writes go to a temporary file beside the target and are renamed
    # into place, so the previous export survives byte for byte.
    print("\na failed export leaves the previous one intact:")
    from prefetch_core.output import atomic_write                     # noqa: PLC0415

    target = os.path.join(tmp, "export.csv")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write("complete,export\n1,2\n")
    before = open(target, "rb").read()
    try:
        with atomic_write(target) as fh:
            fh.write("half a line")
            raise OSError("simulated write failure")
    except OSError:
        pass
    check("the previous file is byte-identical", open(target, "rb").read() == before)
    leftovers = [f for f in os.listdir(tmp) if f.endswith(".partial")]
    check("no temporary file is left behind", not leftovers, leftovers)
    with atomic_write(target) as fh:
        fh.write("new,content\n")
    written = open(target).read()
    check("a successful write does replace it", written == "new,content\n", written)
    check("...atomically, so no temp survives that either",
          not [f for f in os.listdir(tmp) if f.endswith(".partial")])

    # And the CLI-level contract: one unwritable destination must not cost the other.
    csv_out = os.path.join(tmp, "still-written.csv")
    code, out, err = run("parse", corpus.WIN10, "--db", tmp, "--csv", csv_out)
    check("a failing database does not stop the CSV", os.path.exists(csv_out), err.strip()[:80])
    check("...which is complete", sum(1 for _ in open(csv_out)) > 100)
    check("...and the run still exits non-zero", code != 0, f"exit={code}")
    check("...naming the cause, not a traceback",
          "could not write database" in err and "Traceback" not in err, err.strip()[:80])

    # A capability that does not exist on this host is an environment failure, not evidence.
    # `--decompressor ntdll` on Linux used to parse the whole folder, fail every file at the
    # container stage, and exit 0 - a script driving the tool recorded a clean run with no
    # findings (AUDIT BUG 79).
    print("\na forced decompressor that does not exist fails before parsing:")
    from prefetch_core import available_decompressors                 # noqa: PLC0415

    if "ntdll" in available_decompressors():
        print("  - this host HAS ntdll, so the unavailable-decompressor path cannot be tested")
    else:
        code, out, err = run("--decompressor", "ntdll", "parse", corpus.WIN10)
        check("exits 2", code == 2, f"exit={code}")
        check("names what is available instead", "available: pure" in err, err.strip()[:70])
        check("does not parse the folder first", "file(s)" not in out, out.strip()[:70])
        check("...and the same for `info`",
              run("--decompressor", "ntdll", "info", SEED)[0] == 2)
    code, out, _err = run("--decompressor", "pure", "parse", SEED)
    check("forcing the decompressor that does exist works", code == 0, f"exit={code}")

    # The exit-code table in docs/DOCUMENTATION.md, asserted. Scripts read these, and the same
    # condition returning 1 from `parse` and 120 from `artifacts` is a contract that cannot be
    # relied on (AUDIT BUG 82).
    # Round 47, the Windows lane. Windows chooses stdout's encoding from the environment, and
    # it is UTF-8 only for a real console: REDIRECT the output - `> report.txt`, a pipe, any
    # script that captures it - and the stream becomes the ANSI code page. Printing a Cyrillic
    # or CJK filename to that stream raised UnicodeEncodeError, which nothing catches, so the
    # run died with a traceback and produced no report at all (AUDIT BUG 97). Forcing
    # PYTHONIOENCODING reproduces that here, on any host.
    print("\na name the console cannot spell does not end the run:")
    import shutil as _sh                                              # noqa: PLC0415

    wide = os.path.join(tmp, "wide")
    os.makedirs(wide, exist_ok=True)
    _sh.copyfile(SEED, os.path.join(wide, "КАЛЬК.EXE-3FBEF7FD.pf"))
    _sh.copyfile(SEED, os.path.join(wide, "日本語.EXE-1234ABCD.pf"))
    with open(os.path.join(wide, "Layout.ini"), "w", encoding="utf-8") as fh:
        fh.write("[Files]\r\nC:\\WINDOWS\\SYSTEM32\\ЖЖЖ.DLL\r\n")
    with open(os.path.join(wide, "Ag日本語.db"), "wb") as fh:
        fh.write(b"MEM0" + b"\x00" * 32)
    hostile_env = dict(os.environ, PYTHONIOENCODING="cp1252")
    for argv in (("info", os.path.join(wide, "КАЛЬК.EXE-3FBEF7FD.pf")),
                 ("parse", wide),
                 ("parse", wide, "--csv", os.path.join(tmp, "wide.csv")),
                 ("artifacts", wide),
                 ("ads", wide)):
        proc = subprocess.run([sys.executable, "-m", "pfcli", *argv], cwd=ROOT, env=hostile_env,
                              capture_output=True, text=True, timeout=300)
        label = " ".join(a if not a.startswith(tmp) else "…" for a in argv)
        # `ads` exits 2 where streams cannot be enumerated, which is a different answer, not a
        # crash. What must never happen is a traceback.
        check(f"{label}: no traceback on a cp1252 stream",
              "Traceback" not in proc.stderr and "UnicodeEncodeError" not in proc.stderr,
              proc.stderr.strip()[-160:])
        check(f"{label}: exits with a documented code", proc.returncode in (0, 1, 2, 120),
              proc.returncode)
    # ...and the export itself is UTF-8 regardless of what the console is set to.
    with open(os.path.join(tmp, "wide.csv"), encoding="utf-8") as fh:
        exported = fh.read()
    check("the CSV keeps the name exactly, whatever the console encoding",
          "КАЛЬК.EXE-3FBEF7FD.pf" in exported and "日本語.EXE-1234ABCD.pf" in exported,
          exported[:200])

    # Round 48. A filename does not have to be valid text: NTFS allows unpaired surrogates, and
    # a Prefetch folder copied out of an image onto Linux carries whatever bytes the name held.
    # SQLite refused to bind them and the CSV writer refused to encode them - neither caught -
    # so ONE such file ended the whole run with a traceback and no report at all (AUDIT BUG
    # 102). Planted here as a raw byte in the name, which is exactly how it arrives.
    print("\na name that is not valid text costs that name, not the run:")
    undecodable = os.path.join(tmp, "undecodable")
    os.makedirs(undecodable, exist_ok=True)
    _sh.copyfile(SEED, os.path.join(undecodable, "CALC.EXE-3FBEF7FD.pf"))
    with open(SEED, "rb") as src:
        raw = src.read()
    with open(os.fsdecode(os.fsencode(undecodable) + b"/CALC.EXE-3FBEF7FD\xff.pf"), "wb") as fh:
        fh.write(raw)
    with open(os.fsdecode(os.fsencode(undecodable) + b"/Ag\xffhist.db"), "wb") as fh:
        fh.write(b"MEM0" + b"\x00" * 40)
    bad_csv = os.path.join(tmp, "undecodable.csv")
    bad_db = os.path.join(tmp, "undecodable.db")
    code, out, err = run("parse", undecodable, "--csv", bad_csv, "--db", bad_db)
    check("the run completes", code == 0 and "Traceback" not in err, f"exit={code} {err[-160:]}")
    with open(bad_csv, encoding="utf-8") as fh:
        exported = list(csv.DictReader(fh))
    check("both files are exported, not one", len(exported) == 2, len(exported))
    conn = sqlite3.connect(bad_db)
    stored = sorted(r[0] for r in conn.execute("SELECT source_name FROM prefetch"))
    conn.close()
    from_csv = sorted(r["SourceName"] for r in exported)
    # One file, one spelling. The database renders the byte; so must the CSV, or the two
    # exports of one run disagree about the name of the evidence.
    check("the CSV and the database spell the name identically", stored == from_csv,
          f"{stored} vs {from_csv}")
    check("...and they show the BYTE, which is what the name actually held",
          any(name.endswith("\\xff.pf") for name in stored), stored)
    check("the record says its own name is not valid text",
          any("not valid text" in (r["Problems"] or "") for r in exported),
          [r["Problems"][:60] for r in exported])
    # The artifact half of the same folder, through its own export.
    art_csv = os.path.join(tmp, "undecodable-arts.csv")
    code, out, err = run("artifacts", undecodable, "--csv", art_csv)
    check("artifacts survives it too", code == 0 and "Traceback" not in err,
          f"exit={code} {err[-160:]}")
    from prefetch_core.export import summary_path_for                 # noqa: PLC0415

    with open(summary_path_for(art_csv), encoding="utf-8") as fh:
        arts = [r["SourceName"] for r in csv.DictReader(fh)]
    check("...and spells the artifact's name the same way",
          any(name.endswith("\\xffhist.db") for name in arts), arts)

    # The guard modifies cells, so the run must say so: an unexplained apostrophe in an export
    # is its own trust problem (AUDIT BUG 103).
    print("\nthe run says which cells it prefixed, and why:")
    guard_csv = os.path.join(tmp, "guarded.csv")
    code, out, err = run("parse", corpus.WIN10, "--csv", guard_csv)
    with open(guard_csv, encoding="utf-8") as fh:
        guarded_cells = sum(1 for r in csv.DictReader(fh) for v in r.values()
                            if v.startswith("'"))
    # On stderr, not stdout: diagnostics must not reach the stream a script reads rows from
    # (AUDIT BUG 107).
    said = "prefixed with an apostrophe" in err
    check("a run that prefixed cells says so on the console", said or guarded_cells == 0,
          f"{guarded_cells} guarded cells, note printed: {said}")
    check("...and names --raw-csv as the exact-bytes alternative",
          ("--raw-csv" in err) or guarded_cells == 0, err[-200:])
    check("...and says it on stderr, never on stdout",
          "prefixed with an apostrophe" not in out, out[-160:])
    raw_csv = os.path.join(tmp, "guarded-raw.csv")
    code, out, err = run("parse", corpus.WIN10, "--csv", raw_csv, "--raw-csv")
    with open(raw_csv, encoding="utf-8") as fh:
        raw_guarded = sum(1 for r in csv.DictReader(fh) for v in r.values()
                          if v.startswith("'"))
    # `check` here takes (label, condition, detail) - passing the count itself made a correct
    # zero read as a failure.
    check("--raw-csv prefixes nothing at all", raw_guarded == 0, raw_guarded)
    check("...and says nothing about prefixing",
          "prefixed with an apostrophe" not in (out + err))

    # Round 48, feature 9. Three properties a script depends on.
    print("\nstdout carries rows; everything else goes to stderr:")
    quiet_csv = os.path.join(tmp, "quiet.csv")
    quiet_db = os.path.join(tmp, "quiet.db")
    code, out, err = run("parse", corpus.WIN10, "--csv", quiet_csv, "--db", quiet_db)
    # "wrote 184 records to ...", the spreadsheet notes and the apostrophe note all went to
    # stdout, so a script piping the rows got commentary mixed into its data (AUDIT BUG 107).
    strays = [l for l in out.splitlines()
              if l.startswith(("wrote ", "note:", "!!")) or "file(s)," in l]
    check("no diagnostic reaches stdout when an export is written", not strays, strays[:3])
    check("...and the diagnostics are on stderr, not lost",
          "wrote" in err and str(len(glob.glob(os.path.join(corpus.WIN10, "*.pf")))) in err,
          err.strip()[-120:])

    print("\n`info` never truncates a path it prints:")
    seed_info = run("info", SEED)[1]
    record = parse_file(SEED)
    # `filename[-60:]` cut paths from the LEFT with no marker, so the corpus printed
    # `UME{01d8559f...}\WINDOWS\...` - a path that does not exist (AUDIT BUG 108).
    shown = [m.filename for m in record.metrics[:20]]
    cut = [f for f in shown if f and f not in seed_info]
    check("every path in the metric table is printed whole", not cut, cut[:2])

    print("\nthe run never reports an access time it caused:")
    # Reading a file updates its atime, and stat-ing AFTER the read reported the tool's own
    # read as the evidence's last access - the export was not even identical between two runs
    # (AUDIT BUG 109). The stat now happens before the open.
    import datetime as _dt                                            # noqa: PLC0415

    atime_dir = os.path.join(tmp, "atime")
    os.makedirs(atime_dir, exist_ok=True)
    _sh.copyfile(SEED, os.path.join(atime_dir, os.path.basename(SEED)))
    old_time = time.time() - 3600
    os.utime(os.path.join(atime_dir, os.path.basename(SEED)), (old_time, old_time))
    started = _dt.datetime.now(_dt.timezone.utc)
    atime_csv = os.path.join(tmp, "atime.csv")
    run("parse", atime_dir, "--csv", atime_csv)
    with open(atime_csv, encoding="utf-8") as fh:
        stamps = [r["SourceAccessed"] for r in csv.DictReader(fh) if r["SourceAccessed"]]
    late = [s for s in stamps if _dt.datetime.fromisoformat(s) >= started]
    check("no record reports an access time at or after the run began", not late, late[:2])
    check("...and the access time it does report is the one from before the read",
          bool(stamps) and abs(_dt.datetime.fromisoformat(stamps[0]).timestamp()
                               - old_time) < 2, stamps[:1])

    print("\nthe documented exit codes, every subcommand:")
    empty_folder = os.path.join(tmp, "nothing-here")
    os.mkdir(empty_folder)
    not_a_folder = os.path.join(tmp, "plain.txt")
    with open(not_a_folder, "w") as fh:
        fh.write("x")
    unwritable_db = os.path.join(readonly, "out.db")
    unwritable_csv = os.path.join(readonly, "out.csv")
    matrix = [
        ("parse a real file", 0, ("parse", SEED)),
        ("parse a folder with no .pf", 1, ("parse", empty_folder)),
        ("parse a path that does not exist", 1, ("parse", os.path.join(tmp, "nope"))),
        ("parse with an unwritable database", 120,
         ("parse", SEED, "--db", unwritable_db, "--csv", os.path.join(tmp, "ok.csv"))),
        ("parse with an unwritable CSV", 120,
         ("parse", SEED, "--db", os.path.join(tmp, "ok.db"), "--csv", unwritable_csv)),
        ("info on a real file", 0, ("info", SEED)),
        ("info on a path that does not exist", 1, ("info", os.path.join(tmp, "nope.pf"))),
        ("artifacts on a folder with artifacts", 0, ("artifacts", corpus.WIN10)),
        ("artifacts on a folder with none", 0, ("artifacts", empty_folder)),
        ("artifacts on a path that does not exist", 1,
         ("artifacts", os.path.join(tmp, "nope"))),
        ("artifacts on a file where a folder belongs", 1, ("artifacts", not_a_folder)),
        ("artifacts with an unwritable database", 120,
         ("artifacts", corpus.WIN10, "--db", unwritable_db)),
        ("artifacts with an unwritable CSV", 120,
         ("artifacts", corpus.WIN10, "--csv", unwritable_csv)),
        ("capabilities", 0, ("capabilities",)),
        ("no arguments at all", 2, ()),
        ("an unknown subcommand", 2, ("wat",)),
        # Two outputs on one path: the second write destroyed the first while the console
        # reported both, and the run exited 0 (AUDIT BUG 90). Refused before any work.
        ("parse with --db and --csv on one path", 2,
         ("parse", SEED, "--db", os.path.join(tmp, "collide.out"),
          "--csv", os.path.join(tmp, "collide.out"))),
        ("...the same path written two ways", 2,
         ("parse", SEED, "--db", os.path.join(tmp, "collide2.out"),
          "--csv", os.path.join(tmp, "sub", "..", "collide2.out"))),
        ("ads with --db and --csv on one path", 2,
         ("ads", tmp, "--db", os.path.join(tmp, "collide3.out"),
          "--csv", os.path.join(tmp, "collide3.out"))),
        # `artifacts --csv` writes a -summary.csv beside the file it is given; a --db aimed at
        # that derived name collides just as destructively and is just as invisible.
        ("artifacts with --db on the derived summary path", 2,
         ("artifacts", corpus.WIN10, "--csv", os.path.join(tmp, "arts.csv"),
          "--db", os.path.join(tmp, "arts-summary.csv"))),
    ]
    for label, want, argv in matrix:
        if not unwritable_works and "unwritable" in label:
            print(f"  {label:52} skipped (chmod cannot make a directory unwritable here)")
            continue
        got = run(*argv)[0]
        check(f"{label} -> {want}", got == want, f"exit={got}")

    # Refusing is only half of it: the refusal must happen before anything is written, and an
    # export that was already on disk must survive the attempt untouched.
    keep = os.path.join(tmp, "keep.csv")
    run("parse", SEED, "--csv", keep)
    before = open(keep, encoding="utf-8").read()
    code, out, err = run("parse", SEED, "--db", keep, "--csv", keep)
    check("a collision names both flags and the path", "--db" in err and "--csv" in err
          and "keep.csv" in err, err.strip()[:160])
    check("...and the existing export is untouched", open(keep, encoding="utf-8").read() == before)
    check("...and nothing claims to have been written", "wrote" not in out, out.strip()[:160])
    # Distinct names, one file. realpath cannot see a hard link, so the check must stat.
    linked = os.path.join(tmp, "linked.csv")
    if not os.path.exists(linked):
        os.link(keep, linked)
    check("two names for one file are refused too", run("parse", SEED, "--db", linked,
                                                        "--csv", keep)[0] == 2)
    # And the ordinary two-output run still works, or the guard would be worse than the bug.
    two = run("parse", SEED, "--db", os.path.join(tmp, "pair.db"),
              "--csv", os.path.join(tmp, "pair.csv"))
    check("two different paths are still written", two[0] == 0
          and os.path.exists(os.path.join(tmp, "pair.db"))
          and os.path.exists(os.path.join(tmp, "pair.csv")), two[2][:160])

    # With an export requested the per-file table is not printed, and the summary then said
    # "N failed to parse" without saying which - the names were in the export and nowhere on
    # the console (Round 45, feature 11).
    print("\nfailures are named on the console even when an export was written:")
    mixed = os.path.join(tmp, "mixed")
    os.mkdir(mixed)
    import shutil as _shutil                                          # noqa: PLC0415

    _shutil.copyfile(SEED, os.path.join(mixed, os.path.basename(SEED)))
    with open(os.path.join(mixed, "BROKEN.EXE-DEADBEEF.pf"), "wb") as fh:
        fh.write(b"\x1e\x00\x00\x00NOPE" + b"\x00" * 80)
    code, out, err = run("parse", mixed, "--csv", os.path.join(tmp, "mixed.csv"))
    named = out + err
    check("the failing file is named", "BROKEN.EXE-DEADBEEF.pf" in named, named.strip()[:80])
    check("...with the stage it failed at", "[signature]" in named, named.strip()[:80])
    check("...and the run still succeeds for the rest", code == 0, f"exit={code}")

    print("\nsuccess path still returns 0:")
    code, out, err = run("parse", SEED, "--csv", os.path.join(tmp, "fine.csv"))
    check("clean run exits zero", code == 0, f"exit={code}")

    os.chmod(readonly, stat.S_IRWXU)
    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
