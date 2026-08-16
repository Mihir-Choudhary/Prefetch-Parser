#!/usr/bin/env python3
"""CLI must fail usefully: no tracebacks, a stated cause, and never discard the whole run.

Parsing a large folder costs real time. Losing all of it behind a Python traceback because one
output path had the wrong permissions is the difference between a tool an analyst trusts and
one they work around. Every failure mode here must print `!! <what> : <why>`, exit non-zero,
and still write whatever other output was requested.

Run:  python3 test_cli_errors.py
"""

import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import corpus  # noqa: E402
SEED = "" + corpus.WIN10 + "/7ZFM.EXE-7C92DCA0.pf"

failures = []


def run(*args):
    p = subprocess.run([sys.executable, "-m", "pfcli", *args],
                       cwd=ROOT, capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout, p.stderr


def check(label, ok, detail=""):
    # str(detail): callers pass counts as well as strings, and a harness that raises TypeError
    # while reporting a failure hides the failure behind a traceback.
    print(f"  {label:52} {'ok' if ok else 'FAIL'}"
          f"{'  ' + str(detail) if detail and not ok else ''}")
    if not ok:
        failures.append(label)


def main():
    tmp = tempfile.mkdtemp()
    readonly = os.path.join(tmp, "ro")
    os.mkdir(readonly)
    os.chmod(readonly, stat.S_IRUSR | stat.S_IXUSR)
    notadb = os.path.join(tmp, "notadb")
    with open(notadb, "w") as fh:
        fh.write("this is not a database")

    cases = [
        ("db in a read-only directory", os.path.join(readonly, "x.db")),
        ("db path is a directory", tmp),
        ("db path is not a database", notadb),
        ("db in a nonexistent directory", os.path.join(tmp, "nope", "x.db")),
    ]
    print("database failures:")
    for label, target in cases:
        code, out, err = run("parse", SEED, "--db", target)
        check(f"{label}: exits non-zero", code != 0, f"exit={code}")
        check(f"{label}: reports the cause", "!! could not write database" in err)
        check(f"{label}: no traceback", "Traceback" not in err and "Traceback" not in out)

    print("\nCSV failures:")
    code, out, err = run("parse", SEED, "--csv", os.path.join(readonly, "x.csv"))
    check("unwritable CSV: exits non-zero", code != 0)
    check("unwritable CSV: reports the cause", "!! could not write CSV" in err)
    check("unwritable CSV: no traceback", "Traceback" not in err)

    print("\nwork is not discarded when one destination fails:")
    good_csv = os.path.join(tmp, "good.csv")
    code, out, err = run("parse", SEED, "--db", os.path.join(readonly, "x.db"),
                         "--csv", good_csv)
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
    check("folder listed twice", len(list(discover([folder, folder]))), once)
    check("folder plus a file inside it", len(list(discover([folder, SEED]))), once)
    check("same file twice", len(list(discover([SEED, SEED]))), 1)
    check("a ./ alias of the same file", len(list(discover(
        [SEED, os.path.join(os.path.dirname(SEED), ".", os.path.basename(SEED))]))), 1)

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

    print("\nsuccess path still returns 0:")
    code, out, err = run("parse", SEED, "--csv", os.path.join(tmp, "fine.csv"))
    check("clean run exits zero", code == 0, f"exit={code}")

    os.chmod(readonly, stat.S_IRWXU)
    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
