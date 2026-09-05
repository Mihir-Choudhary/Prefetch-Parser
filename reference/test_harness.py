#!/usr/bin/env python3
"""The harness's own contract: a suite that cannot run must SKIP, never pass and never accuse.

Every other suite in this directory tests the tool. This one tests the thing that decides
whether those suites ran at all, because that turned out to be the place where a wrong answer
is least visible: on a machine without the corpora configured, the suite reported

  - "DRIFT - docs and measurement disagree"  (compare_pathsources, edge_cases)
  - "saw 55 files, expected 691 - corpus moved?"  (test_core_vs_spec)
  - four raw tracebacks
  - and four PASSes, one of them "ALL CHECKS PASSED" over 54 synthetic files where the
    documented figure is 683.

Three different ways of blaming the evidence for an unset environment variable, plus the
vacuous green `corpus.py` was written to prevent. `corpus.require()` existed for exactly this
and was called from nowhere.

What is pinned here:

  1. every suite named by run_tests.sh exits SKIP_EXIT when nothing is configured - never 0,
     never a traceback;
  2. the runner reports that run as NOT a pass, and exits non-zero;
  3. the SUITE list covers every test file present, so a new suite cannot be added to the
     directory and silently never run;
  4. corpus-paths.env is read when the environment is unset, and the environment wins over it.

Run:  python3 test_harness.py
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import corpus  # noqa: E402

RUNNER = os.path.join(ROOT, "run_tests.sh")
SELF = os.path.basename(__file__)[:-3]

CHILD = "PREFETCH_HARNESS_SELFTEST"   # set on the inner run; see main()

failures = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {label:<58} {'ok' if ok else 'FAIL'}"
          + ("" if ok else f"  got {got!r} want {want!r}"))
    if not ok:
        failures.append(label)


def suite_names():
    """The SUITE array in run_tests.sh, which is the list that actually gets run."""
    text = open(RUNNER, encoding="utf-8").read()
    body = text[text.index("SUITE=("):text.index(")", text.index("SUITE=("))]
    return [line.split()[0] for line in body.splitlines()[1:] if line.strip()]


def unconfigured_env():
    """A machine with no corpus: variables unset and the paths file pointed at nothing."""
    env = dict(os.environ)
    for name in corpus.SETTINGS:
        env.pop(name, None)
    env["CORPUS_PATHS_FILE"] = os.devnull
    env[CHILD] = "1"
    return env


# Suites whose inputs are vendored in the repository rather than configured: they need no
# corpus path, so "skips when nothing is configured" is the wrong contract for them. They must
# instead PASS unconfigured, and this list is checked in both directions below.
SELF_CONTAINED = ("test_vendor_truth", "test_windows_lane")


def main():
    if os.environ.get(CHILD):
        # run_tests.sh lists this suite, and this suite runs run_tests.sh. Without a marker the
        # two call each other forever. The inner instance reports what is true of it - it did
        # not run - which is also what the outer instance is checking every suite reports.
        corpus.skip("this is the harness self-test invoked by its own runner check")

    names = suite_names()
    print(f"run_tests.sh runs {len(names)} suites\n")

    print("the SUITE list covers every suite in the directory:")
    on_disk = {f[:-3] for f in os.listdir(HERE)
               if f.startswith(("test_", "fuzz_", "validate_", "compare_", "edge_", "diff_"))
               and f.endswith(".py")}
    missing = sorted(on_disk - set(names))
    check("no suite exists that the runner never runs", missing, [])
    check("no suite is listed that does not exist", sorted(set(names) - on_disk), [])

    print("\nwith nothing configured, every suite skips - none passes, none crashes:")
    env = unconfigured_env()
    swept = 0
    for name in names:
        if name == SELF:
            continue
        if name in SELF_CONTAINED:
            # This suite's inputs are vendored in the tree, so it needs no configuration and a
            # pass from it is not vacuous. The rule still bites both ways: it must PASS here,
            # and if it ever starts needing configuration it will skip and be reported.
            r = subprocess.run([sys.executable, f"{name}.py"], cwd=HERE, env=env,
                               capture_output=True, text=True, timeout=600)
            passed = r.returncode == 0
            print(f"  {name:<58} "
                  f"{'runs unconfigured (vendored inputs)' if passed else 'FAIL exit=' + str(r.returncode)}")
            if not passed:
                failures.append(
                    f"{name} is listed as self-contained but did not pass unconfigured "
                    f"(exit={r.returncode}); either its inputs moved or it should be removed "
                    f"from SELF_CONTAINED")
            swept += 1
            continue
        r = subprocess.run([sys.executable, f"{name}.py"], cwd=HERE, env=env,
                           capture_output=True, text=True, timeout=300)
        output = r.stdout + r.stderr
        detail = f"exit={r.returncode}"
        if r.returncode != corpus.SKIP_EXIT:
            detail += " " + " ".join(output.strip().splitlines()[-1:])
        ok = r.returncode == corpus.SKIP_EXIT
        print(f"  {name:<58} {'skip' if ok else 'FAIL ' + detail}")
        if not ok:
            failures.append(f"{name} did not skip ({detail})")
        # A skip must say why. "SKIP:" with no reason is the same silence in a new costume.
        if ok and "SKIP:" not in output:
            failures.append(f"{name} skipped without a reason")
        if ok and "Traceback" in output:
            failures.append(f"{name} skipped but printed a traceback")
        swept += 1

    # The sweep is only worth what it covered. Without this, dropping a suite from SUITE would
    # quietly shrink it while every line still read "skip" - the coverage lesson again.
    check("the sweep covered every suite but this one", swept, len(names) - 1)

    print("\nthe runner refuses to call that a pass:")
    r = subprocess.run(["bash", RUNNER], cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=900)
    check("run_tests.sh exits non-zero", r.returncode != 0, True)
    check("...specifically SKIP_EXIT, not a failure", r.returncode, corpus.SKIP_EXIT)
    check("it never reports a clean sweep", "suites green" in r.stdout, False)
    check("...and the self-contained suites did run", 
          all(f"{name}" in r.stdout for name in SELF_CONTAINED), True)
    check("it names the suites that did not run", "NOT a full pass" in r.stdout, True)
    # ...except the self-contained suites, which really did run. Anything else reading PASS
    # would be a vacuous green, which is the whole point of this file.
    unexpected_pass = [line for line in r.stdout.splitlines()
                       if re.search(r"\bPASS\b", line)
                       and not any(line.startswith(name) for name in SELF_CONTAINED)]
    check("no suite reports PASS except the ones with vendored inputs", unexpected_pass, [])

    print("\ncorpus-paths.env is read when the environment is unset:")
    with tempfile.TemporaryDirectory() as tmp:
        fake10 = os.path.join(tmp, "win10")
        fake11 = os.path.join(tmp, "win11")
        os.mkdir(fake10)
        os.mkdir(fake11)
        paths_file = os.path.join(tmp, "corpus-paths.env")
        with open(paths_file, "w", encoding="utf-8") as fh:
            fh.write("# comment\n\n"
                     f"PREFETCH_CORPUS_WIN10={fake10}\n"
                     f'PREFETCH_CORPUS_WIN11="{fake11}"\n'
                     "IGNORED_KEY=/nowhere\n")

        def probe(extra_env):
            e = unconfigured_env()
            e["CORPUS_PATHS_FILE"] = paths_file
            e.update(extra_env)
            code = ("import corpus, sys;"
                    "print(corpus.WIN10);print(corpus.WIN11);print(corpus.PECMD_CSV)")
            out = subprocess.run([sys.executable, "-c", code], cwd=HERE, env=e,
                                 capture_output=True, text=True, timeout=60)
            return out.stdout.splitlines()

        got = probe({})
        check("WIN10 comes from the file", got[0], fake10)
        check("quotes are stripped", got[1], fake11)
        check("an unconfigured setting stays empty", got[2], "")

        other = os.path.join(tmp, "other")
        os.mkdir(other)
        got = probe({"PREFETCH_CORPUS_WIN10": other})
        check("the environment wins over the file", got[0], other)
        check("...for that setting only", got[1], fake11)

        # A configured-but-missing path must skip too: it is a stale setting, not a corpus.
        gone = os.path.join(tmp, "gone")
        e = unconfigured_env()
        e["PREFETCH_CORPUS_WIN11"] = gone
        r = subprocess.run([sys.executable, "test_memory.py"], cwd=HERE, env=e,
                           capture_output=True, text=True, timeout=120)
        check("a path that does not exist skips", r.returncode, corpus.SKIP_EXIT)
        check("...and says which setting is stale",
              "PREFETCH_CORPUS_WIN11" in r.stderr and gone in r.stderr, True)

    print("\na missing seed file skips rather than parsing nothing:")
    # parse_file returns a failed record instead of raising (D10), so a suite pinned to one
    # named file will happily assert against an empty record if the file is not there.
    code = ("import corpus;"
            "corpus.require_seed('/definitely/not/here.pf');"
            "print('reached')")
    r = subprocess.run([sys.executable, "-c", code], cwd=HERE, capture_output=True, text=True,
                       timeout=60)
    check("require_seed exits SKIP_EXIT", r.returncode, corpus.SKIP_EXIT)
    check("...and does not fall through", "reached" not in r.stdout, True)

    print()
    if failures:
        for f in failures:
            print(f"FAILED: {f}")
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("harness contract holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
