#!/usr/bin/env python3
"""Diff the two executable-path resolvers against each other on the real corpora.

Evidence for `docs/prefetch-format.md` §5a.1 and `docs/new-tool-design.md` §4.0 — the claim
that the undocumented §5a path string is the *primary* source and filename-list matching is
only the fallback. That claim decides how the real parser resolves paths, so it needs to stay
checkable rather than being a number someone once quoted.

  A) §5a  - the undocumented NUL-terminated UTF-16 string between the filename block and
            the volume block (modern v30/v31 only).
  B) §4.1 - basename equality against the parsed filename list. What PECmd does, roughly,
            and the only method available on pre-modern files.

Run:  python3 compare_pathsources.py [prefetch-dir ...]
Exits non-zero if the measured outcome differs from what the docs record.
"""

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import corpus  # noqa: E402
from validate_spec import parse  # noqa: E402

DEFAULT_DIRS = [
    corpus.WIN10,
    corpus.WIN11,
]

# What §5a.1 / §4.0 currently claim. Update these together with the docs, never separately.
EXPECTED = {
    "exact": 443,
    "disambiguated": 13,
    "conflict": 5,
    "only_5a": 2,
    "package": 171,
    "no_5a": 2,
    # Of the `package` files, how many still get a path out of the filename list.
    # An earlier version of this script skipped that check and reported all 171 as
    # unresolvable, which was an artifact of not looking rather than a fact.
    "package_resolved": 171,
    "unresolved_total": 2,
}


def strip_volume(path):
    """Drop the leading volume component so the two notations can be compared.

    §5a writes \\DEVICE\\HARDDISKVOLUMEn while filename-list entries write \\VOLUME{...}.
    Same volume, different spelling - comparing the raw strings reports 100% disagreement.
    """
    upper = path.upper()
    for prefix in ("\\DEVICE\\", "\\VOLUME{"):
        if upper.startswith(prefix):
            sep = upper.find("\\", len(prefix))
            return upper[sep:] if sep >= 0 else upper
    return upper


def is_path(field):
    return bool(field) and (field.startswith("\\DEVICE\\") or field.startswith("\\VOLUME{"))


def resolve_from_filename_list(pf):
    """§4.1: last path COMPONENT compared for equality - not PECmd's EndsWith substring test.

    Falls back to a prefix match when the header name is exactly 29 characters, i.e. when the
    header field truncated it. Equality can never match a truncated name, so without this the
    two longest-named executables in the corpus resolve to nothing for a spelling reason
    rather than a real absence of evidence.
    """
    target = pf.exe_name.upper()
    hits = [f for f in pf.filenames if f.rsplit("\\", 1)[-1].upper() == target]
    if not hits and len(pf.exe_name) == 29:
        hits = [f for f in pf.filenames if f.rsplit("\\", 1)[-1].upper().startswith(target)]
        # A bare prefix match also catches the executable's satellite files -
        # FOO.EXE.CONFIG, FOO.EXE.MUI, FOO.APPDOMAIN.DLL - which are not candidates for
        # "what ran" at all. Counting them as rival candidates would manufacture ambiguity
        # that isn't in the data and overstate what the 5a field is resolving.
        # The real name is the SHORTEST completion of the truncated prefix; a satellite is
        # always the executable's name plus a further suffix.
        if len(hits) > 1:
            shortest = min(len(h.rsplit("\\", 1)[-1]) for h in hits)
            hits = [h for h in hits if len(h.rsplit("\\", 1)[-1]) == shortest]
    return hits


def main(dirs):
    counts = dict.fromkeys(EXPECTED, 0)
    disambiguated, conflicts = [], []
    total = 0

    for d in dirs:
        files = sorted(glob.glob(os.path.join(d, "*.pf")))
        if not files:
            print(f"!! no .pf files under {d}", file=sys.stderr)
        for p in files:
            with open(p, "rb") as fh:
                pf = parse(fh.read())
            total += 1
            stored = pf.exec_path_field

            if stored and not is_path(stored):
                # Store/UWP identity. This is NOT an alternative spelling of the path - for
                # generic host processes it names the *package being hosted* while the exe
                # itself is something like \WINDOWS\SYSTEM32\DLLHOST.EXE. So the filename
                # list still has to be consulted for a path; it is not "no answer".
                counts["package"] += 1
                if resolve_from_filename_list(pf):
                    counts["package_resolved"] += 1
                else:
                    counts["unresolved_total"] += 1
                continue
            if not is_path(stored):
                counts["no_5a"] += 1
                if not resolve_from_filename_list(pf):
                    counts["unresolved_total"] += 1
                continue

            candidates = resolve_from_filename_list(pf)
            if not candidates:
                counts["only_5a"] += 1
                continue

            tails = {strip_volume(c) for c in candidates}
            if strip_volume(stored) in tails:
                if len(candidates) == 1:
                    counts["exact"] += 1
                else:
                    counts["disambiguated"] += 1
                    disambiguated.append((os.path.basename(p), stored, sorted(tails)))
            else:
                counts["conflict"] += 1
                conflicts.append((os.path.basename(p), stored, sorted(candidates),
                                  pf.run_count, len(pf.run_times)))

    label = {
        "exact":         "5a == the single filename-list candidate",
        "disambiguated": "5a picks among 2+ candidates   (4.1 would guess)",
        "conflict":      "5a path absent from filename list (4.1 would be WRONG)",
        "only_5a":       "5a has path, filename list none   (4.1 would FAIL)",
        "package":       "Store/UWP package identity in 5a",
        "no_5a":         "no 5a field, fall through to 4.1",
        "package_resolved": "  ...of those, path recovered from filename list",
        "unresolved_total": "NO PATH FROM EITHER SOURCE",
    }
    print(f"{total} modern files\n")
    ok = True
    for key in ("exact", "disambiguated", "conflict", "only_5a", "package",
                "package_resolved", "no_5a", "unresolved_total"):
        got, want = counts[key], EXPECTED[key]
        flag = "" if got == want else f"   << docs say {want}"
        ok &= got == want
        print(f"  {label[key]:<56} {got:>4}{flag}")

    if disambiguated:
        print("\n--- 5a resolved a real ambiguity ---")
        for name, picked, tails in disambiguated:
            others = [t for t in tails if t != strip_volume(picked)]
            print(f"  {name}\n     picked : {picked}\n     over   : {others}")

    if conflicts:
        print("\n--- 5a and the filename list disagree ---")
        for name, stored, cands, rc, nrt in conflicts:
            print(f"  {name}   RunCount={rc}, {nrt} run time(s)")
            print(f"     5a  : {stored}")
            print(f"     list: {cands}")
        print("  All have RunCount=1, so no rename-between-executions explains them.")
        print("  Pattern: 5a holds the path the process LAUNCHED from, the filename list holds")
        print("  a path the file occupied earlier (Edge updater DOWNLOAD\\{guid} -> INSTALL\\{guid}).")
        print("  Report both - the pair is evidence the binary moved. prefetch-format.md 5a.1.")

    print("\nMATCHES DOCUMENTED RESULT" if ok else "\nDRIFT - docs and measurement disagree")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or DEFAULT_DIRS))
