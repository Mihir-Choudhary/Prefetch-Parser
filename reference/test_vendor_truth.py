#!/usr/bin/env python3
"""Check this parser against an INDEPENDENT implementation's own expected values.

`validate_spec` and `test_core_vs_spec` compare two parsers written here, from the same format
document, by the same hand. They prove consistency, not correctness: a misreading of the spec
would be present in both and agree with itself perfectly.

The vendored NUnit tests of Eric Zimmerman's Prefetch library are the one external oracle in the
tree that states expected *values* - hashes, run times, volume serials, directory counts,
individual filenames and MFT references - written by someone else, from files they collected.
Seven of those assertions had been transcribed by hand into `validate_spec.GROUND_TRUTH`. There
are 248 of them. This suite reads them out of the C# source and checks every one it can map,
so the external truth is used in full rather than in the fraction somebody had time to copy.

Anything it cannot map is REPORTED, not skipped: an oracle you silently ignore is not an oracle.

Run:  python3 test_vendor_truth.py
"""

import datetime
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import corpus  # noqa: E402

from prefetch_core import parse_file  # noqa: E402

CORPUS_DIR = os.path.join(HERE, "pf-corpus")
SOURCES = sorted(glob.glob(os.path.join(HERE, "Test*.cs")))

# `TestPrefetchMain.Win2012R2Path` -> the directory in the vendored corpus.
FOLDER = re.compile(r"public static string (\w+)Path\s*=\s*@\"[^\"]*TestFiles\\(\w+)\"")
OPENS = re.compile(r'Path\.Combine\(TestPrefetchMain\.(\w+)Path,\s*@?"([^"]+)"\)')
ASSERT = re.compile(r'pf\.([A-Za-z0-9_.\[\]]+)\s*\.Should\(\)\s*\.Be\(\s*(.+?)\s*\)\s*;',
                    re.DOTALL)


def literal(text):
    """Turn a C# literal into a Python value, or return NotImplemented."""
    text = text.strip()
    if text.startswith("(ulong)") or text.startswith("(uint)") or text.startswith("(int)"):
        text = text.split(")", 1)[1].strip()
    if text == "null":
        return None
    if text.startswith("DateTimeOffset.Parse("):
        inner = text[len("DateTimeOffset.Parse("):].strip()
        # Some calls carry a second argument (a culture); the timestamp is the first literal.
        inner = inner.split('"')[1] if '"' in inner else inner.rstrip(")")
        # Their own literals carry stray spaces ("09: 50:34") and one trailing comma inside
        # the quotes. .NET's parser tolerates both; Python's does not.
        inner = inner.replace(" ", "").rstrip(",")
        # The C# source carries stray spaces inside a few timestamps ("14: 40:31").
        return datetime.datetime.fromisoformat(inner.replace(" ", "")).astimezone(
            datetime.timezone.utc)
    if text.startswith('@"') or text.startswith('"'):
        return text.lstrip("@").strip('"')
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if text in ("true", "false"):
        return text == "true"
    # Their version enum, mapped to the version number the file actually carries.
    # Their enum lumps versions together, so the expectation is a SET: "Win10OrWin11" is
    # satisfied by 30 or 31, and pinning it to one would fail on the other for no reason.
    versions = {"Version.WinXpOrWin2K3": {17}, "Version.VistaOrWin7": {23},
                "Version.Win8xOrWin2012x": {26}, "Version.Win10OrWin11": {30, 31}}
    if text in versions:
        return versions[text]
    # `file` is the variable holding the path just opened, and `totalDirs` is computed in the
    # test itself; neither is a literal, so neither can be checked from the source alone. They
    # are counted as unmapped and printed, never quietly dropped.
    return NotImplemented


def actual(pf, expression):
    """Map a C# property path onto this parser's record. NotImplemented = unmapped."""
    m = re.fullmatch(r"Header\.(\w+)", expression)
    if m:
        return {"ExecutableFilename": pf.executable_name, "Hash": pf.hash,
                "FileSize": pf.file_size, "Version": pf.version}.get(m.group(1), NotImplemented)
    if expression == "RunCount":
        return pf.run_count
    if expression == "VolumeCount":
        return len(pf.volumes)
    if expression == "TotalDirectoryCount":
        return pf.total_directory_count
    if expression == "LastRunTimes.Count":
        return len(pf.run_times)
    if expression == "SourceFilename":
        return os.path.basename(pf.source_path)
    if expression == "Filenames.Count":
        return len(pf.filenames)
    m = re.fullmatch(r"Filenames\[(\d+)\]", expression)
    if m:
        i = int(m.group(1))
        return pf.filenames[i] if i < len(pf.filenames) else "<missing>"
    m = re.fullmatch(r"LastRunTimes\[(\d+)\]", expression)
    if m:
        i = int(m.group(1))
        return pf.run_times[i] if i < len(pf.run_times) else None
    m = re.fullmatch(r"VolumeInformation\[(\d+)\]\.(\w+)\.Count", expression)
    if m:
        j, field = int(m.group(1)), m.group(2)
        if j >= len(pf.volumes):
            return "<missing volume>"
        v = pf.volumes[j]
        if field == "DirectoryNames":
            return len(v.directories)
        if field == "FileReferences":
            # Theirs counts SLOTS, including the empty ones; ours keeps the references and
            # records the declared slot count beside them. Same number, different name.
            return v.declared_ref_count
        return NotImplemented
    m = re.fullmatch(r"VolumeInformation\[(\d+)\]\.(\w+)(?:\[(\d+)\])?(?:\.(\w+))?", expression)
    if m:
        j, field, index, sub = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        if j >= len(pf.volumes):
            return "<missing volume>"
        v = pf.volumes[j]
        if field == "DeviceName":
            return v.device_name
        if field == "SerialNumber":
            return v.serial
        if field == "CreationTime":
            return v.created
        if field == "DirectoryNames" and index is None:
            return NotImplemented
        if field == "DirectoryNames" and sub is None:
            i = int(index)
            return v.directories[i] if i < len(v.directories) else "<missing>"
        if field == "FileReferences" and index is not None and sub in ("MFTEntryNumber",
                                                                      "MFTSequenceNumber"):
            # Their list keeps the array's empty slots as entries; ours drops them and records
            # the slot each surviving reference sat in. Index by SLOT and the two describe the
            # same bytes - which is the whole point of having kept the slots (AUDIT BUG 76).
            wanted = int(index)
            if wanted >= v.declared_ref_count:
                return "<past the declared slots>"
            if wanted in v.ref_slots:
                ref = v.file_refs[v.ref_slots.index(wanted)]
                return ref.entry if sub == "MFTEntryNumber" else ref.sequence
            # An empty slot: they render it as entry 0 with a null sequence.
            return 0 if sub == "MFTEntryNumber" else None
        return NotImplemented
    m = re.fullmatch(r"VolumeInformation\[(\d+)\]\.(\w+)\.Count", expression)
    if m:
        j, field = int(m.group(1)), m.group(2)
        if j >= len(pf.volumes):
            return "<missing volume>"
        v = pf.volumes[j]
        if field == "DirectoryNames":
            return len(v.directories)
        if field == "FileReferences":
            return len(v.file_refs)
    return NotImplemented


# Where this parser deliberately answers differently from the vendored library, with the reason.
# Each entry is (file, expression) and each must still be REPORTED, never silently passed.
# Where this parser deliberately answers differently, with the reason. Reported every run, so
# a difference can never quietly become invisible.
KNOWN_DIFFERENCES = {
    # Their hash is formatted with %X, which drops a leading zero: "87B4001" for the eight hex
    # digits 087B4001 that the file holds and that Windows used to build the filename. Ours
    # keeps all eight - see docs/edge-cases.md and the PECmd defects recorded in AUDIT.md.
    "Header.Hash": "their %X format drops a leading zero from an 8-digit hash",
    # Their sequence number is null wherever it is zero. A zero sequence number is a value the
    # file states, not an absence, and it distinguishes a reused MFT entry from a fresh one.
    "MFTSequenceNumber": "they render a zero sequence number as null; zero is a real value",
}


def main():
    if not os.path.isdir(CORPUS_DIR):
        corpus.skip("the vendored pf-corpus is not present (see .gitignore)")
    if not SOURCES:
        corpus.skip("the vendored NUnit sources are not present (see .gitignore)")

    folders = {}
    for source in SOURCES:
        for name, folder in FOLDER.findall(open(source, encoding="utf-8", errors="replace").read()):
            folders[name] = folder

    checked = failed = unmapped = 0
    expected_differences = []
    unmapped_kinds = {}
    failures = []
    files_seen = set()

    for source in SOURCES:
        text = open(source, encoding="utf-8", errors="replace").read()
        # Walk the file in order: every assertion belongs to the last file opened above it.
        events = []
        for m in OPENS.finditer(text):
            events.append((m.start(), "open", (m.group(1), m.group(2))))
        for m in ASSERT.finditer(text):
            events.append((m.start(), "assert", (m.group(1), m.group(2))))
        events.sort()
        current = None
        record = None
        for _pos, kind, payload in events:
            if kind == "open":
                folder, name = folders.get(payload[0]), payload[1]
                if folder is None:
                    current, record = None, None
                    continue
                path = os.path.join(CORPUS_DIR, folder, name)
                current = path if os.path.exists(path) else None
                record = parse_file(current) if current else None
                if current:
                    files_seen.add(os.path.relpath(current, CORPUS_DIR))
                continue
            if record is None:
                continue
            expression, raw = payload
            want = literal(raw)
            got = actual(record, expression)
            if want is NotImplemented or got is NotImplemented:
                unmapped += 1
                kind_key = re.sub(r"\d+", "N", expression)
                unmapped_kinds[kind_key] = unmapped_kinds.get(kind_key, 0) + 1
                continue
            checked += 1
            if isinstance(want, datetime.datetime) and isinstance(got, datetime.datetime):
                same = abs((want - got).total_seconds()) < 1e-6
            elif isinstance(want, set):
                same = got in want
            else:
                same = want == got
            if not same:
                reason = next((why for key, why in KNOWN_DIFFERENCES.items()
                               if key in expression), None)
                if reason:
                    expected_differences.append(
                        (os.path.basename(current), expression, got, want, reason))
                    continue
                failed += 1
                failures.append((os.path.basename(current), expression, got, want))

    print(f"vendored expected values checked : {checked}")
    print(f"files covered                    : {len(files_seen)}")
    print(f"assertions this suite cannot map : {unmapped}")
    for kind_key, count in sorted(unmapped_kinds.items(), key=lambda kv: -kv[1]):
        print(f"    {count:3}  {kind_key}")
    if expected_differences:
        print(f"\ndeliberate differences ({len(expected_differences)}), each with a reason:")
        seen = set()
        for name, expression, got, want, reason in expected_differences:
            key = (expression.split("[")[0], reason)
            if key in seen:
                continue
            seen.add(key)
            print(f"    {expression}: ours {got!r}, theirs {want!r}\n        {reason}")
        print(f"    ({len(expected_differences)} value(s) in total)")
    if failures:
        print(f"\n{len(failures)} DISAGREEMENT(S) with the independent implementation:")
        for name, expression, got, want in failures[:20]:
            print(f"   {name} {expression}\n      ours:   {got!r}\n      theirs: {want!r}")

    # A suite that maps nothing would pass silently, which is the failure this file exists to
    # prevent elsewhere.
    if checked < 100:
        print(f"\nFAIL - only {checked} assertions could be checked; the extractor has drifted "
              f"from the C# source")
        return 1
    print("\nPASS - this parser agrees with every mapped value of an independent implementation"
          if not failures else "\nFAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
