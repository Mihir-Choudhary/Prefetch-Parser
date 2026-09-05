# Prefetch Parser

A cross-platform Windows Prefetch (`.pf`) parser with a CLI and a GUI. Runs on Windows, Linux
and macOS — it does not need Windows to read Windows 10/11 prefetch.

![The grid](docs/images/main-grid.png)

- **Parses every version** — 17, 23, 26, 30, 31 (XP through Windows 11)
- **No Windows dependency** — pure-Python XPRESS Huffman decompressor, so compressed
  Win10/11 prefetch opens anywhere
- **Full executable paths**, from a file field no other tool reads
- **Nothing skipped** — loaded files with MFT references, every volume, directories, trace
  chains, and a row for files that fail to parse
- **The rest of the Prefetch folder too** — `Layout.ini`, the whole SuperFetch family
  (`Ag*.db`, `.7db`, `.ebd` — every recovered path checked against its own stored name hash,
  [how](docs/superfetch-format.md)), and Windows 11 **ReadyBoot boot traces**: an undocumented
  format reverse-engineered for this tool, giving every file a boot read and how much of it
  ([how](docs/readyboot-format.md))
- **Nothing walked past** — an unrecognised file in the folder is still reported, and every
  non-zero byte of a `.pf` is either parsed into a field or reported as residue left behind by
  an earlier version of that record
- **Says when a file has been renamed** — a prefetch filename is built from the executable name
  and a path hash, and the header holds both; the two are compared on every file, so a renamed
  or planted `.pf` is reported instead of read at face value
- **Alternate data streams** — recovers prefetch hidden in an ADS, without pretending the
  carrier's timestamps are its own
- **Everything exports** — `.pf` records to SQLite and CSV; the folder's other artifacts to
  their own tables and their own CSV (`pfcli artifacts --db --csv`), because access evidence
  does not belong in an execution table but does belong in the report
- **GUI** with Excel-style per-column filters, tagging and export; **CLI** for scripting

## Quick start

```bash
pip install PySide6                 # GUI only; the CLI and library need nothing

python -m pfcli parse C:\Windows\Prefetch --csv out.csv --db out.db
python -m pfcli info  SOME.EXE-ABCD1234.pf
python -m pfcli ads   C:\Windows\Prefetch      # hunt for prefetch hidden in streams
python -m pfgui       C:\Windows\Prefetch      # GUI
```

## Documentation

**[Full documentation](docs/DOCUMENTATION.md)** — every output field explained, the file format,
how paths are resolved, ADS handling, cross-platform notes, the test suite, and the
**limitations and open questions**.

## Status

23 test suites. Verified against 699 real prefetch files across all five versions and four
independent sources, against an independently written parser built from the format
specification, and against **224 expected values taken from a different implementation's own
test suite** — an external oracle, not a second opinion from the same author.

A suite that cannot run on a given machine — corpus not configured, Qt bindings absent — **skips
rather than passing**, and the runner refuses to report a skipped run as a pass. So "all green"
means all of it actually ran.

**Not yet run on Windows.** The Windows-specific code paths — the `ntdll` decompressor and ADS
enumeration — are written and unit-tested but have never executed on Windows. See the
[limitations](docs/DOCUMENTATION.md#limitations-and-open-questions).

## Licence

MIT.
