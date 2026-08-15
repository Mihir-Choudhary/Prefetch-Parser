# Prefetch Parser — full documentation

Everything the tool parses, everything it reports, how it decides what it reports, and what it
cannot do. Screenshots use the upstream project's **published sample corpus**, not data from
anyone's machine.

- [What prefetch is](#what-prefetch-is)
- [Installing and running](#installing-and-running)
- [The GUI](#the-gui)
- [Every field explained](#every-field-explained)
- [How the executable path is resolved](#how-the-executable-path-is-resolved)
- [The file format](#the-file-format)
- [Other files in the Prefetch folder](#other-files-in-the-prefetch-folder)
- [Alternate data streams](#alternate-data-streams)
- [Cross-platform](#cross-platform)
- [Outputs](#outputs)
- [Testing](#testing)
- [Limitations and open questions](#limitations-and-open-questions)

---

## What prefetch is

Windows watches roughly the first ten seconds of a process launch and writes
`%SystemRoot%\Prefetch\<NAME>-<HASH>.pf`. Forensically it answers: **this executable ran on
this machine, this many times, at these timestamps, from this volume, and it touched these
files and directories.**

Two things follow that shape everything below:

- A prefetch file is **execution evidence**. The other files in the folder are not.
- Only the **last 8 run times** are kept. `RunCount` can be in the hundreds; the earlier runs
  are gone from the record.

---

## Installing and running

Python 3.10+. The library and CLI have **no dependencies**; the GUI needs PySide6.

```bash
pip install PySide6
```

### CLI

```bash
python -m pfcli parse <path> [--csv out.csv] [--db out.db] [--no-recurse] [--raw-csv]
python -m pfcli info <file.pf>
python -m pfcli artifacts <folder> [--paths]
python -m pfcli ads <folder> [--db out.db] [--files-only]
python -m pfcli capabilities
```

`parse` accepts files or folders and recurses by default (ReadyBoot lives in a subfolder).
Overlapping arguments are de-duplicated, so `parse FOLDER FOLDER` does not double every row.

Exit codes: `0` success, `1` nothing parsed or an output could not be written, `2` alternate
data streams cannot be enumerated on this host.

### GUI

```bash
python -m pfgui [folder]
```

---

## The GUI

![The grid](images/main-grid.png)

**Filtering.** Right-click any column header. The dropdown lists the distinct values *available
under the other columns' filters*, with a search box; `All` / `None` / `Invert` act on the
search-narrowed subset, so you can tick forty matching values in one click.

![Column filter](images/column-filter.png)

Filters **intersect**. Every header carries a `▿`; an active filter shows `▼`.

**Highlighted rows** mark facts about the evidence, never a verdict about badness:

| Tint | Meaning |
|---|---|
| Red | the file failed to parse — the row is partial |
| Red | the name or path contains deceptive characters |
| Amber | the two path sources disagree (see `Alt Path`) |

Colours are derived from your theme, so they stay legible on light and dark desktops.

**Detail tabs** describe the selected row: Summary, Run times, Volumes, Loaded files. Each is a
sortable, filterable, copyable table.

![Loaded files](images/detail-loaded-files.png)

**Folder artifacts** (toolbar or `Ctrl+R`) opens a *separate* window, because it describes the
whole folder rather than the selected row.

**Other:** `Columns` menu to show/hide (persisted); `Views` menu to save and restore filter
sets; right-click a cell to copy; tag rows with notes; export tagged rows or the current
filtered view.

---

## Every field explained

### Identity

| Field | Meaning |
|---|---|
| `Source` / `source file` | the `.pf` file this row came from |
| `Executable` | the executable name **from the file header**. The header field holds only 29 characters, so long names are cut — see `Name Cut` |
| `Name Cut` | `yes` = the 29-character header field was full. **The path is not truncated**; it comes from elsewhere in the file and is complete, which is how the full name is recovered |
| `Hash` | the hash in the filename, 8 hex digits. **Not recomputable** — see [limitations](#limitations-and-open-questions) |
| `Ver` | format version: 17, 23, 26, 30, 31 |

### Timestamps

| Field | Meaning |
|---|---|
| `source created/modified/accessed` | filesystem timestamps of the `.pf` itself. Creation is only reported where the OS supplies a real birth time |
| `Last Run (UTC)` | the **newest** of the stored run times |
| `run times kept` | how many of the 8 slots hold a time |
| `first run approx` | `source created − 10s`, an estimate of the first execution. Shown with `~`. Blank when no creation time is available |

Everything is UTC.

> **The 8 run-time slots are not reliably newest-first.** In a 636-file corpus, 6 files have a
> newer timestamp in a later slot — near-simultaneous launches recorded out of order. `Last Run`
> is therefore `max()`, not slot 0. The Run times tab shows the **stored order**, because that
> order is itself evidence.

### Paths

| Field | Meaning |
|---|---|
| `Executable Path` | the resolved full path |
| `Path Source` | how it was determined — see [below](#how-the-executable-path-is-resolved) |
| `Alt Path` | the other source's answer when the two disagree |
| `Hosted Package` | the UWP package identity |

**`Hosted Package` is often not the executable.** For generic hosts it names the *package being
hosted*, which the executable name alone cannot tell you:

| Executable that ran | Package it was hosting |
|---|---|
| `\WINDOWS\SYSTEM32\DLLHOST.EXE` | `Microsoft.WindowsTerminal_…` |
| `\WINDOWS\SYSTEM32\RUNTIMEBROKER.EXE` | `Microsoft.StorePurchaseApp_…` |

This is the UWP analogue of knowing which *service* an `svchost.exe` was running. A package
name is `Publisher.Name_Version_Arch__PublisherHash`.

### Counts and contents

| Field | Meaning |
|---|---|
| `Runs` | executions since the record was created. May exceed the 8 retained times |
| `Vols` | volumes referenced. More than one is uncommon and worth noticing |
| `Files` | files recorded during the traced startup window |
| `Dirs` | directories touched |
| `trace chains` | prefetcher block-load bookkeeping (see the format section) |
| `MFT references` | NTFS file references for loaded files — entry number and sequence |

### Flags and status

| Field | Meaning |
|---|---|
| `Op File` | an `Op-*.pf`. Not ordinary prefetch: no embedded path field, and it does not list its own executable |
| `Deceptive` | the name or path contains right-to-left overrides, zero-width or control characters — it *displays* differently from how it is stored. The GUI shows the escaped form; CSV and SQLite carry the raw bytes |
| `Parsed` / `Failed Stage` | whether parsing completed, and which stage stopped it |
| `Problems` | non-fatal findings recorded during parsing |
| `Note` | your own note, attached when tagging |

**Every input produces a row**, including files that fail to parse. A partial record is still
evidence; a file that silently disappears from a report is not.

---

## How the executable path is resolved

Modern prefetch (v30/31) stores the executable's full path in an **undocumented
NUL-terminated UTF-16 string** between the filename block and the volume block, pointed at by
no offset field. No other parser reads it.

Resolution order:

1. **That field**, if it holds a device path → `Path Source: stored`
2. Otherwise **match the executable name against the file list** → `resolved`

`Path Source` values:

| Value | Meaning |
|---|---|
| `stored` | read directly from the file. Most reliable |
| `resolved` | matched against the loaded-file list |
| `conflict` | both sources present and they **disagree**. Both paths are reported |
| `ambiguous` | several candidates, none decisive |
| `unresolved` | no path from any source |

Measured over 636 modern files: 443 exact agreement, 13 where the stored field decisively
picks among candidates (System32 vs SysWOW64, `Git\bin` vs `Git\usr\bin`), 5 conflicts, 2 with
no path from either source.

**Conflicts are a finding, not noise.** All five have `RunCount = 1`, and three are the Edge
updater with `EDGEUPDATE\INSTALL\{guid}` in one source and `EDGEUPDATE\DOWNLOAD\{guid}` in the
other — consistent with the stored field recording where the process *launched from* while the
file list holds a path it occupied earlier. Same file name, different directory, one execution.
The tool reports both and asserts nothing.

**Truncated names.** A 29-character header name cannot match by equality, so a prefix match is
used, taking the *shortest* completion — a bare prefix would also catch `FOO.EXE.CONFIG` and
`FOO.EXE.MUI`.

---

## The file format

A `.pf` is: an 84-byte header, a file-information section, a file-metrics array, trace chains,
a filename string block, and one or more volume records. Windows 10/11 wrap all of it in a
`MAM` container compressed with XPRESS Huffman.

Findings that contradict every public source and the reference implementation:

| Finding | Detail |
|---|---|
| **The executable path is stored outright** | undocumented UTF-16 string; no parser reads it |
| **The file-information section is 212 bytes** on modern builds, 220 on 2015-era v30 — never the 224 the reference uses |
| **RunCount sits 96 bytes before the section end** | the reference probes `+120` and is right by accident |
| **`\VOLUME{hex-hex}` encodes the volume's creation FILETIME and serial** | a free integrity check; it agreed on all 648 volumes tested |
| **The header size field equals the decompressed length** | agreed on all 690 files, so a mismatch is a tamper signal and is reported |

Version 31 is real and structurally identical to modern v30 — an OS label, not a format change.

**Trace chains** are parsed and stored, which no other tool does. Only the "next index" field
is confidently identified; on v17/23/26 the second field behaves like a block-load count and is
exposed as such, and on v30/31 it holds values that are plainly not a count, so it is left
**unnamed** rather than given a label it does not deserve.

Full byte-level specification: [`prefetch-format.md`](prefetch-format.md).

---

## Other files in the Prefetch folder

A Prefetch folder is not only prefetch. These carry **file-access and prefetcher-priority
evidence — not execution**, and have no run times. The GUI keeps them in a separate window for
that reason.

| File | What it is |
|---|---|
| `Layout.ini` | UTF-16 list of files the prefetcher wants laid out contiguously. **The only artifact in the folder with a drive letter**, and on Windows 11 it names user accounts and installed software |
| `PfPre_<hex>.mkd` | a fixed **16,384-slot event ring buffer**. The header count is events *ever written*, so a count above 16,384 means older events were overwritten. The event types are not decoded |
| `*.7db`, `*.ebd` | SuperFetch resource-priority databases. One self-validating container; `.ebd` is MAM-compressed. Holds paths in prefetch's own `\VOLUME{serial}` notation |
| `ReadyBoot/Trace*.fx`, `rblayout.xin` | boot traces. The container is decoded; **the payload is not** (see limitations) |

Detailed analysis: [`prefetch-artifacts.md`](prefetch-artifacts.md).

---

## Alternate data streams

An executable launched from an NTFS alternate data stream gets a prefetch file that **itself
lives in a stream**. The carrier's primary stream is typically 0 bytes, so a folder listing
shows an empty file and every tool that globs `*.pf` sees nothing.

```bash
python -m pfcli ads C:\Windows\Prefetch
python -m pfcli ads C:\Users --db out.db
```

This scans **every file regardless of extension, and directories too** (NTFS directory objects
carry streams), and detects prefetch by **content**, not by the stream being named `.pf`.

### The timestamp rule

**A stream has no timestamps of its own.** NTFS keeps them per *file*, not per *stream*, so any
timestamp for an ADS-hosted prefetch belongs to the **carrier**.

| Field | Behaviour for an ADS record |
|---|---|
| `source created` | **stays empty** — never filled from the carrier |
| `first run approx` | **refuses to estimate** |
| `timestamp source` | `stream` / `carrier` / `unavailable` |
| `carrier created/modified/accessed` | the carrier's times, under their own names |

Feeding a carrier's creation time into the first-run estimate would print a confident timestamp
for an execution it has nothing to do with.

**"Cannot look" is never reported as "found nothing."** On a host where streams cannot be
enumerated the command exits 2 and says so.

---

## Cross-platform

The one thing that ties prefetch parsing to Windows is decompression: Win10/11 files are
compressed and the usual approach calls `ntdll!RtlDecompressBufferEx`, which is why the
reference tool refuses to start on other systems.

This tool ships a **pure-Python XPRESS Huffman decompressor** written from Microsoft's
[MS-XCA] specification. It decompresses all 642 compressed files in the test corpora with zero
failures, so Linux and macOS are first-class.

Where `ntdll` is available it is used, chosen by a **capability probe rather than an OS check** —
`ntdll` can be blocked on hardened Windows and is present under Wine. `--decompressor
ntdll|pure` overrides; `pfcli capabilities` reports what is available.

Other platform care:
- **Windows paths are never handled with `os.path`** — it does not split `\` on POSIX.
- **Creation time** comes from `st_birthtime` where it exists, falling back to `st_ctime`
  **on Windows only**, because on Linux that field is inode-change time and would invent
  creation timestamps.
- All timestamps are UTC; output is byte-identical regardless of the machine's timezone.

---

## Outputs

### SQLite (`--db`) — the primary artifact

Relational, so nothing is flattened away: `prefetch`, `run_time`, `volume`, `directory`,
`loaded_file`, `file_ref`, `problem`, plus a `timeline` view of one row per execution. Trace
chains are stored as a blob rather than millions of rows.

Ingest is **idempotent per source file**, so re-scanning a folder updates rather than
duplicates. The database is self-contained — journal mode is `DELETE`, not WAL, so a copied
`.db` is complete even if the process was killed mid-run.

### CSV (`--csv`) — an export

A **strict superset of PECmd's columns** — all 27, plus 14 more.

Two safety behaviours, because a filename is attacker-chosen and a forensic CSV is opened in a
spreadsheet:

- **Formula injection** — a cell starting `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
  Values that are simply numbers are left exact. `--raw-csv` disables this.
- **List cells** hold multiple values separated by ` | `, with a literal `|` escaped as `^p`
  (and `^` as `^^`), so an element containing the separator cannot inject extra entries.

The SQLite store is never sanitised — it is the source of truth.

### Differences from PECmd, deliberate

| | PECmd | Here |
|---|---|---|
| Hash | printed with `X`, dropping leading zeros — **13 of 160** files disagreed with their own filename | 8 digits always |
| `LastRun` | slot 0 | `max()` of the run times |
| Executable path | resolved only in the timeline CSV, so its two outputs disagree | resolved once in the core |
| Volumes | first two, then a note | all of them |
| Directories | concatenated across volumes with no separator | volume-tagged |
| Failed files | console only | a row, with the failing stage |

---

## Testing

```bash
export PREFETCH_CORPUS_WIN10=/path/to/a/Win10/Prefetch
export PREFETCH_CORPUS_WIN11=/path/to/a/Win11/Prefetch
export PECMD_CSV=/path/to/PECmd_Output.csv        # optional
./run_tests.sh
```

Real prefetch contains the account names and installed software of the machine it came from, so
**the corpora are not in this repository** — their location is configuration. The vendored
`reference/pf-corpus/` is the upstream project's published sample data.

| Suite | What it pins |
|---|---|
| `validate_spec` | an independent parser written from the format doc alone, 683 files |
| `test_core_vs_spec` | the library agrees with it field-for-field, 690 files, all 5 versions |
| `fuzz_parser` | 1,464 malformed inputs: no crash, no hang, no silent garbage |
| `diff_against_pecmd` | agreement with real PECmd output |
| `test_output_fidelity` | **every value in the CSV, database, grid and detail panes matches the parsed record exactly** |
| `test_store` | relational invariants, idempotent re-ingest, durability after a kill |
| `test_csv_coverage` / `test_csv_escaping` | column superset; injection and escaping |
| `test_gui_logic` | filter/sort/tag semantics, contrast on light and dark themes |
| `test_artifacts` / `test_ads` | non-`.pf` parsing; ADS logic and the carrier-timestamp rule |
| `test_memory` / `test_layering` / `test_cli_errors` | memory ceiling; the core stays Qt-free; failures are useful |

---

## Limitations and open questions

Stated plainly, because a forensic tool that hides its limits is worse than one that has them.

### Not yet run on Windows

The Windows-specific paths — the `ntdll` decompressor and `FindFirstStreamW` stream
enumeration — are written and unit-tested against a simulated backend, but **have never
executed on Windows**. Everything above those calls is tested; the calls themselves are not.

### Not packaged

There is no `.exe` yet. The PyInstaller spec and build script exist and the frozen-build
hazards are fixed, but no bundle has been produced.

### The filename hash cannot be recomputed

All three published algorithms were implemented and run against the stored paths: **0 matches
in 463 files.** And the hash is not a function of the path alone — `MSEDGE.EXE` has seven
prefetch files with *near-consecutive* hashes, which no digest produces for seven distinct
paths.

**Consequence:** multiple prefetch files for one executable name is **normal**, not evidence of
multiple locations. The widely repeated "several hashes ⇒ ran from several places ⇒ suspicious"
heuristic false-positives on `svchost`, `runtimebroker`, `dllhost` and `msedge` on any normal
system. Compare resolved **paths** instead.

### ReadyBoot payload undecoded

The `PfB` container header is decoded; the payload is compressed (entropy ≈7.9 bits/byte) and
is **not** XPRESS Huffman at any offset tried. File inventory and timestamps are reported; the
contents are not. Earlier documentation claiming ReadyBoot is an ETL trace is wrong — there is
no ETL magic in these files.

### `PfPre_*.mkd` semantics unknown

The structure is proven (16,384-slot ring, cumulative counter). The ~12 event types and the
second field are not identified, and the filename's hex digits do not match the header's
identifier.

### Path conflicts unexplained

Five files where the two path sources disagree. The launch-path-versus-earlier-path hypothesis
fits four of five; it is not proven, so the tool reports both and asserts nothing.

### `Op-*.pf`

Detected and flagged. They lack the embedded path field and do not list their own executable,
so **no method recovers a path** for them — 2 of 636.

### Things that cannot be checked from a copied folder

Copying a Prefetch folder to a non-NTFS filesystem loses alternate data streams and creation
times. `first run approx` therefore cannot be validated against such a copy, and ADS recovery
cannot be exercised at all. Both need a live Windows host or a raw NTFS image.

### Access artifacts are not execution artifacts

`Layout.ini`, the SuperFetch databases and ReadyBoot record that a file was *accessed* or
prioritised. They carry no timestamps and prove nothing about execution. The tool separates
them deliberately; do not read a `Layout.ini` path as "this program ran".
