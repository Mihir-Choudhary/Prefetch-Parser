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

`ads` reports every entry whose streams could not be enumerated and **exits `1`** when any
were skipped, because a locked or ACL-restricted file is not a file that came back clean — and
on a live system those are exactly the ones worth hiding a payload in.

`artifacts` distinguishes **"scanned and found nothing"** (exit `0`, and it names the folder it
scanned) from **"could not scan"** — a missing path, or a file passed where a folder belongs —
which exits `1`. The first is evidence; the second is not, and `pfcli artifacts "$DIR" && …`
must not treat them alike.

**Streams.** The rows go to **stdout**; every summary, note and error goes to **stderr**, so a
script can pipe the rows without commentary landing in them.

**The tool's own footprint.** Reading a file updates its access time on a filesystem that
records one. Timestamps are therefore read **before** the file is opened, so `SourceAccessed` is
never this tool's own read — but the folder itself is still touched, which is one more reason to
work from a copy. Nothing is ever written to the evidence directory.

Exit codes, the same for every subcommand:

| Code | Meaning |
|---|---|
| `0` | success — including "scanned and found nothing", which is a result |
| `1` | nothing was produced: no `.pf` files found, a path that does not exist, a file where a folder belongs, or (for `ads`) entries that could not be examined |
| `2` | the run cannot be started as asked: a capability this host does not have (alternate data streams cannot be enumerated, or a `--decompressor` was forced that is not available), or two outputs aimed at one path — `--db X --csv X`, or a `--db` aimed at the `-summary.csv` that `artifacts --csv` derives. Nothing is parsed and nothing is written first |
| `120` | the evidence parsed, but an output could not be written. The other outputs are still written — one unwritable destination never costs the other |

`1` and `120` are deliberately different: a script needs to tell "there was nothing" from
"there was something and the file could not be saved". Every code in this table is asserted in
`reference/test_cli_errors.py`, so the table and the program cannot drift apart.

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

**Export folder artifacts** (`Ctrl+Shift+R`) writes what that window shows: one CSV row per
path plus a `-summary.csv` with the facts, the volume records and the problems — the same export
`pfcli artifacts --csv` produces, from the same code. Both exports are atomic, and the dialog
says when a cell is too wide for a spreadsheet to hold.

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
| `Chains` (per loaded file) | how many trace-chain entries **that file** accounts for. The metric entry's first two dwords, which every other tool discards as unknown, are the file's own slice of the chain array — measured to tile it exactly across 284 files |
| `Fetched` (per loaded file) | a subset of that slice, never larger. Reported as a number; its exact meaning is not established |
| `Flags` (per loaded file) | a small bitfield that tracks file type — DLLs `0x100`, data files `1`/`2`/`4` |
| `ResidueBytes` / `ResidueText` | bytes in the file belonging to **no field of it** — fragments of an earlier version of the same record left behind when the prefetcher rewrote it shorter. 134 of 754 corpus files carry some (1,708 bytes in 170 regions), 4–20 bytes each, often a path tail like `TY\RESO`. Bounded on retention — at most 256 regions, 4 KB per region and 64 KB per record kept — while the reported total stays exact. Never merged into the parsed lists |
| unclaimed MFT references | reference-shaped values found in the declared array past the count it states — 19 of 183 files. Stored with `source='slack'` so a query includes them deliberately |

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
| `Ag*.db` (+ `.db.trx`) | **SuperFetch databases** — Windows Vista/7/8 names: `AgGlGlobalHistory.db`, `AgAppLaunch.db`, `AgRobust.db`, `AgCx_SC*.db`, `AgGlUAD_<SID>.db`. Tens of thousands of file paths per volume, each volume carrying its serial and creation time. See [SuperFetch](superfetch-format.md) |
| `*.7db`, `*.ebd` | The same format under the Windows 10/11 names, MAM-compressed in the `.ebd` case. Paths in prefetch's own `\VOLUME{serial}` notation; the static `ResPri*` databases also carry a per-record timestamp |
| anything else | **reported as unrecognised**, with its size and first bytes. A file present in a collection is a fact about the collection whether or not this tool can parse it |
| `ReadyBoot/Trace*.fx`, `rblayout.xin` | **per-boot file-access traces.** Fully decompressed — see [ReadyBoot](#readyboot) below. Each file's mtime dates one boot |

Findings measured across 636 real `.pf` files — the two volume notations and the
"ran from N locations" trap, volume creation timestamps, how much execution history the 8-slot
limit destroys, and what interpreter prefetch reveals:
[`prefetch-findings.md`](prefetch-findings.md).

Detailed analysis: [`prefetch-artifacts.md`](prefetch-artifacts.md). What the decoded ReadyBoot
data is worth in a case — drive-letter mapping, boot history, shadow-copy access, and the
caveats that matter: [`readyboot-findings.md`](readyboot-findings.md).

### ReadyBoot

Windows 11 keeps a `ReadyBoot/` subfolder of boot traces in a `PfB` container. This tool
decompresses them; as far as I can tell no other prefetch tool does.

The container is **not** one compressed stream — that is why it resisted decoding for so long.
It is a chain of independently compressed 64 KB XPRESS Huffman chunks:

```
u32  magic 0xE3426650 ('PfB\xe3')
u32  total uncompressed size
u32  compressed length of chunk 0
     chunk 0
     u32 unidentified   u32 length of chunk 1
     chunk 1
     ...
```

Each chunk resets the LZ77 history, so chunks decode independently. The final chunk's declared
length is **not** valid — it must be clamped to the end of the file.

Verified on all six files in the corpus: each decompresses to exactly its declared size, the
chunk count equals `ceil(size / 65536)`, and all 708 chunk boundaries land on a complete
canonical Huffman table. Derivation and evidence: [`readyboot-format.md`](readyboot-format.md).

Inside sits a **directory tree** — records of `[u32 parent offset][u16 length][UTF-16LE name]`
— which resolves into whole paths. Two inner formats put that table in opposite places:
`xFcE` (the traces) keeps it last, `iLdR` (`rblayout.xin`) first at offset 16.

Every link resolves on every file — 8,927 to 20,179 paths each, none dropped:

```
\Device\HarddiskVolume3\Windows\System32\ntoskrnl.exe
\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
\Device\HarddiskVolume1\EFI\Microsoft\Boot\ko-KR\bootmgfw.efi.mui
\Device\HarddiskVolume3\$Mft
```

They use the same `\Device\HarddiskVolumeN\` notation as `.pf`, so the volume correlation
applies unchanged.

The rest of the payload is the **trace itself** — one 40-byte record per read, carrying the
file, the byte offset, the I/O size and a monotonic tick. A single boot yields 173,000–229,000
events covering 7–9 GB of reads across 4,400–7,200 files, and **every event resolves to a named
file**. The tool reports per-file totals, heaviest first:

```
  394 reads  784.4 MB  \Device\HarddiskVolume3\$WinREAgent\Scratch\update.wim
  384 reads  576.1 MB  \Device\HarddiskVolume3\Windows\System32\config\SOFTWARE
  150 reads  268.1 MB  ...\Windows Defender\Definition Updates\{...}\mpasbase.vdm
```

14-22.5% of events belong to `FI_UNKNOWN` — reads the tracer could not attribute to a file,
mostly from early boot before the filesystem is up. That is the tracer's own marker, not a
decode failure.

Standing caveat: this is **access, not execution**. A path here means the boot read that file,
never that a program ran. Events are ordered and relatively timed by their ticks, but the tick
unit is unknown, so no wall-clock time is claimed for an individual event.

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
[MS-XCA] specification. It decompresses all 642 compressed files in the two real corpora plus
the vendored samples (6 + 184 + 452) with zero
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

### Running on Windows — what to expect

The Windows-only code paths cannot be executed on any other machine, so they are exercised
against stubs and forced environments by `reference/test_windows_lane.py` (see the suite table
below). What follows is what an analyst on Windows actually meets.

- **Console output is safe whatever the code page.** Windows gives a *redirected* stream the
  ANSI code page, not UTF-8, and a Cyrillic or CJK filename printed to it used to end the run
  with a `UnicodeEncodeError` and no report at all. Redirected output is now written as
  **UTF-8**; a real console keeps its own encoding and escapes what it cannot draw.
- **The Prefetch folder needs elevation.** `C:\Windows\Prefetch` is readable only by
  administrators. Run from an elevated prompt, or point the tool at a collected copy — an
  unelevated run reports every file as a failed record with a permissions message rather than
  claiming the folder is empty.
- **Long paths are handled.** Triage output nests deeply
  (`C:\Cases\<case>\<host>\<tool>\<timestamp>\C\Windows\Prefetch\…`) and the Win32 file
  APIs stop at 260 characters. Paths at or past that are addressed through the `\\?\`
  device-namespace form, which the reported path never carries.
- **A SQLite database has its own limit**, and it is lower: SQLite holds pathnames in a
  512-byte buffer, so a `--db` more than ~503 characters deep cannot be opened at all. The
  error says so, with the length and the remedy — the database does not have to sit beside the
  evidence.
- **`pfgui.exe` is a windowed binary**, so it has no console to print to: `pfgui.exe --help`
  writes nothing on Windows. `pfcli.exe --help` is the console half, and is what a script pipes.

---

## Outputs

### SQLite (`--db`) — the primary artifact

Relational, so nothing is flattened away: `prefetch`, `run_time`, `volume`, `directory`,
`loaded_file`, `file_ref`, `residue`, `problem`, plus a `timeline` view of one row per
execution. Trace chains are stored as a blob rather than millions of rows.

The `prefetch` table also carries the record's **own filesystem timestamps** (`source_created`,
`source_modified`, `source_accessed`, `source_size`, and `source_created_est` — the documented
created-minus-10-seconds first-run approximation), the **ADS provenance** of a record recovered
from a stream (`from_ads`, `carrier_path`, `stream_name`, `timestamp_source`, the carrier's own
times, and whether the carrier sat outside the Prefetch folder), and the **undecoded regions**
kept verbatim as blobs (`header_raw`, `fileinfo_raw`, `volume.raw_tail`). All three groups
existed on the parsed record and reached no export before Round 45 — see `AUDIT.md` BUG 71–73.

A database written by an older build is **upgraded on open**, per table, and the schema version
is stamped in `PRAGMA user_version`; a database written by a *newer* build is refused with a
message rather than half-read. Columns added by an upgrade are NULL for rows written before it:
absent, not measured.

Ingest is **idempotent per source file**, so re-scanning a folder updates rather than
duplicates. The database is self-contained — journal mode is `DELETE`, not WAL, so a copied
`.db` is complete even if the process was killed mid-run.

### CSV (`--csv`) — an export

A **strict superset of PECmd's columns** — all 27, plus 38 more (**65 in total**). Round 45 added
the last group of them, each one evidence that was in the database and in no export anyone
opens: the volume self-check verdicts (`VolumeNameChecks`), the references a file does not
declare (`SlackReferences`, `SlackReferenceCount`), the directory count the file states beside
the one recovered (`DeclaredDirectoryCount`), the first-run estimate (`FirstRunApprox`), and the
provenance of a record recovered from an alternate data stream (`FromAds`, `CarrierPath`,
`StreamName`, `StreamSize`, `TimestampSource` (**every** record answers this: `stream` means
the file's own times, `carrier` means the host file's, `unavailable` means none could be read),
`CarrierCreated`, `CarrierModified`,
`CarrierAccessed`, `CarrierIsPrefetch`, `OutsidePrefetchFolder`). `pfcli ads` takes `--csv` as
well as `--db`, so a stream finding can be exported without losing what makes it evidence.

Three more came from the audit of the parser and the container: `FilenameHashMatch` and
`FilenameNameMatch` (the file's name against the record inside it — `ok` / `mismatch` / `n/a`),
`ContainerTrailingBytes` and `Decompressor` (bytes carried after the compressed stream ended,
and which decoder measured that — empty means *not measured*), and `DeclaredReferenceCount`
beside `ReferenceCount` (slots the file declares, against slots that hold a reference).

**Spreadsheets truncate wide cells, silently.** Excel, LibreOffice and Sheets all cap a cell at
32,767 characters, and drop the rest on import with no warning. Prefetch list cells go far past
that — the widest in the Windows 10 corpus is **323,778 characters**, ten times the limit — so a
spreadsheet shows a complete-looking list that is missing most of its entries. The export cannot
raise the limit, so it reports: every CSV write prints how many cells exceed it and in which
columns, and the GUI says the same in its export dialog. The file itself and the database hold
the complete values.

**A wide cell also stops Python's `csv` module**, which refuses any field over **131,072**
characters with `_csv.Error: field larger than field limit` — a reader default that looks
exactly like a corrupt export. Where the widest cell passes that mark the note says so and names
the fix (`csv.field_size_limit()`); pandas, R and `awk` read these files unchanged.

Two safety behaviours, because a filename is attacker-chosen and a forensic CSV is opened in a
spreadsheet:

- **Formula injection** — a cell starting `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
  Values that are simply numbers are left exact. `--raw-csv` disables this.
- **Silent re-interpretation** — a spreadsheet corrupts more than formulas. Excel reads the
  hash `1482E648` as 1482 × 10⁶⁴⁸ (**6 of the 452 hashes** in the Windows 11 corpus have that
  shape), drops the leading zero from `03583356`, turns `3-15` into a date, and loses the low
  digits of anything past 15. Each is silent, and each changes an identifier that ties a
  prefetch file to what ran, so those cells get the same `'` prefix. It cannot fire on a
  quantity — nothing here writes a count in exponent form — and `--raw-csv` disables it.
- **List cells** hold multiple values separated by ` | `, with a literal `|` escaped as `^p`
  (and `^` as `^^`), so an element containing the separator cannot inject extra entries.

The SQLite store is never sanitised — it is the source of truth.

### The other artifacts export separately — `pfcli artifacts --db/--csv`

`pfcli parse --db/--csv` carries **`.pf` records only**. The rest of the Prefetch folder —
`Layout.ini`, the SuperFetch databases, the ReadyBoot traces with their per-file I/O totals,
`PfPre_*.mkd`, and anything unrecognised — is exported by `pfcli artifacts` instead:

```bash
pfcli artifacts C:\Windows\Prefetch --db case.db --csv artifacts.csv
```

- **SQLite**: `artifact`, `artifact_path` (one row per path, with ReadyBoot's read count and
  byte total in `detail`), `artifact_fact` and `artifact_problem`. Separate tables, not merged
  into `prefetch`.
- **CSV**: one row per path, plus a `-summary.csv` beside it with one row per artifact carrying
  the facts, the volume records and the problems. Two files because repeating an artifact's
  facts across 10,118 path rows is not an export anyone can read, and dropping them would lose
  the record counts and the volume identity.

They are kept apart from the `.pf` tables on purpose: these record **access and prefetcher
priority, not execution**, and putting them in a per-execution table invites exactly the
misreading the artifact section exists to prevent. Until Round 45 that separation was enforced
by exporting them *nowhere*, which meant an investigator could see 10,118 SuperFetch paths on
screen and had no way to get them into a report except by retyping them — see `AUDIT.md`
BUG 80.

The fidelity guarantee under [Testing](#testing) — every value in CSV, SQLite, the grid and the
detail panes matching the parsed record — is a statement about `.pf` records. The artifact
exports have their own check in `test_artifacts`: every artifact, every path, every problem and
every per-file I/O total that was parsed appears in both exports, and a re-scan does not double
them.

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
`reference/pf-corpus/` is the upstream project's published sample data, and it covers four of
the five format versions: it is not a substitute for a real collection, and no figure quoted in
these docs is derived from it alone.

The same three settings can live in a gitignored `corpus-paths.env` at the repository root
(`KEY=/path` per line), so the configuration outlives the shell that set it. The environment
wins over the file.

**A suite that cannot run skips — it never passes.** A missing corpus, a stale path, a seed file
that is not there, or absent Qt bindings all exit `77`, which `run_tests.sh` reports as `SKIP`
and refuses to count as a pass; the run as a whole then exits non-zero and names what did not
run. This is the same rule the tool applies to an unscanned folder, and it is pinned by
`test_harness`.

A suite requires only what **all** of its checks need. `PREFETCH_SAMPLES` — the downloaded
public samples — is required by `test_superfetch` alone, because those files are its subject;
every other suite runs on the two corpora and treats sample-only assertions as extras, printing
which extras did not run. A requirement drawn any wider makes unrelated checks disappear on a
machine that has real prefetch but no download.

If PySide6 cannot be installed system-wide, put it anywhere and point the suite at it — no
virtualenv or root required:

```bash
pip install --break-system-packages --target /some/dir PySide6
echo "PREFETCH_PYLIBS=/some/dir" >> corpus-paths.env
```

| Suite | What it pins |
|---|---|
| `validate_spec` | an independent parser written from the format doc alone, 683 files |
| `test_core_vs_spec` | the library agrees with it field-for-field, 690 files, all 5 versions |
| `test_vendor_truth` | 224 expected values read out of an **independent implementation's** own NUnit tests — the only check in the tree that does not share this project's reading of the format |
| `fuzz_parser` | 1,464 malformed inputs: no crash, no hang, no silent garbage |
| `diff_against_pecmd` | agreement with real PECmd output |
| `test_output_fidelity` | **every value in the CSV, database, grid and detail panes matches the parsed record exactly** |
| `test_store` | relational invariants, idempotent re-ingest, durability after a kill |
| `test_csv_coverage` / `test_csv_escaping` | column superset; injection and escaping |
| `test_gui_logic` | filter/sort/tag semantics, contrast on light and dark themes |
| `test_artifacts` / `test_ads` | non-`.pf` parsing; ADS logic and the carrier-timestamp rule |
| `test_memory` / `test_layering` / `test_cli_errors` | memory ceiling; the core stays Qt-free; failures are useful |
| `test_readyboot` | the `PfB` chunk chain decodes to exactly its declared size; crafted chains are refused |
| `test_superfetch` | `Ag*.db` / `.7db` / `.ebd`: every recovered path verified against its own stored name hash |
| `test_byte_coverage` | **the parser reads the whole file** — no non-zero byte of any corpus file escapes both the parser and the residue report |
| `test_windows_lane` | the Windows-only paths, off Windows: the `ntdll` wrapper and `FindFirstStreamW` against stubs (including the ctypes declarations themselves), the `\\?\` long-path transformation, creation-time semantics, and the console encoding that used to kill a run |
| `test_invariants` | properties only a whole corpus shows: parsing is deterministic, every datetime equals its own FILETIME ticks, every SuperFetch path re-hashes to its stored value, and a folder holding a device node or a FIFO is still reported |
| `test_harness` | the suite itself: an unrunnable suite skips, and the runner never calls that a pass |

---

## Limitations and open questions

Stated plainly, because a forensic tool that hides its limits is worse than one that has them.

### Vista-era SuperFetch, and other things with no sample

`MEMO`/LZNT1 (Windows Vista) is implemented and verified against the published test vectors —
including a boundary case that was wrong until those vectors were run — but **no real Vista
database has been through it**, and the tool says so in the compression field rather than
implying otherwise.

The same applies to `AgRobust.db` (documented to carry prefetch hashes in its source records),
ReadyBoot `PfB` traces beyond the five in hand, and `PfPre_*.mkd`: no public samples exist. For
undocumented entry sizes the parser probes the layouts it knows and accepts one **only if the
stored name hashes verify**, so an unseen variant is either parsed correctly or reported as
unparsed — never guessed at.

### Not yet run on Windows

The Windows-specific paths — the `ntdll` decompressor and `FindFirstStreamW` stream
enumeration — are written and unit-tested against a simulated backend, but **have never
executed on Windows**. Everything above those calls is tested; the calls themselves are not.

### No Windows `.exe` yet — but the bundle has now been built and measured

PyInstaller does not cross-compile, so a `.exe` has to be produced **on Windows**. What exists
is a Linux build of the same spec, which settles the sizes:

| Build | Size |
|---|---|
| GUI + CLI, `--onedir` (what the spec produces) | **153 MB** |
| the same, zipped for distribution | 89 MB |
| CLI only, `--onedir` | **24 MB** |
| CLI only, `--onefile` | 11 MB — *measured for comparison; not shipped, see below* |

The split is entirely Qt. The library and CLI have no dependencies, which is why dropping the
GUI takes 179 MB to 24 MB.

The spec **excludes the Qt modules the GUI never imports**, which is where the 179 MB first
measured became 153 MB. The GUI uses exactly three — `QtWidgets`, `QtCore`, `QtGui` — but the
PySide6 hook collects the whole family, so Quick, Qml, Pdf, Network, OpenGL, Svg and
VirtualKeyboard all rode along. Removing them takes out 15 files and adds none.

Two levers were needed, because they do different jobs: `excludes` stops the Python *bindings*
being importable, while the shared libraries survive that (the hook adds them as data) and are
filtered out of `binaries`/`datas` by name.

What is left is genuinely required, and two items of it are **Linux-only**:

| Component | Size | Status |
|---|---|---|
| `libicudata` | 30.6 MB | Qt6Core links it on Linux. Windows Qt6 uses the OS locale APIs and does not ship it |
| `libQt6Gui` / `Widgets` / `Core` | 26.0 MB | required |
| `libpython3.14` | 7.9 MB | required |
| GTK theme | 7.1 MB | Linux platform integration; absent on Windows |
| OpenSSL | 6.1 MB | pulled in by Python's own `hashlib`/`ssl`, **not** by Qt — excluding it would break the stdlib |

So a **Windows** build should land near **115 MB** without any further work, simply because ICU
and GTK are not part of it.

`QtDBus` and ICU are deliberately *not* excluded: Linux platform integration reaches for DBus,
and removing ICU stops Qt loading at all rather than saving 30 MB.

Both frozen binaries were smoke-tested: the CLI parses a compressed Windows 11 prefetch file
and resolves the executable path, and the GUI starts Qt successfully.

**Everything ships as `--onedir`. `--onefile` is not used, for the CLI either.**

A onefile binary unpacks itself into `%TEMP%\_MEIxxxx` on *every* launch. It cleans up on exit,
but it has still written megabytes to a disk the examiner may be treating as evidence, and it
has perturbed the very `%TEMP%` someone might be about to examine. A tool that alters the
machine it is documenting is the wrong shape, however tidy the cleanup.

Two lesser reasons point the same way: self-extraction is a strong antivirus heuristic on top
of an already frequently-flagged packed Python binary, and the unpacking costs measurable
startup time — 237 ms against 146 ms for onedir on the same trivial command.

The 11 MB onefile figure above is recorded only because it was measured while sizing the
options. It is not a deliverable.

### The filename hash cannot be recomputed

All three published algorithms were implemented and run against the stored paths: **0 matches
in 463 files.** And the hash is not a function of the path alone — `MSEDGE.EXE` has seven
prefetch files with *near-consecutive* hashes, which no digest produces for seven distinct
paths.

**Consequence:** multiple prefetch files for one executable name is **normal**, not evidence of
multiple locations. The widely repeated "several hashes ⇒ ran from several places ⇒ suspicious"
heuristic false-positives on `svchost`, `runtimebroker`, `dllhost` and `msedge` on any normal
system. Compare resolved **paths** instead.

### ReadyBoot: three fields and the tick unit

The container, chunk chain, name table, path tree and I/O trace are all decoded (see
[ReadyBoot](#readyboot)); every event resolves to a named file. What remains unidentified is
small: two flag words and the last dword of each I/O record, a constant `402` that never
varies, and the 4-byte field between chunks.

The event **tick unit** is inferred rather than read. Two physical constraints put it at
microseconds — that reading gives 35–81 second traces at 100–256 MB/s, where milliseconds would
give 10–22 hour traces at 0.1 MB/s — but the file never states it. Raw ticks are stored, and
the derived figure is named `io_seconds_assuming_us` so the assumption is visible.

### `PfPre_*.mkd` semantics unknown

The structure is proven (16,384-slot ring, cumulative counter) and the third field is a
monotonic clock whose single backwards step confirms the ring wrapped. Field 2 is an
identifier **shared between unrelated Windows installations** — 27 values appear on both
corpus machines — so it hashes or tags something shipped with Windows rather than anything
machine-specific. It is not a prefetch filename hash (1 of 107 values matches any of 636
corpus hashes, i.e. chance).

Not identified: which event each of the ~12 types represents, and what field 2 hashes. The
filename's hex digits match neither the header identifier nor any volume serial in the corpus.
The tool reports the structure and the counts, and claims no semantics.

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
