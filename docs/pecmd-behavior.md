# PECmd tool behavior — what the CLI does around the parser

Companion to `prefetch-format.md`. That document covers *bytes → structure*; this one covers
everything PECmd layers on top: input discovery, the four output writers, and the three
acquisition features (VSS, dedupe, ADS).

Source: `<pecmd checkout>/PECmd/Program.cs` (1657 lines, single file). The parser itself
is the external `Prefetch` NuGet package — PECmd contains **no format knowledge at all**.

---

## 1. Architecture in one paragraph

`Program.cs` is a `System.CommandLine` root command with 17 options. `DoWork()` does
everything: configure Serilog → validate input → optionally mount VSS → collect a list of
`.pf` paths (single file or recursive directory) → call `PrefetchFile.Open()` on each,
accumulating `IPrefetch` objects in a static `_processedFiles` list and failure strings in
`_failedFiles` → optionally scan alternate data streams → then iterate `_processedFiles`
once, writing CSV + timeline CSV + line-delimited JSON + XHTML simultaneously from one pass.
Console output is written *during* parsing (per file), not from the final list.

The split worth preserving in a rewrite: **parsing library and presentation tool are separate
artifacts.** The library exposes one interface (`IPrefetch`) and the tool never touches
offsets.

---

## 2. CLI surface

| Option | Meaning |
|---|---|
| `-f` | single file to process (mutually alternative with `-d`; one is required) |
| `-d` | directory, recursed |
| `-k` | extra comma-separated keywords to highlight; **always unioned with the built-in `temp`, `tmp`** |
| `-o` | write the raw (decompressed) prefetch bytes to this path — the way to inspect a Win10 `.pf` uncompressed |
| `-q` | suppress the per-file detail dump (big speedup when only CSV/JSON matters) |
| `--csv` / `--csvf` | output directory / override filename |
| `--json` / `--jsonf` | output directory / override filename |
| `--html` | output directory (XHTML + CSS + PNGs) |
| `--dt` | custom timestamp format, default `yyyy-MM-dd HH:mm:ss` |
| `--mp` | high precision — overrides `--dt` with `yyyy-MM-dd HH:mm:ss.fffffff` |
| `--vss` | also process every Volume Shadow Copy on the target's drive |
| `--dedupe` | skip files whose SHA-1 was already seen (first wins) |
| `--ads` | scan alternate data streams for hidden prefetch (local addition, see §6) |
| `--debug` / `--trace` | log level |

Defaults worth flagging: **`--dedupe` defaults to `false` in code (`Program.cs:169`) while
the README says "Default is TRUE".** Real doc/code mismatch — pick one deliberately in a
rewrite.

Guard rails at startup: non-Windows exits immediately (the decompressor needs `ntdll`);
missing `-f`/`-d` prints help; `--vss` without admin is a hard error; non-admin generally
just warns.

---

## 3. Input discovery

**`-f`**: parse that one file. Under `--ads`, if the file's primary stream is zero bytes,
skip the direct parse entirely and only scan its streams — an ADS-hosted prefetch carrier
legitimately has an empty primary stream.

**`-d`**: recursive enumeration of `*.pf`, with a hard fork by target framework:

- **net472** uses AlphaFS `EnumerateFileSystemEntries` with an inclusion filter that skips
  zero-byte files, skips reparse points/mount points/symlinks, swallows enumeration errors,
  warns loudly if the path contains `[ROOT]` (FTK Imager mount detection — Eric's stance is
  that FTK Imager mounts are broken; use Arsenal Image Mounter), and — importantly —
  **enumerates each `.pf` file's alternate data streams and tries to parse each as prefetch**.
- **net9** uses plain `Directory.EnumerateFileSystemEntries(d, "*.pf", …)` with
  `IgnoreInaccessible`. No ADS handling, no zero-byte skip, no FTK warning.

That asymmetry is the whole reason `--ads` exists (§6).

Then per file: existence recheck → optional SHA-1 dedupe → `LoadFile()` → console dump
unless `-q` → append to `_processedFiles`.

---

## 4. Output writers (all fed from one pass over `_processedFiles`)

All four are optional and can run simultaneously. Default filenames are stamped
`{UTC:yyyyMMddHHmmss}_PECmd_Output.<ext>`.

### 4.1 Main CSV — 27 columns

`Note, SourceFilename, SourceCreated, SourceModified, SourceAccessed, ExecutableName, Hash,
Size, Version, RunCount, LastRun, PreviousRun0..PreviousRun6, Volume0Name, Volume0Serial,
Volume0Created, Volume1Name, Volume1Serial, Volume1Created, Directories, FilesLoaded,
ParsingError`

Semantics that are not obvious from the column names:

- **`LastRun` = `LastRunTimes[0]`, `PreviousRun0..6` = `LastRunTimes[1..7]`.** These are
  *post-filter* indices — zero slots were already dropped by the parser, so `PreviousRun3`
  is "the 5th surviving run time", not "slot 5 in the file".
- **Only two volumes get columns.** A third volume does not add columns; it sets
  `Note = "File contains > 2 volumes! Please inspect output from main program for full
  details!"`. So the CSV silently under-reports multi-volume prefetch — a real limitation to
  fix in a rewrite (emit one row per volume, or a separate volumes table).
- `Volume0Created` is blanked when its year is 1601 (unset FILETIME).
- **`Directories` concatenates all volumes' directory lists with no separator between
  volumes** (`sbDirs.Append(...)` per volume, joined internally by `", "`) — a real bug: the
  last directory of volume 0 runs into the first of volume 1.
- `FilesLoaded` is `", "`-joined `Filenames`. On a busy binary this single cell is tens of
  kilobytes (see the sample output in `$PECMD_CSV`
  — 2.5 MB for one machine's prefetch directory). Consider a normalized/long-form output
  instead.
- On `ParsingError`, `Directories` and `FilesLoaded` are left empty but the row is still
  written.
- `SourceFilename` for a VSS-sourced file is rewritten from `C:\___vssMount\vss2\...` to
  `VSS2\...` so the origin is visible.

### 4.2 Timeline CSV — 2 columns

`RunTime, ExecutableName`, one row **per run time per file** — i.e. the main CSV exploded
into events. `ExecutableName` here is not the header's bare name; it's the *full path*
resolved by finding the first entry in `Filenames` that ends with
`Header.ExecutableFilename`, falling back to the bare name. This is what makes the timeline
directly loadable into a super-timeline.

### 4.3 JSON

Line-delimited JSON: each `CsvOut` record serialized with ServiceStack and written one per
line (labelled `//hack` in the source). Not a JSON array — consumers must read it line by
line.

**Timestamps are *not* ISO8601, despite appearances.** The JSON branch calls
`GetCsvFormat(processedFile, "o")` intending the round-trip format, but `GetCsvFormat` never
reads its `dt` parameter — every timestamp goes through `ActiveDateTimeFormat`. And every
`CsvOut` field is a `string` that was already formatted, so `JsConfig.DateHandler =
DateHandler.ISO8601` never applies either. Net effect: JSON timestamps are byte-identical to
the CSV's, in whatever `--dt`/`--mp` produced, and the `"o"` argument is dead code. A rewrite
that "faithfully" emits ISO8601 here will not match PECmd — emitting real ISO8601 is the
better choice, just make it a deliberate one.

### 4.4 XHTML

Creates `<dir>/<timestamp>_PECmd_Output_for_<mangled path>/index.xhtml` plus a `styles/`
folder whose `normalize.css`, `style.css`, `directories.png` and `filesloaded.png` are
**base64 blobs embedded in `ExternalFiles.cs`** and written out at runtime. The XHTML is a
flat `<document>` of `<Container>` elements mirroring the CSV fields, with `title=`
attributes carrying tooltips.

### 4.5 Console output (`DisplayFile`)

The interactive view, per file: source timestamps → executable name / hash / size / version
→ run count and all run times → per-volume summary line → the full directory list, indexed →
the full filename list, indexed. Two kinds of highlighting:

- the entry matching `Header.ExecutableFilename` is tagged `(Executable: True)`
- any entry containing a keyword (default `temp`/`tmp`) is tagged `(Keyword: True)`; for
  directories this is escalated to **`Log.Fatal`** purely to get the red color.

The keyword idea is the analyst-facing feature worth keeping: execution from a temp
directory is the classic malware signal.

---

## 5. VSS handling

With `--vss` (requires admin):

1. Take the drive letter from `-f`/`-d`, call `Helper.MountVss(driveLetter, @"C:\___vssMount")`.
   From the `ERZHelpers` assembly's symbols, this enumerates shadow copies (`GetVssInfoViaWmi`
   / `GetVssForVolumeVssAdmin` — WMI `Win32_ShadowCopy` with a `vssadmin` fallback) and
   creates one **symbolic link per shadow copy** (`CreateSymbolicLink` from kernel32) inside
   `C:\___vssMount`.
2. For each subdirectory of `C:\___vssMount`, rebuild the target path by stripping the root
   from the original path and re-rooting it under the VSS mount, then run the same
   parse/enumerate logic.
3. At the end, delete every subdirectory and then the mount directory itself.

Display paths are rewritten `C:\___vssMount\vssN\…` → `VSSN\…`.

This is entirely Windows-specific and admin-gated. In a rewrite targeting images rather than
live systems, the equivalent is "iterate the shadow-copy volumes exposed by your image
mounter", which is a cleaner abstraction anyway.

---

## 6. ADS scanning (`--ads`) — the local addition

**Why it exists.** When a binary is executed out of an NTFS alternate data stream (e.g.
`notepad.exe` stashed as `host.txt:np.exe`), Windows still writes a prefetch entry — but the
carrier file `C:\Windows\Prefetch\HOST.TXT:NP.EXE-F3E0231A.pf` has an **empty primary stream**
with the real prefetch inside a stream. A normal `.pf` scan never looks inside streams, so
the execution is invisible. Upstream had partial coverage of this in the net472 enumeration
filter only; the net9 build had none at all. `--ads` makes it explicit, opt-in, and
framework-independent.

Behavior:

- `-d --ads`: **every** file under the directory is checked, not just `.pf` — the hiding place
  need not be in the Prefetch folder.
- `-f --ads`: scan that file's streams; if its primary stream is empty, skip the primary parse.
- Detection is **content-based**, not name-based: each stream is fed to `PrefetchFile.Open()`
  and kept if it parses. `Zone.Identifier` and friends simply fail to parse and are ignored
  at debug level (expected for the overwhelming majority of streams).
- Deduplicated against `_processedFiles` by `SourceFilename` (case-insensitive) so the net472
  built-in path doesn't double-report.
- Reports `Checked N files … found M prefetch file(s) hidden in alternate data streams`.
- Results are flagged in the CSV `Note` column as `Prefetch found in ADS` (prepended if a
  multi-volume note is already there).
- Works under `--vss` too: the same scan is run against each shadow copy.

**Timestamp caveat, and the reason `GetSourceTimestamps()` exists.** A stream has no
timestamps of its own. On .NET Framework, `new FileInfo("host:stream")` cannot stat the path
and the source timestamps come back as `DateTime.MinValue` (year 1601); modern .NET resolves
it to the host file and populates them. `GetSourceTimestamps()` normalizes this: if the
created year is ≤ 1601 **and** the source name contains a `:` after position 2 (i.e. it's an
ADS path, not just a drive letter), re-stat the carrier file — whose timestamps the stream
inherits — and use those. Reported values are therefore the *carrier's*, which is documented
in the README because it changes how an analyst reads them.

Stream enumeration and opening both go through AlphaFS
(`FileInfo.EnumerateAlternateDataStreams`, `File.Open(..., PathFormat.LongFullPath)`) on
both target frameworks, because .NET's own APIs have no ADS enumeration.

---

## 7. Dedupe

`--dedupe` hashes each candidate file's full stream with SHA-1 (`Helper.GetSha1FromStream`)
before parsing and skips any hash already seen — first occurrence wins. Its real purpose is
`--vss`: the same prefetch file typically appears unchanged in many shadow copies. Note it
hashes the *file*, so a Win10 `.pf` is hashed compressed.

---

## 8. Behaviors a rewrite should keep, fix, or drop

**Keep**
- Library/tool separation, with the parser exposing one interface.
- Timeline CSV as a separate exploded output — it is what makes the tool timeline-friendly.
- Keyword highlighting, executable-vs-loaded-file distinction.
- Partial results on parse failure, plus a failed-files summary at the end.
- `-o` raw-bytes dump for decompressed Win10 files.
- Content-based ADS detection (`--ads`), including the empty-primary-stream case.

**Fix**
- Two-volume ceiling in the CSV; emit all volumes.
- Missing separator when concatenating multiple volumes' directory lists.
- `--dedupe` default documented vs. implemented.
- Hash / serial hex formatting (`X` → `X8`).
- Per-file MFT references are unusable on Win10/11 (`porting-notes.md` §2.1) — expose them
  properly; they are the highest-value field the current CSV omits entirely.
- Single giant `FilesLoaded` cell; consider a long-form table.

**Drop / reconsider**
- Global mutable statics (`_processedFiles`, `_failedFiles`, `ActiveDateTimeFormat`) — they
  prevent parallelism, and directory scans of a real Prefetch folder are I/O-bound work that
  parallelizes trivially.
- The 1657-line single `DoWork()`.
- Telemetry: `ExceptionlessClient.Default.Startup(<hardcoded key>)` fires on every run
  (`Program.cs:88`). A forensics tool phoning home is a defensible thing to leave out.
- Serilog `Log.Fatal` used as a color code.
