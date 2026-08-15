# New tool — design and stack recommendation

Status: **proposal**, 2026-08-12. No code written. Supersedes nothing; builds on
`prefetch-format.md` (the validated `.pf` spec), `pecmd-behavior.md` (what PECmd does) and
`porting-notes.md` (what not to copy).

Requirements captured from the user, 2026-08-12:

- Single distributable `.exe`, **both CLI and GUI**, easy to use.
- GUI shows parsed data as a grid with **Excel-style per-column filters** (distinct-value
  checklist + search box), like Timeline Explorer.
- **Full executable path** in the outputs — PECmd doesn't give it properly.
- **No data from the prefetch file skipped.**
- **ADS handling done properly**, including the timestamp problem.
- Parse **ReadyBoot, SuperFetch, and everything else** a Prefetch folder can contain.

---

## 0. Scope honesty up front

Only one of the artifacts in a Prefetch folder has a spec we have validated against real
files. Everything else ranges from "documented but incomplete" to "undocumented." The design
below puts each artifact behind a plugin interface **so scope can be cut without redesigning
anything** — see §6. Read that section before promising coverage to anyone.

---

## 1. Stack: Python 3.12 + PySide6 + PyInstaller — **DECIDED 2026-08-12**

Chosen by the user, along with **cross-platform** as the target. Consequences of the
cross-platform answer, which are not small:

- **A pure-Python XPRESS Huffman decoder is now mandatory**, not a fallback. `ctypes` →
  `ntdll` remains the fast path *when running on Windows*, but there is no `ntdll` on
  Linux/macOS, so without a Python implementation the tool simply cannot open a Win10/11
  prefetch file there. **This is smaller than it sounds** — Microsoft publishes the algorithm
  as pseudocode in **[MS-XCA]**, and MIT-licensed Python implementations already exist to
  reference or vendor ([`pyxca`](https://github.com/jborean93/pyxca), and the
  `Xpress_LZ77Huffman` code behind the Volatility3 prefetch plugin). Borrow, then validate
  against the six Win10 corpus files.
- **ADS enumeration off-Windows cannot use `FindFirstStreamW`.** Against a mounted image or
  raw volume it needs an NTFS reader (`dissect.ntfs`, pure Python, is the candidate to
  evaluate). Windows keeps the native path. With carving parked (§10), this is the *only*
  thing needing an NTFS reader — so it can wait until ADS work starts.

### 1.1 Choosing between the two decompressors: probe the capability, not the OS name

`platform.system() == "Windows"` asks the wrong question — `ntdll` calls can be blocked on a
hardened Windows host, and can work off-Windows under Wine. Resolve the symbol once at import
and branch on whether that succeeded:

```python
try:
    import ctypes
    _rtl = ctypes.WinDLL("ntdll").RtlDecompressBufferEx  # WinDLL doesn't exist off-Windows
    NATIVE_AVAILABLE = True
except (ImportError, AttributeError, OSError, FileNotFoundError):
    NATIVE_AVAILABLE = False
```

Both implementations expose the same signature, so nothing above the container layer knows
which one ran. Two guard rails keep this from becoming a "works on my machine" bug source:

- **`--decompressor auto|native|python`** — forces either path. Needed to prove the two agree,
  and so an analyst can state in a report exactly what code produced the output.
- **A test asserting byte-identical output from both** across all six Win10 corpus files, run
  on Windows in CI. If they ever diverge you find out there, not from a wrong parse in a case.

This probe is specific to decompression. **ADS enumeration is a genuine OS branch** (Windows
API vs. reading NTFS structures out of an image) and stays one.

The reasoning that led here, in order of weight:

1. **The GUI is the expensive part of this project, not the parser.** The `.pf` parser is a
   few hundred lines of offset arithmetic — the spec is already written and validated. An
   Excel-style per-column filter popup over a large virtualized grid is real UI work. Qt
   (`QTableView` + a model over SQLite + custom header widgets) is the shortest credible path
   to it, and PySide6 is the official LGPL binding.
2. **One codebase, two front-ends.** A pure core library with a `typer`/`argparse` CLI and a
   PySide6 GUI on top is the natural Python shape.
3. **The "Python is too slow to decompress" objection doesn't apply here.** On Windows, go
   `ctypes` → `ntdll.RtlDecompressBufferEx` with `COMPRESSION_FORMAT_XPRESS_HUFF` — the exact
   call PECmd makes, at native speed, no build step. Elsewhere, the pure-Python decoder. Add
   `multiprocessing` over the file list and a 1024-file Prefetch folder parses in seconds
   either way.
4. You already know you can produce an `.exe` from it.

### The cost, stated plainly

**PyInstaller binaries get flagged by AV and EDR.** This is a genuine operational problem for
a tool analysts run on live systems, not a theoretical one — packed Python is a common malware
shape and heuristics treat it accordingly. Mitigations, in order of effectiveness:

- Build `--onedir`, not `--onefile`. Fewer detections, and much faster cold start (`--onefile`
  unpacks to temp on every launch — 2–5 s with Qt).
- Get a code-signing certificate once the tool stabilizes.
- Submit builds to AV vendors for whitelisting; publish reproducible builds and source.
- Ship a plain "run from source" path for analysts in locked-down environments.

Expect ~80–120 MB with Qt bundled either way.

### Runner-up: C# / .NET 8 + WPF

**Flip to this if AV false positives turn out to block real use**, or if you want the
smallest, fastest-starting native binary. Concretely: single-file self-contained ~70 MB or
framework-dependent ~2 MB, no packed-interpreter stigma, native P/Invoke for decompression,
and WPF's `DataGrid` starts closer to the target UI than `QTableView` does. It is also what
Timeline Explorer itself is built in, so the interaction model you're copying is a known
quantity there. The cost is that you'd be writing C# — and the whole point of this exercise
was to get off the existing C# tool.

**Not recommended:** Rust or Go. Best runtime characteristics, worst development time for
exactly the widget you need. The runtime was never the bottleneck.

---

## 2. Architecture

```
prefetch_core/            pure logic - never prints, never formats a timestamp,
                          never decides an output path
  container.py            MAM detection; xpress_huffman(ctypes) | xpress_huffman(pure)
  scca.py                 the .pf parser - ONE parser driven by a version table
  ads.py                  stream enumeration + carrier stat
  model.py                dataclasses: SourceFile, Prefetch, Run, Volume, Directory,
                          LoadedFile, MftRef, TraceChain, UnknownField
  store.py                SQLite writer + reader
  artifacts/              one plugin per artifact type (see section 6)
    __init__.py           registry: can_handle(path, head) -> parse(...) -> records
    pf.py  layout_ini.py  agdb.py  readyboot.py  unidentified.py
pfcli/                    CLI
pfgui/                    PySide6
```

**Rule:** the core returns records. The CLI and GUI are both just consumers. Anything that
formats, colors, or writes belongs outside `prefetch_core`.

### One parser, not four

PECmd's library has four near-identical version classes that drift apart (that's how the
Win10 file-metrics bug survived). Drive it from a table instead:

```python
LAYOUT = {
    17: Layout(fileinfo=68,  metric=20, chain=12, volume=40,  runtime_slots=1, ...),
    23: Layout(fileinfo=156, metric=32, chain=12, volume=104, runtime_slots=1, ...),
    26: Layout(fileinfo=220, metric=32, chain=12, volume=104, runtime_slots=8, ...),
    30: Layout(fileinfo=224, metric=32, chain=8,  volume=96,  runtime_slots=8, ...),
    31: ...,
}
```

Note `fileinfo=220` for v26 — measured, not the 224 the C# uses. See `prefetch-format.md` §3.

### Bounds-checked, staged errors

Replace PECmd's single catch-all with per-stage bounds checks that record **which** stage
failed and keep everything parsed before it. A half-parsed prefetch is still evidence; a
boolean `ParsingError` isn't enough to know what you're looking at.

---

## 3. "No data skipped" — the relational model

This requirement is why the output can't be a single wide CSV. One `.pf` is a
one-to-many-to-many structure; a flat row physically cannot hold it, which is exactly why
PECmd drops volumes past the second and never emits the per-file MFT references at all.

**SQLite is the primary output artifact**, not an implementation detail. It holds the full
structure, it's what the GUI grid queries (so filtering stays fast at 100k+ rows), and it
leaves the analyst something queryable after the tool closes.

| Table | Holds |
|---|---|
| `source_file` | path, sha1, size, carrier path + stream name if ADS, C/M/A + their provenance, VSS origin, parse status, per-stage errors |
| `prefetch` | version, exe name (bare, from header), path hash (as `X8`), **resolved executable path + `ExecPathStatus`**, header file size, run count, total dir count |
| `exec_path_candidate` | the candidate paths when `ExecPathStatus = ambiguous` |
| `run` | one row per run time (1–8), with slot index |
| `volume` | per volume: device name, serial, creation time — **all** volumes, no ceiling — plus `NameSelfCheck` (D1) |
| `directory` | one row per directory string, with its volume and index |
| `loaded_file` | one row per filename, with its index, its file-metric fields, and its MFT entry/sequence |
| `volume_file_ref` | the per-volume MFT reference array |
| `trace_chain` | block load counts — surfaced, not just stored (D5) |
| `collection` | one row per scan: source folder, file count vs the 128/1024 cap, oldest/newest record (D6) |
| `unknown_field` | every documented-as-unknown field, preserved as hex, keyed by record |

The `unknown_field` table is what "nothing skipped" means literally: the fields nobody has
decoded yet are kept rather than dropped, so a future finding can be applied retroactively to
old cases.

### 3.1 Derived columns and flags (the accepted D-items)

Computed once in the core, available to every output. Each is cheap, and each states a fact
rather than a verdict.

| Column | From | Rule |
|---|---|---|
| `LastRun` | `edge-cases.md` §1 | **`max(run_times)`, never `run_times[0]`.** The 8 slots are broadly newest-first but not reliably so — 6/636 files have a newer time in a later slot (worst error 1.284 s). Keep the stored slot order as evidence; derive this separately. |
| `ExecutablePath`, `ExecPathSource` | §4.0 | `stored` (the §5a field) \| `resolved` (filename-list match) \| `conflict` (both present, different) \| `ambiguous` \| `unresolved` |
| `ExecPathAlternate` | §4.0 | the §4.1 filename-list path when it disagrees with §5a; empty otherwise. 1 file in 636 — but it's the interesting one |
| `PackageIdentity` | §5a | the Store/UWP identity when §5a holds one instead of a path |
| `ExecNameTruncated` | D9 | header name is exactly 29 chars **and** the full name from §5a or the resolved path is longer |
| `TotalDirCountMatches` | D4 | stored `TotalDirectoryCount` vs. the summed per-volume lists; `n/a` on v17, which stores `-1` |
| `NameSelfCheck` (per volume) | D1 | `\VOLUME{...}`'s embedded FILETIME + serial vs. the parsed fields; `n/a` for `\DEVICE\HARDDISKVOLUMEn` |
| `PrefetchOutsidePrefetchFolder` | D8 | valid `.pf` parsed from anywhere but `\Windows\Prefetch` |
| `CarrierNotPrefetch` | D8 | prefetch recovered from a stream on a non-`.pf` carrier |
| `TraceChainCount`, `TotalBlockLoadCount` | D5 | already parsed; just surface them |

**Three states, never two.** `NameSelfCheck` and `TotalDirCountMatches` must distinguish
`ok` / `mismatch` / `not-applicable`. Collapsing "this check doesn't apply to this version"
into "failed" would fire on every v17 file and every `\DEVICE\HARDDISKVOLUMEn` volume — which
is most of the vendored corpus.

**Every input produces a row (D10).** On parse failure the row carries the source path, the
stage-specific error, and whatever partial data was recovered. PECmd's failed-file list only
ever reached the console, so a file that failed to parse silently disappeared from the
analysis; that must not be repeated.

**Also emit**, all from the same store: a PECmd-shaped wide CSV (tooling parity — people have
scripts), long-form CSVs per table, JSONL, and a timeline CSV.

---

## 4. The full-executable-path requirement (three separate deliverables)

PECmd's gap decomposes into three things; conflating them causes bugs.

**4.0 — On modern Windows the path is stored explicitly; just read it.** Discovered
2026-08-12: v30/v31 files from current builds carry the executable's full device path as a
NUL-terminated UTF-16 string between the filename block and the volume block
(`prefetch-format.md` §5a). No matching, no ambiguity, no hash arithmetic.

It also **recovers names the 29-char header field truncated** (54 of 636 real files), and for
Store/UWP apps it holds the **package identity** instead of a path (172 of 636) — e.g.
`Microsoft.AAD.BrokerPlugin_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy`. Keep that case,
labelled; nothing else surfaces it.

So the resolution order is:

1. **Modern v30/v31** → read §5a's string. If it starts `\DEVICE\` or `\VOLUME{` it's the
   path; otherwise it's a package identity (record it as such, and fall through to step 2 for
   a path).
2. **v17 / v23 / v26 / 2015-era v30, or §5a absent** → resolve from the filename list, per
   4.1 below.

That makes §4.1 the *fallback*, not the primary path — but it still matters, because it covers
every pre-modern file.

**Verified, not assumed.** Both resolvers were run against all 636 modern files and diffed
(`STATE.md` finding 10). §5a is never worse than §4.1 and is decisive on 66 files:

| Outcome | Files |
|---|---|
| §5a == the one filename-list candidate | 397 |
| §5a picks correctly among 2+ candidates — §4.1 alone would guess | 9 |
| §5a names a path absent from the filename list — §4.1 alone would be **wrong** | 1 |
| §5a has a path, filename list has none — §4.1 alone would **fail** | 56 |
| Store/UWP package identity, no path | 171 |
| no §5a field, fall through to §4.1 | 2 |

The 9 disambiguations are the forensically load-bearing ones: `MSIEXEC.EXE` System32 vs
SysWOW64, `BASH.EXE` `Git\bin` vs `Git\usr\bin`, `ELEVATION_SERVICE.EXE` Edge vs EdgeWebView,
`INETMGR.EXE` System32\inetsrv vs WinSxS. §4.1 has no way to choose in any of them.

**When they disagree, show both — don't pick.** One file in the corpus
(`BROWSINGHISTORYVIEW.EXE-4C972525.pf`) has §5a saying
`\FORENSIC_PROGRAM_FILES\NIRSOFT\BROWSINGHISTORYVIEW.EXE` while the filename list says
`\TEMP\NIRSOFT\BROWSINGHISTORYVIEW.EXE`. `RunCount` is 1 with a single run time and a single
volume, so a rename between executions cannot explain it and **the mechanism is unconfirmed**.
Emit `ExecPathSource = conflict`, populate `ExecutablePath` from §5a, keep the §4.1 path in
`ExecPathAlternate`, and let the analyst judge. A tool run from `TEMP` under a second name is
exactly the finding a filter should be able to reach.

**4.1 — Resolve the executable's own entry from the filename list (fallback). DECIDED
2026-08-12: same source as PECmd, fixed implementation.**

The path is already in the file. Every `.pf` lists every file loaded during the traced startup
window, and the executable is one of them — so resolution is a lookup in data we already
parsed, needing no external input and no hash arithmetic. PECmd gets the source right and the
lookup wrong (`porting-notes.md` §2.6): `EndsWith` is a substring test, `FirstOrDefault`
silently discards ambiguity, and the fallback quietly writes a bare name into a full-path
column.

```python
def resolve_exec_path(filenames: list[str], header_name: str) -> ExecPath:
    """header_name is a bare name ('NOTEPAD.EXE'); filenames are full device paths."""
    target = header_name.upper()
    matches = [f for f in filenames if f.rsplit("\\", 1)[-1].upper() == target]
    #                                  ^ last path COMPONENT, compared for equality
    return ExecPath(
        path       = matches[0] if len(matches) == 1 else None,
        candidates = matches,
        status     = "resolved"  if len(matches) == 1 else
                     "ambiguous" if matches else "unresolved",
    )
```

Three outcomes, all explicit:

| Matches | `ExecutablePath` | `ExecPathStatus` | Notes |
|---|---|---|---|
| 1 | the path | `resolved` | the overwhelmingly common case |
| >1 | empty | `ambiguous` | all candidates kept in `exec_path_candidate`; optionally narrowed by §4.1a |
| 0 | empty | `unresolved` | never silently substitute the bare name |

`ExecutableName` (bare, from the header) stays its own column — **never overloaded** with a
path, which is the type-confusion in PECmd's fallback.

**Resolve once, in the core; use in every output.** PECmd resolves only in the timeline
writer, so its main CSV shows `7ZFM.EXE` while its timeline shows the full path for the same
file (`porting-notes.md` §2.7). Both come from one `ExecPath` on the record here.

### 4.1a Disambiguating by hash — forward, never reversed

> **DROPPED 2026-08-12, superseded by §4.0.** This existed only to choose between filename-list
> candidates. §5a makes that choice directly and correctly in all 9 real ambiguities in the
> 636-file corpus, so the hash buys nothing on modern files — and on pre-modern files, which
> have no §5a field, ambiguity is rare enough to surface rather than resolve. Kept below
> because the reasoning is right and carving (§10) would need it if unparked.

When several filename entries share the executable's basename, the header hash decides between
them.

**The hash cannot be reversed.** It maps an arbitrary-length path onto 32 bits, so the path is
not recoverable from `D8414F97` and many paths collide onto any given value. Go forwards
instead: hash each candidate path and keep the one whose hash equals the header's.

```
\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NOTEPAD.EXE   -> D8414F97   <-- match
\DEVICE\HARDDISKVOLUME2\WINDOWS\NOTEPAD.EXE            -> (differs)
\DEVICE\HARDDISKVOLUME2\USERS\BOB\DESKTOP\NOTEPAD.EXE  -> (differs)
```

This is exact for our case because the true path is already one of the candidates — we're
selecting, not searching. The version in the header tells us which hash variant to use
(XP / Vista-7 / Win10); the algorithms are documented in libscca and by Hexacorn, **not**
derivable from PECmd, which never computes them.

Cost: three small hash functions. Benefit: the `ExecPathAmbiguous` flag disappears.

**Not the same thing as a lookup table.** Precomputing hashes for a dictionary of known
Windows paths (Hexacorn published one) lets you *guess* a path when the file list is missing
or truncated. It only finds paths already in the dictionary and can collide, so it's a lead,
not an answer. Out of scope unless carving (§10) is ever unparked, where it would matter.

This is **path resolution, not planted-prefetch detection** — that idea is dropped per the
user. Nothing depends on it, and as of the §4.0 verification nothing needs it.

**4.2 — Always emit the raw device path.** `\VOLUME{01d8559f…-b0737add}\…` or
`\DEVICE\HARDDISKVOLUME2\…` is the ground truth that's actually in the file. Never discard it.

**4.3 — Drive letters are an optional enrichment, never a fabrication.** The device→letter
mapping **does not exist anywhere in the `.pf` file.** It has to come from outside: the volume
serial matched against registry `MountedDevices`, or the mount table of whatever mounted the
image. Make it an explicit input; when absent, leave the column empty rather than guessing.

Put the resolved path in **both** the main table and the timeline output.

---

## 5. ADS handling, done properly

**Enumeration.** On Windows: `FindFirstStreamW` / `FindNextStreamW` from `kernel32` via
`ctypes`, opening streams with the `path:streamname` syntax. Everywhere else (and for images):
read the **named `$DATA` attributes** straight out of the MFT record — mandatory now that the
target is cross-platform, and the same NTFS reader carving needs in §10.

**Coverage.** Scan every file regardless of extension (PECmd's built-in check only looks at
`*.pf`), and **also scan directories** — NTFS directory objects can carry streams and both of
PECmd's enumeration paths are files-only, so it misses them entirely.

**Detection stays content-based.** Try to parse each stream; keep what parses. Name-based
detection would miss the whole point.

**Timestamps — the thing that bit you.** A stream has no timestamps of its own; it inherits
the carrier file's. PECmd papers over this with a repair function that re-stats the carrier
when the values come back as year 1601, and then presents the result in the ordinary
`SourceCreated/Modified/Accessed` columns, so the reader can't tell what they're looking at.

Do it explicitly instead — model it, don't repair it:

| Column | Meaning |
|---|---|
| `CarrierPath` | the host file |
| `StreamName` | the ADS name |
| `StreamSize` | bytes in the stream |
| `TimestampSource` | `stream` \| `carrier` \| `unavailable` |
| `CarrierCreated/Modified/Accessed` | carrier's own times, labelled as such |

Also handle the zero-byte primary stream case (the normal shape for an ADS-hosted prefetch
carrier) without treating it as a parse failure, and flag every ADS-recovered record loudly —
a prefetch file hiding in a stream is a finding in itself, not a footnote.

---

## 5a. Approximate first-execution time (user's idea, sharpened)

Windows writes the `.pf` roughly 10 seconds after a process starts. So the `.pf` file's own
**creation** time ≈ first execution + lag, and subtracting the lag estimates the first run.

**Fixed 10 seconds — decided 2026-08-12.** A per-file measured lag was considered and
rejected in favour of the simple constant. Keep it a single named constant so it can be tuned
later without touching call sites.

```
FIRST_RUN_LAG = 10  # seconds
FirstRunApprox = SourceCreated - FIRST_RUN_LAG      # display with a leading "~"
```

**The payoff is when `RunCount > 8.`** Only eight run times are retained, so every execution
before those is gone from the record — but the creation time still marks the run that
*created* it. `FirstRunApprox` therefore recovers a first-execution estimate **older than any
embedded timestamp**, which every current tool throws away. That's the reason to build this.

**Caveats to carry in the UI:** creation time is the first run *for this record* (deleting the
`.pf` resets it), NTFS **file tunneling** can restore an old creation timestamp on a
delete-and-recreate within ~15 s with no adversary involved, and filesystem times are
stompable. Always show it with the `~` and never as a precise timestamp.

## 5b. Hosted processes and same-name-different-path

For a small set of **hosting applications**, the prefetch hash is computed from the executable
device path **plus the command line**, so one binary at one path legitimately produces many
`.pf` files. Documented members: `SVCHOST.EXE`, `RUNDLL32.EXE`, `DLLHOST.EXE`, `MMC.EXE`.

**Make the list user-editable** — it is Windows-version-dependent and cannot be enumerated
authoritatively from any public source.

Behavior — **revised 2026-08-12 after measuring the real corpus**:

- Hosting apps: **exclude from the flag entirely.** Multiple hashes are the expected case.
  Group them as distinct command-line contexts instead.
- For everything else, **do not flag on differing hashes. Flag on differing resolved paths.**

**Why the change.** Profiling the user's own 221-record output: 20 executable names carry
multiple path hashes — a flag on that alone fires on 9% of records, which is noise. Worse,
inspecting `MSEDGE.EXE` shows seven hashes (`BA103770`–`BA103778`) that **all resolve to the
identical path**:

```
BA103770  11 runs   \VOLUME{...}\PROGRAM FILES (X86)\MICROSOFT\EDGE\APPLICATION\MSEDGE.EXE
BA103771  13 runs   ...the same path...
BA103775  27 runs   ...the same path...
```

Near-sequential hashes for one path means the hash covers something beyond the path — command
line, as with the documented hosting apps — for a binary nobody lists as a hosting app. So the
hosting-app list is **necessarily incomplete**, and a hash-difference flag is wrong by
construction.

Since §4.1 resolves the real path anyway, compare *paths*: `SameNameDifferentPath` is set only
when one basename resolves to two or more genuinely different paths. On this corpus that
collapses the 20 candidates to a handful.

Keep it **observational**, not a verdict — benign multi-path cases are common: portable tools
run from a USB stick and the Desktop, 32- vs 64-bit installs, versioned updater directories
(`DOTNET-SDK-9.0.315-WIN-X64.EX` in this very corpus). Show those explanations beside the flag.
A flag that cries wolf gets ignored, and then it's worse than not having one.

## 6. Artifact coverage — four tiers, cut from the bottom

A Prefetch folder is not just `.pf` files. Each tier below is a plugin; **none of them shape
the architecture.**

**Tier 1 — `*.pf` (SCCA).** Validated spec, all five versions. Full parse. This is the
product; everything else is a bonus.

**Tier 2 — `Layout.ini`.** Plain UTF-16 text, a list of paths. Trivial. Ship it.

**Tier 3 — SuperFetch / SysMain `Ag*.db`. Possibly moot: neither the real Win10 nor Win11
folder contains any `Ag*.db`.** Confirm they still exist on current builds before investing.
What those folders *do* contain instead — `PfPre_<hex>.mkd`, `dynrespri.7db`,
`cadrespri.7db`, `ResPri*.ebd` — is undocumented and belongs in Tier 5. `AgGlGlobalHistory.db`, `AgGlFaultHistory.db`,
`AgGlFgAppHistory.db`, `AgAppLaunch.db`, `AgRobust.db`, `AgCx_SC1/2/4.db`,
`AgCx_SC3_<id>.db`. The reference is **libagdb** (Joachim Metz), whose format spec is
explicitly a *working document* — incomplete and version-variable. Most of these are
XPRESS_HUFFMAN compressed (reportedly except `AgRobust.db` and `AgAppLaunch.db`), so your
existing decompressor is reused. Forensically they corroborate usage but carry no reliable
per-execution timestamp — position them as corroboration, never as execution timing.
**Shipping looks like:** decompress, parse the documented structures (path/volume lists,
application launch info), preserve everything else as blobs, and never claim field
completeness.

**Tier 4 — `ReadyBoot\`. CORRECTED 2026-08-12 against a real Win11 folder.** The earlier claim
that this is an ETL trace was wrong. The real directory holds `Trace2.fx`–`Trace6.fx`
(2.5–3.2 MB each) and `rblayout.xin`, all six beginning `50 66 42 e3` (`PfB` + 0xE3) — an
undocumented container, not ETL, so `tracerpt` does not apply. **Shipping looks like:**
Tier 5 treatment until someone reverses it. See `porting-notes.md` §5.3.

**Tier 5 — `PfSvPerfStats.bin` and anything unrecognized.** Undocumented. **Shipping looks
like:** identify, hash, record size and timestamps, carve strings, flag for manual review.
Never claim to parse it.

**Design rule for the unknown case:** a file in the Prefetch folder that no plugin recognizes
must produce an *"unidentified artifact"* row, not silence. Malware has hidden in this folder;
"there's a file here nobody can explain" is a finding.

---

## 7. GUI specification

The reference screenshot is **Excel's column filter dropdown**, which is a specific
implementable widget, not a vague "good filtering" ask:

- Click the header chevron → popup containing, in order: sort ascending / descending, "clear
  filter from this column", a **search box**, and a **scrollable checkbox list of distinct
  values** with `(Select All)`.
- **Type-aware filter submenus**: text (contains / equals / begins with), number (equals, >,
  <, **between**, top N), datetime (between, on date, last N days).
- Filters across columns **AND** together. Show a chip row of active filters with one-click
  clear-all — the single biggest usability failure in grid tools is not knowing why rows are
  missing.
- Backed by SQLite: distinct values are `SELECT DISTINCT`, filtering is `WHERE`. Never load
  the full result set into Python memory — use a `QAbstractTableModel` that pages.

Plus the Timeline-Explorer behaviors analysts already expect: column show/hide/reorder/pin,
copy cell/row, **export the current filtered view** (not the whole set), saved layouts,
keyword highlight rules with colors, and a detail pane for the selected row showing the
one-to-many data (all volumes, all loaded files, all MFT refs) that can't fit in the grid.

---

## 9. Bookmarks, tags, and evidence export

The one analyst-convenience feature in scope. Tag rows, attach a free-text note, export **only
the tagged/selected rows** — not a generated report.

**Formats, in order of preference:**

| Format | Use | Notes |
|---|---|---|
| **HTML** (default) | pastes into Word / Confluence / OneNote as a real table, keeping highlight colors, staying selectable and searchable | the right default |
| CSV / XLSX | further analysis, joining with other artifacts | plain data |
| PNG | pasting into slide decks | offered, but see below |

**On the image idea:** it's genuinely what people paste into decks, so ship it — Qt renders a
view selection to a pixmap in a few lines. But be clear it's the *weaker* artifact: an image
isn't searchable, isn't verifiable, and can't be diffed or re-parsed. It should be an option,
never the only one.

**What actually makes an export evidence-grade is provenance travelling with each row**, not
the file format:

- source `.pf` path (and carrier path + stream name if it came from an ADS)
- SHA-1 of the source file
- tool version **and** parser-spec version
- export timestamp in UTC
- the analyst's own note

Put those in every format, as a per-row column set plus a footer block.

## 10. Carving deleted prefetch — **PARKED 2026-08-12, not dropped**

Out of scope for now (the user is unconvinced about the MFT dependency), but the approach is
recorded here so it isn't re-derived from scratch later. **Nothing in the current build
depends on it** — with carving parked, the NTFS reader is only needed for off-Windows ADS.

The question was: with no directory entry, where do you start reading? Three mechanisms, in
descending yield.

**10.1 MFT-driven recovery first — this is the high-yield path, not signature carving.** A
deleted `.pf` usually still has its MFT record: the filename gives you the executable name and
path hash *for free*, `$STANDARD_INFORMATION` gives the timestamps, and the `$DATA` runlist
points straight at the clusters. Prefetch files are kilobytes, so they are never resident —
there is always a runlist. Follow it and you get the file even when the signature sits mid-
cluster. This reuses the NTFS reader that cross-platform ADS support already requires.

**10.2 Signature carving for what the MFT no longer covers.**

Uncompressed (v17/23/26) has an **8-byte fixed anchor** — version dword immediately followed
by `SCCA`:

```
11 00 00 00 53 43 43 41     v17  (XP / 2003)
17 00 00 00 53 43 43 41     v23  (Vista / 7)
1A 00 00 00 53 43 43 41     v26  (8.x / 2012)
```

Eight fixed bytes makes the false-positive rate negligible, and **the length comes free**:
`FileSize` is at +0x0C.

Compressed (v30/31) only anchors on `4D 41 4D 04` (`MAM\x04`) plus a uint32 size at +4 — four
bytes is weak. Two things rescue it: bound the declared size to something plausible (say 1 KB
– 16 MB), and note that **the XPRESS Huffman decoder is driven by the output size, not the
input size** — you never need to know where the compressed data ends. Attempt the decompress;
if the first eight bytes of output are a valid version + `SCCA`, it's real. **Decompression is
the validator.**

**10.3 Validation — you already have it.** The four section-geometry identities from
`prefetch-format.md` §3 are a far stronger filter than string-spotting, and
`reference/validate_spec.py` already implements them:

```
metrics_offset == 84 + fileinfo_size
chains_offset  == metrics_offset + metrics_count * metric_size
names_offset   == chains_offset  + chains_count  * chain_size
vols_offset    == align8(names_offset + names_size)
```

Plus: every offset inside `FileSize`, executable name printable UTF-16 with a NUL terminator,
run times inside a sane date range. A candidate satisfying all of these *is* a prefetch file.

**10.4 Fragmentation, and why it hurts less than you'd expect.** A carved fragment often
parses only partially — but **every high-value field lives in the first 308 bytes**: version,
executable name, path hash, file size, run count, and all eight run times. That's inside a
single 4 KB cluster. So even one recovered cluster yields the execution evidence, and the
staged-error parser (§2) reports "header and run times recovered, filename block truncated"
instead of failing outright. Directory and loaded-file lists are what you lose.

**Where to scan:** cluster boundaries first (fast), then byte-granular for embedded and
fragmented cases. Worth including unallocated space, `pagefile.sys`, `hiberfil.sys`, and VSS.

## 11. What not to do

- Don't port PECmd's global mutable statics — they block the parallelism this obviously wants.
- Don't reproduce the two-volume CSV ceiling or the missing separator between volumes'
  directory lists.
- Don't emit `X`-formatted hex (leading zeros dropped) for the path hash or volume serial.
- Don't silently pick one candidate for the executable path, and don't write a bare name into
  a column that otherwise holds full paths.
- Don't resolve the executable path in one writer only — the main CSV and the timeline must
  agree.
- Don't phone home. PECmd fires Exceptionless telemetry on every run; a forensics tool
  shouldn't.
- Don't let Tier 3–5 delay Tier 1 shipping.
