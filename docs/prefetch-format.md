# Windows Prefetch (SCCA) file format — reimplementation spec

Derived by reading Eric Zimmerman's `Prefetch` library source (the parsing engine behind
PECmd) line by line, cross-checked against the real `.pf` corpus in
`../reference/pf-corpus/`. Everything here is **little-endian**. Offsets marked "rel" are
relative to the base named next to them, not to the start of the file.

Source of truth for this document: `../reference/Prefetch-lib-src/` (vendored copy of
<https://github.com/EricZimmerman/Prefetch>, cloned 2026-08-12).

**Where the format is ambiguous or the C# looks wrong, this document says so inline.** Do
not port the C# arithmetic blindly — see `porting-notes.md`.

## Validation status

**Every version in this document is executed, not transcribed.**
`../reference/validate_spec.py` is an independent parser written from *this document only*
(not from the C#), using `../reference/xpress.py` — a pure-Python XPRESS Huffman decoder
written from [MS-XCA] — to open the compressed files. Latest run:

```
ground truth:      7 files checked          (upstream NUnit assertions)
vendored:         54 files   v17x12, v23x13, v26x23, v30x6
Prefetch_win10:  184 files   v30x184
Prefetch_win11:  452 files   v31x452
ALL CHECKS PASSED
```

683 files, every version, both corpora (7 of them also checked against the upstream
NUnit ground-truth assertions). Checked per file: the four section-geometry
identities, `len(filenames) == FileMetricsCount`, `VolumeCount == len(volumes)`, per-metric
filename offsets reproducing the NUL-split list, bounded directory-string walk,
`TotalDirectoryCount` against the summed per-volume lists, and RunCount plausibility against
the retained run times. **Re-run it after any edit here.**

The decoder decompresses **all 642 MAM files with zero failures**, so v30/v31 are measured on
real data rather than inferred.

---

## 0. What a prefetch file *is* (the why)

Windows' cache manager watches the first ~10 seconds of a process launch and writes
`%SystemRoot%\Prefetch\<EXENAME>-<HASH>.pf`. Forensically it answers: *this executable ran
on this machine, this many times, at these timestamps, from this volume, and it touched
these files and directories.* That is why every field below matters — the run times and run
count are execution evidence, and the filename/directory lists are a snapshot of what the
binary loaded, including paths that may no longer exist on disk.

`<HASH>` in the filename is a hash of the **executable's full path** (plus, on some Windows
versions, command line for certain hosts). The parser only *reads* the hash out of the
header — it never recomputes it. See `porting-notes.md` §"Feature gaps".

---

## 1. Top-level dispatch

```
read whole stream into rawBytes

if rawBytes[0..3] == "MAM":          # Windows 10/11 — compressed container
    decompressedSize = uint32 @ 4
    payload          = rawBytes[12..] if (rawBytes[3] & 0x80) else rawBytes[8..]
    rawBytes         = XpressHuffman.decompress(payload, decompressedSize)

version   = int32 @ 0      # 17 | 23 | 26 | 30 | 31
signature = int32 @ 4      # must be 0x41434353 == "SCCA", else hard error
dispatch on version
```

Observed in the corpus (`xxd -l 12`):

| Corpus dir | First bytes | Meaning |
|---|---|---|
| `XPPro/`, `Win2k3/` | `11 00 00 00 "SCCA"` | version 17 |
| `Win7/`, `Vista/` | `17 00 00 00 "SCCA"` | version 23 |
| `Win8x/`, `Win2012*/` | `1a 00 00 00 "SCCA"` | version 26 |
| `Win10/` | `4d 41 4d 04` (`MAM\x04`) then uint32 size | version 30 after decompression |

Version → OS label used in output:

| Value | Label |
|---|---|
| 17 | Windows XP or Windows Server 2003 |
| 23 | Windows Vista or Windows 7 |
| 26 | Windows 8.0 / 8.1 / Server 2012(R2) |
| 30 | Windows 10 or Windows 11 |
| 31 | Windows 11 |

30 and 31 are parsed by the *same* code path.

### 1.1 The MAM container

```
0x00  4  "MAM" + compression-type byte (0x04 == XPRESS_HUFF in every corpus file)
0x04  4  uint32 uncompressed size
0x08  .. XPRESS Huffman compressed stream
```

The C# only tests the three ASCII chars `MAM` and assumes byte 3 is 0x04. **A `MAM\x84`
variant does occur** — bit 7 set — on the `ResPri*.ebd` files in both real Prefetch folders
(`porting-notes.md` §5.2). `reference/xpress.py` treats bit 7 as inserting a 4-byte field, so
the payload starts at +12 instead of +8; **untested**, because those two files are not
prefetch and carry no `SCCA` to verify against. No `.pf` file uses it.

Decompression in the C# is a P/Invoke to `ntdll!RtlDecompressBufferEx` with
`COMPRESSION_FORMAT_XPRESS_HUFF (4)`. This is the single biggest portability constraint —
see `porting-notes.md` §1.

---

## 2. Header — 84 bytes at offset 0, identical in all versions

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | Version | 17/23/26/30/31 |
| 0x04 | 4 | Signature | ASCII `SCCA` |
| 0x08 | 4 | unknown | |
| 0x0C | 4 | FileSize | total size of the (decompressed) `.pf` |
| 0x10 | 60 | Executable filename | UTF-16LE, NUL-terminated, ≤29 chars + NUL |
| 0x4C | 4 | Path hash | uint32; rendered as uppercase hex, matches `-XXXXXXXX` in the filename |
| 0x50 | 4 | unknown | inside the 84-byte block but unread by the C# |

Executable name parsing: decode all 60 bytes as UTF-16, cut at the first NUL, trim. **A
rewrite must handle "no NUL found"** — the C# does `IndexOf('\0')` and would throw on a
truncated/planted file.

Hash rendering: the C# uses `.ToString("X")`, which drops a leading zero nibble. Use the
equivalent of `X8` so it always matches the 8-char filename hash.

---

## 3. File information section — starts at offset 84 (0x54)

Section size is the first real per-version difference:

| Version | Section size | Absolute range | Status |
|---|---|---|---|
| 17 | 68 | 84 … 151 | measured, 12 files |
| 23 | 156 | 84 … 239 | measured, 13 files |
| 26 | **220** | 84 … 303 | measured, 23 files |
| 30 (2015-era) | **220** | 84 … 303 | measured, 5 files |
| 30 (modern) | **212** | 84 … 295 | measured, 184 files |
| 31 | **212** | 84 … 295 | measured, 452 files |

"Measured" = `FileMetricsOffset` equals `84 + size` on every file of that version, across
both corpora (`porting-notes.md` §5). **The C# uses 224 for both v26 and v30/31 and is wrong
in every case** — the over-read is harmless there only because nothing past +136 is read.

### 3.0a The file-info section shrank — and that explains PECmd's RunCount hack

The 2015-era Win10 corpus files use a **220**-byte section; every modern Win10 and Win11 file
uses **212**. That 8-byte shrink is exactly the "newer versions of Windows 10 shift the counter
backward 8 bytes" that `Version30or31.cs:87` works around with a probe.

The underlying rule is simpler than the probe: **RunCount sits 96 bytes before the end of the
file-info section.**

| Section size | RunCount offset | PECmd calls it |
|---|---|---|
| 220 | +124 | the default |
| 212 | +116 | the "shifted" case |

So PECmd's heuristic is right by accident. A rewrite should derive the offset from the
measured section size (`FileMetricsOffset - 84 - 96`) rather than probing `+120` — same answer,
no guessing, and it self-corrects if Microsoft resizes the section again.

**Version 31 is confirmed as a real, distinct value** (452 files), but structurally identical
to modern v30 — same 212-byte section, same 32-byte metrics, same 8-byte chains. It is an OS
label, not a format change.

**Sections are not contiguous — always use the offsets.** Measured across all 683 validated
files:

```
metrics_offset == 84 + fileinfo_size                              # exact
chains_offset  == metrics_offset + metrics_count * metric_size    # exact
names_offset   == chains_offset  + chains_count  * chain_size     # exact
vols_offset    == align8(names_offset + names_size + exec_path_string)
```

The last one has two cases. On pre-modern files the gap is pure padding, 0-6 bytes. On modern
v30/v31 it holds the **executable path string** of section 5a, and `vols_offset` is 8-aligned
with under 16 bytes of total slack. Either way: read the stored offset, never compute it.

The volume information block is 8-byte aligned, so the filename string block is followed by
up to 6 bytes of padding. A parser that computes the next section's start instead of reading
the stored offset will be wrong on most files. (These same four identities are the sharpest
available check on the v30/31 entry sizes — assert them first once a decompressor exists.)

### 3.1 Fields common to every version (rel. to section start = +84 absolute)

| Rel | Size | Field |
|---|---|---|
| +0 | 4 | FileMetricsOffset (absolute, from start of file) |
| +4 | 4 | FileMetricsCount |
| +8 | 4 | TraceChainsOffset (absolute) |
| +12 | 4 | TraceChainsCount |
| +16 | 4 | FilenameStringsOffset (absolute) |
| +20 | 4 | FilenameStringsSize |
| +24 | 4 | VolumesInfoOffset (absolute) |
| +28 | 4 | VolumeCount |
| +32 | 4 | VolumesInfoSize |

### 3.2 Version 17 (68 bytes)

| Rel | Size | Field |
|---|---|---|
| +36 | 8 | Last run time (FILETIME) — **only one** |
| +60 | 4 | RunCount |

`TotalDirectoryCount` does not exist; the library sets it to `-1` and the *caller* (PECmd)
compensates by summing per-volume directory counts before display.

### 3.3 Version 23 (156 bytes)

| Rel | Size | Field |
|---|---|---|
| +36 | 4 | TotalDirectoryCount — **verified**: equals the sum of every volume's directory count on all corpus files (the C# comment claiming +36 is "8 unknown bytes" is stale) |
| +40 | 4 | unknown |
| +44 | 8 | Last run time (FILETIME) — **only one** |
| +52 | 16 | unknown |
| +68 | 4 | RunCount |
| +72 | 84 | unknown |

### 3.4 Version 26 (220 bytes)

| Rel | Size | Field |
|---|---|---|
| +36 | 4 | TotalDirectoryCount |
| +44 | 64 | **8 × FILETIME** last run times, most recent first |
| +108 | 16 | unknown |
| +124 | 4 | RunCount |
| +128 | 92 | unknown |

Windows 8 is where the format starts keeping **eight** run times instead of one. Unused
slots are zero and are dropped (`rawTime > 0` filter) — so the surviving list is dense and
its indices are *post-filter*. This matters for output column mapping (see
`pecmd-behavior.md`).

### 3.5 Version 30/31 (220 or 212 bytes) — same as 26, but the section size varies

Layout matches §3.4 except for the section size and, consequently, the RunCount offset:

```
fileinfo_size = FileMetricsOffset - 84       # 220 on 2015-era v30, 212 on modern v30/v31
runCount      = int32 @ (fileInfo + fileinfo_size - 96)
```

Do **not** port PECmd's probe (`read +124; if +120 != 0 then read +116`). It produces the
right answer on both layouts but only by coincidence — see §3.0a for the actual rule.

Entry sizes, measured on 566 v30/v31 files across both corpora: metrics **32**, trace chains
**8**, volume entries **96**. Same for v30 and v31.

---

## 4. File metrics array — at `FileMetricsOffset`, `FileMetricsCount` entries

One entry per loaded file, index-aligned with the filename strings list
(`Filenames.Count == FileMetricsCount` is asserted by the upstream tests).

### Version 17 — 20 bytes/entry

| Off | Size | Field |
|---|---|---|
| 0 | 4 | unknown0 (prefetch start time, in ms since start?) |
| 4 | 4 | unknown1 (duration?) |
| 8 | 4 | FilenameStringOffset — **byte** offset rel. to `FilenameStringsOffset` |
| 12 | 4 | FilenameStringSize — **character** count, excluding the NUL |
| 16 | 4 | unknown2 (flags) |

### Versions 23 / 26 / 30 / 31 — 32 bytes/entry

| Off | Size | Field |
|---|---|---|
| 0 | 4 | unknown0 |
| 4 | 4 | unknown1 |
| 8 | 4 | unknown2 |
| 12 | 4 | FilenameStringOffset — **byte** offset rel. to `FilenameStringsOffset` |
| 16 | 4 | FilenameStringSize — **character** count, excluding the NUL |
| 20 | 4 | unknown3 |
| 24 | 8 | **MFT file reference** (see §7) |

The MFT reference from v23 onward is the forensically valuable part: it ties each loaded
filename to a concrete MFT record, which survives renames and lets you correlate against
`$MFT`/USN output. **The upstream C# reads it into a buffer and then passes the wrong buffer
to the constructor for v30/31, so every Win10/11 metric is a duplicate of entry 0. Do not
port that.** See `porting-notes.md` §2.1.

The library never actually uses `FilenameStringOffset` to resolve names — it splits the
whole filename block on NULs instead (§5). Using the per-metric offset/size is the more
correct approach and lets a rewrite pair a metric with its exact name.

**Verified**: reading `FilenameStringSize * 2` bytes at `FilenameStringsOffset +
FilenameStringOffset` reproduces the NUL-split list exactly, entry for entry, across all 48
uncompressed corpus files. The units are the trap here — the offset is in bytes, the size is
in characters. Entries are laid out consecutively (`offset[i+1] == offset[i] + (size[i]+1)*2`).

---

## 5. Filename strings — at `FilenameStringsOffset`, `FilenameStringsSize` bytes

A single UTF-16LE blob of NUL-terminated full paths, e.g.
`\VOLUME{01d8559f7371205e-b0737add}\WINDOWS\SYSTEM32\NTDLL.DLL`.

Upstream decodes the whole blob and splits on `\0`, discarding empties. Order is preserved
and is index-aligned with the file metrics array.

Paths are volume-device-relative (`\VOLUME{...}`), **not** drive-letter paths; the
`\VOLUME{...}` prefix maps to a volume entry via §6 device name.

---

## 5a. The executable path string (modern v30/v31) — **not in any prior spec**

Between the filename block and the volume block, modern Windows 10/11 writes a
**NUL-terminated UTF-16 string holding the executable's own full path**, followed by padding
to an 8-byte boundary.

```
FilenameStringsOffset + FilenameStringsSize
   └── UTF-16LE string, NUL-terminated   e.g. \DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\WSL.EXE
   └── padding
VolumesInfoOffset  (8-byte aligned; total slack < 16 bytes)
```

No offset or length field points at it — it is implied by the gap, which is why every
existing parser walks straight past it. Measured across 636 real files:

| Content | Win10 | Win11 |
|---|---|---|
| Full device path, basename == header name | 137 | 272 |
| Full device path, **recovers a name the 29-char header truncated** | 13 | 41 |
| **Package identity** instead of a path (Store/UWP apps) | 33 | 139 |
| Absent (padding only) | 1 | 0 |

Absent on every v17/v23/v26 file and on the 2015-era v30 corpus — those have 0–6 bytes of
pure alignment padding. So this is a modern-build addition, arriving with the 212-byte
file-info section.

**Two things this gives you for free:**

1. **The executable's full path, authoritatively.** No basename matching against the filename
   list, no ambiguity when several entries share a name, no hash arithmetic. See
   `new-tool-design.md` §4.
2. **The untruncated executable name.** The header name field caps at 29 characters, so
   `BULK_EXTRACTOR-1.6.0-DEV-REC0` is all you get there — while this field holds
   `\DEVICE\HARDDISKVOLUME1\SROC\BULK_EXTRACTOR-1.6.0-DEV-REC03-WINDOWSINSTALLER_X64.EXE`.

**Packaged apps store an identity here instead of a path** — e.g.
`Microsoft.AAD.BrokerPlugin_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy` or
`57540AMZNMobileLLC.AmazonAlexa_3.25.1156.0_x64__22t9g3sebte08`. Detect by the leading
`\DEVICE\` or `\VOLUME{`; anything else is an identity.

**The identity is not a spelling of the path — for host processes it names a different
program.** Of the 171 identity files, **64 have an identity whose package is not the
executable at all**. The executable is a generic Windows host and §5a names *the package it
was hosting*:

| Executable that ran | §5a identity — the package being hosted |
|---|---|
| `\WINDOWS\SYSTEM32\DLLHOST.EXE` | `Microsoft.WindowsTerminal_1.24.11911.0_x64__8wekyb3d8bbwe` |
| `\WINDOWS\SYSTEM32\RUNTIMEBROKER.EXE` | `Microsoft.StorePurchaseApp_22605.1401.3.0_x64__8wekyb3d8bbwe` |
| `\WINDOWS\SYSTEM32\BACKGROUNDTASKHOST.EXE` | `Microsoft.AAD.BrokerPlugin_1000.19041.1023.0_neutral_…` |
| `\WINDOWS\SYSTEM32\BACKGROUNDTRANSFERHOST.EXE` | `Microsoft.Windows.ContentDeliveryManager_10.0.26100.1_…` |
| `…\EDGEWEBVIEW\APPLICATION\151.0.4129.72\MSEDGEWEBVIEW2.EXE` | `MicrosoftWindows.Client.CBS_1000.26100.344.0_x64__…` |

This is **the UWP analogue of the service name inside an `svchost` prefetch hash** — it tells
you *which application* a generic host was actually running, which is otherwise unrecoverable
from prefetch. No existing parser surfaces it. `RUNTIMEBROKER.EXE` on its own is noise;
`RUNTIMEBROKER.EXE hosting Microsoft.StorePurchaseApp` is an event.

So they are **two independent columns**, never one:

- `ExecutablePath` — from §5a when it holds a path, otherwise the filename list. Note the
  filename list resolves a path for **all 171** identity files, so an identity in §5a never
  means "no path available".
- `HostedPackage` — the §5a identity, whether or not it matches the executable.

The remaining 107 identity files have an identity matching their own executable (a packaged
app running as itself, e.g. `GETHELP.EXE` under
`\PROGRAM FILES\WINDOWSAPPS\MICROSOFT.GETHELP_…\`). Both columns still populate; they simply
agree.

### 5a.1 Cross-checked against the filename-list resolver

The field is not merely plausible — it was diffed against the conventional resolution method
(basename match into the filename list, §4.1 of the design doc) on all 636 modern files, via
`reference/compare_pathsources.py`:

| Outcome | Files |
|---|---|
| §5a equals the single filename-list candidate | 443 |
| §5a selects correctly among 2+ candidates | 13 |
| §5a names a path **absent** from the filename list | 5 |
| §5a has a path where the filename list has no match at all | 2 |
| Package identity in §5a — path still recovered from the filename list | 171 |
| No §5a field (both are `Op-*.pf`, see §5a.3) | 2 |
| **No path from either source** | **2** |

Two measurement traps, both of which produced wrong numbers on the first attempt and are
worth stating because any reimplementation will hit them:

1. **The volume notation differs.** §5a writes `\DEVICE\HARDDISKVOLUMEn`; filename-list
   entries write `\VOLUME{...}`. Strip the leading volume component before comparing, or
   everything looks like a mismatch.
2. **A 29-character header name is truncated, so equality can never match it.** Fall back to
   a prefix match — but restrict it, because a bare prefix also catches the executable's
   satellite files (`FOO.EXE.CONFIG`, `FOO.EXE.MUI`, `FOO.APPDOMAIN.DLL`). Taking the
   *shortest* completion of the prefix picks the real executable. Skipping this understates
   the filename list badly: an earlier run scored 56 files as "filename matching finds
   nothing" when the true figure is 2 — the other 54 were the matcher's fault, not the data's.

Both traps cut the same way: they made §5a look better than it is. §5a is still the better
primary source, but the honest margin is **20 files out of 636**, not 66.

All 9 selections are real ambiguities that no other method resolves from the file alone —
reproduce them with `reference/compare_pathsources.py`:

| Executable | §5a picked | over |
|---|---|---|
| `MSIEXEC.EXE` (×2) | `\WINDOWS\SYSTEM32\` | `\WINDOWS\SYSWOW64\` |
| `WSL.EXE` | `\WINDOWS\SYSTEM32\` | `\PROGRAM FILES\WSL\` |
| `SEARCHPROTOCOLHOST.EXE` | `\WINDOWS\SYSTEM32\` | `\WINDOWS\WINSXS\AMD64_WINDOWSSEARCHENGINE_…\` |
| `INETMGR.EXE` | `\WINDOWS\SYSTEM32\INETSRV\` | `\WINDOWS\WINSXS\AMD64_…IIS-MANAGEMENTCONSOLE…\` |
| `BASH.EXE` | `\PROGRAM FILES\GIT\BIN\` | `\PROGRAM FILES\GIT\USR\BIN\` |
| `GIT.EXE` | `\PROGRAM FILES\GIT\CMD\` | `\PROGRAM FILES\GIT\MINGW64\BIN\` |
| `GIT-LFS.EXE` | `\PROGRAM FILES\GIT\CMD\` | `\PROGRAM FILES\GIT\MINGW64\BIN\` |
| `ELEVATION_SERVICE.EXE` | `…\MICROSOFT\EDGE\APPLICATION\` | `…\MICROSOFT\EDGEWEBVIEW\APPLICATION\` |

Two patterns dominate: **System32 vs its shadow** (SysWOW64, WinSxS) and **shipped-twice
binaries** (Git's three copies, Edge vs EdgeWebView). Both are exactly the cases where picking
the wrong candidate changes the conclusion — a 32-bit `msiexec` and a 64-bit one are different
executions, and WinSxS is where a servicing copy lives rather than the one that ran.

### 5a.2 When the two disagree, the binary moved

Five files have a §5a path that is absent from their own filename list. **Every one has
`RunCount = 1`**, so a rename between executions cannot explain any of them — and three of the
five share a pattern that names the mechanism:

| File | §5a says | filename list says |
|---|---|---|
| `MICROSOFTEDGEUPDATESETUP_X86_…` | `EDGEUPDATE\INSTALL\{EF21780E-…}\` | `EDGEUPDATE\DOWNLOAD\{F3C4FE00-…}\` |
| `MICROSOFTEDGE_X64_151.0.4129.…` | `EDGEUPDATE\INSTALL\{EA73957F-…}\` | `EDGEUPDATE\DOWNLOAD\{F3017226-…}\` |
| `MICROSOFTEDGE_X64_151.0.4129.…` | `EDGEUPDATE\INSTALL\{A2493382-…}\` | `EDGEUPDATE\DOWNLOAD\{56EB18F8-…}\` |
| `BROWSINGHISTORYVIEW.EXE` | `\FORENSIC_PROGRAM_FILES\NIRSOFT\` | `\TEMP\NIRSOFT\` |
| `LENOVO.MODERN.IMCONTROLLER.PL…` | `…\PLUGINHOST\….COMPANIONAPP.EXE` | `…\PLUGINHOST\….APPDOMAIN.DLL` |

Same filename, different directory, one execution. The Edge updater is a controlled natural
experiment: it downloads an installer to `DOWNLOAD\{guid}` and runs it from `INSTALL\{guid}`.
So the working hypothesis is that **§5a records the path the process launched from, while the
filename list records a path the file occupied earlier in the same trace window.**

That makes the disagreement *the interesting part*, not noise. A binary that ran from a
different directory than the one the trace saw it in is exactly what a stage-then-execute
looks like — including `BROWSINGHISTORYVIEW` running out of `TEMP\NIRSOFT`.

**Still report both and don't assert the cause in the UI.** The hypothesis fits 4 of 5 cases;
the Lenovo one is different (§5a names an executable that simply is not in the filename list
at all, and the "candidate" is a satellite DLL surfaced by prefix matching). Emit
`ExecPathSource = conflict` with both paths and let the analyst read it.

### 5a.2a The filename hash cannot verify §5a — tested, negative

The obvious way to *prove* §5a holds the real launch path is to recompute the prefetch filename
hash from it: the hash in `7ZFM.EXE-7C92DCA0.pf` was computed by Windows over the executable's
path, so a match would settle it. **This was tried and it does not work on this corpus.**

All three published algorithms (`libscca`'s XP, Vista and 2008 variants) were run over the §5a
string, uppercased, on all 463 files that have a device path: **0 matches for all three.** A
further sweep of 84 input variants on a known-answer file — `\VOLUME{...}` form, all
`HARDDISKVOLUMEn` for n=0..8, path with and without the device prefix, lower-case, trailing
NUL — also produced nothing.

More importantly, **the hash is not a pure function of the path at all**, which no choice of
algorithm can fix. Whatever the extra input is — command line, an instance discriminator, or an
increment-on-collision rule — a path-only hash cannot reproduce it.

**Confirmed independently against real PECmd output** (`20260703230020_PECmd_Output.csv`, 221
rows from the same machine), so this does not rest on my parser:

| Executable | Rows in PECmd's own CSV | Hashes |
|---|---|---|
| `SVCHOST.EXE` | 39 | scattered |
| `RUNTIMEBROKER.EXE` | 12 | scattered |
| `DLLHOST.EXE` | 9 | scattered |
| `MSEDGE.EXE` | **7** | `BA103770`–`BA103775`, `BA103778` — **near-consecutive** |
| `WINDOWSTERMINAL.EXE` | 7 | scattered |
| `RUNDLL32.EXE` | 6 | scattered |
| `PECMD.EXE` | 5 | scattered |

Two things stand out. **`MSEDGE.EXE`'s seven hashes are near-consecutive**, which a real hash
function cannot produce for seven distinct paths — that is a counter, not a digest. And
`ACRORD32.EXE-62938E58.pf` / `-62938E59.pf` have byte-identical §5a paths *and* identical
RunCounts, differing only in the last hash digit.

Note also that `WINDOWSTERMINAL.EXE` and `PECMD.EXE` are **not** hosting applications, so the
"hosting apps hash the command line" rule does not explain the whole phenomenon.

Consequences:

1. **No hash-based verification of §5a is available.** The 443 agreements between §5a and the
   filename list remain *consistency*, not proof. This is an honest limit of the corpus, not an
   unexplored option.
2. It independently reconfirms dropping hash disambiguation (§4.1a). A hash that cannot be
   recomputed cannot select among candidates either.
3. **Multiple prefetch files for one executable path are normal**, not evidence of tampering —
   which is why the multi-hash flag was already replaced by a multi-*path* flag.

Reproduce/extend: the algorithms and the sweep are trivial to re-derive from this section; they
were deliberately not kept as a script because the result is negative and the code would only
invite someone to trust it.

### 5a.3 The two files with no §5a field are both `Op-*.pf`

`Op-EXPLORER.EXE-7A3328DA-000000F5.pf` and `Op-MSEDGE.EXE-BA103770-00000001.pf`. Both parse as
v30, both lack the §5a string, and **neither contains its own executable in its filename
list** — so no method resolves a path for them. They are the only 2 of 636 with no path from
any source, and they are not ordinary prefetch. See `porting-notes.md` §5.4.

## 6. Volume information array — at `VolumesInfoOffset`, `VolumeCount` entries

Entry size by version:

| Version | Entry size |
|---|---|
| 17 | 40 |
| 23 | 104 |
| 26 | 104 |
| 30/31 | **96** |

First 36 bytes are identical across all versions:

| Off | Size | Field |
|---|---|---|
| 0 | 4 | DeviceNameOffset (**rel. to `VolumesInfoOffset`**) |
| 4 | 4 | DeviceNameLength in UTF-16 chars (excl. NUL) |
| 8 | 8 | Volume creation time (FILETIME) |
| 16 | 4 | Volume serial number (uint32, rendered uppercase hex) |
| 20 | 4 | FileReferencesOffset (**rel. to `VolumesInfoOffset`**) |
| 24 | 4 | FileReferencesSize |
| 28 | 4 | DirectoryStringsOffset (**rel. to `VolumesInfoOffset`**) |
| 32 | 4 | NumberOfDirectoryStrings |
| 36 | … | unknown, pads out to the version's entry size |

Device name: read `DeviceNameLength * 2` bytes at `VolumesInfoOffset + DeviceNameOffset`,
decode UTF-16LE. Two forms occur:

- `\DEVICE\HARDDISKVOLUME2`, `\DEVICE\HARDDISKVOLUMESHADOWCOPY7` — older systems / VSS
- `\VOLUME{01d8559f7371205e-b0737add}` — **the name encodes the other two fields**

### 6.0a The `\VOLUME{...}` name is a self-check (verified)

`\VOLUME{<16 hex>-<8 hex>}` decomposes as:

| Part | Is |
|---|---|
| the 16 hex digits | the volume creation FILETIME, big-endian |
| the 8 hex digits | the volume serial number |

Both duplicate values already parsed from the volume entry at +8 and +16. Verified on all
four distinct volumes in `$PECMD_CSV` (221 real
Win10 records) — creation time and serial matched to the second in every case — and on the
two Win10 ground-truth files in `TestVersion30.cs`. Example:

```
\VOLUME{01d8559f7371205e-b0737add}
        └── 0x01d8559f7371205e as FILETIME = 2022-04-21 16:47:13 == Volume0Created
                             └── b0737add  = B0737ADD            == Volume0Serial
```

Useful two ways: as a **consistency check** (a mismatch means tampering or a mis-parse — no
benign cause is known), and as a **recovery path** when the volume entry is truncated but the
device-name string survives, which is the common shape for a carved fragment.

The `\DEVICE\HARDDISKVOLUMEn` form carries no embedded data; the check simply doesn't apply.

Serial number rendering has the same leading-zero-trim issue as the header hash — use `X8`.

### 6.1 File references sub-block — at `VolumesInfoOffset + FileReferencesOffset`

| Off | Size | Field |
|---|---|---|
| 0 | 4 | version / unknown |
| 4 | 4 | NumberOfFileReferences |
| 8 | 8×N | array of MFT references (§7) |

Read until either `NumberOfFileReferences` entries are collected or the block is exhausted
— the block can be padded, so both bounds are needed.

### 6.2 Directory strings — at `VolumesInfoOffset + DirectoryStringsOffset`

Repeat `NumberOfDirectoryStrings` times:

```
uint16 charCount          # number of UTF-16 chars, NOT counting the NUL
bytes  charCount*2 + 2    # UTF-16LE string including its terminating NUL
```

Trim the trailing NUL after decoding. Entries are consecutive with no padding — **verified**:
walking exactly `charCount*2 + 2` bytes per entry lands within the file and yields the
asserted directory strings and counts on all 48 uncompressed corpus files.

Note v17 directory strings carry a trailing backslash
(`\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\`) where v23+ do not — don't normalize it away if
you compare across versions.

Upstream reads "from `dirStringsIndex` to end of file" into a scratch buffer and walks it,
which is why a malformed count can walk off the end and trip the catch-all — a rewrite
should bound the walk by the remaining buffer explicitly.

---

## 7. MFT file reference — 8 bytes

| Off | Size | Field |
|---|---|---|
| 0 | 6 | MFT entry number (48-bit) |
| 6 | 2 | MFT sequence number |

A sequence number of 0 means "unset" and is reported as null.

**The upstream arithmetic is suspect**: it reads `lo = uint32 @0`, `hi = uint16 @4`, and
computes `entry = lo + hi * 16777216` (`hi << 24`), where a 48-bit little-endian field wants
`hi << 32`. A rewrite should just read six bytes little-endian.

Reading six bytes little-endian reproduces every MFT entry/sequence number the upstream tests
assert (v17 entry 250 seq 1; v23 entry 352; v26 entries 0 / 18972 / 27324 / 29316).
**Caveat: every asserted value is below 2²⁴, so the corpus cannot distinguish `<< 24` from
`<< 32`** — the six-byte read is right on first principles and agrees everywhere it can be
checked, but confirm against libscca if you ever see an entry number above 2³².

---

## 8. Timestamps

All timestamps are Windows FILETIME (100-ns ticks since 1601-01-01 UTC), read as int64 and
converted to UTC. Two consequences visible in output:

- A zero/unset FILETIME converts to year 1601. Callers treat "year == 1601" as "empty"
  (PECmd blanks the volume creation column on that test) and the parser skips run-time slots
  where the raw value is ≤ 0.
- `DateTimeOffset.FromFileTime` in .NET interprets the value as **local** time and then
  `.ToUniversalTime()` normalizes it — net effect is correct UTC, but a rewrite should just
  do the epoch math directly in UTC and avoid the local-timezone round trip entirely.

---

## 9. Error posture

The upstream parser wraps the entire per-version parse in one `try/catch`. On any
exception it sets `ParsingError = true` and keeps whatever was populated before the throw,
so a partially parsed file still yields a record (PECmd prints "PARTIAL OUTPUT SHOWN
BELOW"). The only hard failures that propagate are:

- signature != `SCCA` → `"Invalid signature! Should be 'SCCA'"`
- unrecognized version → `"Unknown version '<hex>'"`

A rewrite should keep the "partial record + error flag" behavior — for triage, a half-parsed
prefetch is still evidence — but should record *which* stage failed rather than a single
boolean.
