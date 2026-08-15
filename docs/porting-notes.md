# Porting notes — constraints, bugs, and what the language choice hinges on

Read this before `prefetch-format.md` is turned into code. It separates *the format* from
*this implementation's accidents*, and lists the Windows couplings that decide what
languages are actually viable.

---

## 1. The load-bearing constraint: XPRESS Huffman decompression

Every Windows 10/11 prefetch file is a `MAM\x04` container. Upstream decompresses it with a
single P/Invoke:

```
ntdll!RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF /* 4 */, …)
```

Consequences that ripple through the whole tool:

- **PECmd refuses to run on non-Windows at all** (`Program.cs:259-266`) — not because
  anything else is Windows-only in the parse path, but because of this one call.
- The README's "if you are running less than Windows 8 you cannot process Windows 10
  prefetch" is the same constraint: `RtlDecompressBufferEx` with XPRESS_HUFF appeared in
  Windows 8. On Win7 the call fails and PECmd surfaces a specially-worded error.
- **`Xpress2.Decompress` ignores the ntdll return code** and returns the output buffer
  regardless. A failed decompress therefore yields a buffer of zeros, which then fails the
  `SCCA` check — so the symptom an analyst sees is *"Invalid signature!"*, never
  *"decompression failed"*. Any rewrite must check the status and say what actually broke.

**For a rewrite:** if the tool should run anywhere except Windows (analyst workstations are
frequently Linux/macOS, and images are usually processed offline), it needs a **pure
XPRESS Huffman decompressor**. Do not reconstruct the bit format from memory. Authoritative
references:

- Microsoft **[MS-XCA]**, "Xpress Compression Algorithm" — sections on Huffman variant.
- **libscca** (Joachim Metz) — pure-C implementation plus the best public prefetch format
  documentation; also the cross-check for every ambiguity flagged in `prefetch-format.md`.

**Resolved 2026-08-12:** `../reference/xpress.py` is that pure implementation, written from
the [MS-XCA] decompression pseudocode. It decompresses all 642 MAM files in ~20 s with no
dependencies, so the cross-platform constraint is no longer a risk — see §6 for the three
non-obvious bugs a port must avoid.

---

## 2. Bugs in the reference implementation — do not port these

### 2.1 Win10/11 file metrics are all identical (real, confirmed)

`Version30or31.cs:101-107`:

```csharp
var fileMetricsTempBuffer = new byte[32];
while (tempIndex < fileMetricsBytes.Length)
{
    Buffer.BlockCopy(fileMetricsBytes, tempIndex, fileMetricsTempBuffer, 0, 32);
    FileMetrics.Add(new FileMetric(fileMetricsBytes, false));   // <-- wrong buffer
    tempIndex += 32;
}
```

It copies each 32-byte entry into `fileMetricsTempBuffer` and then constructs the
`FileMetric` from `fileMetricsBytes` — the *whole* array, always read at offset 0. So every
Win10/11 metric is a copy of entry 0, including its MFT reference.

`Version17.cs:76`, `Version23.cs:82`, and `Version26.cs:93` all correctly pass
`fileMetricsTempBuffer`. The bug survived because PECmd never surfaces `FileMetrics` in any
output — no CSV column, no console line. It is invisible until you expose the field, which a
rewrite should, because per-file MFT entry numbers are the most useful thing in the
structure.

### 2.2 Hex formatting drops leading zeros

`Header.cs:49` — `BitConverter.ToInt32(...).ToString("X")` for the path hash, and the same
pattern for the volume serial in all four version classes. A hash of `0x0B3BA786` renders as
7 characters and will not match the `-XXXXXXXX` in the filename. Use `X8`.

### 2.3 48-bit MFT entry number combined with `<< 24`

`MFTInformation.cs:31`: `entryIndex2 *= 16777216` where the field layout (6-byte entry + 
2-byte sequence) implies `<< 32` for the high half. Unreachable unless an entry number
exceeds 2³², but wrong. Read the six bytes little-endian and be done.

### 2.4 Executable name assumes a NUL exists

`Header.cs:45`: `tempName.Substring(0, tempName.IndexOf('\0'))` throws if the 60-byte name
field has no terminator — exactly the shape of a hand-crafted or truncated file. It's caught
by the outer handler and reported as a parse error, but the message is unhelpful.

### 2.5 Volume-2+ data is dropped from the CSV, and directory lists run together

See `pecmd-behavior.md` §4.1. Both are output-layer bugs, not parser bugs.

### 2.6 Executable path resolution — three defects in five lines

`Program.cs:867-874`, the *only* place PECmd resolves the executable's full path (used for the
timeline CSV's `ExecutableName`):

```csharp
var exePath = processedFile.Filenames.FirstOrDefault(
                  y => y.EndsWith(processedFile.Header.ExecutableFilename));

if (exePath == null)
    exePath = processedFile.Header.ExecutableFilename;
```

**(a) `EndsWith` is a substring test, not a path-component test.** `Header.ExecutableFilename`
is a bare name like `NOTEPAD.EXE`, and
`"\...\SYSTEM32\XNOTEPAD.EXE".EndsWith("NOTEPAD.EXE")` is `true`. Any filename whose last
component *ends with* the executable's name matches — `SVCHOST.EXE` matches against
`HOST.EXE`, `MALWARE_CMD.EXE` against `CMD.EXE`. Fix: split on `\`, compare the final segment
for equality, case-insensitively.

**(b) `FirstOrDefault` silently discards ambiguity.** When several entries share the basename
— genuinely common: `\WINDOWS\SYSTEM32\NOTEPAD.EXE` and `\WINDOWS\NOTEPAD.EXE`, or a portable
binary present in two directories — the first hit in file-list order wins with no indication a
choice was made. Fix: emit all matches with an ambiguity flag, optionally narrowed by forward
hashing (`new-tool-design.md` §4.1a).

**(c) The fallback is silent and type-confusing.** When nothing matches, the bare name is
written into a column that otherwise holds full device paths, so a consumer cannot distinguish
"resolved to a path" from "never found one". Fix: keep them in separate fields, or flag it.

### 2.7 The main CSV never resolves the path at all

Only the timeline writer runs the lookup above. The main CSV's `ExecutableName`
(`Program.cs:1096`) is assigned straight from `pf.Header.ExecutableFilename`, so the two
outputs disagree for the same file:

| Output | `ExecutableName` |
|---|---|
| `..._PECmd_Output.csv` | `7ZFM.EXE` |
| `..._PECmd_Output_Timeline.csv` | `\VOLUME{01d8559f7371205e-b0737add}\PROGRAM FILES\7-ZIP\7ZFM.EXE` |

(Verified against `<pecmd checkout>/20260703230020_PECmd_Output*.csv`.) The path is
available to both writers — the main CSV just doesn't ask for it. This is the "no full exe
path" complaint, and it is a one-call fix: resolve once, use everywhere.

### 2.8 Doc/code mismatch on `--dedupe`

README says default TRUE, `Program.cs:169` sets FALSE.

---

### 2.9 The hash is printed unpadded, so it disagrees with the filename

**Confirmed against real output**, not read from source: `APPLICATIONFRAMEHOST.EXE-0CF44CC4.pf`
is reported in the CSV as `CF44CC4` — seven characters. PECmd formats the hash with `X`
instead of `X8`, so every hash beginning with a zero loses it.

**13 of 160** overlapping corpus files are affected. The defect is self-evident because the
`.pf` filename carries the correct 8-character form, so PECmd's own output contradicts the
name of the file it just parsed.

Consequences for anyone joining on this column: a naive join between PECmd's CSV and a
filename-derived hash silently drops those 13 rows, and sorting by hash puts them in the wrong
place. `prefetch_core` emits `%08X`. `reference/diff_against_pecmd.py` pins the count at 13 so
the divergence stays visible rather than being quietly accepted.

## 3. Other Windows-only surface (beyond decompression)

| Dependency | Used for | Portable? |
|---|---|---|
| `ntdll!RtlDecompressBufferEx` | Win10/11 MAM decompression | No — needs a pure implementation |
| **AlphaFS** (`AlphaFS.New` 2.3.0) | ADS enumeration, long paths, resilient recursive enumeration | Windows/NTFS only; ADS is an NTFS concept. On other platforms you read streams out of a mounted image / raw NTFS parser instead |
| VSS mount (`ERZHelpers.Helper.MountVss`) | WMI `Win32_ShadowCopy` + `vssadmin` fallback, then `CreateSymbolicLink` into `C:\___vssMount` | No — live-Windows only |
| `WindowsIdentity` / `WindowsPrincipal` | admin check | Trivially replaced |
| Costura.Fody | single-file exe packing | Replaced by whatever the new toolchain does |

**Important asymmetry to understand before repeating it:** the net472 build and the net9
build of PECmd do *not* behave the same on `-d`. The net472 inclusion filter skips zero-byte
files, warns on FTK Imager `[ROOT]` paths, and parses `.pf` alternate data streams; the net9
path (`Directory.EnumerateFileSystemEntries(d, "*.pf", …)`) does none of that, because
AlphaFS's enumeration API is net472-only. That gap is what commit `c4dfc7f` fixed for
`--ads` and is the reason `--ads` had to be implemented framework-independently. A rewrite in
a single-target language avoids the whole class of problem — worth counting as a point in
favor of leaving .NET.

---

## 4. Feature gaps in the reference — candidates for the new tool

- **The filename hash is never recomputed.** PECmd reads the hash out of the header and
  prints it; it never derives it from the executable path. Recomputing it (the XP, Vista/7,
  and Win10 SCCA hash variants — documented in libscca, *not* derivable from this codebase)
  would let the tool flag renamed, planted, or mismatched prefetch files. This is a genuinely
  new capability, not a port.
- **Per-file MFT references are parsed but never output** (and broken on Win10/11, §2.1).
- **Trace chains are parsed and never used at all** — `TotalBlockLoadCount` per entry.
  Low forensic value, but free once parsed.
- **`FilenameStringOffset`/`Size` in the metrics are ignored** in favor of splitting the
  whole string blob; using them properly gives an exact metric↔name pairing.
- **No parallelism.** A Prefetch directory is ~128 (XP-Win8) to 1024 (Win10+) files of
  independent work; the current loop is serial with global mutable state.
- **No `--ads` upstream** — that's this fork's contribution.

---

## 5. Acceptance corpus and validation strategy

`../reference/pf-corpus/` is the upstream test corpus, vendored so it survives this session:

| Directory | Files | Version |
|---|---|---|
| `XPPro/` | 7 | 17 |
| `Win2k3/` | 5 | 17 |
| `Vista/` | 4 | 23 |
| `Win7/` | 9 | 23 |
| `Win8x/` | 12 | 26 |
| `Win2012/` | 5 | 26 |
| `Win2012R2/` | 6 | 26 |
| `Win10/` | 6 | 30 (MAM compressed) |
| `Bad/` | 1 | `notAPrefetch.pf` — must throw "Invalid signature! Should be 'SCCA'" |

55 `.pf` files total: 54 real (48 uncompressed v17/23/26 + 6 MAM-compressed v30) and 1
deliberately invalid.

### 5.1 Second corpus — real Win10 and Win11 Prefetch folders (added 2026-08-12)

Supplied by the user, **not vendored** (636 `.pf` plus ~14 MB of ReadyBoot traces):

- `$PREFETCH_CORPUS_WIN10` — 184 `.pf`
- `$PREFETCH_CORPUS_WIN11` — 452 `.pf`

These are complete folders, not just `.pf` files, so they finally cover the non-`.pf` tiers.
**Every one of the 636 `.pf` files is MAM-compressed** — so none of them can be validated
until the XPRESS Huffman decoder exists, and then all of them can be, at once. Declared
decompressed sizes range 5 KB–1 MB (ratios 3.1×–9.2×), which gives the decoder a real
workout beyond the six small corpus files.

**What's in the folders beyond `.pf`:**

| Artifact | Win10 | Win11 | Header | Notes |
|---|---|---|---|---|
| `Layout.ini` | 7 KB | 584 KB | `[.O.p.t.i.m.a.l.` | UTF-16LE text. Tier 2, trivially parseable |
| `PfPre_<hex>.mkd` | 196620 B | 196620 B | `05 00 00 00` | **Identical size in both** — fixed-length structure. Undocumented |
| `ResPriStaticDb.ebd` / `ResPriHMStaticDb.ebd` | 50 KB | 20 KB | **`MAM\x84`** | see 5.2 |
| `dynrespri.7db`, `cadrespri.7db` | ✓ | ✓ | `03 00 00 00 … 50 00 00 00 13 00 00 00` | Consistent header shape across both hosts and both files |
| `ReadyBoot/Trace2-6.fx` | — | 5 files, 2.5–3.2 MB | **`PfB\xe3`** | Not ETL as assumed — see 5.3 |
| `ReadyBoot/rblayout.xin` | — | 425 KB | `PfB\xe3` | Same container as the traces |

No `Ag*.db` SuperFetch files in either folder — consistent with SysMain being disabled or
those files living elsewhere on modern builds. **Tier 3 may be moot on current Windows**;
confirm before spending effort there.

### 5.2 `MAM\x84` — the bit-7 variant, now confirmed real

`prefetch-format.md` §1.1 flagged a libscca-documented variant where bit 7 of byte 3 signals
an extra field, and noted it was absent from the original corpus. **Both `ResPri*.ebd` files
use it** (`4d 41 4d 84`), and the header shape differs from ordinary `MAM\x04`:

```
ResPriStaticDb.ebd     4d 41 4d 84 | bc f9 00 00 | f5 1c e4 69 | 74 87 88 98 ...
                       MAM  0x84     63932         0x69E41CF5    compressed data?
ResPriHMStaticDb.ebd   4d 41 4d 84 | 0c 56 02 00 | 0b f7 e8 93 | 64 77 87 88 ...
                       MAM  0x84     153100        0x93E8F70B
```

The uint32 at +4 is plausibly the uncompressed size (3.1× and 3.0× the file size — matching
the ratio range of the known-good `.pf` files). The uint32 at +8 is high-entropy and does
*not* look like a size; on the `MAM\x04` layout that position is already compressed data.
**Working hypothesis:** bit 7 inserts a 4-byte field (checksum, per libscca's chunk-size
note) and compressed data starts at +12 rather than +8. **Unverified — test it the moment the
decoder works.** If it holds, the container parser needs the branch.

### 5.3 ReadyBoot is `PfB\xe3`, not ETL — the design doc was wrong

`new-tool-design.md` §6 Tier 4 asserted `ReadyBoot.etl` is an ETW/ETL trace and recommended
shelling out to `tracerpt`. **The real folder contains no `.etl` at all** — it has
`Trace2.fx`–`Trace6.fx` and `rblayout.xin`, all six starting `50 66 42 e3` (`PfB` + 0xE3),
an undocumented container that is *not* the ETL signature. The Tier 4 plan does not apply as
written. Treat these as Tier 5 (identify, hash, record, carve) until someone reverses the
format.

### 5.4 Coverage still missing

- ~~No version-31 sample.~~ **Resolved: version 31 confirmed, 452 files** in the Win11 folder
  (Win10 folder is 171× v30). Structurally identical to modern v30 — 212-byte file-info
  section, 32-byte metrics, 8-byte trace chains. v31 is an OS label, not a format change.
- **The ADS carriers are present; their streams are not.** `HOST.TXT` and `BLAH.TXT` in the
  Win10 folder are the `--ads` test carriers. **A 0-byte primary stream is the correct,
  expected shape** — that is exactly what the technique produces (see below); the prefetch
  lives in a named stream, which a normal listing never shows. What's missing here is only the
  *stream data*, lost in transit to Linux: ext4 has no ADS, and `PF.zip` (206 bytes, both
  entries 0-length with CRC `00000000`) stored only the primary streams. So the carriers
  demonstrate the shape but **cannot exercise the parser**. Testing the ADS path needs a
  Windows host or a raw NTFS image.

### 5.5 The ADS technique, as documented

Per [thelocalh0st.com](https://thelocalh0st.com/posts/guest-in-prefetch-directory/) — the
write-up behind the `--ads` feature:

Executing `C:\Users\x\Pictures\Screenshot.png:malware.exe` makes Windows write the prefetch
record to a path where the colon is an NTFS stream delimiter:

```
C:\Windows\Prefetch\Screenshot.png:malware.exe-3F2A9C10.pf
                    └─ carrier, 0 bytes    └─ named stream holding the real prefetch
```

Three properties a parser must handle, all confirmed by the local carriers:

1. **The carrier is a 0-byte, non-`.pf`, non-executable file** (`.png`, `.txt`, `.jpg`) sitting
   in the Prefetch folder. Its presence there is itself anomalous — hence flag D8
   (`CarrierNotPrefetch`).
2. **The prefetch name is a stream name, not a file name.** A `*.pf` glob cannot match it;
   only stream enumeration finds it.
3. **A 0-byte primary stream must not be treated as a failure** — `Program.cs:364` already
   skips the empty primary and scans streams instead, and the rewrite must keep that.

Detection reference: `Get-Item -Path <file> -Stream * | Where-Object Stream -ne ':$DATA'`.
The blog notes both PECmd and WinPrefetchView miss these by design, which is what `--ads`
addresses.

---

## 6. The XPRESS Huffman decoder — **working** (2026-08-12)

`../reference/xpress.py`, written from the [MS-XCA LZ77+Huffman decompression
pseudocode](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b).
Decompresses **all 642 MAM files with zero failures** (6 corpus + 184 Win10 + 452 Win11) in
~20 s. Pure Python, no dependencies — this is the component that makes cross-platform viable.

Three bugs cost real time; a reimplementation in another language will hit the same ones.

**6.1 — Decode match LENGTH before match OFFSET.** The length's extra bytes are read from the
same input pointer the 32-bit bit register refills from, so doing the offset first consumes
the wrong bytes and silently desynchronizes the stream. The spec's ordering is deliberate.

**6.2 — Symbol 256 is only EOF when the expected output is already complete.** Otherwise it
falls straight through to the match path, where `256 - 256 = 0` decodes as length nibble 0,
offset-bit-length 0 → a **3-byte match at offset 1**. Treating it as an unconditional
end-of-stream (or skipping it) loses 3 bytes and desynchronizes everything after. This is what
broke the 20 multi-block files: they hit an inline 256 partway through and the block ended
early, so the next block's Huffman table was read from the wrong offset.

**6.3 — The long-length escape is a byte equal to 255, and `+15` applies on both paths:**

```
if length_nibble == 15:
    length = read_byte()
    if length == 255:
        length = read_u16()          # if 0, a u32 follows (encoder emits it; the
        if length < 15: error        #  spec's decoder pseudocode omits the case)
        length -= 15
    length += 15                     # <- applies to BOTH the short and escaped path
length += 3
```

**Also required:** the match copy must be byte-at-a-time — length may exceed offset (`aaaaaa`
encodes as literal `a` + match offset 1 length 5), so a `memcpy` breaks it. And the Huffman
table is 2^15 entries where a symbol of bit length X occupies 2^(15−X) of them; building it
that way makes it **self-validating**, since a complete code must fill exactly 32768 entries.

- **`Op-*.pf` files** (Win10 only, 2 of them): `Op-EXPLORER.EXE-7A3328DA-000000F5.pf`,
  `Op-MSEDGE.EXE-BA103770-00000001.pf`. Normal `MAM\x04` headers, small (1.3 KB / 3.9 KB),
  and each sits alongside a conventional `.pf` with the *same* name and hash. The `Op-` prefix
  and trailing 8-hex counter are undocumented here. **A tool that globs `*.pf` picks these up
  and may mis-report them as ordinary prefetch** — decide deliberately how to label them.

`../reference/TestVersion17.cs`, `TestVersion23.cs`, `TestVersion26.cs`, `TestVersion30.cs`
and `TestPrefetchMain.cs` are the upstream NUnit tests, vendored alongside. **These are the
new tool's acceptance criteria** — they assert concrete ground truth per file (executable
name, hash, file size, run count, exact run times, volume device names, serial numbers,
volume creation times, directory counts and specific directory strings, filename counts and
specific filenames, file-reference counts, and specific MFT entry/sequence numbers).

Example, from `TestVersion30.cs` for `Win10/CHROME.EXE-B3BA7868.pf`: hash `B3BA7868`, size
116042, run count 20, 8 run times, 1 volume `\VOLUME{01d1217a9c4c6779-8c9f49ec}` serial
`8C9F49EC`, 23 directories, 282 filenames, 284 file references, `FileReferences[5]` = MFT
entry 55125 seq 1.

Two invariants asserted across the whole corpus (`TestPrefetchMain.SignatureShouldBeSCCA`):

- `Filenames.Count == FileMetricsCount`
- `VolumeCount == VolumeInformation.Count`

**Already done:** `../reference/validate_spec.py` implements steps 1–2 below in Python,
parsing from `prefetch-format.md` alone. It passes: 7 ground-truth files and 48 uncompressed
corpus files, invariants included. It is a throwaway spec check, **not** a starting point for
the tool — but it is the thing to re-run after editing the format spec, and the model for the
new tool's test suite.

Suggested validation ladder for the rewrite:

1. Port the assertions above verbatim into the new language's test framework.
2. Add the two invariants as property checks over the whole corpus.
3. Diff the new tool's CSV against
   `$PECMD_CSV` (2.5 MB, a real machine's Prefetch
   directory, generated by this very build) — column-for-column, expecting differences
   *only* where §2 says the reference is wrong. That's a much stronger test than the unit
   tests because it covers hundreds of real Win10 files.
4. Fuzz/robustness: truncated files, no-NUL executable names, absurd counts and offsets —
   the reference relies on one catch-all, which a rewrite should replace with bounds checks
   that name the failing stage.

Note the corpus contains **no** version 31 file and no ADS-hosted sample; both need to be
created by hand (or on a test VM) to cover those paths.
