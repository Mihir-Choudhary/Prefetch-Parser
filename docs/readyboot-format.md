# The ReadyBoot `PfB` container — decoded

**Status: SOLVED on 2026-08-15.** Previously recorded in `prefetch-artifacts.md` §4 as
"structure identified, payload NOT decoded". That section is now superseded by this file.

All six Win11 `ReadyBoot/` files now decompress to **exactly** their declared uncompressed
size. This is not a heuristic that mostly works — the length check is exact on 6 of 6 files,
and the chunk chain is self-validating at every link.

## How it was cracked

The earlier dead end was caused by attacking the file as a *single* compressed stream. Every
whole-stream hypothesis failed and was ruled out for the right reason:

| Hypothesis | Result |
|---|---|
| XPRESS Huffman, whole stream at +8/+12/+16 | table overflow / `incomplete Huffman code: 31210 of 32768` |
| LZNT1 | no chunk header with signature 3 at any offset |
| zlib / raw deflate / gzip | rejected at every offset |
| XPRESS plain (LZ77, no Huffman) | decodes ~17 literals, then a match offset points before the start of output |

The breakthrough came from taking one of those failures seriously instead of discarding it.
`incomplete Huffman code: 31210 of 32768` is a **95%-complete** canonical Huffman table.
Random bytes miss Kraft equality by orders of magnitude; landing that close means the decoder
was reading a real table and losing sync later.

So rather than guessing offsets, every position in the file was tested for Kraft equality —
a 256-byte window is a valid canonical XPRESS Huffman table iff
`sum(2**(15-len)) == 32768` over its 512 nibble-encoded code lengths:

| File | Complete tables found | Median gap |
|---|---|---|
| `Trace2.fx` | 169 | 20,448 |
| `Trace3.fx` | 200 | 19,864 |
| `Trace4.fx` | 187 | 19,363 |
| `Trace5.fx` | 164 | 20,549 |
| `Trace6.fx` | 187 | 19,686 |
| `rblayout.xin` | 31 | 16,318 |

The **first table sits at offset 12** — exactly the payload start — and the rest recur every
~20 KB. `Trace2.fx` declares 7,795,764 uncompressed bytes; ÷ 65536 = 118.95 chunks. The file
is chunked XPRESS Huffman: one 256-byte table per 64 KB of output.

## The container

```
offset 0   u32   magic            0xE3426650  ('PfB\xe3')
offset 4   u32   uncompressed size    total across all chunks
offset 8   u32   length of chunk 0's compressed data
offset 12        chunk 0 compressed data
                 u32  unknown (high-entropy; consistent with a checksum)
                 u32  length of chunk 1's compressed data
                 chunk 1 compressed data
                 u32  unknown
                 u32  length of chunk 2
                 ...
```

Each chunk is standard XPRESS Huffman and decompresses to exactly 65,536 bytes (the final
chunk to the remainder). **LZ77 history resets at every chunk** — no match in any chunk was
observed reaching back past its own start, verified explicitly during analysis.

### The header field at offset 8 was mislabelled

`prefetch-artifacts.md` recorded offset 8 as `count  18,693 - 21,591`. It is **not a count**.
It is the compressed length of the first chunk, which is why its range is exactly the range of
chunk lengths. The proof is arithmetic: for `Trace2.fx`, `12 + 19,934 = 19,946`, plus the
8-byte trailer = **19,954**, which is precisely where the independent Kraft scan located the
second table.

The chain then validates itself all the way down, each trailer predicting the next table:

| Chunk | Table at | Trailer's next-length | Predicted next table | Scan found |
|---|---|---|---|---|
| 0 | 12 | 19,713 | 19,954 | 19,954 |
| 1 | 19,954 | 20,166 | 39,675 | 39,675 |
| 2 | 39,675 | 21,132 | 59,849 | 59,849 |
| 3 | 59,849 | 20,928 | 80,989 | 80,989 |
| 4 | 80,989 | 20,562 | 101,925 | 101,925 |

Note the last row. The Kraft scan reported complete tables at **both** 101,924 and 101,925 —
an ambiguity a scan alone cannot resolve, and the one that desynchronised an earlier attempt.
The trailer chain picks 101,925, and the following chunk then decodes cleanly. The two methods
are independent, which is what makes the result trustworthy rather than merely fitted.

## What is inside — the name table

The decompressed payload holds a **directory tree**, stored as a table of back-to-back records:

```
u32  parent's offset within the table, or 0xFFFFFFFF for a root
u16  character count
     that many UTF-16LE characters
```

Two different inner formats travel inside the same `PfB` container, and they put the table in
**opposite** places, so no single rule or scan finds both:

| Inner magic | Files | Name table | Table size from |
|---|---|---|---|
| `xFcE` (`0x45634678`) | `Trace2-6.fx` | **last** in the payload, ending exactly at EOF | u32 at offset 16 |
| `iLdR` (`0x52644C69`) | `rblayout.xin` | **first**, starting at offset 16 | u32 at offset 8 |

The `xFcE` header also carries `DMIO:ID:` followed by a 16-byte disk GUID, length-prefixed at
offset 20.

### Finding the table, and why the first attempt failed

An early attempt walked records from an arbitrary point in the middle of the table and then
brute-forced the origin. It resolved **23%** of links and reconstructed obvious nonsense
(`\Branding\Branding\Branding…`), which looked like proof that the linkage was undecodable.

It was not. Starting mid-table means every link pointing *backwards* to an earlier record has
nothing to resolve against, so a correct format produces a low score anyway. The fix was to
derive the origin arithmetically instead of fitting it: children of `HarddiskVolume3` link to
274, so that record sits at table offset 274, so the table begins 274 bytes earlier. That
address lands exactly on a record whose parent is `0xFFFFFFFF` and whose name is `Device` — the
root. The derived table size then matched the header field exactly, which is what turned a
guess into a rule.

**Result: every link resolves, on every file.**

| File | Records | Paths | Broken links |
|---|---|---|---|
| `Trace2.fx` | 11,733 | 11,733 | 0 |
| `Trace3.fx` | 11,607 | 11,607 | 0 |
| `Trace4.fx` | 10,233 | 10,233 | 0 |
| `Trace5.fx` | 8,927 | 8,927 | 0 |
| `Trace6.fx` | 11,605 | 11,605 | 0 |
| `rblayout.xin` | 20,179 | 20,179 | 0 |

### What comes out

Whole paths, in the same `\Device\HarddiskVolumeN\` notation `.pf` uses, so the existing volume
correlation applies unchanged:

```
\Device\HarddiskVolume1\EFI\Microsoft\Boot\ko-KR\bootmgfw.efi.mui
\Device\HarddiskVolume3\Windows\System32\ntoskrnl.exe
\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
\Device\HarddiskVolume3\Windows\System32\DriverStore\FileRepository\i3chost.inf_amd64_…\i3chost.sys
\Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.LanguageExperiencePacken-GB_…
\Device\HarddiskVolume3\$Mft            (rblayout.xin)
\Device\HarddiskVolume3\System Volume Information\FVE2.{…}   (BitLocker metadata)
```

Reconstruction is cycle-safe: a crafted table can point a record at itself or form a loop, so
visited offsets are tracked per path and depth is capped at 128.

## Why this matters for the tool

Combined with the mtimes already recorded (five traces spanning 2026-07-18 to 2026-08-12,
`Trace6.fx` and `rblayout.xin` sharing an mtime to the second), this is a **per-boot record of
which files the system touched during boot** — evidence that exists nowhere in `.pf` and that
PECmd does not read.

It is still an **access** artifact, not an execution record: a path here means the boot read
that file, never that a program ran.

The "no per-entry timestamps" caveat recorded earlier is **wrong** and is corrected here. Every
I/O event carries a monotonic tick, so events are ordered and their relative timing is known.
What is not known is the tick's *unit*, so the tool reports raw ticks and converts nothing. The
trace's mtime dates the boot in absolute terms; the ticks position events within it.

## The I/O trace — the rest of the payload

Everything in an `xFcE` payload before the name table (about 7 MB of `Trace2.fx`'s 7.8 MB) is
the trace itself: **one 40-byte record per read the system performed while booting.**

The record size was found by autocorrelation — stride 40 scores 0.79 against a 0.37 baseline,
with clean harmonics at 80 and 120, uniformly across the whole region.

```
u32  flags                    7 distinct values
u32  flags                    almost always 0
u64  byte offset of the read  within the file; a volume offset when unattributed
u32  name-table offset  <-- WHICH FILE
u32  unidentified             constant 402 in every record seen
u32  I/O size in bytes        4096, 65536, 1048576, …
u32  timestamp                monotonic tick since boot
u32  sequence within block
u32  unidentified
```

Records are grouped into **blocks of 1024** followed by an 8-byte trailer. The trailer looks
like a live count and is not one — it reads `0` on a block holding 63 real records — so the
authority is the pair of counts in the header at offsets 8 and 12. They are two consecutive
sections in the same block stream, and they sum **exactly** to the number of non-empty records:
`105,535 + 67,874 = 173,409` on `Trace2.fx`. Section 1 ends mid-block (block 103, record 63),
its block is zero-filled from there, and section 2 begins at the next block.

Identifying the file field took a phase correction. Read at the wrong alignment, every column
scores 22–27% against the name table — high enough to look meaningful, uniform enough to be
meaningless. Aligned correctly, one column is unambiguous:

| Field | Valid name-table offsets | Distinct values |
|---|---|---|
| f2 | 0.0% | 81,638 |
| **f4** | **100.0%** | **4,464** |
| f7 | 0.0% | 102,032 |
| f9 | 15.2% | 4,060 |

**Every event in every trace resolves to a named file** — verified as a test assertion, not a
spot check.

### What it yields

| File | I/O events | Bytes read | Distinct files |
|---|---|---|---|
| `Trace2.fx` | 173,409 | 8,161 MB | 4,485 |
| `Trace3.fx` | 228,938 | 8,903 MB | 7,152 |
| `Trace4.fx` | 220,729 | 7,544 MB | 6,249 |
| `Trace5.fx` | 176,095 | 8,039 MB | 4,462 |
| `Trace6.fx` | 222,611 | 6,971 MB | 5,544 |

Heaviest reads from one real boot:

```
  394 reads  784.4 MB  \Device\HarddiskVolume3\$WinREAgent\Scratch\update.wim
  384 reads  576.1 MB  \Device\HarddiskVolume3\Windows\System32\config\SOFTWARE
  150 reads  268.1 MB  …\Windows Defender\Definition Updates\{…}\mpasbase.vdm
    6 reads  153.9 MB  \Device\HarddiskVolume3\Windows\System32\DriverStore\...\amdkmdag.sys
```

14-22.5% of events resolve to `FI_UNKNOWN`, a real entry in the name table. These are reads
the tracer could not attribute to a file — dominated by early boot, before the filesystem is
available — and their offset field is a volume offset rather than a file offset. They are not
decode failures: they resolve perfectly, to a marker the tracer itself writes.

## Still open

- The 4-byte inter-chunk field. High entropy, no relation to length or count. **Unidentified** —
  a checksum is a guess, not a finding, and it is not needed to decode the file.
- Three record fields: the two flag words and the last dword. The flags take 7 and 2 distinct
  values; the constant `402` never varies in any record on any trace.
### The tick unit — inferred, not read

Nothing in the file states it, but two independent physical constraints agree on
**microseconds**:

| Trace | Span (ticks) | Bytes | As µs | As ms |
|---|---|---|---|---|
| `Trace2.fx` | 78,295,611 | 8,161 MB | 78.3 s @ 104 MB/s | 21.7 h @ 0.10 MB/s |
| `Trace3.fx` | 34,735,772 | 8,903 MB | 34.7 s @ 256 MB/s | 9.6 h @ 0.26 MB/s |
| `Trace4.fx` | 37,025,421 | 7,544 MB | 37.0 s @ 204 MB/s | 10.3 h @ 0.20 MB/s |
| `Trace5.fx` | 80,561,446 | 8,039 MB | 80.6 s @ 100 MB/s | 22.4 h @ 0.10 MB/s |
| `Trace6.fx` | 51,515,953 | 6,971 MB | 51.5 s @ 135 MB/s | 14.3 h @ 0.14 MB/s |

Microseconds give 35–81 second traces reading at 100–256 MB/s — an ordinary SSD boot.
Milliseconds would make every trace a 10–22 hour recording averaging 0.1 MB/s, which is not a
boot and not any disk. The tool still stores raw ticks; the derived figure is reported as
`io_seconds_assuming_us` so the inference is visible in the name rather than hidden in a
converted number.

What is **not** open any more: the compression, the chunk chain, the name table, the path tree,
and the I/O trace itself.
