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

## What is inside

The decompressed payload is a **boot file-access trace**, and it is rich:

```
offset 0   u32   magic  0x45634678  ('xFcE')
...        'DMIO:ID:' followed by a 16-byte disk GUID
```

`Trace2.fx` alone yields **11,620 UTF-16LE strings**, including:

- Device paths in prefetch's own notation — `Device`, `HarddiskVolume1`, `HarddiskVolume3`
- Full file paths — `Windows\System32\DriverStore\FileRepository\i3chost.inf_amd64_...`
- UWP package identity —
  `Microsoft.LanguageExperiencePacken-GB_26100.135.253.0_neutral__8wekyb3d8bbwe`
- EFI boot artifacts — `EFI\Microsoft\Boot\bootmgfw.efi.mui`
- Even `.pf` filenames — `AM_DELTA_PATCH_1.455.104.0.EX-6F772A54.pf`

Because the paths use the same `\Device\HarddiskVolumeN\` notation as `.pf` records, the
existing volume-correlation logic applies unchanged.

## Why this matters for the tool

Combined with the mtimes already recorded (five traces spanning 2026-07-18 to 2026-08-12,
`Trace6.fx` and `rblayout.xin` sharing an mtime to the second), this is a **per-boot record of
which files the system touched during boot** — evidence that exists nowhere in `.pf` and that
PECmd does not read.

Standing caveat, unchanged: this is still an **access** artifact, not an execution record, and
the entries carry no per-file timestamps. The trace's own mtime dates the boot; it does not
date any individual file access within it.

## Still open

- The 4-byte inter-chunk field. High-entropy, no relation to length or count; consistent with
  a checksum but unconfirmed. It is not needed to decode the file.
- The record structure *inside* the decompressed payload. The strings are extractable now, but
  the surrounding binary layout (`xFcE` header, record framing) is not yet mapped, so file
  paths can be recovered while per-record metadata cannot.
