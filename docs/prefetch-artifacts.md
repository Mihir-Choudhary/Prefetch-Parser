# Non-`.pf` artifacts in the Prefetch folder

Manual byte-level analysis, no parser involved. Everything here was measured against the two
real corpora on 2026-08-13 and is separated by OS, because the two differ substantially.

**Why this document exists:** PECmd parses `.pf` and nothing else. Every file below sits in
the same folder an analyst already collected, and several carry evidence `.pf` does not —
including real drive letters, user file paths, and which UWP package a host process ran.

## Folder census

| File | Win10 | Win11 | Notes |
|---|---|---|---|
| `*.pf` | 184 | 452 | v30 / v31 |
| `Layout.ini` | 7,128 B | 584,492 B | UTF-16 INI, **drive-letter paths** |
| `PfPre_<8hex>.mkd` | 196,620 B | 196,620 B | fixed-size ring buffer, identical size |
| `dynrespri.7db` | 277,952 B | 393,184 B | SuperFetch, uncompressed |
| `cadrespri.7db` | 5,644 B | — | **Win10 only** |
| `ResPriHMStaticDb.ebd` | 50,254 B | — | **Win10 only**, `MAM\x84` |
| `ResPriStaticDb.ebd` | — | 20,512 B | **Win11 only**, `MAM\x84` |
| `ReadyBoot/Trace2-6.fx` | — | 5 files, 2.5–3.2 MB | **Win11 only** |
| `ReadyBoot/rblayout.xin` | — | 424,963 B | **Win11 only** |
| `BLAH.TXT`, `HOST.TXT`, `PF.zip` | present | — | analyst's own ADS test artifacts, not OS files |

The Win10 folder has **no `ReadyBoot` subdirectory at all**. A tool must not treat its absence
as an error, and must recurse — the ReadyBoot files are one level down, so a flat `*.pf` glob
misses the whole subtree.

---

## 1. `Layout.ini` — the only artifact with drive letters

UTF-16LE INI. One section, `[OptimalLayoutFile]`, `Version=1`, then one absolute path per line.
Written by the disk-layout optimizer; it lists the files the prefetcher wants laid out
contiguously, i.e. **files the system considered hot**.

| | Win10 | Win11 |
|---|---|---|
| Path lines | 89 | 4,269 |
| Content | boot binaries only | boot **plus user-space** |
| Non-system paths | 0 | 358 |

The Win10 file stops after the kernel/driver set. The Win11 file continues into user space.

**This is the only artifact in the folder that uses a drive letter.** Every `.pf` path is
`\DEVICE\HARDDISKVOLUMEn\…` or `\VOLUME{serial}\…`, and `new-tool-design.md` §4.3 states the
device→letter mapping "does not exist anywhere in the `.pf` file" and must be supplied from
outside.

**That requirement stands — narrow what this buys you.** Layout.ini contains exactly one drive
letter (`C:`, on all 4,269 Win11 lines), so it identifies **the boot volume's letter and
nothing else**. Matching a distinctive shared path such as `\WINDOWS\SYSTEM32\NTOSKRNL.EXE`
against `.pf` filename lists tells you which device string is the boot volume. It says nothing
about any other volume, and the Win11 `.pf` set references more than one. So:

- Infer and label **`C:` for the boot volume only**, marked as inferred.
- Every other volume still needs external input per §4.3. Do not generalise this into a
  device→letter mapper.

What Win11's user-space lines expose, none of which is in any `.pf`:

- **The account name** — `C:\USERS\<user>\…` (241 + 102 lines).
- **Installed software**, including non-Microsoft: Brave, Cursor, VS Code, Python 3.11,
  Perplexity Comet, `C:\PLATFORM-TOOLS` (Android adb).
- **A project directory under active build** —
  `C:\USERS\<user>\DESKTOP\IR-AGENT-BUILDER\TARGET\DEBUG` (a Rust `cargo build` layout).
- **Credential-adjacent paths** — `\APPDATA\LOCAL\MICROSOFT\CREDENTIALS\<hash>`,
  `\MICROSOFT\TOKENBROKER\CACHE\<hash>.TBRES`.

Caveat that must reach the UI: this is a **frequency/optimization** artifact, not an execution
record. It carries no timestamps and no run counts. A path here means "accessed enough to be
worth optimizing", never "executed at time T".

## 2. `PfPre_<8hex>.mkd` — a 16,384-slot event ring buffer

Undocumented. Identical total size on both machines: **196,620 = 12-byte header + 16,384 ×
12-byte records**. That exact factorization is the structural proof.

```
offset 0   u32  version          = 5        (both machines)
offset 4   u32  identifier                  win10 0x27A79B2C, win11 0x2367D896
offset 8   u32  records written             win10 2603, win11 17779
offset 12       record[16384], 12 bytes each
                  u32 event id    only 11-12 distinct values, all 0x3E8D49A0..0x3E8D49AB
                  u32 field2      win10 49 distinct, win11 88 distinct
                  u32 sequence    monotonically increasing
```

**Verified, not guessed.** On Win10 the header count is 2,603 and there are exactly 2,603
non-zero slots, contiguous from index 0, with the third field monotonic across all of them
(0 → 1,503,292). On Win11 the count is 17,779, which exceeds 16,384, all slots are populated,
and monotonicity breaks — precisely what a wrapped ring looks like. So the count is
**cumulative events ever written**, not slots used, and `count > 16384` means older events
were overwritten.

The event-id field taking only ~12 values from a fixed range **shared across two unrelated
machines** makes it an enum of event types, not data.

### What the three fields are (updated 2026-08-15)

**Field 1 — event type.** Confirmed. Exactly 11 values on Win10 and 12 on Win11, all within
`0x3E8D49A0`–`0x3E8D49AB`, identical on both machines. Machine-invariant and consecutive means
a compile-time enum base.

**Field 2 — an identifier shared between installations, not machine data.** This is the new
result. Counting only values above 1, Win10 holds 47 distinct and Win11 holds 86 — and **27 of
them are common to both machines**, which are unrelated systems:

```
0x0a8758da 0x2de86155 0x2e53e318 0x2eb80c14 0x44330089 0x4a483460 0x4f5660f6
0x50a6beb2 0x58d4d4be 0x59554537 0x5c8c4038 0x65588d61 0x67fe5159 0x68684cb0
0x71f4b781 0x7659e9fc 0x853afc73 0xb28367fa 0xd17bca6f 0xd5fedbef 0xd828c64a
0xde1af8a3 0xe10b2949 0xe270127b 0xea89a369 0xf548da1e 0xf5b3514d
```

Anything machine-specific — an MFT reference, an address, a volume-derived value — cannot
collide across two installs 27 times. So field 2 identifies something shipped with Windows,
by hash or by tag. The remaining 20 Win10-only and 59 Win11-only values would then be the
machine-specific items.

It is **not** a prefetch filename hash: of 107 distinct values across both files, exactly 1
matches any of the 636 `.pf` filename hashes in the corpora, which is chance. The hash function
and the strings it consumes are still unknown.

**Field 3 — a monotonic clock, and it proves the ring wraps.** Win10 runs 0 → 1,503,292 with
**no** decrease across all 2,603 records. Win11 runs 83,207 → 4,487,912 with **exactly one**
decrease — and Win11 is the file whose header count (17,779) exceeds the 16,384 slots. A single
step backwards in an otherwise monotonic sequence is exactly what reading a wrapped ring buffer
linearly produces, so this confirms the wrap independently of the header count.

Read as milliseconds the maxima are 25 minutes and 75 minutes of uptime, which is plausible;
the median step is 0 (many events share a tick). Millisecond-since-boot is the best fit but
the unit is not proven.

Still not decoded: which event each of the 12 types is, and what field 2 hashes.

The 8 hex digits in the filename do **not** match the header identifier
(`cb1e3c5c` vs `0x27A79B2C`), so they are two different values. Unresolved.

## 3. SuperFetch databases — `.7db` and `.ebd` are one format

`.7db` files are stored plain. `.ebd` files are `MAM\x84`-compressed, and **decompressing one
yields the same container as a `.7db`**. One parser covers both.

### 3.1 This settles the `MAM\x84` question

`MAM\x84` sets bit 7 of the flags byte, which per the container spec adds a 4-byte field.
`reference/xpress.py` assumed the payload therefore starts at **+12** rather than +8, and that
was flagged as untested because the only two such files were not prefetch and offered no
`SCCA` to check against. Now tested directly:

| File | payload at +8 | payload at +12 |
|---|---|---|
| `ResPriHMStaticDb.ebd` (Win10) | fails — Huffman table overflows 2^15 | **OK, 153,100 bytes = declared size** |
| `ResPriStaticDb.ebd` (Win11) | fails — Huffman table overflows 2^15 | **OK, 63,932 bytes = declared size** |

Both decompress to exactly their declared output size and to a valid, self-consistent
container. **`MAM\x84` payload starts at +12. Open question closed.** The extra dword at +8 is
`0BF7E893` / `F51CE469` — high-entropy, no relation to size or count, consistent with a
checksum. Unconfirmed.

### 3.2 The shared container

```
offset 0   u32  version      = 3      (all five files, both machines)
offset 4   u32  total size            equals the file/decompressed length exactly - self-validating
offset 8   u32  header size  = 80
offset 12  u32  type         = 19 (0x13) for .7db,  22 (0x16) for .ebd
offset 16  u32               = 96
offset 20  u32  record size  = 56 for .7db,  64 for .ebd
offset 24  u32               = 80
offset 28  u32               = 8
```

`total size == len(data)` held on all five files across both OSes — a free integrity check and
a reliable way to recognise the format.

### 3.3 What they hold

UTF-16LE paths, in the **same `\VOLUME{serial}` notation as prefetch** — so the volume-name
decoding in `prefetch-format.md` §6.0a (creation FILETIME + serial) applies here unchanged, and
the serial can be correlated against the `.pf` volume records.

| File | OS | Paths | Character |
|---|---|---|---|
| `dynrespri.7db` | Win10 | 559 | system + user, e.g. `\USERS\<user>\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\…` |
| `dynrespri.7db` | Win11 | 531 | system + user |
| `cadrespri.7db` | Win10 | 13 | small; Edge-related resources |
| `ResPriHMStaticDb.ebd` | Win10 | 754 | static list, opens with the literal `Volume Serial Number : 1` |
| `ResPriStaticDb.ebd` | Win11 | 346 | same shape as Win10's |

`dyn` = dynamic (observed), `static` = shipped/static list, which is why the static DBs are
near-identical between the two machines while the dynamic ones differ. Same caveat as
Layout.ini: **access/priority evidence, not execution evidence, and no timestamps.**

## 4. ReadyBoot — **DECODED** (2026-08-15)

> **This section has been superseded. See [`readyboot-format.md`](readyboot-format.md).**
> The payload is a chain of 64 KB XPRESS Huffman chunks and now decodes to exactly its
> declared size on all six files. Two claims below were wrong and are kept only to show what
> changed: the payload is **not** undecodable, and the field at offset 8 is **not** a count —
> it is the compressed length of the first chunk.

**Win11 only**, in a `ReadyBoot/` subdirectory. All six files share the magic `PfB\xe3`
(`50 66 42 E3`).

This **corrects an earlier assumption** recorded in `STATE.md`: ReadyBoot was expected to be an
ETL trace parseable with `tracerpt`. There is no `.etl` here and no ETL magic. That plan is
void.

```
offset 0   u32  magic = 0xE3426650  ('PfB\xe3')
offset 4   u32  total uncompressed size    2.4-9.9 MB, ~3x the file size
offset 8   u32  compressed length of chunk 0   (NOT a record count)
offset 12       first chunk, then a repeating [u32 unidentified][u32 next length] chain
```

| File | Size | mtime | uncompressed | chunk-0 length |
|---|---|---|---|---|
| `Trace2.fx` | 2,523,375 | 2026-07-18 23:17 | 7,795,764 | 19,934 |
| `Trace3.fx` | 3,158,061 | 2026-07-19 10:54 | 9,770,700 | 20,427 |
| `Trace4.fx` | 2,898,950 | 2026-07-26 17:35 | 9,379,950 | 20,145 |
| `Trace5.fx` | 2,499,346 | 2026-08-12 00:11 | 7,745,050 | 20,067 |
| `Trace6.fx` | 3,067,169 | 2026-08-12 08:34 | 9,889,868 | 18,693 |
| `rblayout.xin` | 424,963 | 2026-08-12 08:34 | 1,583,772 | 21,591 |

**Even undecoded, the mtimes are evidence**: five boot traces, numbered 2–6, spanning
2026-07-18 to 2026-08-12. `Trace6.fx` and `rblayout.xin` share an mtime to the second, so the
layout is rewritten when the newest trace is taken. There is **no `Trace1.fx`** — either the
numbering is a rotation that has wrapped or slot 1 was reclaimed. Each file plausibly
corresponds to one boot, which would make this a boot history independent of the event log.

**How it was eventually cracked.** The payload's first bytes
(`94 8A A9 9A 99 99 89 89 97 77 78 79 …`) read convincingly as packed 4-bit XPRESS Huffman
code lengths — values 7–11 are exactly the right range. That reading was **correct**, and was
wrongly dismissed as a coincidence of the first 64 bytes.

The mistake was treating the file as one compressed stream. It is a *chain* of independently
compressed 64 KB chunks, so a whole-stream decode desynchronises after the first chunk — which
is why every offset tried produced a table error rather than a clean failure. The measured
entropy of 7.885 bits/byte was right and simply did not distinguish "one stream" from "many".

The decisive step was scanning every offset for Kraft-complete Huffman tables instead of
guessing offsets. Full derivation, the chunk chain, and the verification:
**[`readyboot-format.md`](readyboot-format.md)**.

**Status: closed.** All six files decode to exactly their declared size; every chunk boundary
lands on a complete Huffman table. The name table inside is a directory tree, and **every link
resolves on every file** — 8,927 to 20,179 whole paths each, none dropped. What remains
undecoded is the per-access data preceding the name table, which would supply ordering and
timing.

---

## Priority for the tool

1. **`Layout.ini`** — cheap (UTF-16 INI), high value, and the only source of drive letters.
2. **`.7db` / `.ebd`** — one container, self-validating, contains paths and volume serials that
   correlate with `.pf`.
3. **ReadyBoot** — decodes to a boot file-access trace; surface the recovered name components
   and the per-boot mtimes. Full paths are not reconstructable yet.
4. **`PfPre_*.mkd`** — structure is solid but the semantics are unknown; low analyst value.

All four are **access/priority artifacts, not execution records.** They must be visually
distinct from `.pf`-derived rows so nobody reads a Layout.ini path as "this program ran".
