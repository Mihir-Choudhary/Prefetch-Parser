# SuperFetch databases — `Ag*.db`, `*.7db`, `*.ebd`

What sits in the Prefetch folder besides prefetch, and what an investigator can take from it.

Structure follows libyal's *Windows SuperFetch (DB) format* document — the only public
description — with two corrections measured against real files, marked **[corrected]** below.
Everything stated here was verified against files this tool parses; anything not verified is
labelled as inferred or untested rather than left to look like fact.

---

## Why it matters

| Windows | Files in `C:\Windows\Prefetch` | Held |
|---|---|---|
| Vista / 7 / 8 | `AgGlGlobalHistory.db`, `AgGlFaultHistory.db`, `AgGlFgAppHistory.db`, `AgRobust.db`, `AgCx_SC*.db`, `AgGlUAD_<SID>.db`, and `.db.trx` logs beside them | tens of thousands of file paths per volume |
| 8.1 / 10 / 11 | `*.7db`, `*.ebd` (`dynrespri`, `cadrespri`, `ResPriStaticDb`, `ResPriHMStaticDb`) | hundreds to thousands of paths, plus per-file timestamps on the static databases |

The measured Windows 7 sample holds **10,118 file records across 2 volumes** — user profile
paths, browser cache entries, temporary files, installer leftovers — each tied to a volume whose
**serial number and creation time** the database states outright. A `.pf` file names the files
*one program* loaded; this names what the *whole system* read.

**It is access evidence, not execution evidence.** Nothing here says a program ran. Files appear
because the prefetcher decided they were worth keeping warm.

---

## Compression wrappers

The database is usually wrapped. The wrapper is identified by magic, and the payload underneath
is identical in every case.

| Magic | Windows | Method | Block size | Status here |
|---|---|---|---|---|
| `MAM\x84` | 8.1, 10, 11 | XPRESS Huffman, one stream | — | verified — same container as `.pf` |
| `MEM0` | 7 | XPRESS Huffman, blocked | 64 KiB | **verified** on the 2 MB sample: 100 blocks, 6,543,992 bytes, exactly the declared total |
| `MEM\xb0` | 8.0 → 11 | XPRESS Huffman, blocked | 64 KiB (8.x), 128 KiB (10), 1.375 MiB (11) | implemented; the header does not say which size, so the parser takes the one that consumes the input exactly. No sample |
| `MEMO` | Vista | LZNT1 | 4 KiB | implemented and **verified against libyal's published vectors** — see below. Still reported as `MEMO (LZNT1, untested - no sample)` because no real Vista database has been through it |
| none | Vista → 11 | — | — | verified (`dynrespri.7db`, `cadrespri.7db`) |

Block layout for `MEM0` / `MEM\xb0`: `[u32 compressed size][compressed data]`, repeated, each
block decompressing to the block size or to whatever remains.

---

## Database layout

```
file header      12 bytes   signature, total size, header size
database header  variable   type, 9 parameters, counts
volume entries              each followed by its own file entries
source entries              when the header declares any
```

### File header

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Signature — `3` (Win8+ compressed), `5` (`AgAppLaunch`), `0x0e` (Vista/7), `0x0f` (Win8+ `AgRobust`) |
| 4 | 4 | Total size — **equals the decompressed length on every file measured**, so a mismatch is a real integrity signal |
| 8 | 4 | Header size — where the volume entries begin |

### Database header

| Offset (from +12) | Field |
|---|---|
| 0 | Database type — 1, 11, 14 on Vista/7; 19, 21, 22 on Win8+ |
| **4** | **[corrected]** the nine database parameters. The reference document places them at +12; measured at **+4** on all five files parsed here |
| 40 | Number of volumes |
| 44 | Total number of files |
| 52 | Number of sources |

The nine parameters are structure sizes, and they are what makes the format self-describing:

```
volume entry size, file entry size, source entry size,
file sub-entry type 1 size, file sub-entry type 2 size, …
```

Measured combinations:

| File | Type | Parameters | Meaning |
|---|---|---|---|
| `AgGlGlobalHistory.db` (Win7 64-bit) | 1 | `72, 88, 96, 24, 32, …` | matches the reference table exactly |
| `dynrespri.7db` (Win11) | 19 | `96, 56, 80, 8, …` | type not in the reference table |
| `cadrespri.7db` (Win10) | 19 | `96, 56, 80, 8, …` | |
| `ResPriStaticDb.ebd` (Win11) | 22 | `96, 64, 80, 8, …` | type and file-entry size not in the reference table |
| `ResPriHMStaticDb.ebd` (Win10) | 22 | `96, 64, 80, 8, …` | |

### Volume information entry

Fields differ between the Vista/7 and Win8+ families, which reuse the same entry *sizes*, so the
layout is keyed by `(entry size, family)`.

| Entry size | Family | files | created (FILETIME) | serial | device-path chars | device path |
|---|---|---|---|---|---|---|
| 56 | Vista/7 32-bit | +8 | +24 | +32 | +44 | at +56 |
| 72 | Vista/7 64-bit | +16 | +32 | +40 | +56 | at +72 |
| 72 | Win8+ 32-bit | +8 | +24 | +32 | +44 | at +72 |
| 96 | Win8+ 64-bit | +16 | +32 | +40 | +56 | at +96 |

The device path is written the way prefetch writes it — `\DEVICE\HARDDISKVOLUME2` on Vista/7,
`\VOLUME{01d6d2b931a49a11-cc31b5d5}` on Windows 10/11, which encodes the creation FILETIME and
serial in the name itself and agrees with the entry's own fields.

The static databases (`ResPri*`) name no real volume: device `Volume Serial Number : 1`,
serial 1, creation time zero. They are a shipped baseline, not a record of this machine.

### File information entry

| Entry size | Family | name hash | path chars | sub-entry count | flags | FILETIME |
|---|---|---|---|---|---|---|
| 36, 52, 72 | Vista/7 32-bit | +4 (u32) | +28 | +8 | +12 | — |
| 64, 88 | Vista/7 64-bit | +8 (u64) | +48 | +16 | +20 | — |
| 48 | Win8+ 32-bit | +4 (u32) | +8 | — | — | — |
| 56 | Win8+ 64-bit | +8 (u64) | +16 | +32 | — | — |
| 64 | Win8+ 64-bit | +8 (u64) | +16 | — | — | +56 *(inferred)* |
| 80 | Win8+ 64-bit | +8 (u64) | +16 | +76 | — | — |

Two things the reference document does not say, both measured:

* **[corrected]** the path is written **immediately after the fixed-size entry**, and the
  sub-entry array follows the *path*. Reading it the other way round yields garbage paths whose
  lengths still happen to advance the walk correctly — so the error is invisible without the
  hash check below.
* the path character count must be **shifted right by 2**; the low two bits are unexplained and
  are always zero in the files measured.

The `64 (Win8+)` row's FILETIME at +56 is **inferred, not documented**: the field decodes to
plausible dates on both static databases (753 records spanning 2019-12-07 → 2022-07-15 on Win10,
and 2024–2025 on Win11) and to nothing sensible read any other way. Treated as a per-record
timestamp and labelled as inferred wherever it is shown.

---

## The name hash — why any of this can be trusted

Every file entry stores a hash of its own path. libagdb documents the function, and this tool
implements and **checks** it:

```
value = 0x4cb2f
for each 8-byte group:  value = (mix of the 8 bytes) - 0x2fe8ed1f * value + byte[7]
trailing bytes:         value = value * 0x25 + byte
```

Measured: **12,316 of 12,316 paths verify** across the six databases parsed
(10,118 + 558 + 530 + 753 + 345 + 12). Nothing was recovered that its own hash did not vouch
for.

This is what makes the parser safe on undocumented variants. A wrong offset changes the hash, so
a mis-parse announces itself instead of producing a plausible wrong path — the same property the
`\VOLUME{…}` self-check gives in `.pf`.

---

## LZNT1, and the off-by-one it hid

Windows Vista wraps these databases in `MEMO`/LZNT1 rather than XPRESS. No public Vista sample
exists, so the decoder was written from the specification — and was wrong.

LZNT1 splits each 16-bit tuple into an offset and a length, and the split moves as the chunk
fills. The specification is explicit: the shift narrows when **`(bytes written − 1) >= 0x10`**.
Written as `bytes written >= 0x10`, a back-reference landing at *exactly* 16 bytes written
decodes with the wrong split — and LZNT1 carries no checksum, so the result is plausible bytes
rather than an error.

Now pinned by four vectors in `reference/test_superfetch.py`:

| Vector | Exercises |
|---|---|
| libyal's published `02 20 fc 0f` → 4,096 spaces | the tuple whose offset stays fixed at the output end |
| `#include <ntfs.h>\n#include <stdio.h>\n` rebuilt per the documented algorithm | the split narrowing through 12 → 11 → 10 bits |
| a back-reference at exactly 16 bytes written | the boundary above, which was wrong |
| an uncompressed chunk | the stored-chunk flag |

*(libyal's second published example is reproduced here from its stated tuples, not its hex
dump: the dump and the tag-byte listing beside it disagree with each other.)*

## Undocumented entry sizes: probe, and let the hash decide

`AgRobust.db`'s 64-bit file entry is 112 bytes and libyal's table for it reads `TODO`. Rather
than refuse, the parser tries each layout it *does* know and accepts one only if the stored
name hashes verify against the paths it produces. A wrong layout reads a wrong length at a
wrong offset and its hashes do not match, so the probe either finds the real layout or finds
nothing — it never guesses. When it succeeds, the record says so in its problems.

## Source information entries

Two fields are documented — a name hash and an entry count — and **no database this tool has
seen declares a single source**, so the path has only ever run against a synthetic file built
to the documented shape. It is implemented because `AgRobust.db`'s sources are documented to
carry *process information including prefetch hashes*, which would tie a SuperFetch record to a
`.pf` file directly. Counts are reported; nothing is interpreted.

## Three parse strategies, and the record says which ran

| Method | When | Guarantee |
|---|---|---|
| `structural` | the documented layout walks cleanly | every entry's hash verified **and** the record count equals the declared count |
| `scan` | the sub-entry sizing for this variant is undocumented (`ResPri*.ebd`) | each entry accepted only because its stored hash matches the path that follows; recovered-vs-declared counts reported |
| `sweep` | neither walks | UTF-16 string sweep — paths, no structure, and the facts say so |

Measured: structural on `AgGlGlobalHistory.db`, `dynrespri.7db`, `cadrespri.7db`; scan on both
`ResPri*.ebd` (345/345 and 753/753 recovered).

A database that cannot be parsed at all is reported as unparsed. It is never reported as empty.

---

## What is still unknown

* **Source information entries** — implemented from the two documented fields and exercised
  only by a synthetic database, because every real one measured declares **zero** sources. What
  the remaining ~130 bytes of each entry hold is unknown.
* **Sub-entry contents** — walked over, not decoded. The reference document has them as
  unknown identifiers too.
* **The low 2 bits of the path character count.**
* **`AgAppLaunch.db`** (signature 5) — a different format per the reference document; no sample.
* **`.db.trx`** transaction logs — recognised by name, contents undecoded.

Each of these is a place where more could be recovered with a sample to work from. None of them
is silently skipped: the parser reports what it did not parse.
