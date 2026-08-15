# Windows 10 vs Windows 11 prefetch — what actually differs

Answered by measurement, 2026-08-12, from the user's two real Prefetch folders (184 Win10 +
452 Win11 files) using the partial XPRESS decoder in `../reference/`. Published sources were
searched first and had **nothing** at format level — the difference below is not written down
anywhere public that I could find; it comes from the files.

*Updated after the decoder was finished — all 636 files now fully decompress, so these numbers
are complete rather than sampled.*

## Short answer

**The format is the same. Only the version number changes.**

| | Win10 (this host) | Win11 (this host) |
|---|---|---|
| `.pf` files | 184 | 452 |
| Container | `MAM\x04`, XPRESS Huffman — **100%** | same, 100% |
| Version dword | **30** (all 184) | **31** (all 452) |
| Executable-path string (§5a) | present in 183/184 | present in 452/452 |
| …of which package identities | 33 | 139 |
| File-info section | 212 bytes | 212 bytes |
| File metric entry | 32 bytes | 32 bytes |
| Trace chain entry | 8 bytes | 8 bytes |
| Retained run times | 8 | 8 |
| RunCount offset | section end − 96 | section end − 96 |

Every structural measurement is identical. A parser that handles modern v30 handles v31 with
no code change beyond accepting `31` in the version switch — which is what the reference
implementation already does (`PrefetchFile.cs` routes both to `Version30or31`).

## The real split isn't Win10 vs Win11 — it's old vs modern

The one substantive change is a **file-info section that shrank from 220 to 212 bytes**, and
it happened *within* the Windows 10 line:

| Corpus | Version | Section size |
|---|---|---|
| 2015-era Win10 (vendored test corpus, 5 files) | 30 | **220** |
| Modern Win10 (this host, 166 files) | 30 | **212** |
| Win11 (this host, 395 files) | 31 | **212** |

Those 8 bytes are exactly what `Version30or31.cs:87` compensates for with its comment
*"newer versions of windows 10 shift the counter backward 8 bytes"*. So the discontinuity a
parser must handle is **a Windows 10 servicing change, not the Win10→Win11 boundary** — and
keying off the version number alone would get it wrong, because v30 appears with both sizes.

Derive it instead: `fileinfo_size = FileMetricsOffset - 84`, then
`RunCount = int32 @ fileinfo + fileinfo_size - 96`. See `prefetch-format.md` §3.0a.

## Folder contents do differ

This is where the two OSes actually diverge, and it matters more for tool scope than the `.pf`
format does:

| Artifact | Win10 | Win11 |
|---|---|---|
| `Layout.ini` | 7 KB | **584 KB** (83× larger) |
| `PfPre_<hex>.mkd` | 196,620 B | 196,620 B — *identical size*, fixed-length structure |
| `ResPriHMStaticDb.ebd` | 50 KB, `MAM\x84` | — |
| `ResPriStaticDb.ebd` | — | 20 KB, `MAM\x84` |
| `cadrespri.7db` | 5.6 KB | — |
| `dynrespri.7db` | 278 KB | 393 KB |
| `ReadyBoot/` | absent | `Trace2–6.fx` + `rblayout.xin`, all `PfB\xe3` |
| `Ag*.db` (SuperFetch) | **none** | **none** |

Three things worth carrying into the design:

- **No `Ag*.db` on either host.** The SuperFetch databases that libagdb documents and that
  most prefetch-forensics writing still references are simply absent from current Windows.
  Tier 3 may be dead scope — confirm before investing.
- **ReadyBoot is Win11-only here, and it is not ETL.** Six files, all `50 66 42 e3`
  (`PfB`+0xE3), no `.etl` anywhere. Corrected in `new-tool-design.md` §6.
- **`MAM\x84` appears on both**, on the `ResPri*` files only — the libscca bit-7 variant,
  previously unverified. See `porting-notes.md` §5.2.

## The other modern-build addition

Both OSes carry the **executable-path string** described in `prefetch-format.md` §5a — the
full device path (or Store package identity) written after the filename block. It is absent
from every pre-modern file in the vendored corpus, so like the 212-byte section it arrived
with a Windows 10 servicing update rather than with Windows 11. Win11 simply has proportionally
more packaged apps (139/452 vs 33/184), which is an app-ecosystem difference, not a format one.

## Caveats

- **One host each.** These are two machines, not a survey. "Win10 has no ReadyBoot" means *this*
  Win10 host didn't; ReadyBoot depends on boot configuration and storage type.
- All 636 files now decode fully, so the counts are complete for these two hosts.
- Version 30 vs 31 tracks the OS on these two hosts, but a Win10 host patched past the change
  still reports 30 — the version dword identifies the *format revision*, and Microsoft's own
  labelling of 30 as "Windows 10 or Windows 11" reflects that overlap.

## Sources

Format-level facts above are measured from the files, not cited — no public source documents
the 220→212 change. Background consulted:

- [MS-XCA: LZ77+Huffman Compression Algorithm Details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c0244bfe-fd96-4fe5-97dd-39b9fc99b801)
- [MS-XCA: Processing (encoder pseudocode)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b66751f2-be7b-4d20-a87c-5147c563ff2d)
- [libscca — Windows Prefetch File (PF) format](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
- [A guest in the Prefetch directory — thelocalh0st](https://thelocalh0st.com/posts/guest-in-prefetch-directory/)
- [SysMain/SuperFetch naming history](https://www.guiahardware.es/en/diferencias-entre-prefetching-y-superfetch-en-windows/)
