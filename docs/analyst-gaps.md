# What analysts complain about — and which gaps a tool can actually close

Research pass, 2026-08-12. Sources listed at the bottom. The useful output here isn't the
complaint list; it's the mapping from each complaint to a **concrete tool behavior**, with an
honest mark on the ones **no parser can fix**.

A tool that states its limits gets trusted. A tool that presents an inference as a fact gets
an analyst burned in court once and then abandoned.

---

## A. Closable — tooling gaps with a concrete fix

| # | Complaint | What the tool does |
|---|---|---|
| A1 | Executable's **full path isn't in the CSV** — only the bare header name | Resolve it from the filename list by basename equality; emit in every output. `new-tool-design.md` §4 |
| A2 | Paths are `\VOLUME{…}` / `\DEVICE\HARDDISKVOLUMEn`, not usable drive paths | Always emit the device path; offer drive-letter resolution as an optional enrichment from volume serial + `MountedDevices`/mount table. Never fabricate |
| A3 | **Data is dropped**: volumes past the 2nd, all per-file MFT references, all file metrics, trace chains | Relational SQLite store; every field kept, unknowns preserved as hex |
| A4 | Hidden prefetch **in alternate data streams is invisible** to both PECmd and WinPrefetchView | Content-based ADS scan over all files *and directories*, flagged loudly |
| A5 | ADS-hosted prefetch has **broken/misleading timestamps** | Model it explicitly: `CarrierPath`, `StreamName`, `TimestampSource`, carrier times labelled as carrier times |
| A6 | Win10+ files need Windows 8+ because of the `ntdll` decompression call | ctypes `RtlDecompressBufferEx` on Windows, **pure XPRESS Huffman fallback** everywhere else — parses Win10/11 prefetch offline on any OS |
| A7 | Decompression failure surfaces as *"Invalid signature"*, hiding the real cause | Check the decompressor's return status; report the actual failing stage |
| A8 | Only 8 run times are retained, so executions before those are simply lost | **Approximate first-execution time**: `SourceCreated − 10s`, shown with a `~`. When `RunCount > 8` this recovers an estimate older than any embedded timestamp. `new-tool-design.md` §5a |
| A9 | Same binary name run from different paths is easy to miss — a known masquerading technique — but naive flagging cries wolf | Observational `SameNameDifferentPath` column, with hosting apps excluded and benign explanations shown alongside. `new-tool-design.md` §5b |
| A10 | `svchost.exe` / `rundll32.exe` / `dllhost.exe` / `mmc.exe` produce many entries and analysts lose the thread | Their hash includes the command line, so multiple entries are *expected*. Group them as distinct command-line contexts and exclude them from A9's flag |
| A11 | The giant `FilesLoaded` CSV cell is unusable (tens of KB per row) | Long-form `loaded_file` table + a detail pane; the wide CSV stays only for tooling parity |
| A12 | No filtering/pivoting without exporting to Timeline Explorer or Excel first | Excel-style per-column filters in-app; export the **filtered** view |
| A13 | Running the tool on a live system **creates new prefetch and can age out evidence** | Read-only by design, no admin needed for already-copied files, and a startup warning naming this risk on live-system runs |
| A14 | MFT entry numbers aren't exposed, so nobody correlates prefetch with `$MFT`/USN | Export MFT entry + sequence per loaded file; make it a joinable column |
| A15 | Non-`.pf` files in the folder are ignored entirely | Tiered plugins; unrecognized files still produce an "unidentified artifact" row |
| A16 | Deleted prefetch is evidence nobody recovers | MFT-driven recovery first, signature carving second, with the section-geometry identities as the validator. `new-tool-design.md` §10 |

---

## B. Not closable by tooling — the tool's job is to not overclaim

These come up repeatedly in the literature as the **most common analytical failures**. No
parser can fix them. What a tool can do is refuse to present inferences as facts, and point at
corroboration.

| # | Reality | How the tool behaves |
|---|---|---|
| B1 | Prefetch shows Windows *observed an execution start* — not intent, not success, not impact | Never label anything "executed by user". Ship a standing caveat in reports |
| B2 | Can't distinguish user-launched from scheduled task / service / updater / EDR agent | Surface corroboration hooks (logon sessions, shell artifacts) as *suggested next steps*, not conclusions |
| B3 | Only the **first ~10 seconds** of a launch are recorded — later behavior leaves no trace here | Annotate the observation window next to the timestamps |
| B4 | Referenced files may be touched by a dependency, loader, or framework — not by user action | Present `loaded_file` as "referenced during startup", never "opened by the user" |
| B5 | **Run count is per-record**: deleting/recreating the `.pf` resets it; a relocated exe gets a separate record with its own count | Show run count with that caveat attached, and show sibling records for the same basename (A9) |
| B6 | Only 8 run times are retained; earlier executions are gone | Label the run list "last 8 retained", not "all executions". A8's `~FirstRunApprox` estimates *earlier* than those 8, but it is an estimate and must stay marked as one. (No flag for the run-count/retained gap — D2 rejected) |
| B7 | `SourceCreated` ≈ first observed run, `SourceModified` ≈ last run — but both lag by up to 10 s and are file-system times, so **time-stomping applies** | Present them as filesystem times distinct from the embedded run times, and show the delta |
| B8 | Copied/extracted prefetch files carry **collection** timestamps, not original ones | Record acquisition provenance; warn when filesystem times postdate the newest embedded run time |
| B9 | Absence ≠ non-execution (disabled, aged out, deleted, reimaged, VDI/non-persistent) | Never phrase a missing entry as "did not run" |
| B10 | Timestamps are relative to the host's local time and clock | Store UTC, display both, and record the source machine's timezone if supplied |

---

## C. Scope — what's in

**Decided 2026-08-12.** The gap-closing items in section A are the feature set. From the
wider suggestion list, the user selected exactly one convenience feature:

- **Bookmark / tag rows with notes**, exporting only the tagged or selected rows.
  HTML by default, CSV/XLSX for data, PNG for slide decks, with per-row provenance.
  `new-tool-design.md` §9.

Everything else offered has been dropped rather than deferred, so it doesn't get
re-litigated: fleet stacking, diff mode, IOC list import, saved-CLI-from-GUI-state, l2t
timeline export, derived run-rate columns, plugin API for third parties, the byte-walk
"explain this record" pane, and planted/renamed prefetch detection via hash comparison.
See the decision log in `STATE.md`.

*(The collection-context panel was also dropped here, but D6 below revives a narrow version of
it — file count against the retention cap — which the user accepted.)*

---

## D. Second round — measured against the real corpus

Proposed 2026-08-12 from profiling real data rather than speculation: the user's 221-record
Win10 CSV, the 48-file uncompressed corpus, and the 636-file real Win10/Win11 folders.

**User's decision: D2 and D7 rejected. D1, D3–D6 and D8–D10 accepted.**

### D1. Volume-name self-check — ACCEPTED

`\VOLUME{01d8559f7371205e-b0737add}` embeds the volume creation FILETIME (16 hex, big-endian)
and the serial (8 hex), both of which are also parsed as separate fields. Verified consistent
on every volume across the corpus — see `prefetch-format.md` §6.0a. Cross-check them; a
mismatch has no known benign cause. One comparison, no UI. Also a recovery path when a
fragment's volume entry is truncated but the device-name string survives.

The `\DEVICE\HARDDISKVOLUMEn` form carries no embedded data; the check doesn't apply and
should report "not applicable", not "failed".

### D2. `RunCountExceedsRetained` flag — **REJECTED**

Would have flagged records where `RunCount` exceeds the retained run-time list (78/221 = 35%
of the user's real data). Not built. Note `~FirstRunApprox` (A8) is unaffected and still in —
it was the user's own idea and stands on its own.

### D3. Volume as a first-class dimension — ACCEPTED

12 records span two volumes and 2 exceed two volumes in the sample data. Removable and network
volumes are where the interesting executions live. The relational store already keeps every
volume (`new-tool-design.md` §3), so this is GUI work: "group by volume" and "show only
executions touching volume X".

### D4. Directory-count sanity check — ACCEPTED

v23+ store `TotalDirectoryCount`; the corpus confirms it equals the sum of the per-volume
directory lists. Compare parsed against stored and flag a mismatch as a truncation/tampering
signal. v17 stores `-1` (no such field) → report "not applicable".

### D5. Trace-chain totals — ACCEPTED

`TraceChainsCount` and per-entry `TotalBlockLoadCount` are parsed by every implementation and
displayed by none. Surface them. Low individual value, but free, and an atypical value for a
common binary is a cheap anomaly signal.

### D6. Prefetch-directory census — ACCEPTED

**Supersedes the collection-context panel declined earlier** — this is the narrow version:
file count against the 128 (≤Win7) / 1024 (Win8+) cap, plus oldest and newest record. At the
cap, aging-out is actively destroying evidence and the analyst needs to know that before
drawing any conclusion from an absence. A collection-level fact, not a per-record one.

### D7. `LoadedFileCount` and `DirectoryCount` columns — **REJECTED**

Would have added counts of the parsed lists as sortable integers. Not built.

### D8. Two provenance flags the ADS work gives for free — ACCEPTED

`PrefetchOutsidePrefetchFolder` (a valid `.pf` parsed from anywhere other than
`\Windows\Prefetch`) and `CarrierNotPrefetch` (prefetch inside a stream on a non-`.pf`
carrier). Both are direct signals of the hiding technique that motivated `--ads`. Zero extra
parsing — just record where each record came from.

### D9. Executable-name truncation flag — ACCEPTED

The header name field is 60 bytes = 29 UTF-16 chars + NUL, so longer names are silently cut.
**Far more common than first estimated**: 13 Win10 and 44 Win11 files sit exactly at the cap —
`DOTNET-SDK-9.0.315-WIN-X64.EX`, `MICROSOFTEDGE_X64_151.0.4129.`, `AM_DELTA_PATCH_1.457.104.0.EX`,
`LENOVO.MODERN.IMCONTROLLER.PL`. When the resolved path (§4.1) supplies the full name, show it
and flag the header value as truncated, so nobody greps for a name that was never written in
full.

### D10. Parse failures as rows, not console output — ACCEPTED

PECmd's `_failedFiles` list reaches the console only — it appears in **no** output file, so a
file that failed to parse silently vanishes from the analysis. Every input must produce a row:
on failure, with its path, its stage-specific error, and whatever partial data was recovered.
Depends on the staged-error model, which is already planned (`new-tool-design.md` §2).

---

## Sources

- [Windows Prefetch Forensics: Execution Evidence and Its Limits — sethenoka.com](https://sethenoka.com/prefetch-execution-evidence-and-its-limits/)
- [Prefetch: The Little Snitch That Tells on You — TrustedSec](https://trustedsec.com/blog/prefetch-the-little-snitch-that-tells-on-you)
- [Creating a Hidden Prefetch File to Bypass Normal Forensic Analysis — B!n@ry z0ne](https://www.binary-zone.com/2019/05/26/creating-a-hidden-prefetch-file-to-bypass-normal-forensic-analysis/)
- [Hunting For Attackers' Tactics And Techniques With Prefetch Files — Forensic Focus](https://www.forensicfocus.com/articles/hunting-for-attackers-tactics-and-techniques-with-prefetch-files/)
- [Forensic Analysis of Prefetch files in Windows — Magnet Forensics](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/)
- [libagdb — Windows SuperFetch (DB) format documentation](https://github.com/libyal/libagdb/blob/main/documentation/Windows%20SuperFetch%20(DB)%20format.asciidoc)
- [SuperFetch Forensics on Windows: Files, Tools, Analysis — IT-Connect](https://www.it-connect.tech/forensic-windows-part-4-exploiting-superfetch-artifacts/)
- [Windows SuperFetch Format — ForensicsWiki](https://forensics.wiki/windows_superfetch_format/)
- [SysMainView — reverse engineering of the SysMain service](https://github.com/MathildeVenault/SysMainView)
