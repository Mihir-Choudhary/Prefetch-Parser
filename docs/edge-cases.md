# Prefetch edge cases and odd behaviours

Measured across both real corpora (636 files) on 2026-08-13 unless marked otherwise. Every
number here is reproducible; claims taken from published sources rather than measured are
labelled as such, and two of them turn out to be **wrong**.

The organising question is not "what is unusual" but **"what would make a parser or an analyst
draw a false conclusion"**.

---

## 1. The 8 run-time slots are NOT guaranteed newest-first

The single most actionable finding here, because every tool including PECmd reports
`LastRun = slot[0]`.

| Measurement | Files |
|---|---|
| Any adjacent pair out of order | **27 / 636** |
| **Slot 0 is not the newest run time** | **6 / 636** |
| Largest error in reported "last run" | **1.284 s** (`GIT.EXE-DA7EFDD1.pf`) |

```
BRAVE.EXE-3118B3E9.pf   RunCount=299
   slot0: 2026-08-12 03:35:54.405739
   slot1: 2026-08-12 03:35:54.459317   <-- 54 ms NEWER than slot 0
   slot2: 2026-08-11 18:25:50.577766
```

**Cause:** near-simultaneous launches. Every affected pair is separated by milliseconds to ~1
second — a program spawning several processes at once (Brave, Git, msiexec), whose recording
order isn't strictly serialised. The array is *broadly* newest-first, not *reliably* so.

**Rule: `LastRun = max(run_times)`, never `run_times[0]`.** One line, and without it the
reported last-execution time is wrong on ~1% of files. The error is sub-second so it will
rarely change a conclusion — but it is free to get right, and "the tool's timestamp is off by
1.3 s" is not a sentence anyone wants to say in testimony.

Corollary: **do not silently sort the slots either.** Keep the stored order (it is evidence of
how the OS recorded them) and derive `LastRun` separately.

## 2. Duplicate run times within one file

**4 / 636** files contain the same timestamp twice —
`SYSTEMSETTINGSADMINFLOWS.EXE-79DECAFD`, `REG.EXE-A93A1343`, `WERMGR.EXE-F439C551`, and one
more. Consistent with the same cause as §1: two launches inside the same 100 ns tick, or the
same launch recorded twice.

Consequence: **`len(set(run_times))` is not a run count.** Deduplicating the timeline output
would silently drop real executions.

## 3. "Multiple hashes for one executable name" does NOT mean multiple locations

This is repeated in most published prefetch guidance — e.g. Magnet Forensics and several
practitioner blogs state that several `.pf` files sharing an executable name indicates the
program ran from several paths, and is a malware-relocation indicator.

**Measured against real PECmd output, that is false often enough to be dangerous:**

| Executable | `.pf` files | Distinct resolved paths |
|---|---|---|
| `SVCHOST.EXE` | 39 | few |
| `RUNTIMEBROKER.EXE` | 12 | 1 |
| `DLLHOST.EXE` | 9 | 1 |
| `MSEDGE.EXE` | 7 | **1** |
| `WINDOWSTERMINAL.EXE` | 7 | few |
| `PECMD.EXE` | 5 | few |

`MSEDGE.EXE`'s seven hashes are `BA103770`–`BA103775` and `BA103778` — **near-consecutive**,
which no hash function produces for seven distinct paths, and all seven resolve to one path.
`ACRORD32.EXE-62938E58` and `-62938E59` have byte-identical §5a paths *and* identical
RunCounts.

So the flag must compare **resolved paths, not hashes** (already decided; this is the
supporting evidence). And note `WINDOWSTERMINAL.EXE` and `PECMD.EXE` are not hosting
applications, so "hosting apps also hash the command line" does not explain the whole
phenomenon. See `prefetch-format.md` §5a.2a.

## 4. Prefetch exists for things that are not `.exe`

| Header name ends in | Files | Examples |
|---|---|---|
| `.EXE` | 569 | — |
| **`.TMP`** | **8** | `PROCESSHACKER-2.39-SETUP.TMP`, `SHADOWEXPLORER-0.9-SETUP.TMP`, `_IU14D2N.TMP` |
| **`.BIN`** | 1 | `SOFFICE.BIN` (LibreOffice's real binary) |
| truncated / no extension | 57 | see §5 |

The `.TMP` entries are the interesting class: **installers that extract a payload to `%TEMP%`
and execute it**. `_IU14D2N.TMP` is an Inno Setup uninstaller. One corpus file
(`F-RESPONSE-INSTALLER-8.3.1.15`) has §5a pointing at
`…\TEMP\IS-227JG.TMP\F-RESPONSE-INSTALLER-8.3.1.15.TMP` while the filename list holds the
`.EXE` — the stage-then-run pattern captured in one record.

**A tool must not filter on `.exe`, and must not assume the header name has an extension.**

## 5. The header name truncates at 29 characters — and it bites the resolver

**57 / 636** files have a header name of exactly 29 characters, i.e. truncated. Examples:
`BULK_EXTRACTOR-1.6.0-DEV-REC0`, `MICROSOFTEDGE_X64_151.0.4129.`, `EXTRACT NIMI PLACES (PORTABLE`.

Two traps, both hit during this work:

1. **Basename *equality* against the filename list can never match a truncated name.** Prefix
   matching is required; skipping it made 54 files look unresolvable when they were not.
2. **A bare prefix match is wrong too** — it also catches `FOO.EXE.CONFIG`, `FOO.EXE.MUI`,
   `FOO.APPDOMAIN.DLL`. Take the **shortest completion** of the prefix.

Note the truncation is at 29 characters, not 29 bytes, and names can contain spaces and
parentheses (`EXTRACT NIMI PLACES (PORTABLE`).

## 6. Multi-volume prefetch is rare but real, and the reference truncates it

| Volumes | Files |
|---|---|
| 1 | 625 |
| 2 | 10 |
| **3** | **1** — `MSIEXEC.EXE-B5AFA339.pf` |

PECmd's CSV has only `Volume0*` and `Volume1*` columns and emits a `Note` instead. Confirmed
verbatim from its own output, on exactly two rows:

> `File contains > 2 volumes! Please inspect output from main program for full details!`
> — `MSIEXEC.EXE B5AFA339`, `PECMD.EXE EB011713`

A relational store makes this a non-issue; the point is that the flat-CSV shape is what caused
the data loss, so the new tool's CSV export must not repeat it.

## 7. `Op-*.pf` files are structurally different

The two `Op-` files in the Win10 folder are the corpus's only genuine dead ends:

- They parse as v30 but **carry no §5a path field**.
- Their **header "executable name" is the whole filename**, hash included:
  `Op-EXPLORER.EXE-7A3328DA`, `Op-MSEDGE.EXE-BA103770`.
- **Neither lists its own executable** in its filename list.
- Consequently they are the **only 2 of 636 with no recoverable executable path** by any method.

A naive `*.pf` glob ingests them as ordinary prefetch and they will silently produce a row with
a malformed executable name. Detect the `Op-` prefix and label them separately.

## 8. Things that were checked and are clean

Worth recording so nobody re-tests them, and so their absence is known rather than assumed:

| Check | Result |
|---|---|
| Files with zero run times | **0** |
| `RunCount == 0` | **0** |
| Run time in the future | **0** |
| Run time earlier than its volume's creation time | **0** |
| `RunCount == len(run_times)` where RunCount ≤ 8 | **98 / 98 exact** |

That last one independently validates the "RunCount = section end − 96" rule
(`prefetch-format.md` §3.0a) without reference to PECmd.

## 9. Not testable from this corpus — do not measure, do not guess

- **Anything depending on NTFS `SourceCreated`.** The folders were copied to ext4, which did not
  preserve original creation times. This directly affects the *approximate first-run =
  SourceCreated − 10 s* feature: the logic is unchanged, but **it cannot be validated here.**
  Do not "verify" it against these copies and report a number.
- **ADS behaviour.** ext4 has no alternate data streams and the `PF.zip` in the Win10 folder
  stored only primary streams. Testing the user's own finding — that an executable run from an
  ADS gets a `.pf` which itself lives in an ADS — needs a Windows host or a raw NTFS image.
  `porting-notes.md` §5.4–5.5.
- **Prefetch disabled / SSD behaviour, UNC execution, `>MAX_PATH` paths.** No instances in
  either corpus. Absence here is not evidence of absence in general; leave the parser tolerant
  and don't build detection logic on unmeasured assumptions.

## 10. Published claims worth flagging

- *"Multiple hashes for one name ⇒ multiple locations ⇒ possible malware."* **Contradicted by
  measurement** — see §3. This is the most widely repeated prefetch heuristic and it generates
  false positives on `svchost`, `runtimebroker`, `dllhost` and `msedge` on any normal system.
- *"Deleting a `.pf` resets its creation time, so first-execution estimates are floors, not
  facts."* Consistent with everything observed; it is exactly why the ~10 s estimate is
  displayed with a `~` and never as a timestamp.

---

**Sources for the published claims** (measurements above are this project's own):
[Magnet Forensics](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/) ·
[Belkasoft](https://belkasoft.com/windows-prefetch-forensics) ·
[Prefetch execution evidence and its limits](https://sethenoka.com/prefetch-execution-evidence-and-its-limits/) ·
[oR10n Labs](https://or10nlabs.tech/prefetch-forensics/) ·
[Velociraptor artifact reference](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/)
