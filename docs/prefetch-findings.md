# Findings from the `.pf` files themselves

Measured across **636 real prefetch files** from two machines (Windows 10 and Windows 11).
Companion to [`readyboot-findings.md`](readyboot-findings.md), which covers the boot traces.

Account names and machine-specific paths are redacted to `<user>`.

---

## 1. Prefetch records the executable path in **two different notations**

This is systematic, not incidental, and it maps exactly onto how the path was obtained:

| Notation | Count | Always comes from |
|---|---|---|
| `\DEVICE\HARDDISKVOLUMEn\…` | 463 | the **stored** undocumented path field |
| `\VOLUME{creation-serial}\…` | 171 | **resolved** by matching the executable name against the file list |

The correlation is total — 458 of 463 `\DEVICE\` paths are `stored` (the other 5 are conflicts),
and **all 171** `\VOLUME{}` paths are `resolved`. The two sources inside a `.pf` simply write
volumes differently.

### Why this matters: it inflates "ran from N locations"

The widely used heuristic *"several prefetch hashes for one name ⇒ it ran from several places
⇒ suspicious"* is already weak. This makes it weaker, because the **same file** appears as two
different path strings:

```
\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\RUNTIMEBROKER.EXE
\VOLUME{01d6d2b931a49a11-cc31b5d5}\WINDOWS\SYSTEM32\RUNTIMEBROKER.EXE
```

Seven volume-relative paths in the corpus appear under **both** notations. Grouping by the raw
string overcounts distinct locations for five executables:

| Executable | Raw distinct paths | After normalising |
|---|---|---|
| `MSEDGEWEBVIEW2.EXE` | 15 | **12** |
| `DLLHOST.EXE` (Win11) | 3 | **2** |
| `RUNTIMEBROKER.EXE` | 2 | **1** |

**Strip the volume component before comparing paths.** Any tool or script that groups on the raw
string will report locations that do not exist. (This tool compares volume-relative paths
internally, so its conflict detection and `Alt Path` are unaffected.)

## 2. `.pf` carries volume **creation** timestamps — for every volume, not just the boot one

The `\VOLUME{creation-serial}\…` form embeds a FILETIME. Decoding it yields the creation (i.e.
format) time of each volume the machine referenced, straight from prefetch, with no other
artifact needed:

| Machine | Serial | Volume created (UTC) |
|---|---|---|
| Win10 | `FA013FB0` | 2017-02-21 00:32:34 |
| Win10 | `B0737ADD` | 2022-04-21 16:47:13 |
| Win10 | `5CE2B751` | 2023-05-28 23:12:34 |
| Win10 | `6BE43A52` | 2023-07-11 02:48:41 |
| Win11 | `CC31B5D5` | 2020-12-15 08:06:29 |
| Win11 | `5232ED87` | 2020-12-15 08:06:31 |
| Win11 | `EAC10B4D` | 2025-11-16 04:37:44 |

Two readings fall straight out:

- **`CC31B5D5` and `5232ED87` were created two seconds apart.** They were partitioned in the
  same operation — the original install of that machine.
- **`EAC10B4D` was created 2025-11-16, five years later**, and is referenced by `VLC.EXE`. A
  volume formatted long after the system volumes, used for media, is the signature of **storage
  attached later** — an external disk or a second drive. Prefetch dates its creation even if the
  device is long gone.

Read as an interval: the boot volume's creation time is an **upper bound on when Windows was
installed**, and a hard lower bound on every execution recorded on it.

## 3. 85% of the execution history has no surviving timestamp

Only the last **8** run times are retained, but `RunCount` keeps counting. Across the corpus:

| | |
|---|---|
| Executions recorded (sum of `RunCount`) | **19,193** |
| Timestamps actually retained | **2,903** (15.1%) |
| **Executions with no surviving timestamp** | **16,290** |

Worst offenders keep 8 timestamps out of hundreds of runs:

```
SVCHOST.EXE              1,155 runs → 8 times kept
SPPSVC.EXE                 838 runs → 8 times kept
MICROSOFTEDGEUPDATE.EXE    649 runs → 8 times kept
```

The practical consequence: **"the earliest run time in the file" is not the first execution.**
For a heavily used binary it may be minutes old while the program has run for years. `RunCount`
minus retained times is the number of executions you can prove happened but cannot date — worth
stating explicitly in a report rather than leaving implied.

## 4. Interpreter prefetch names the scripts and payloads

A `.pf` lists the files loaded during the traced startup window. For an interpreter, that list
identifies **what it was asked to run** — evidence that survives deletion of the script itself.
From the corpus:

```
POWERSHELL.EXE   25 runs
    …\TEMP\__PSSCRIPTPOLICYTEST_UWSZYKFY.YWT.PS1      (8 such files)

CMD.EXE          80 runs
    …\<user>\DESKTOP\<project>\NODE_MODULES\.BIN\WRANGLER.CMD
    …\<user>\DESKTOP\<project>\NODE_MODULES\.BIN\ASTRO.CMD

CURL.EXE         15 runs
```

`__PSScriptPolicyTest_*.ps1` files are written by PowerShell when it submits script content for
AMSI/policy evaluation. Their presence is evidence that PowerShell **executed script content**,
not merely that a console was opened — a distinction that matters when someone claims they only
opened a prompt.

Worth checking for every interpreter and LOLBin: `powershell`, `pwsh`, `cmd`, `wscript`,
`cscript`, `mshta`, `rundll32`, `regsvr32`, `wmic`, `certutil`, `bitsadmin`, `curl`, `msiexec`.

## 5. Executables run from user-writable locations

**49 of 636** records resolve to a path under `Temp`, `Downloads`, `AppData`, `ProgramData`,
`Desktop` or `Public`. Most are ordinary installer behaviour — NSIS and InnoSetup extract to
`%TEMP%\is-XXXXX.tmp\` and execute from there, which is why `.TMP` files appear as executables:

```
…\TEMP\IS-4HRGD.TMP\PROCESSHACKER-2.39-SETUP.TMP
…\WINDOWS\TEMP\{GUID}\.CR\DOTNET-SDK-9.0.315-WIN-X64.EXE
```

That is the point: the location is **normal enough to hide in**, so the path alone is not a
finding. What makes it one is the pairing with run count and timing — e.g. a `Downloads`
executable with 6 runs over weeks is a different story from a setup stub with 1 run.

## 6. Multi-volume records place a program on a second volume

Eleven records reference more than one volume, which is uncommon enough to be worth reading
individually:

```
[win10] MSIEXEC.EXE     3 volumes   FA013FB0, B0737ADD, 5CE2B751
[win10] NOTEPAD.EXE     2 volumes   B0737ADD, 6BE43A52
[win11] VLC.EXE         2 volumes   CC31B5D5, EAC10B4D   ← the 2025 volume from §2
```

`VLC.EXE` touching `EAC10B4D` ties a media player to a volume created five years after the
system drive. Combined with §2 that is a dated, per-volume statement about removable or added
storage, from prefetch alone.

## 7. Flags across the corpus, for calibration

Useful as a baseline for what "normal" looks like on two ordinary machines:

| Flag | Count of 636 |
|---|---|
| Deceptive characters in the name or path | **0** |
| `Op-*.pf` (no embedded path, no self-reference) | 2 |
| Multi-volume | 11 |
| Executable name truncated at 29 chars | 57 |
| `RunCount` exceeds retained timestamps | 234 |
| Parse failures | 0 |

Zero deceptive-character hits across 636 files means that check is **quiet on clean systems** —
so a single hit is worth investigating rather than dismissing as noise.

---

## Applying this

| Question | What to use |
|---|---|
| Did this binary run from more than one location? | Normalise volume prefixes first (§1) |
| When was this volume formatted? | `\VOLUME{}` FILETIME (§2) |
| Was there another disk attached? | Volume creation years apart + multi-volume records (§2, §6) |
| How many runs can I actually date? | `RunCount` vs retained times (§3) |
| What script did PowerShell run? | Loaded-file list of the interpreter's `.pf` (§4) |
| When was Windows installed? | Boot-volume creation time as an upper bound (§2) |

**Standing limitation.** A `.pf` proves an executable *ran*. It does not prove who ran it, with
what arguments, or to what effect — and the loaded-file list is what the program touched in
roughly its first ten seconds, not everything it ever did.
