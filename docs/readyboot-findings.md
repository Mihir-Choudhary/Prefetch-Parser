# What ReadyBoot gives an investigator

Decoding ReadyBoot ([format](readyboot-format.md)) turned five Windows 11 files into roughly
**one million file-read events with whole paths, sizes and ordering**, across five dated boots.
This is what that is good for, what it is *not* good for, and one experiment worth running.

Everything here was measured on a real machine's Prefetch folder. Paths are redacted where they
named the account.

---

## Read this first: absence is not deletion

A ReadyBoot trace records only what was read during **that boot's 35–80 second window**. The
overlap between consecutive boots on the corpus is poor — 2,000 to 4,500 files differ each time
— because what a boot touches depends on services, timing and caching.

So:

- **A file appearing in a trace is strong evidence it existed and was read at that boot.**
- **A file missing from a later trace is almost no evidence of anything.** Not deletion, not
  uninstallation, not tampering.

Diffing two traces on the corpus produces 313 binaries "present in the first boot and absent
from all later ones", essentially all of which are ordinary Office and ClickToRun files still
sitting on the disk. That list is exactly the kind of finding that ends up in a report as
"evidence of removal" and is worth nothing. Use the presence direction only.

---

## 1. Drive letters for device paths — previously believed impossible

Prefetch records `\Device\HarddiskVolume3\…`; an analyst needs `C:\…`. The mapping is in no
`.pf` file, and the design notes in this repository stated it could not be recovered beyond
guessing the boot volume.

It can. ReadyBoot lists tens of thousands of files **per device**. `Layout.ini` lists thousands
**per drive letter**. Where the two sets overlap, they are the same volume:

| Drive letter | Device | Shared paths | Match | Next-best device |
|---|---|---|---|---|
| `C:` | `\Device\HarddiskVolume3` | 4,238 | **99.3%** | **0.0%** |

The discrimination is absolute, which is what separates a match from a correlation. A letter is
claimed only when **all four** of these hold, because a percentage on its own can be confidently
wrong:

- one device explains at least half of the letter's paths, and
- every other device explains essentially none (≤2%), and
- at least 20 paths are actually shared — *one* shared path is also "100%", and
- no other letter best-matches the same device — one device cannot be two letters, and with
  only one device present there is no competing device for the second rule to catch.

Paths that exist on every NTFS volume (`$Mft`, `$LogFile`, `System Volume Information`,
`$Recycle.Bin`, anything beginning `$`) are excluded from both sides before scoring. Left in,
a drive letter whose only known paths are filesystem metadata matches *any* device at 100% and
gets mapped to the wrong one.

If any of that fails the tool reports nothing, because a wrong drive letter in a report is worse
than a missing one.

`pfcli artifacts` prints this under **Volume identity**, labelled inferred.

## 2. One volume identity across four artifacts

Each artifact knows a different name for the same volume. Together they resolve to one:

```
C:  =  \Device\HarddiskVolume3            (ReadyBoot x Layout.ini)
    =  serial CC31B5D5                    (.pf volume records, SuperFetch)
    =  \VOLUME{01d6d2b931a49a11-cc31b5d5} (SuperFetch)
    =  created 2020-12-15 08:06:29 UTC    (the FILETIME in that name)
```

The creation time is the volume's, so it dates the **install or format** of the system drive —
a fact that appears nowhere in the `.pf` files themselves.

## 3. A boot history independent of the event log

Each trace is one boot. The file's mtime dates it; the decoded events give its duration and
volume set. When event logs have been cleared, this survives in a folder nobody thinks to wipe.

| Trace | Boot (file mtime) | Trace span | Reads | Read | Volumes seen |
|---|---|---|---|---|---|
| `Trace2.fx` | 2026-07-18 17:47:47 | 78.3 s | 173,409 | 8.0 GB | HD0, Vol1–4 |
| `Trace3.fx` | 2026-07-19 05:24:13 | 34.7 s | 228,938 | 8.7 GB | HD0, Vol1, 3, 4 |
| `Trace4.fx` | 2026-07-26 12:05:43 | 37.0 s | 220,729 | 7.4 GB | + ShadowCopy1 |
| `Trace5.fx` | 2026-08-11 18:41:51 | 80.6 s | 176,095 | 7.9 GB | + ShadowCopy3 |
| `Trace6.fx` | 2026-08-12 03:04:55 | 51.5 s | 222,611 | 6.8 GB | + ShadowCopy3 |

There is no `Trace1.fx`; the numbering has either wrapped or slot 1 was reclaimed, so treat the
set as the last five retained boots rather than the first five.

**A caution on volume presence.** `HarddiskVolume2` appears in two of the five boots and not the
other three — but with **one path and zero bytes read**, i.e. the volume was enumerated, not
used. That is not attach/detach evidence and must not be used as such. Only a device with real
reads behind it says anything.

## 4. Volume Shadow Copy access, dated

Three of the five boots read from shadow copies:

```
\Device\HarddiskVolumeShadowCopy1\$Mft
\Device\HarddiskVolumeShadowCopy1\$Secure:$SDS
\Device\HarddiskVolumeShadowCopy3\$Extend\$Reparse:$R:$INDEX_ALLOCATION
```

This places a **snapshot in existence and mounted on a specific boot**, with NTFS metadata being
read from it. Shadow copies are both a recovery source and a standard anti-forensics target
(`vssadmin delete shadows`), so evidence that one existed on 2026-07-26 and 2026-08-12 has value
even if the snapshot is now gone.

## 5. Software version timeline

Versioned install directories cannot exist before the version is installed, which makes them the
one direction of the diff that is safe to use. From the corpus:

| Product | Versions, by boot date |
|---|---|
| Edge / EdgeWebView | `150.0.4078.65` (07-19) → `150.0.4078.83` (07-26) → `151.0.4129.72` (08-12) |
| Brave | `150.1.92.141` (07-19, 07-26) → `151.1.93.132` (08-12) |
| Office ClickToRun | `16.0.20131.20154` (07-18) → `16.0.20228.20158` (08-11) |
| OneDrive | `26.108.0607.0002` (07-19) → `26.134.0713.0004` (08-12) |
| Lenovo Vantage | `5.1.2606.17` (07-18…07-26) → `5.1.2607.5` (08-11) |

Read as: the first boot showing a version bounds the install from above. It does **not** bound it
from below — the update may have happened at any point since the previous boot.

This is deliberately *not* a tool feature. Deciding what counts as a version directory is a
heuristic, and heuristics belong in an analyst's hands, not silently inside a parser.

## 6. Boot-time reads that no `.pf` records

ReadyBoot sees things prefetch does not, because it traces disk I/O rather than process launches:

- **NTFS metadata** — `$Mft` (41.8 MB in 9,609 reads on one boot), `$LogFile`, `$BitMap`,
  `$Secure`, `$UsnJrnl:$J`. The USN journal being read is itself notable; it is another common
  anti-forensics target.
- **EFI boot files** — `\Device\HarddiskVolume1\EFI\Boot\bootx64.efi` and GUID-suffixed copies
  staged by Windows Update. Bootloader tampering would surface here.
- **Registry hives as files** — `\Windows\System32\config\SOFTWARE` (576 MB read on one boot),
  `COMPONENTS`, and the `TxR` transaction logs.
- **Defender state** — definition updates and `mpcache-*` scan caches, by version-stamped path.
- **BitLocker metadata** — `System Volume Information\FVE2.{…}` in `rblayout.xin`, evidence the
  volume is encrypted.

---

## The ADS question — a mechanism proven, a case untested

ReadyBoot records paths at **NTFS stream level, not file level**. Across the corpus, 892 paths
carry stream syntax in 260 distinct forms:

```
$Secure:$SDS                              $Mft::$BITMAP
$UsnJrnl:$J                               resources.en-GB.pri::$ATTRIBUTE_LIST
$Extend\$Reparse:$R:$INDEX_ALLOCATION     …db-wal:$DSC:$LOGGED_UTILITY_STREAM
```

So the format preserves `file:stream` naming, and the tool recovers it.

**But every one of those 260 is an NTFS system attribute. The corpus contains zero user-named
alternate data streams**, because nothing on this machine stored a payload in one that was read
during boot. Whether a user-named ADS appears in the same `file.ext:streamname` form is a
reasonable inference from the system-attribute evidence — and it is *not proven here*.

That distinction matters: prefetch's own ADS behaviour was established by planting a file and
observing the result, not by reasoning about it. The same is needed here.

### The experiment

On a Windows 11 host with a ReadyBoot folder:

1. Plant a payload in an alternate data stream — e.g. `notepad.exe:payload` — and arrange for it
   to be **read during boot** (a Run key, a service, or a scheduled task set to boot trigger).
2. Reboot, then wait for a new `Trace*.fx` to be written.
3. `python -m pfcli artifacts C:\Windows\Prefetch --paths` and search the recovered paths for
   `:payload`.

If the stream name appears, ReadyBoot becomes a way to detect ADS execution **on a machine where
the ADS and its carrier have since been deleted**, because the trace is a separate file. That
would pair directly with the existing finding that an executable launched from an ADS gets its
own prefetch file inside an ADS.

If it does not appear, the honest result is that stream naming is preserved only for NTFS's own
attributes, and that is worth recording too.

---

## Applying this to a case

| Question | What to use |
|---|---|
| What does `\Device\HarddiskVolume3` mean? | Volume identity table (§1) |
| When was this system installed? | Volume creation time (§2) |
| When did this machine boot? | Trace mtimes (§3) — survives event-log clearing |
| Did a shadow copy exist on date X? | ShadowCopy device paths (§4) |
| When was this software updated? | Version directories (§5), upper bound only |
| Was the bootloader touched? | EFI paths under `HarddiskVolume1` (§6) |
| Did *this file* exist on date X? | Presence in that boot's trace — presence only, never absence |

**Standing limitation.** ReadyBoot is an **access** artifact. A path here means the boot read
that file. It never means a program ran, and it never means a user opened anything.
