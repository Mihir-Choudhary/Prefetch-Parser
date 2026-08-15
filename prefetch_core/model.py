"""Record types. Pure data - nothing here formats, prints, or decides an output path.

Two shapes here exist because measurement forced them, and both are easy to get wrong:

  * `last_run` is `max(run_times)`, **not** `run_times[0]`. The 8 slots are broadly
    newest-first but not reliably so - 6 of 636 corpus files have a newer timestamp in a later
    slot. `run_times` keeps the stored order because that order is itself evidence.
  * `executable_path` and `hosted_package` are separate. For generic hosts the 5a field names
    the *package being hosted* (DLLHOST running Microsoft.WindowsTerminal), not the exe.
"""

from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass, field

from .errors import Problem

# Windows writes the .pf roughly this long after a process starts. Single named constant so
# it can be tuned without touching call sites (design doc §5a).
FIRST_RUN_LAG_SECONDS = 10


class PathSource(enum.Enum):
    """Where `Prefetch.executable_path` came from. Never collapse these into a bare string."""

    STORED = "stored"          # the 5a field held a device path - the best case
    RESOLVED = "resolved"      # matched a single entry in the filename list
    CONFLICT = "conflict"      # both present and they disagree; see `executable_path_alt`
    AMBIGUOUS = "ambiguous"    # several filename-list candidates and nothing to choose with
    UNRESOLVED = "unresolved"  # no path from any source


@dataclass(slots=True)
class MftRef:
    """An NTFS file reference: 6-byte entry number + 2-byte sequence number."""

    entry: int
    sequence: int | None

    def __str__(self) -> str:
        return f"{self.entry}-{self.sequence}" if self.sequence is not None else str(self.entry)


@dataclass(slots=True)
class FileMetric:
    """One entry of the file-metrics array, paired with its filename.

    The reference implementation passes the wrong buffer here on v30/31, so every metric comes
    out a duplicate of entry 0. It went unnoticed because PECmd never outputs the field.
    """

    index: int
    filename: str
    name_offset: int
    name_size: int
    mft_ref: MftRef | None = None


@dataclass(slots=True)
class TraceChain:
    """One trace-chain entry. Parsed because "no data skipped" means this too.

    **Only `next_index` is confidently identified.** On v17/23/26 the second dword behaves like
    a block load count - small, ascending (10, 130, 178, 242 …) - and is exposed as such. On
    the 8-byte v30/31 entry the same slot holds values like 0xFC9FF80A and 0xFFFFF808, i.e.
    large negatives, which is not a count; naming it one would have put fabricated numbers in
    a report. It stays in `raw` under no name at all.

    `raw` always holds every dword of the entry, so nothing is lost to the naming being
    incomplete.
    """

    index: int
    next_index: int
    raw: tuple[int, ...]                    # every dword, verbatim
    block_load_count: int | None = None     # v17/23/26 only; None where unidentified

    # slots=True is load-bearing here, not tidiness: a single prefetch file carries up to
    # ~15,000 chain entries, so 150 files materialise 1.7 million of these. Without slots the
    # per-object __dict__ dominated total memory (3.1 MB per record).


@dataclass
class Volume:
    device_name: str
    serial: str
    created: datetime.datetime | None
    created_ticks: int = 0             # raw FILETIME; datetime truncates the 100-ns digit
    directories: list[str] = field(default_factory=list)
    file_refs: list[MftRef] = field(default_factory=list)
    # `\VOLUME{hex-hex}` encodes the creation FILETIME and serial, so the name can be checked
    # against the parsed fields for free. None where the name is \DEVICE\HARDDISKVOLUMEn.
    name_self_check: bool | None = None


@dataclass
class Prefetch:
    """One parsed `.pf`. Populated as far as parsing got; check `problems` and `failed_stage`."""

    source_path: str
    version: int = 0
    executable_name: str = ""          # from the header; truncates at 29 characters
    hash: str = ""                     # from the header, NOT recomputable - see below
    file_size: int = 0

    run_count: int = 0
    run_times: list[datetime.datetime] = field(default_factory=list)  # stored order, unsorted
    # Raw FILETIME ticks for the same runs, same order. datetime cannot represent the 100-ns
    # digit, so this is the only lossless copy - keep it for anything that must be exact.
    run_times_ticks: list[int] = field(default_factory=list)

    executable_path: str | None = None
    executable_path_alt: str | None = None    # the other source's answer when they disagree
    path_source: PathSource = PathSource.UNRESOLVED
    path_candidates: list[str] = field(default_factory=list)
    hosted_package: str | None = None         # Store/UWP identity from the 5a field

    filenames: list[str] = field(default_factory=list)
    metrics: list[FileMetric] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)

    total_directory_count: int = -1           # v17 stores -1; not an error
    trace_chain_count: int = 0                # as stored in the header

    # The chain array is kept as RAW BYTES and decoded on demand, not materialised.
    #
    # A single file carries up to ~15,000 chain entries; eagerly building objects for them cost
    # 1.7 million allocations per 150 files and 3.1 MB per record, which put a full 1024-file
    # folder near 3 GB. Almost nothing reads individual chains - the store persists them as a
    # blob and the UI shows a count - so paying for them up front was pure waste.
    trace_chain_raw: bytes = b""
    trace_chain_entry_size: int = 0

    @property
    def trace_chains(self) -> list[TraceChain]:
        """Decode the chain array on demand. Cheap to ignore, correct when you need it."""
        if not self.trace_chain_raw or not self.trace_chain_entry_size:
            return []
        import struct
        words_per = self.trace_chain_entry_size // 4
        count = len(self.trace_chain_raw) // self.trace_chain_entry_size
        flat = struct.unpack(f"<{count * words_per}I", self.trace_chain_raw)
        named = self.trace_chain_entry_size >= 12
        return [
            TraceChain(index=i,
                       next_index=flat[i * words_per],
                       raw=flat[i * words_per:(i + 1) * words_per],
                       block_load_count=flat[i * words_per + 1] if named else None)
            for i in range(count)
        ]

    @property
    def trace_chains_parsed(self) -> int:
        """How many entries the raw block actually holds, without decoding it."""
        if not self.trace_chain_entry_size:
            return 0
        return len(self.trace_chain_raw) // self.trace_chain_entry_size

    @property
    def total_block_load_count(self) -> int | None:
        """Summed block loads, or None on v30/31 where the field is not identified.

        None rather than 0: a zero would read as "nothing was loaded", which is a claim. None
        says the file does not tell us, which is the truth.
        """
        counts = [c.block_load_count for c in self.trace_chains
                  if c.block_load_count is not None]
        return sum(counts) if counts else None

    # Filesystem timestamps of the .pf itself. `source_created` is the artifact the
    # "approximate first run = created - 10s" estimate is built on, so it matters that it is a
    # real birth time. It stays None where the host cannot supply one (ext4 has no birth time
    # exposed via os.stat, and a copied corpus has lost it anyway). st_ctime is NOT a
    # substitute - it is inode-change time, and reporting it as creation would be a lie.
    source_created: datetime.datetime | None = None
    source_modified: datetime.datetime | None = None
    source_accessed: datetime.datetime | None = None
    source_size: int = 0

    # --- ADS provenance --------------------------------------------------
    # A prefetch recovered from an alternate data stream. `source_created` stays None for
    # these: NTFS keeps timestamps per file, not per stream, so the carrier's creation time is
    # NOT this prefetch's, and feeding it to the first-run estimate would invent an execution
    # time. Carrier times are kept below under their own names. See prefetch_core/ads.py.
    from_ads: bool = False
    carrier_path: str = ""                    # the file hosting the stream
    stream_name: str = ""                     # the ADS name, without ":...:$DATA"
    stream_size: int = 0
    timestamp_source: str = "stream"          # 'stream' | 'carrier' | 'unavailable'
    carrier_primary_size: int = 0             # 0 is the normal shape for this technique
    carrier_is_prefetch: bool = False         # was the host file itself a .pf?
    outside_prefetch_folder: bool = False
    carrier_created: datetime.datetime | None = None
    carrier_modified: datetime.datetime | None = None
    carrier_accessed: datetime.datetime | None = None

    is_op_file: bool = False                  # Op-*.pf: no 5a field, no recoverable path
    # True when a name or path contains characters that render differently than they are
    # stored - RTL overrides, zero-width, control chars. Zero occurrences in the corpora; a
    # viewer that silently renders a spoofed name shows the analyst a filename that is not the
    # filename. See winpath.has_deceptive_characters.
    deceptive_characters: bool = False
    name_truncated: bool = False              # header name is exactly 29 chars
    problems: list[Problem] = field(default_factory=list)
    failed_stage: str | None = None

    @property
    def last_run(self) -> datetime.datetime | None:
        """The newest run time.

        Deliberately `max()`, not `run_times[0]`. Near-simultaneous launches land out of order
        in the stored array; trusting slot 0 reports a stale time on ~1% of real files.
        """
        return max(self.run_times) if self.run_times else None

    @property
    def parsed_ok(self) -> bool:
        return self.failed_stage is None

    @property
    def first_run_approx(self) -> datetime.datetime | None:
        """Estimated first execution: the record's own creation time minus the write lag.

        Returns None for ADS-hosted records. They have no creation time of their own, and the
        carrier's would produce a confident-looking estimate for an unrelated event - the exact
        failure this model exists to prevent. Display with a leading "~"; never as exact.
        """
        if self.from_ads or self.source_created is None:
            return None
        return self.source_created - datetime.timedelta(seconds=FIRST_RUN_LAG_SECONDS)

    @property
    def multi_volume(self) -> bool:
        return len(self.volumes) > 1
