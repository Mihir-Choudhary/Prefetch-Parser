"""Staged error model.

PECmd has a single catch-all and a boolean `ParsingError` column, so a file that failed to
parse tells you nothing about *where* it failed and loses everything parsed up to that point.
A half-parsed prefetch is still evidence.

Every parse stage is named. A failure records the stage, keeps the partial record, and becomes
a row like any other (design doc D10: every input produces a row).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Stage(enum.Enum):
    """Parse stages, in the order they run. The failing stage tells you what survived."""

    READ = "read"                 # reading bytes off disk / out of a stream
    CONTAINER = "container"       # MAM detection and decompression
    SIGNATURE = "signature"       # version dword + 'SCCA'
    HEADER = "header"             # 84-byte header: name, hash, size
    FILEINFO = "fileinfo"         # the file-information section
    METRICS = "metrics"           # file metric array
    TRACE_CHAINS = "trace_chains"
    FILENAMES = "filenames"       # the filename string block
    EXEC_PATH = "exec_path"       # the undocumented 5a string
    VOLUMES = "volumes"           # volume records, MFT refs, directory strings


class PrefetchError(Exception):
    """Raised inside a stage. Carries the stage so the caller can record where it stopped."""

    def __init__(self, stage: Stage, message: str):
        super().__init__(f"[{stage.value}] {message}")
        self.stage = stage
        self.message = message


@dataclass
class Problem:
    """A non-fatal finding. The parse continued; the record is usable but imperfect."""

    stage: Stage
    message: str
    fatal: bool = False

    def __str__(self) -> str:
        return f"[{self.stage.value}] {self.message}"


@dataclass
class Bounds:
    """Bounds-checked reader over the decompressed buffer.

    Every field read goes through here so an offset pointing outside the file raises a
    PrefetchError naming its stage instead of an opaque struct.error or, worse, silently
    reading adjacent data as if it were the field.
    """

    data: bytes
    stage: Stage = Stage.HEADER
    problems: list[Problem] = field(default_factory=list)

    def at(self, stage: Stage) -> "Bounds":
        self.stage = stage
        return self

    def note(self, message: str) -> None:
        """Record a non-fatal problem and carry on."""
        self.problems.append(Problem(self.stage, message))

    def check(self, offset: int, length: int, what: str) -> None:
        if offset < 0 or length < 0:
            raise PrefetchError(self.stage, f"{what}: negative offset/length ({offset}, {length})")
        if offset + length > len(self.data):
            raise PrefetchError(
                self.stage,
                f"{what}: wants bytes {offset}..{offset + length} but the file is "
                f"{len(self.data)} bytes",
            )
