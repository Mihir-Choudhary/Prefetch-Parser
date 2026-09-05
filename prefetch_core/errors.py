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
    # The furthest byte any read has reached. One integer, updated per read - enough to answer
    # "is there anything after the last structure this parser understood?", which is where
    # residual data from an earlier, longer version of the file turns up.
    high_water: int = 0
    # Merged ranges of everything read, so the parser can answer the stronger question: is
    # there anything ANYWHERE in this file that no field accounts for? Reads run mostly in
    # order, so the list stays a handful of intervals - the common case appends to or extends
    # the last one and never scans.
    covered: list[list[int]] = field(default_factory=list)

    def at(self, stage: Stage) -> "Bounds":
        self.stage = stage
        return self

    def note(self, message: str) -> None:
        """Record a non-fatal problem and carry on."""
        self.problems.append(Problem(self.stage, message))

    def fail(self, stage: "Stage", message: str) -> None:
        """Record the problem that ENDED the parse.

        `note()` says "the record is usable but imperfect", and using it for the exception that
        stopped the parse made a record whose two halves disagreed: `parsed_ok` said the file
        failed while every problem on it said `fatal = 0`, so a query for records with a fatal
        problem returned nothing at all for a folder full of failures (AUDIT BUG 111).
        """
        self.problems.append(Problem(stage, message, fatal=True))

    def check(self, offset: int, length: int, what: str) -> None:
        if offset < 0 or length < 0:
            raise PrefetchError(self.stage, f"{what}: negative offset/length ({offset}, {length})")
        if offset + length > len(self.data):
            raise PrefetchError(
                self.stage,
                f"{what}: wants bytes {offset}..{offset + length} but the file is "
                f"{len(self.data)} bytes",
            )
        if offset + length > self.high_water:
            self.high_water = offset + length
        self._cover(offset, offset + length)

    def _cover(self, start: int, end: int) -> None:
        spans = self.covered
        if spans:
            last = spans[-1]
            if start >= last[0] and start <= last[1]:     # extends or sits inside the last
                if end > last[1]:
                    last[1] = end
                return
            if start > last[1]:                           # ordinary forward step
                spans.append([start, end])
                return
        else:
            spans.append([start, end])
            return
        # Out-of-order read: insert and merge. Rare enough that the cost does not matter.
        spans.append([start, end])
        spans.sort()
        merged = [spans[0]]
        for span in spans[1:]:
            if span[0] <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], span[1])
            else:
                merged.append(span)
        self.covered = merged

    def gaps(self) -> list[tuple[int, int]]:
        """Byte ranges of the file that no read touched, in order."""
        out = []
        cursor = 0
        for start, end in self.covered:
            if start > cursor:
                out.append((cursor, start - cursor))
            cursor = max(cursor, end)
        if cursor < len(self.data):
            out.append((cursor, len(self.data) - cursor))
        return out
