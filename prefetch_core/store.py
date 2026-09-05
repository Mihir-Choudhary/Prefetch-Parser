"""SQLite store. The primary artifact - CSV is an export, not the source of truth.

Why relational rather than one wide row per prefetch (design doc §3): a `.pf` holds several
one-to-many relationships - run times, loaded files, volumes, per-volume directories, MFT
references. Flattening them is what makes PECmd's CSV lose data: it has columns for only two
volumes and concatenates every volume's directory list with no separator.

Nothing here formats for display. Timestamps are stored as ISO-8601 UTC strings *and* as raw
FILETIME ticks, because Python's datetime cannot represent the 100-ns digit and the lossless
value must survive into the database.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import sqlite3

from . import winpath
from .model import PathSource, Prefetch

SCHEMA = """
-- Deliberately NOT WAL. WAL leaves `-wal` and `-shm` sidecars, and if the process is killed
-- before a checkpoint the committed data lives only in the `-wal`. An analyst who then copies
-- just the `.db` - the obvious thing to do with an evidence artifact - opens a database that
-- reports "no such table: prefetch". Silent total data loss with no error.
--
-- Measured: WAL is not even faster here (0.13 s vs 0.11 s to ingest 184 files), so it was
-- costing correctness for nothing.
PRAGMA journal_mode = DELETE;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS prefetch (
    id                  INTEGER PRIMARY KEY,
    source_path         TEXT    NOT NULL,   -- as supplied, for reporting
    -- Normalised path used for de-duplication. Comparing raw source_path let `dir/x.pf` and
    -- `dir/./x.pf` insert twice, so a re-scan spelled differently silently doubled rows.
    source_key          TEXT,
    source_name         TEXT    NOT NULL,
    version             INTEGER,
    executable_name     TEXT,
    hash                TEXT,            -- always 8 hex chars; PECmd drops leading zeros
    file_size           INTEGER,
    run_count           INTEGER,
    last_run            TEXT,            -- max(run_times), NOT the first slot
    last_run_ticks      INTEGER,
    executable_path     TEXT,
    executable_path_alt TEXT,            -- the other source's answer when they disagree
    path_source         TEXT,
    hosted_package      TEXT,            -- UWP package a generic host was running
    total_dir_count     INTEGER,
    trace_chain_count   INTEGER,
    -- The chain array verbatim, plus its entry width so it can be decoded back. Stored as one
    -- blob rather than a row per entry: files carry up to ~15,000 entries, which would be
    -- millions of rows of data with a single identified field. "No data skipped" is satisfied
    -- losslessly either way; this way the database stays usable.
    trace_chain_raw     BLOB,
    trace_chain_width   INTEGER,
    volume_count        INTEGER,
    file_count          INTEGER,
    is_op_file          INTEGER,
    deceptive_chars     INTEGER,   -- name/path renders differently than it is stored
    name_truncated      INTEGER,
    failed_stage        TEXT,            -- NULL when the parse completed
    parsed_ok           INTEGER,
    -- Filesystem timestamps of the .pf file itself. The CSV has carried these since the first
    -- release and the database did not, so the artifact described as the source of truth held
    -- no file times at all - and `source_created` is what the first-run estimate is built on
    -- (AUDIT BUG 71).
    source_created      TEXT,
    source_created_est  TEXT,      -- created - 10s: approximate first run, NULL for ADS records
    source_modified     TEXT,
    source_accessed     TEXT,
    source_size         INTEGER,
    -- Where the record came from, when it was not a file in a Prefetch folder. Without these a
    -- record recovered from an alternate data stream sits in the same columns as an ordinary
    -- one, carrying the CARRIER's timestamps with nothing to say so (AUDIT BUG 72).
    from_ads            INTEGER NOT NULL DEFAULT 0,
    carrier_path        TEXT,
    stream_name         TEXT,
    stream_size         INTEGER,
    timestamp_source    TEXT,      -- 'stream' | 'carrier' | 'unavailable'
    carrier_primary_size INTEGER,
    carrier_is_prefetch INTEGER,
    outside_prefetch_folder INTEGER,
    carrier_created     TEXT,
    carrier_modified    TEXT,
    carrier_accessed    TEXT,
    -- Regions no published description names, kept verbatim so a field nobody has decoded yet
    -- is still recoverable from the tool's own output. They were retained on the record and
    -- printed by `pfcli info`, but reached neither export - which made the claim true only for
    -- someone reading console text (AUDIT BUG 73). Stored like residue: bytes, not a guess.
    header_raw          BLOB,
    fileinfo_raw        BLOB,
    fileinfo_offset     INTEGER,
    -- The filename against the record's own header: 'ok' | 'mismatch' | 'n/a'. A prefetch
    -- filename is derived from the executable name and a path hash, and the header holds both
    -- independently - so a disagreement means renamed, copied, or planted (AUDIT BUG 75).
    filename_hash_match TEXT,
    filename_name_match TEXT,
    -- Bytes riding along after the end of the compressed stream, and which decoder measured
    -- it. NULL means not measured (the OS decompressor does not report input consumed), which
    -- is not the same as zero (AUDIT BUG 78).
    container_trailing_bytes INTEGER,
    decompressor_used   TEXT
);

CREATE TABLE IF NOT EXISTS run_time (
    prefetch_id INTEGER NOT NULL REFERENCES prefetch(id) ON DELETE CASCADE,
    slot        INTEGER NOT NULL,        -- stored position; NOT sorted, and that is evidence
    run_time    TEXT    NOT NULL,
    ticks       INTEGER NOT NULL,
    is_newest   INTEGER NOT NULL         -- 1 for max(); not always slot 0
);

CREATE TABLE IF NOT EXISTS volume (
    id            INTEGER PRIMARY KEY,
    prefetch_id   INTEGER NOT NULL REFERENCES prefetch(id) ON DELETE CASCADE,
    ordinal       INTEGER NOT NULL,
    device_name   TEXT,
    serial        TEXT,
    created       TEXT,
    created_ticks INTEGER,
    name_check    TEXT,                  -- 'ok' | 'mismatch' | 'n/a' - three states, never two
    dir_count     INTEGER,
    ref_count     INTEGER,
    -- The undecoded tail of this volume entry, and the version word of its reference array.
    -- Same reason as `header_raw` above.
    raw_tail      BLOB,
    ref_array_version INTEGER,
    -- What the reference array's own header declares, beside the number of slots that actually
    -- hold a reference (`ref_count`). Reporting only the latter turned "3 of 35 slots" into
    -- "3 references" and lost what the file said (AUDIT BUG 76).
    declared_ref_count INTEGER
);

CREATE TABLE IF NOT EXISTS directory (
    volume_id INTEGER NOT NULL REFERENCES volume(id) ON DELETE CASCADE,
    ordinal   INTEGER NOT NULL,
    path      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS loaded_file (
    prefetch_id  INTEGER NOT NULL REFERENCES prefetch(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    path         TEXT    NOT NULL,
    mft_entry    INTEGER,
    mft_sequence INTEGER,
    -- The file's own slice of the trace-chain array, and the metric flags. Every other
    -- prefetch tool discards these as "unknown"; they are the only link between a loaded file
    -- and the prefetcher's block-load bookkeeping.
    chain_start  INTEGER,
    chain_count  INTEGER,
    chain_subset INTEGER,
    metric_flags INTEGER
);

CREATE TABLE IF NOT EXISTS file_ref (
    volume_id    INTEGER NOT NULL REFERENCES volume(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    -- The slot this reference occupied in the array. Empty slots are not stored - they hold
    -- nothing - but the position of the ones that are is evidence in itself.
    slot         INTEGER,
    mft_entry    INTEGER NOT NULL,
    mft_sequence INTEGER,
    -- 'declared': counted by the file. 'slack': found in the array past the count it states,
    -- so it is evidence the file does not claim. Filter on this before reporting.
    source       TEXT NOT NULL DEFAULT 'declared'
);

-- Bytes belonging to no field of the record: residue of an earlier version of the same file.
-- Stored verbatim (capped) so an examiner can carve or hash them, with the decoded text where
-- the bytes read as UTF-16.
CREATE TABLE IF NOT EXISTS residue (
    prefetch_id INTEGER NOT NULL REFERENCES prefetch(id) ON DELETE CASCADE,
    offset      INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    text        TEXT    NOT NULL,
    bytes       BLOB    NOT NULL
);

-- The rest of the Prefetch folder: Layout.ini, the SuperFetch databases, ReadyBoot traces,
-- PfPre_*.mkd and anything unrecognised. Deliberately NOT merged into `prefetch`: these record
-- file ACCESS and prefetcher priority, not execution, and a per-execution table is the wrong
-- shape for them. But "a different table" is not the same as "no table", and until Round 45
-- these existed only as console text and a GUI window - tens of thousands of file paths an
-- investigator could not get into a report without retyping them (AUDIT BUG 80).
CREATE TABLE IF NOT EXISTS artifact (
    id            INTEGER PRIMARY KEY,
    source_path   TEXT    NOT NULL,
    source_key    TEXT,                  -- realpath, for idempotent re-ingest
    name          TEXT    NOT NULL,
    kind          TEXT    NOT NULL,      -- layout | superfetch | readyboot | pfpre | unrecognised | unreadable
    size          INTEGER,
    modified      TEXT,
    path_count    INTEGER
);

-- Every path an artifact names. `detail` carries what the artifact type knows about that path:
-- ReadyBoot's read count and bytes read, SuperFetch's per-record timestamp where it has one.
CREATE TABLE IF NOT EXISTS artifact_path (
    artifact_id INTEGER NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    path        TEXT    NOT NULL,
    detail      TEXT
);

-- Everything else the artifact states about itself: record counts, compression, database type,
-- volume identity, hash-verification totals. Key/value because the fields differ per kind and
-- inventing a column per kind would be a lie about how uniform they are.
CREATE TABLE IF NOT EXISTS artifact_fact (
    artifact_id INTEGER NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
    key         TEXT    NOT NULL,
    value       TEXT
);

CREATE TABLE IF NOT EXISTS artifact_problem (
    artifact_id INTEGER NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
    message     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS problem (
    prefetch_id INTEGER NOT NULL REFERENCES prefetch(id) ON DELETE CASCADE,
    stage       TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    fatal       INTEGER NOT NULL
);

"""

# Indexes are applied AFTER any migration, never inside SCHEMA.
#
# SCHEMA's CREATE TABLE is a no-op on an existing database, so an index over a column that a
# migration is about to add fails with "no such column" before the column exists. Keeping them
# separate makes adding a column to the schema safe by construction rather than by remembering.
INDEXES = """
CREATE INDEX IF NOT EXISTS ix_pf_key      ON prefetch(source_key);
CREATE INDEX IF NOT EXISTS ix_pf_exe      ON prefetch(executable_name);
CREATE INDEX IF NOT EXISTS ix_pf_path     ON prefetch(executable_path);
CREATE INDEX IF NOT EXISTS ix_pf_lastrun  ON prefetch(last_run);
CREATE INDEX IF NOT EXISTS ix_run_pf      ON run_time(prefetch_id);
CREATE INDEX IF NOT EXISTS ix_loaded_pf   ON loaded_file(prefetch_id);
CREATE INDEX IF NOT EXISTS ix_loaded_path ON loaded_file(path);
CREATE INDEX IF NOT EXISTS ix_dir_vol     ON directory(volume_id);
"""

# One row per execution, for the timeline view and CSV export.
#
# DROP first: `CREATE VIEW IF NOT EXISTS` on a database written by an older build keeps that
# build's definition, so a changed view would silently keep returning the old columns - the
# worst kind of drift, because the query succeeds. A view holds no data, so rebuilding it every
# open costs nothing and cannot lose anything.
TIMELINE_VIEW = """
DROP VIEW IF EXISTS timeline;
CREATE VIEW timeline AS
SELECT r.run_time            AS run_time,
       p.executable_name     AS executable_name,
       p.executable_path     AS executable_path,
       p.path_source         AS path_source,
       p.hosted_package      AS hosted_package,
       p.hash                AS hash,
       p.run_count           AS run_count,
       r.is_newest           AS is_last_run,
       p.source_name         AS source_name
FROM run_time r JOIN prefetch p ON p.id = r.prefetch_id
ORDER BY r.run_time DESC;
"""


def _iso(dt: datetime.datetime | None) -> str | None:
    return dt.isoformat(sep=" ") if dt else None


def _tri(value: bool | None) -> str:
    """Three states, never two. Collapsing 'not applicable' into 'failed' would fire on every
    \\DEVICE\\HARDDISKVOLUMEn volume, i.e. most of the older corpus."""
    return "n/a" if value is None else ("ok" if value else "mismatch")


# Bumped whenever SCHEMA changes in a way an older build cannot read. Stamped into the file as
# `PRAGMA user_version`, so a database written by a *newer* build than this one is refused with
# a message instead of failing somewhere deep in an INSERT.
SCHEMA_VERSION = 7


def _expected_schema() -> dict[str, list[dict]]:
    """The tables and columns SCHEMA declares, read back from SQLite itself.

    This used to be a hand-maintained list of added columns, which drifted the moment three
    columns were added to `loaded_file` and one to `file_ref` without anyone updating it: a
    database from the previous release then died on the next INSERT with
    `table loaded_file has 5 columns but 9 values were supplied` (AUDIT BUG 63). Deriving the
    expectation from the same string that creates the tables cannot drift.
    """
    mem = sqlite3.connect(":memory:")
    try:
        mem.executescript(SCHEMA)
        out = {}
        for (table,) in mem.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"):
            out[table] = [{"name": r[1], "type": r[2], "notnull": r[3], "default": r[4]}
                          for r in mem.execute(f"PRAGMA table_info({table})")]
        return out
    finally:
        mem.close()


class StoreError(Exception):
    """Opening or writing the database failed, with a message meant for a human.

    Raw `sqlite3.OperationalError: unable to open database file` reaches the user as a
    traceback that names neither the path nor the likely cause. Callers can catch this and
    print it directly.
    """


# SQLite keeps pathnames in a fixed buffer and must fit its journal suffix beside the name. On
# the POSIX build that buffer is 512 bytes, so the ceiling is 512 - len("-journal") - 1;
# measured on this build (sqlite 3.46.1), 500 characters opens and 505 fails. The Windows build
# uses a larger buffer, so there the number in the message is conservative - the remedy it gives
# is the same, and being early with the explanation is the harmless direction.
_SQLITE_PATH_LIMIT = 512 - len("-journal") - 1


def _clean(params):
    """Render any undecodable filesystem string in a parameter row before SQLite sees it."""
    if isinstance(params, dict):
        return {k: winpath.readable_text(v) if isinstance(v, str) else v
                for k, v in params.items()}
    return type(params)(winpath.readable_text(v) if isinstance(v, str) else v
                        for v in params) if isinstance(params, (tuple, list)) else params


class _TextSafeCursor:
    """A cursor that cannot be killed by a filename which is not valid text.

    A name does not have to be valid UTF-8 - NTFS allows unpaired surrogates, and a folder
    copied out of an image carries whatever bytes it held. `os.walk` returns those as lone
    surrogates, and **SQLite refuses to bind them**: `UnicodeEncodeError`, raised from inside
    the driver, caught by nothing, so one such file ended the entire run with a traceback and
    no report at all (AUDIT BUG 102).

    One seam rather than a call at each of twenty INSERTs: every parameter row for this record
    goes through here, so nothing can be added later that forgets. The escaped form is what is
    stored *and* what is looked up, so `source_key` stays consistent between the two.
    """

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=()):
        return self._cursor.execute(sql, _clean(params))

    def executemany(self, sql, rows):
        return self._cursor.executemany(sql, (_clean(row) for row in rows))

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class Store:
    """Writer/reader over one SQLite database. Use as a context manager."""

    def __init__(self, path: str):
        self.path = path
        try:
            # `long_path` on the connect argument only: `self.path` stays what the analyst
            # typed, and a database inside a deeply nested case folder still opens on Windows,
            # where every file API stops at 260 characters (AUDIT BUG 99). SQLite creates its
            # journal beside the file it was given, so the prefix carries to that as well.
            self.conn = sqlite3.connect(winpath.long_path(path))
            self.conn.row_factory = sqlite3.Row
            # Explicit transaction control. With Python's implicit handling there is no way to
            # undo a record that failed halfway through its own inserts, and `close()` then
            # commits the fragment: a prefetch row with no executable, no loaded files and
            # NULL `parsed_ok`, indistinguishable from a real record until someone queries it
            # (AUDIT BUG 64). Records are now wrapped in a SAVEPOINT each.
            self.conn.isolation_level = None
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.executescript(INDEXES)
            self.conn.executescript(TIMELINE_VIEW)
        except sqlite3.DatabaseError as exc:
            hint = ""
            if "not a database" in str(exc):
                hint = " (the file exists and is not a SQLite database)"
            elif "unable to open" in str(exc):
                directory = os.path.dirname(os.path.abspath(path))
                if os.path.isdir(path):
                    hint = " (that path is a directory)"
                elif not os.path.isdir(directory):
                    hint = f" (no such directory: {directory})"
                elif not os.access(directory, os.W_OK):
                    hint = f" (directory is not writable: {directory})"
                elif len(os.path.abspath(path)) > _SQLITE_PATH_LIMIT:
                    # Not permissions, not a missing directory: SQLite itself holds pathnames
                    # in a 512-byte buffer and has to fit "-journal" beside the name, so a
                    # database more than ~504 characters deep cannot be opened at all. The CSV
                    # beside it writes perfectly, which makes "unable to open database file"
                    # read like a permissions problem and sends the analyst looking in
                    # entirely the wrong place (AUDIT BUG 101). Triage output nests deeply -
                    # C:\Cases\<case>\<host>\<tool>\<timestamp>\C\Windows\Prefetch - so this
                    # is a real place to land, and the database does not have to live beside
                    # the evidence.
                    hint = (f" (the path is {len(os.path.abspath(path))} characters; SQLite "
                            f"holds pathnames in a fixed buffer and cannot open a database "
                            f"much beyond {_SQLITE_PATH_LIMIT} - the exact figure is the "
                            f"POSIX build's; write it to a shorter path, the database need "
                            f"not sit beside the evidence)")
            raise StoreError(f"cannot open database {path!r}: {exc}{hint}") from exc

    def _migrate(self):
        """Bring a database written by an older build up to this build's schema.

        `CREATE TABLE IF NOT EXISTS` leaves an *existing* table alone, so a column added to
        SCHEMA never reaches a database that already has that table: every INSERT then fails
        with a message about a column count, which says nothing useful and loses the whole run.

        Every table is checked, not just `prefetch`. What was added is recorded in
        `self.migrations_applied` so the caller can tell the analyst that their evidence
        database was altered, and that rows written before the upgrade hold NULL in the new
        columns - absent, not measured.
        """
        self.migrations_applied: list[str] = []
        found = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if found > SCHEMA_VERSION:
            raise StoreError(
                f"cannot open database {self.path!r}: it was written by a newer version of "
                f"this tool (schema {found}, this build understands {SCHEMA_VERSION}). "
                f"Use the newer build, or write to a new file.")

        for table, columns in _expected_schema().items():
            have = {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}
            if not have:
                continue                      # CREATE TABLE IF NOT EXISTS just made it
            for column in columns:
                if column["name"] in have:
                    continue
                if column["notnull"] and column["default"] is None:
                    raise StoreError(
                        f"cannot upgrade database {self.path!r}: column "
                        f"{table}.{column['name']} is NOT NULL with no default, so it cannot "
                        f"be added to an existing table. Write to a new file.")
                decl = f"{column['name']} {column['type']}"
                if column["notnull"]:
                    decl += " NOT NULL"
                if column["default"] is not None:
                    decl += f" DEFAULT {column['default']}"
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {decl}")
                self.migrations_applied.append(f"{table}.{column['name']}")

        if found != SCHEMA_VERSION:
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        if self.conn.in_transaction:
            self.conn.execute("COMMIT")

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextlib.contextmanager
    def _sqlite_errors(self, doing: str):
        """Turn any sqlite failure into a StoreError naming the file and what was happening.

        A raw `sqlite3.OperationalError: disk I/O error` escaping from `commit()` or `close()`
        reached the CLI as a traceback and discarded the entire run - including the CSV, which
        the caller explicitly writes separately so that one unwritable destination cannot cost
        the other (AUDIT BUG 65). Errors inside `add` are already wrapped; these are the ones
        that happen between records.
        """
        try:
            yield
        except sqlite3.Error as exc:
            raise StoreError(f"cannot {doing} {self.path!r}: {exc}") from exc

    def _begin(self) -> None:
        """Open a transaction if one is not already running."""
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")

    def commit(self) -> None:
        with self._sqlite_errors("commit to"):
            if self.conn.in_transaction:
                self.conn.execute("COMMIT")

    def close(self) -> None:
        """Commit what completed and close.

        Records that failed have already been rolled back individually, so committing here
        keeps a partial *run* - which is the point of `add_all`'s periodic commits - without
        ever keeping a partial *record*.

        The handle is closed even when the commit fails, so a caller that reports the error and
        carries on is not left holding a locked database.
        """
        try:
            self.commit()
        finally:
            with self._sqlite_errors("close"):
                self.conn.close()

    def add(self, pf: Prefetch) -> int:
        """Insert one record, replacing any previous record for the same source path.

        Re-scanning the same folder into an existing database is a normal thing to do, and
        without this it silently doubles every row - 20 files ingested twice became 40 prefetch
        rows and 188 run times, with no error and no warning. Counts in a report would then be
        wrong in a way nothing surfaces. Ingest is therefore idempotent per source path.

        The whole record is one savepoint: it lands completely or not at all. A record that
        fails partway used to leave its parent row behind, and a half-written row in an
        evidence database looks exactly like a real one (AUDIT BUG 64).
        """
        with self._sqlite_errors("write to"):
            self._begin()
            self.conn.execute("SAVEPOINT record")
        try:
            pid = self._add(pf)
        except BaseException as exc:
            # The undo must not be able to replace the diagnosis. A full disk aborts the whole
            # transaction, savepoint and all, so `ROLLBACK TO record` then fails with
            # "no such savepoint: record" - and that, not "disk full", was what the analyst
            # saw (AUDIT BUG 67). Whatever happens here, the original error is what is raised.
            for statement in ("ROLLBACK TO record", "RELEASE record"):
                try:
                    self.conn.execute(statement)
                except sqlite3.Error:
                    break
            if isinstance(exc, sqlite3.Error):
                raise StoreError(
                    f"cannot write {pf.source_path!r} to {self.path!r}: {exc}") from exc
            raise
        with self._sqlite_errors(f"finish writing {pf.source_path!r} to"):
            self.conn.execute("RELEASE record")
        return pid

    def _add(self, pf: Prefetch) -> int:
        """The inserts themselves. Always called inside `add`'s savepoint."""
        c = _TextSafeCursor(self.conn.cursor())
        # A record with no source path names nothing, so it can be de-duplicated against
        # nothing. Keying those on "" made every such record collide with the last one: two
        # buffers parsed in memory and added to the same database left ONE row, silently
        # (AUDIT BUG 69). NULL never equals NULL in SQL, which is exactly the wanted rule.
        source_key = os.path.realpath(pf.source_path) if pf.source_path else None
        if source_key is not None:
            for (old_id,) in c.execute("SELECT id FROM prefetch WHERE source_key = ?",
                                       (source_key,)).fetchall():
                self._delete(c, old_id)
        last = pf.last_run
        last_ticks = max(pf.run_times_ticks) if pf.run_times_ticks else None
        c.execute(
            """INSERT INTO prefetch (source_path, source_key, source_name, version, executable_name, hash,
                    file_size, run_count, last_run, last_run_ticks, executable_path,
                    executable_path_alt, path_source, hosted_package, total_dir_count,
                    trace_chain_count, trace_chain_raw, trace_chain_width, volume_count,
                    file_count, is_op_file, deceptive_chars, name_truncated, failed_stage,
                    parsed_ok,
                    source_created, source_created_est, source_modified, source_accessed,
                    source_size, from_ads, carrier_path, stream_name, stream_size,
                    timestamp_source, carrier_primary_size, carrier_is_prefetch,
                    outside_prefetch_folder, carrier_created, carrier_modified,
                    carrier_accessed, header_raw, fileinfo_raw, fileinfo_offset,
                    filename_hash_match, filename_name_match,
                    container_trailing_bytes, decompressor_used)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                       ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pf.source_path, source_key, os.path.basename(pf.source_path), pf.version, pf.executable_name,
             pf.hash, pf.file_size, pf.run_count, _iso(last), last_ticks, pf.executable_path,
             pf.executable_path_alt,
             pf.path_source.value if isinstance(pf.path_source, PathSource) else pf.path_source,
             pf.hosted_package, pf.total_directory_count, pf.trace_chain_count,
             pf.trace_chain_raw or None, pf.trace_chain_entry_size or None,
             len(pf.volumes), len(pf.filenames), int(pf.is_op_file),
             int(pf.deceptive_characters), int(pf.name_truncated),
             pf.failed_stage, int(pf.parsed_ok),
             _iso(pf.source_created), _iso(pf.first_run_approx), _iso(pf.source_modified),
             _iso(pf.source_accessed), pf.source_size or None,
             # NULL, not 0 or 'stream', when the record did not come from a stream: three
             # states, never two. A default written as data reads as a measurement.
             int(pf.from_ads), pf.carrier_path or None, pf.stream_name or None,
             pf.stream_size if pf.from_ads else None,
             # Every record, not only the ADS ones: NULL here means "not measured", and whose
             # timestamps these are IS measured for an ordinary file (AUDIT BUG 106).
             pf.timestamp_source,
             pf.carrier_primary_size if pf.from_ads else None,
             int(pf.carrier_is_prefetch) if pf.from_ads else None,
             int(pf.outside_prefetch_folder) if pf.from_ads else None,
             _iso(pf.carrier_created), _iso(pf.carrier_modified), _iso(pf.carrier_accessed),
             pf.header_raw or None, pf.fileinfo_raw or None, pf.fileinfo_offset or None,
             _tri(pf.filename_hash_match), _tri(pf.filename_name_match),
             pf.container_trailing_bytes, pf.decompressor_used or None),
        )
        pid = c.lastrowid

        # Flag exactly one row as newest. 4 corpus files store the same timestamp twice, so
        # `t == max(...)` would flag both and the timeline would report two "last runs" for one
        # program. Pick the first slot holding the maximum.
        newest_slot = (max(range(len(pf.run_times)), key=lambda i: pf.run_times[i])
                       if pf.run_times else None)
        for i, t in enumerate(pf.run_times):
            ticks = pf.run_times_ticks[i] if i < len(pf.run_times_ticks) else 0
            c.execute("INSERT INTO run_time VALUES (?,?,?,?,?)",
                      (pid, i, _iso(t), ticks, int(i == newest_slot)))

        for i, m in enumerate(pf.metrics):
            c.execute("INSERT INTO loaded_file VALUES (?,?,?,?,?,?,?,?,?)",
                      (pid, i, m.filename,
                       m.mft_ref.entry if m.mft_ref else None,
                       m.mft_ref.sequence if m.mft_ref else None,
                       m.chain_start, m.chain_count, m.chain_subset, m.flags))
        # Files present in the string block but with no metric of their own would otherwise be
        # dropped; "no data skipped" means the union, not whichever list is shorter.
        for i in range(len(pf.metrics), len(pf.filenames)):
            c.execute("INSERT INTO loaded_file VALUES (?,?,?,?,?,?,?,?,?)",
                      (pid, i, pf.filenames[i], None, None, None, None, None, None))

        for j, v in enumerate(pf.volumes):
            c.execute("""INSERT INTO volume (prefetch_id, ordinal, device_name, serial, created,
                              created_ticks, name_check, dir_count, ref_count, raw_tail,
                              ref_array_version, declared_ref_count)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (pid, j, v.device_name, v.serial, _iso(v.created), v.created_ticks,
                       _tri(v.name_self_check), len(v.directories), len(v.file_refs),
                       v.raw_tail or None, v.ref_array_version, v.declared_ref_count))
            vid = c.lastrowid
            c.executemany("INSERT INTO directory VALUES (?,?,?)",
                          [(vid, k, d) for k, d in enumerate(v.directories)])
            c.executemany("INSERT INTO file_ref VALUES (?,?,?,?,?,?)",
                          [(vid, k, v.ref_slots[k] if k < len(v.ref_slots) else None,
                            r.entry, r.sequence, "declared")
                           for k, r in enumerate(v.file_refs)])
            # Written with source='slack' so a query can include or exclude them deliberately.
            # A slack reference sits past the declared slots, so it has no slot of its own.
            c.executemany("INSERT INTO file_ref VALUES (?,?,?,?,?,?)",
                          [(vid, len(v.file_refs) + k, None, r.entry, r.sequence, "slack")
                           for k, r in enumerate(v.slack_refs)])

        c.executemany("INSERT INTO residue VALUES (?,?,?,?,?)",
                      [(pid, r.offset, r.size, r.text, r.data) for r in pf.residue])

        for p in pf.problems:
            c.execute("INSERT INTO problem VALUES (?,?,?,?)",
                      (pid, p.stage.value, p.message, int(p.fatal)))
        return pid

    @staticmethod
    def _delete(cursor, prefetch_id: int) -> None:
        """Remove a record and its children.

        Done explicitly rather than relying on ON DELETE CASCADE: `PRAGMA foreign_keys` is
        per-connection and off by default in SQLite, so a caller opening the file with any
        other client would leave orphans behind.
        """
        vol_ids = [r[0] for r in cursor.execute(
            "SELECT id FROM volume WHERE prefetch_id = ?", (prefetch_id,)).fetchall()]
        for vid in vol_ids:
            cursor.execute("DELETE FROM directory WHERE volume_id = ?", (vid,))
            cursor.execute("DELETE FROM file_ref WHERE volume_id = ?", (vid,))
        for table in ("volume", "run_time", "loaded_file", "problem", "residue"):
            cursor.execute(f"DELETE FROM {table} WHERE prefetch_id = ?", (prefetch_id,))
        cursor.execute("DELETE FROM prefetch WHERE id = ?", (prefetch_id,))

    def add_artifact(self, art) -> int:
        """Insert one non-.pf artifact, replacing any previous record of the same file.

        Same savepoint rule as `add`: whole or nothing. Same idempotency rule: keyed on the
        real path, so re-scanning a folder updates rather than doubles.
        """
        with self._sqlite_errors("write to"):
            self._begin()
            self.conn.execute("SAVEPOINT artifact")
        try:
            aid = self._add_artifact(art)
        except BaseException as exc:
            for statement in ("ROLLBACK TO artifact", "RELEASE artifact"):
                try:
                    self.conn.execute(statement)
                except sqlite3.Error:
                    break
            if isinstance(exc, sqlite3.Error):
                raise StoreError(f"cannot write {art.path!r} to {self.path!r}: {exc}") from exc
            raise
        with self._sqlite_errors("finish writing an artifact to"):
            self.conn.execute("RELEASE artifact")
        return aid

    def _add_artifact(self, art) -> int:
        c = _TextSafeCursor(self.conn.cursor())
        source_key = os.path.realpath(art.path) if art.path else None
        if source_key is not None:
            for (old_id,) in c.execute("SELECT id FROM artifact WHERE source_key = ?",
                                       (source_key,)).fetchall():
                for table in ("artifact_path", "artifact_fact", "artifact_problem"):
                    c.execute(f"DELETE FROM {table} WHERE artifact_id = ?", (old_id,))
                c.execute("DELETE FROM artifact WHERE id = ?", (old_id,))
        c.execute("""INSERT INTO artifact (source_path, source_key, name, kind, size, modified,
                          path_count)
                     VALUES (?,?,?,?,?,?,?)""",
                  (art.path, source_key, art.name, art.kind, art.size, _iso(art.modified),
                   len(art.paths)))
        aid = c.lastrowid

        # ReadyBoot states a read count and a byte total per file; SuperFetch's static
        # databases state a timestamp per record. Both are attached to the path they belong to
        # rather than flattened away.
        detail_by_path = {p: f"reads={reads} bytes={nbytes}"
                          for p, reads, nbytes in getattr(art, "io_by_path", [])}
        c.executemany("INSERT INTO artifact_path VALUES (?,?,?,?)",
                      [(aid, i, p, detail_by_path.get(p))
                       for i, p in enumerate(art.paths)])
        # A path that only appears in io_by_path (ReadyBoot lists I/O for files it also names,
        # but a future variant might not) must not be lost either.
        extra = [p for p, _r, _b in getattr(art, "io_by_path", []) if p not in set(art.paths)]
        c.executemany("INSERT INTO artifact_path VALUES (?,?,?,?)",
                      [(aid, len(art.paths) + i, p, detail_by_path[p])
                       for i, p in enumerate(extra)])

        facts = [(aid, key, None if value is None else str(value))
                 for key, value in art.facts.items() if key != "paths"]
        for i, volume in enumerate(getattr(art, "volumes", [])):
            for key, value in volume.items():
                facts.append((aid, f"volume{i}.{key}", None if value is None else str(value)))
        c.executemany("INSERT INTO artifact_fact VALUES (?,?,?)", facts)
        c.executemany("INSERT INTO artifact_problem VALUES (?,?)",
                      [(aid, str(p)) for p in art.problems])
        return aid

    def add_artifacts(self, artifacts, commit_every: int = 20) -> int:
        n = 0
        for art in artifacts:
            self.add_artifact(art)
            n += 1
            if n % commit_every == 0:
                self.commit()
        self.commit()
        return n

    def add_all(self, records, commit_every: int = 100) -> int:
        """Ingest an iterable of records, committing periodically.

        Periodic commits matter for an interrupted run: parsing a large folder takes tens of
        seconds, and a single commit at the end means Ctrl-C loses everything. Committing in
        batches leaves a valid database holding whatever completed.
        """
        n = 0
        for pf in records:
            self.add(pf)
            n += 1
            if n % commit_every == 0:
                self.commit()
        self.commit()
        return n

    # -- reading -----------------------------------------------------------
    def rows(self, sql: str = "SELECT * FROM prefetch", params=()) -> list[sqlite3.Row]:
        """Run a query. A malformed one is the caller's mistake, but it is still reported as a
        StoreError rather than as a traceback out of the GUI's detail pane."""
        with self._sqlite_errors("read from"):
            return self.conn.execute(sql, params).fetchall()

    def counts(self) -> dict[str, int]:
        """Row counts for every table SCHEMA declares.

        Derived rather than listed: the hand-written list here silently omitted `residue` the
        moment that table was added, so a caller asking the store what it holds was told about
        six tables out of seven. Same failure as the migration list (AUDIT BUG 63), same fix.
        """
        with self._sqlite_errors("read from"):
            return {table: self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in sorted(_expected_schema())}
