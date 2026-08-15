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

import datetime
import os
import sqlite3

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
    parsed_ok           INTEGER
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
    ref_count     INTEGER
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
    mft_sequence INTEGER
);

CREATE TABLE IF NOT EXISTS file_ref (
    volume_id    INTEGER NOT NULL REFERENCES volume(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    mft_entry    INTEGER NOT NULL,
    mft_sequence INTEGER
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
TIMELINE_VIEW = """
CREATE VIEW IF NOT EXISTS timeline AS
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


# Columns added after the first release, applied to an existing database by `_migrate`.
# Anything added to the `prefetch` table in SCHEMA must be listed here too, or a database from
# an older build breaks on the next INSERT with a message about a column count.
MIGRATIONS = [
    ("source_key", "TEXT"),
]


class StoreError(Exception):
    """Opening or writing the database failed, with a message meant for a human.

    Raw `sqlite3.OperationalError: unable to open database file` reaches the user as a
    traceback that names neither the path nor the likely cause. Callers can catch this and
    print it directly.
    """


class Store:
    """Writer/reader over one SQLite database. Use as a context manager."""

    def __init__(self, path: str):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
            self.conn.row_factory = sqlite3.Row
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
            raise StoreError(f"cannot open database {path!r}: {exc}{hint}") from exc

    def _migrate(self):
        """Add columns a database written by an older build is missing.

        `CREATE TABLE IF NOT EXISTS` leaves an existing table alone, so a new column would make
        every INSERT fail against a database from a previous version - with a message about a
        column count, which says nothing useful.
        """
        have = {row[1] for row in self.conn.execute("PRAGMA table_info(prefetch)")}
        for column, decl in MIGRATIONS:
            if column not in have:
                self.conn.execute(f"ALTER TABLE prefetch ADD COLUMN {column} {decl}")
        self.conn.commit()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def add(self, pf: Prefetch) -> int:
        """Insert one record, replacing any previous record for the same source path.

        Re-scanning the same folder into an existing database is a normal thing to do, and
        without this it silently doubles every row - 20 files ingested twice became 40 prefetch
        rows and 188 run times, with no error and no warning. Counts in a report would then be
        wrong in a way nothing surfaces. Ingest is therefore idempotent per source path.
        """
        c = self.conn.cursor()
        source_key = os.path.realpath(pf.source_path) if pf.source_path else ""
        old = c.execute("SELECT id FROM prefetch WHERE source_key = ?",
                        (source_key,)).fetchall()
        for (old_id,) in old:
            self._delete(c, old_id)
        last = pf.last_run
        last_ticks = max(pf.run_times_ticks) if pf.run_times_ticks else None
        c.execute(
            """INSERT INTO prefetch (source_path, source_key, source_name, version, executable_name, hash,
                    file_size, run_count, last_run, last_run_ticks, executable_path,
                    executable_path_alt, path_source, hosted_package, total_dir_count,
                    trace_chain_count, trace_chain_raw, trace_chain_width, volume_count,
                    file_count, is_op_file, deceptive_chars, name_truncated, failed_stage,
                    parsed_ok)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pf.source_path, source_key, os.path.basename(pf.source_path), pf.version, pf.executable_name,
             pf.hash, pf.file_size, pf.run_count, _iso(last), last_ticks, pf.executable_path,
             pf.executable_path_alt,
             pf.path_source.value if isinstance(pf.path_source, PathSource) else pf.path_source,
             pf.hosted_package, pf.total_directory_count, pf.trace_chain_count,
             pf.trace_chain_raw or None, pf.trace_chain_entry_size or None,
             len(pf.volumes), len(pf.filenames), int(pf.is_op_file),
             int(pf.deceptive_characters), int(pf.name_truncated),
             pf.failed_stage, int(pf.parsed_ok)),
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
            c.execute("INSERT INTO loaded_file VALUES (?,?,?,?,?)",
                      (pid, i, m.filename,
                       m.mft_ref.entry if m.mft_ref else None,
                       m.mft_ref.sequence if m.mft_ref else None))
        # Files present in the string block but with no metric of their own would otherwise be
        # dropped; "no data skipped" means the union, not whichever list is shorter.
        for i in range(len(pf.metrics), len(pf.filenames)):
            c.execute("INSERT INTO loaded_file VALUES (?,?,?,?,?)",
                      (pid, i, pf.filenames[i], None, None))

        for j, v in enumerate(pf.volumes):
            c.execute("""INSERT INTO volume (prefetch_id, ordinal, device_name, serial, created,
                              created_ticks, name_check, dir_count, ref_count)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (pid, j, v.device_name, v.serial, _iso(v.created), v.created_ticks,
                       _tri(v.name_self_check), len(v.directories), len(v.file_refs)))
            vid = c.lastrowid
            c.executemany("INSERT INTO directory VALUES (?,?,?)",
                          [(vid, k, d) for k, d in enumerate(v.directories)])
            c.executemany("INSERT INTO file_ref VALUES (?,?,?,?)",
                          [(vid, k, r.entry, r.sequence) for k, r in enumerate(v.file_refs)])

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
        for table in ("volume", "run_time", "loaded_file", "problem"):
            cursor.execute(f"DELETE FROM {table} WHERE prefetch_id = ?", (prefetch_id,))
        cursor.execute("DELETE FROM prefetch WHERE id = ?", (prefetch_id,))

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
                self.conn.commit()
        self.conn.commit()
        return n

    # -- reading -----------------------------------------------------------
    def rows(self, sql: str = "SELECT * FROM prefetch", params=()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def counts(self) -> dict[str, int]:
        out = {}
        for table in ("prefetch", "run_time", "volume", "directory", "loaded_file",
                      "file_ref", "problem"):
            out[table] = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return out
