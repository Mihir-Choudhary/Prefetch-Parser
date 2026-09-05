#!/usr/bin/env python3
"""Store integrity: ingest both corpora and assert the relational invariants hold.

The store is where "no data skipped" is actually delivered or quietly broken, and the failure
mode is not an exception - it is a row count that is silently short. So every one-to-many
relationship is checked against what the parser produced, not just spot-checked.

Run:  python3 test_store.py
"""

import glob
import os
import sys
import subprocess as _subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import corpus  # noqa: E402

from prefetch_core import parse_file  # noqa: E402
from prefetch_core.store import Store  # noqa: E402

CORPORA = [
    os.path.join(corpus.WIN10, "*.pf"),
    os.path.join(corpus.WIN11, "*.pf"),
]
EXPECTED = {
    "prefetch": 636,
    "path_source": {"stored": 458, "resolved": 171, "conflict": 5, "unresolved": 2},
    # Every \VOLUME{...} name encodes its own creation FILETIME and serial. All 648 agree.
    "volume_name_ok": 648,
    "volume_name_mismatch": 0,
}


PREVIOUS_RELEASE_SCHEMA = """PRAGMA journal_mode = DELETE;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS prefetch (
    id                  INTEGER PRIMARY KEY,
    source_path         TEXT    NOT NULL,   -- as supplied, for reporting
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


def main():
    corpus.require("WIN10", "WIN11")
    files = []
    for pattern in CORPORA:
        files.extend(sorted(glob.glob(pattern)))
    if not files:
        print("!! no corpus files found", file=sys.stderr)
        return 1

    records = [parse_file(p) for p in files]
    db = os.path.join(tempfile.mkdtemp(), "test.db")
    ok = True

    with Store(db) as s:
        s.add_all(records)
        counts = s.counts()
        q = lambda sql: s.rows(sql)[0][0]  # noqa: E731

        def check(label, got, want):
            nonlocal ok
            flag = "" if got == want else f"   << expected {want}"
            ok &= got == want
            print(f"  {label:44} {got:>7}{flag}")

        print("row counts vs. what the parser produced:")
        check("prefetch rows", counts["prefetch"], EXPECTED["prefetch"])
        check("run_time rows", counts["run_time"], sum(len(r.run_times) for r in records))
        check("volume rows", counts["volume"], sum(len(r.volumes) for r in records))
        check("directory rows", counts["directory"],
              sum(len(v.directories) for r in records for v in r.volumes))
        # References now carry a source: 'declared' is what the file counts, 'slack' is what
        # was found in the array past that count. Both are stored; only the first is what the
        # record claims, and the counts must stay separable.
        check("file_ref rows (declared)",
              q("SELECT COUNT(*) FROM file_ref WHERE source = 'declared'"),
              sum(len(v.file_refs) for r in records for v in r.volumes))
        check("file_ref rows (slack)",
              q("SELECT COUNT(*) FROM file_ref WHERE source = 'slack'"),
              sum(len(v.slack_refs) for r in records for v in r.volumes))
        check("file_ref rows total", counts["file_ref"],
              sum(len(v.file_refs) + len(v.slack_refs) for r in records for v in r.volumes))
        # loaded_file is the UNION of metric-paired names and any extra string-block entries.
        check("loaded_file rows", counts["loaded_file"],
              sum(max(len(r.metrics), len(r.filenames)) for r in records))
        check("problem rows", counts["problem"], sum(len(r.problems) for r in records))

        print("\ninvariants:")
        check("prefetch.last_run != MAX(run_time)", q(
            "SELECT COUNT(*) FROM prefetch p WHERE p.run_count > 0 AND p.last_run <> "
            "(SELECT MAX(run_time) FROM run_time r WHERE r.prefetch_id = p.id)"), 0)
        # Exactly one newest per file. Duplicated timestamps must not flag two rows.
        check("files without exactly one is_newest", q(
            "SELECT COUNT(*) FROM (SELECT prefetch_id, SUM(is_newest) s "
            "FROM run_time GROUP BY 1 HAVING s <> 1)"), 0)
        check("run_time rows orphaned", q(
            "SELECT COUNT(*) FROM run_time r LEFT JOIN prefetch p ON p.id = r.prefetch_id "
            "WHERE p.id IS NULL"), 0)
        check("directory rows orphaned", q(
            "SELECT COUNT(*) FROM directory d LEFT JOIN volume v ON v.id = d.volume_id "
            "WHERE v.id IS NULL"), 0)
        check("hashes not 8 chars", q(
            "SELECT COUNT(*) FROM prefetch WHERE LENGTH(hash) <> 8"), 0)
        check("volume name_check = mismatch", q(
            "SELECT COUNT(*) FROM volume WHERE name_check = 'mismatch'"),
            EXPECTED["volume_name_mismatch"])
        check("volume name_check = ok", q(
            "SELECT COUNT(*) FROM volume WHERE name_check = 'ok'"), EXPECTED["volume_name_ok"])
        check("timeline rows", q("SELECT COUNT(*) FROM timeline"), counts["run_time"])

        # Trace chains are stored as a blob, not a row per entry. Lossless either way; this
        # asserts the blob actually round-trips rather than being silently NULL.
        print("\ntrace chains persisted losslessly:")
        check("  files with chains but no blob", q(
            "SELECT COUNT(*) FROM prefetch WHERE trace_chain_count > 0 "
            "AND trace_chain_raw IS NULL"), 0)
        check("  blobs whose length disagrees with the count", q(
            "SELECT COUNT(*) FROM prefetch WHERE trace_chain_count > 0 AND "
            "LENGTH(trace_chain_raw) / trace_chain_width <> trace_chain_count"), 0)

        # Re-ingesting the same folder is normal and must be idempotent. Without
        # replace-on-same-source-path it silently doubles every table, corrupting any count in
        # a report with no error to notice.
        print("\nre-ingest (must be idempotent):")
        before = dict(counts)
        s.add_all(records)
        after = s.counts()
        for table in ("prefetch", "run_time", "volume", "directory", "loaded_file", "file_ref"):
            check(f"  {table} unchanged after re-ingest", after[table], before[table])
        check("  duplicate source_path rows", q(
            "SELECT COUNT(*) FROM (SELECT source_path FROM prefetch "
            "GROUP BY 1 HAVING COUNT(*) > 1)"), 0)
        check("  orphaned file_refs after replace", q(
            "SELECT COUNT(*) FROM file_ref f LEFT JOIN volume v ON v.id = f.volume_id "
            "WHERE v.id IS NULL"), 0)
        check("  orphaned directories after replace", q(
            "SELECT COUNT(*) FROM directory d LEFT JOIN volume v ON v.id = d.volume_id "
            "WHERE v.id IS NULL"), 0)

        print("\npath_source distribution:")
        got = {r[0]: r[1] for r in s.rows(
            "SELECT path_source, COUNT(*) FROM prefetch GROUP BY 1")}
        for k, want in EXPECTED["path_source"].items():
            check(f"  {k}", got.get(k, 0), want)

    # The database must be self-contained. WAL mode leaves committed data in a `-wal` sidecar
    # until checkpointed; an analyst copying just the `.db` then opens an empty database with
    # no error at all. Verified by hard-killing a writer and reading the .db in isolation.
    print("\ndurability - the .db alone must be complete:")
    import shutil
    import sqlite3
    import subprocess
    workdir = tempfile.mkdtemp()
    victim = os.path.join(workdir, "killed.db")
    script = (
        "import sys, glob, os;"
        "sys.path.insert(0, %r);"
        "from prefetch_core import parse_file;"
        "from prefetch_core.store import Store;"
        "s = Store(%r);"
        "s.add_all(parse_file(p) for p in sorted(glob.glob(%r))[:40]);"
        "os._exit(1)"
    ) % (os.path.dirname(HERE), victim, CORPORA[0])
    subprocess.run([sys.executable, "-c", script], capture_output=True)

    sidecars = [f for f in os.listdir(workdir) if f != "killed.db"]
    print(f"  sidecar files after a hard kill: {sidecars or 'none'}")
    copied = os.path.join(workdir, "copied.db")
    shutil.copy(victim, copied)
    conn = sqlite3.connect(copied)
    try:
        recovered = conn.execute("SELECT COUNT(*) FROM prefetch").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        recovered = f"unreadable: {exc}"
    conn.close()
    print(f"  rows readable from the copied .db alone: {recovered}")
    ok &= sidecars == [] and recovered == 40

    # De-duplication must survive a path being spelled differently. The store keyed on the
    # literal source_path, so `dir/x.pf` and `dir/./x.pf` inserted twice - a re-scan typed a
    # different way silently doubled rows.
    print("\nde-duplication across path spellings:")
    alias_db = os.path.join(tempfile.mkdtemp(), "alias.db")
    sample = files[0]
    aliased = os.path.join(os.path.dirname(sample), ".", os.path.basename(sample))
    with Store(alias_db) as alias_store:
        alias_store.add_all([parse_file(sample), parse_file(aliased)])
        got = alias_store.rows("SELECT COUNT(*) FROM prefetch")[0][0]
    print(f"  same file via two spellings -> {got} row(s)")
    if got != 1:
        ok = False

    # A database written by an older build must migrate, not fail on the next INSERT with a
    # message about a column count.
    #
    # The fixture is the schema of the PREVIOUS RELEASE, copied verbatim from that commit - a
    # historical fact, which cannot drift. The version before this one built its "legacy"
    # database by subtracting a hand-written list of added columns from today's SCHEMA, and
    # that list went stale the moment Round 45 added twenty more: the "legacy" database being
    # tested still contained `source_created`, the ADS columns, the raw-region blobs and the
    # whole artifact table set, so the test passed while exercising a five-column upgrade
    # instead of a twenty-six-column one. Same defect as BUG 63, inside the test written to
    # catch BUG 63.
    print("\nmigration of a database written by the previous release:")
    import re as _re
    import sqlite3 as _sqlite3
    from prefetch_core.store import SCHEMA_VERSION, StoreError, _expected_schema

    legacy_db = os.path.join(tempfile.mkdtemp(), "legacy.db")
    conn = _sqlite3.connect(legacy_db)
    conn.executescript(PREVIOUS_RELEASE_SCHEMA)
    conn.execute("INSERT INTO prefetch (source_path, source_name) VALUES ('old.pf', 'old.pf')")
    conn.commit()
    legacy_tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    legacy_columns = {f"{t}.{r[1]}" for t in legacy_tables
                      for r in conn.execute(f"PRAGMA table_info({t})")}
    conn.close()

    # What SHOULD be added is computed, not listed: everything this build's schema has that the
    # released one does not, for tables that already existed. New tables arrive via CREATE
    # TABLE IF NOT EXISTS and are checked separately below.
    expected_added = {f"{table}.{column['name']}"
                      for table, columns in _expected_schema().items() if table in legacy_tables
                      for column in columns} - legacy_columns
    new_tables = set(_expected_schema()) - legacy_tables

    with Store(legacy_db) as migrated:
        added = set(migrated.migrations_applied)
        migrated.add_all([parse_file(sample)])
        rows_after = migrated.rows("SELECT COUNT(*) FROM prefetch")[0][0]
        indexes = {r[1] for r in migrated.conn.execute("PRAGMA index_list('prefetch')")}
        chained = migrated.rows(
            "SELECT COUNT(*) FROM loaded_file WHERE chain_count IS NOT NULL")[0][0]
        legacy_refs = migrated.rows(
            "SELECT COUNT(*) FROM file_ref WHERE source <> 'declared'")[0][0]
        present_tables = {r[0] for r in migrated.rows(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        stamped = migrated.rows("PRAGMA user_version")[0][0]

    print(f"  columns the released schema lacks: {len(expected_added)}")
    print(f"  columns the migration added      : {len(added)}")
    print(f"  tables the released schema lacks : {len(new_tables)} {sorted(new_tables)}")
    print(f"  legacy row preserved and insert works: {rows_after} rows")
    print(f"  the new record wrote its chain slices: {chained} loaded files")
    print(f"  legacy references default to 'declared': {legacy_refs == 0}")
    print(f"  ix_pf_key created after migration: {'ix_pf_key' in indexes}")
    print(f"  schema stamped: user_version={stamped}")
    # A fixture that has quietly caught up with today's schema would make this test vacuous, so
    # the upgrade must be a real one, not a no-op.
    if len(expected_added) < 20:
        print(f"  !! only {len(expected_added)} columns differ from the released schema - the "
              f"fixture is no longer a previous release")
        ok = False
    if added != expected_added:
        print(f"  !! migration mismatch; missing {sorted(expected_added - added)}, "
              f"unexpected {sorted(added - expected_added)}")
        ok = False
    if not new_tables <= present_tables:
        print(f"  !! tables not created: {sorted(new_tables - present_tables)}")
        ok = False
    if (rows_after != 2 or "ix_pf_key" not in indexes or chained == 0 or legacy_refs
            or stamped != SCHEMA_VERSION):
        ok = False

    # Re-opening must be a no-op: a migration that runs twice would mean ALTER TABLE errors.
    with Store(legacy_db) as reopened:
        if reopened.migrations_applied:
            print(f"  !! re-opening migrated again: {reopened.migrations_applied}")
            ok = False
        else:
            print("  re-opening migrates nothing")

    # A database written by a NEWER build must be refused, not half-read.
    future_db = os.path.join(tempfile.mkdtemp(), "future.db")
    with Store(future_db) as f:
        f.add(parse_file(sample))
    fconn = _sqlite3.connect(future_db)
    fconn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    fconn.commit()
    fconn.close()
    try:
        Store(future_db)
        print("  !! a newer database was opened anyway")
        ok = False
    except StoreError as exc:
        good = "newer version" in str(exc)
        print(f"  a newer database is refused with a message: {good}")
        ok &= good

    # A view definition from an older build must be rebuilt, never inherited. `CREATE VIEW IF
    # NOT EXISTS` kept the old one, so a changed view would keep answering with the old columns
    # and the query would succeed - the worst kind of drift.
    stale_db = os.path.join(tempfile.mkdtemp(), "stale.db")
    with Store(stale_db) as st:
        st.add(parse_file(sample))
    sconn = _sqlite3.connect(stale_db)
    sconn.executescript("DROP VIEW timeline; CREATE VIEW timeline AS SELECT 1 AS wrong;")
    sconn.commit()
    sconn.close()
    with Store(stale_db) as st:
        view_cols = {r[1] for r in st.conn.execute("PRAGMA table_info(timeline)")}
    rebuilt = "run_time" in view_cols and "wrong" not in view_cols
    print(f"  a stale timeline view is rebuilt: {rebuilt}")
    ok &= rebuilt

    # One record must land completely or not at all. A failure partway used to leave the
    # parent row committed: an evidence row with no executable and no loaded files, which
    # looks exactly like a real record (AUDIT BUG 64).
    print("\natomicity - a record lands whole or not at all:")
    atomic_db = os.path.join(tempfile.mkdtemp(), "atomic.db")
    real_add = Store._add

    def explode(self, pf):
        self.conn.execute(
            "INSERT INTO prefetch (source_path, source_key, source_name) VALUES (?,?,?)",
            (pf.source_path, pf.source_path, "half.pf"))
        raise _sqlite3.OperationalError("simulated failure midway through the record")

    # Round 47. A database inside a deep case folder - triage output nests
    # C:\Cases\<case>\<host>\<tool>\<timestamp>\C\Windows\Prefetch - fails with "unable to
    # open database file" while the CSV beside it writes perfectly. The cause is a fixed
    # 512-byte pathname buffer inside SQLite, not permissions, and the bare message sends the
    # analyst looking in the wrong place entirely (AUDIT BUG 101).
    # Round 48. SQLite refuses to bind a string carrying a lone surrogate, and a filename that
    # is not valid UTF-8 produces exactly that: one file killed the whole ingest with an
    # exception the CLI does not catch (AUDIT BUG 102). Every parameter row now passes through
    # one seam, so a column added later cannot forget.
    # Round 49. `add_all` commits in batches and `close()` commits what completed, so an
    # interrupted run is documented to leave "a valid database holding whatever completed".
    # The audit script that used to verify that was lost with a scratch directory; a promise
    # with no pin is a promise nobody is keeping.
    print("\nan interrupted ingest keeps what completed, whole:")
    import signal as _signal                                          # noqa: PLC0415
    import textwrap as _textwrap                                      # noqa: PLC0415
    import time as _time                                              # noqa: PLC0415

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    interrupted = os.path.join(tempfile.mkdtemp(), "interrupted.db")
    child = _textwrap.dedent(f"""
        import glob, os, sys
        sys.path.insert(0, {repo_root!r})
        from prefetch_core import parse_file
        from prefetch_core.store import Store
        files = sorted(glob.glob(os.path.join({corpus.WIN11!r}, "*.pf")))
        with Store(sys.argv[1]) as s:
            s.add_all(parse_file(f) for f in files)
    """)
    proc = _subprocess.Popen([sys.executable, "-c", child, interrupted],
                             stdout=_subprocess.PIPE, stderr=_subprocess.PIPE, text=True)
    _time.sleep(3.0)
    proc.send_signal(_signal.SIGINT)
    proc.communicate(timeout=180)
    icon = _sqlite3.connect(interrupted)
    survived = icon.execute("SELECT COUNT(*) FROM prefetch").fetchone()[0]
    ihalf = icon.execute("SELECT COUNT(*) FROM prefetch WHERE parsed_ok IS NULL").fetchone()[0]
    iorphans = icon.execute("SELECT COUNT(*) FROM loaded_file WHERE prefetch_id NOT IN "
                            "(SELECT id FROM prefetch)").fetchone()[0]
    iintegrity = icon.execute("PRAGMA integrity_check").fetchone()[0]
    icon.close()
    total = len(glob.glob(os.path.join(corpus.WIN11, "*.pf")))
    print(f"  {survived} of {total} records survived the interrupt")
    # The interrupt must land mid-run: all of them, or none, would prove nothing.
    check("  the kill landed mid-ingest", 0 < survived < total, True)
    check("  every survivor is a whole record", ihalf, 0)
    check("  no child row is orphaned", iorphans, 0)
    check("  the database is valid", iintegrity, "ok")
    # This suite's `check` formats `got` with a width, so it takes scalars: a list here raises
    # while REPORTING, which hides whatever it was reporting.
    beside = [f for f in os.listdir(os.path.dirname(interrupted))
              if f != os.path.basename(interrupted)]
    check("  and no journal is left beside it", len(beside), 0)

    print("\na name that is not valid text is stored, not fatal:")
    undecodable = os.path.join(tempfile.mkdtemp(), "undecodable.db")
    hostile = parse_file(sample)
    hostile.source_path = os.path.join(os.path.dirname(sample), "CALC.EXE-3FBEF7FD\udcff.pf")
    hostile.filenames = list(hostile.filenames) + ["\\WINDOWS\\SYSTEM32\\A\udcffB.DLL"]
    with Store(undecodable) as s:
        s.add(hostile)
    conn = _sqlite3.connect(undecodable)
    name = conn.execute("SELECT source_name FROM prefetch").fetchone()[0]
    loaded = conn.execute("SELECT COUNT(*) FROM loaded_file WHERE path LIKE '%A\\xffB.DLL'"
                          ).fetchone()[0]
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    print(f"  the record is stored, named {name!r}")
    ok &= name.endswith("\\xff.pf")
    print(f"  the undecodable byte in a loaded file is kept too: {loaded == 1}")
    ok &= loaded == 1
    print(f"  and the database is sound: {integrity}")
    ok &= integrity == "ok"

    print("\na database path too long for SQLite says so, and says what to do:")
    from prefetch_core.store import _SQLITE_PATH_LIMIT                # noqa: PLC0415

    deep = tempfile.mkdtemp()
    while len(deep) < _SQLITE_PATH_LIMIT:
        deep = os.path.join(deep, "segment" + "-padding" * 3)
    os.makedirs(deep, exist_ok=True)
    deep_db = os.path.join(deep, "out.db")
    try:
        Store(deep_db).close()
        print("  !! the over-long path opened; the limit has moved")
        ok = False
    except StoreError as exc:
        explained = (str(len(os.path.abspath(deep_db))) in str(exc)
                     and "shorter path" in str(exc))
        print(f"  the failure names the length and the remedy: {explained}")
        ok &= explained
    # ...and a database at an ordinary depth is unaffected by the check.
    ordinary = os.path.join(tempfile.mkdtemp(), "fine.db")
    Store(ordinary).close()
    print(f"  an ordinary path still opens: {os.path.exists(ordinary)}")
    ok &= os.path.exists(ordinary)

    good_record = parse_file(sample)
    with Store(atomic_db) as at:
        at.add(good_record)
        Store._add = explode
        try:
            at.add(parse_file(files[1]))
            print("  !! the failing record did not raise")
            ok = False
        except StoreError as exc:
            wrapped = "cannot write" in str(exc)
            print(f"  a sqlite failure is reported as a StoreError: {wrapped}")
            ok &= wrapped
        finally:
            Store._add = real_add
    aconn = _sqlite3.connect(atomic_db)
    kept = aconn.execute("SELECT COUNT(*) FROM prefetch").fetchone()[0]
    half = aconn.execute("SELECT COUNT(*) FROM prefetch WHERE parsed_ok IS NULL").fetchone()[0]
    orphans = aconn.execute(
        "SELECT COUNT(*) FROM loaded_file WHERE prefetch_id NOT IN "
        "(SELECT id FROM prefetch)").fetchone()[0]
    integrity = aconn.execute("PRAGMA integrity_check").fetchone()[0]
    aconn.close()
    print(f"  the record before it survived: {kept} row(s)")
    print(f"  no half-written record: {half == 0}")
    print(f"  no orphaned children: {orphans == 0}")
    print(f"  database integrity after the failure: {integrity}")
    if kept != 1 or half or orphans or integrity != "ok":
        ok = False

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
