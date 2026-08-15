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


def main():
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
        check("file_ref rows", counts["file_ref"],
              sum(len(v.file_refs) for r in records for v in r.volumes))
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
    # message about a column count. Indexes are applied after migration for the same reason.
    print("\nmigration of an older database:")
    import sqlite3 as _sqlite3
    from prefetch_core.store import MIGRATIONS, SCHEMA
    legacy_sql = SCHEMA
    for column, _decl in MIGRATIONS:
        for line in SCHEMA.splitlines():
            if line.strip().startswith(column + " "):
                legacy_sql = legacy_sql.replace(line + "\n", "")
    legacy_db = os.path.join(tempfile.mkdtemp(), "legacy.db")
    conn = _sqlite3.connect(legacy_db)
    conn.executescript(legacy_sql)
    conn.execute("INSERT INTO prefetch (source_path, source_name) VALUES ('old.pf', 'old.pf')")
    conn.commit()
    conn.close()
    with Store(legacy_db) as migrated:
        columns = {r[1] for r in migrated.conn.execute("PRAGMA table_info(prefetch)")}
        migrated.add_all([parse_file(sample)])
        rows_after = migrated.rows("SELECT COUNT(*) FROM prefetch")[0][0]
        indexes = {r[1] for r in migrated.conn.execute("PRAGMA index_list('prefetch')")}
    missing = {c for c, _ in MIGRATIONS} - columns
    print(f"  columns added: {'none missing' if not missing else missing}")
    print(f"  legacy row preserved and insert works: {rows_after} rows")
    print(f"  ix_pf_key created after migration: {'ix_pf_key' in indexes}")
    if missing or rows_after != 2 or "ix_pf_key" not in indexes:
        ok = False

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
