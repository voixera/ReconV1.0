"""SQLite connection and schema management.

The database is a plain local SQLite file (WAL mode, foreign keys ON). There is
no server, no cloud and no telemetry: VXRecon's "memory" is entirely on the
user's disk and fully inspectable with any SQLite client.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Tables counted by ``db stats``. Kept explicit so new tables must be added
# deliberately rather than appearing in output by accident.
COUNTED_TABLES = (
    "targets",
    "scans",
    "snapshots",
    "domains",
    "dns_records",
    "ips",
    "certificates",
    "relationships",
    "timeline_events",
    "cases",
    "case_targets",
)

# Bump when the schema changes in a way that matters for compatibility.
SCHEMA_VERSION = "2"


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open (and create if needed) a connection with sane pragmas."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def schema_path() -> Path:
    return Path(__file__).with_name("schema.sql")


def initialize(conn: sqlite3.Connection) -> None:
    """Apply the schema idempotently and record the schema version."""

    sql = schema_path().read_text(encoding="utf-8")
    conn.executescript(sql)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
        (SCHEMA_VERSION,),
    )
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict[str, int]:
    """Return row counts for the recognized tables."""

    result: dict[str, int] = {}
    for table in COUNTED_TABLES:
        try:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            result[table] = int(row["n"])
        except sqlite3.OperationalError:
            result[table] = 0
    return result
