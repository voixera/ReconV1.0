"""Tests for SQLite schema initialization and stats."""

from __future__ import annotations

from pathlib import Path

from vxrecon.database import db as dbmod


def test_initialize_creates_tables(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    stats = dbmod.stats(conn)
    conn.close()
    assert stats["targets"] == 0
    assert stats["snapshots"] == 0


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    dbmod.initialize(conn)  # must not raise
    conn.close()


def test_insert_target_and_count(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    conn.execute(
        "INSERT INTO targets(kind, value, first_seen, last_seen) VALUES (?,?,?,?)",
        ("domain", "example.com", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    assert dbmod.stats(conn)["targets"] == 1
    conn.close()
