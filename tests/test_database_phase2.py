"""Tests for the Phase 2 database schema additions."""

from __future__ import annotations

from pathlib import Path

from vxrecon.database import db as dbmod


def test_phase2_tables_exist(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    stats = dbmod.stats(conn)
    conn.close()
    for table in ("domains", "dns_records", "ips", "certificates", "relationships", "timeline_events"):
        assert table in stats
        assert stats[table] == 0


def test_schema_version_recorded(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    conn.close()
    assert row["value"] == dbmod.SCHEMA_VERSION


def test_insert_dns_record(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "vxrecon.db")
    dbmod.initialize(conn)
    conn.execute(
        "INSERT INTO domains(name, first_seen, last_seen) VALUES (?,?,?)",
        ("example.com", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    domain_id = conn.execute("SELECT id FROM domains WHERE name='example.com'").fetchone()["id"]
    conn.execute(
        "INSERT INTO dns_records(domain_id, record_type, name, value, observed_at) VALUES (?,?,?,?,?)",
        (domain_id, "A", "example.com", "1.2.3.4", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    assert dbmod.stats(conn)["dns_records"] == 1
    conn.close()
