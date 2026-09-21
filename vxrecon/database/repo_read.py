"""Read-side repository helpers: snapshots, timeline and scan history."""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def get_target_id(conn: sqlite3.Connection, value: str) -> int | None:
    row = conn.execute("SELECT id FROM targets WHERE value=?", (value,)).fetchone()
    return int(row["id"]) if row else None


def latest_snapshots(conn: sqlite3.Connection, target: str, limit: int = 2) -> list[dict[str, Any]]:
    """Return the most recent snapshots for a target, newest first."""

    target_id = get_target_id(conn, target)
    if target_id is None:
        return []
    rows = conn.execute(
        """
        SELECT id, scan_id, created_at, summary_hash, payload
        FROM snapshots WHERE target_id=? ORDER BY id DESC LIMIT ?
        """,
        (target_id, limit),
    ).fetchall()
    snapshots: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            payload = {}
        snapshots.append(
            {
                "id": row["id"],
                "scan_id": row["scan_id"],
                "created_at": row["created_at"],
                "summary_hash": row["summary_hash"],
                "payload": payload,
            }
        )
    return snapshots


def timeline_events(conn: sqlite3.Connection, target: str, limit: int = 200) -> list[dict[str, Any]]:
    """Return timeline events for a target, oldest first."""

    target_id = get_target_id(conn, target)
    if target_id is None:
        return []
    rows = conn.execute(
        """
        SELECT ts, event_type, message, data
        FROM timeline_events WHERE target_id=? ORDER BY ts ASC LIMIT ?
        """,
        (target_id, limit),
    ).fetchall()
    return [
        {
            "ts": row["ts"],
            "event_type": row["event_type"],
            "message": row["message"],
            "data": json.loads(row["data"]) if row["data"] else None,
        }
        for row in rows
    ]


def list_targets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT t.id, t.kind, t.value, t.first_seen, t.last_seen,
               (SELECT COUNT(*) FROM scans s WHERE s.target_id=t.id) AS scans
        FROM targets t ORDER BY t.last_seen DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def list_relationships(conn: sqlite3.Connection, limit: int = 1000) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT src_kind, src_value, dst_kind, dst_value, relation, confidence,
               evidence, created_at
        FROM relationships ORDER BY id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_dns_records(conn: sqlite3.Connection, limit: int = 5000) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT d.name AS domain, r.record_type, r.name, r.value, r.ttl,
               r.observed_at, r.source
        FROM dns_records r JOIN domains d ON d.id = r.domain_id
        ORDER BY r.id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_certificates(conn: sqlite3.Connection, limit: int = 1000) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT fingerprint_sha256, subject_cn, issuer_cn, not_before, not_after,
               key_type, key_bits, observed_at
        FROM certificates ORDER BY id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def vacuum(conn: sqlite3.Connection) -> None:
    """Reclaim space and optimize the database file."""

    conn.execute("VACUUM")
    conn.execute("PRAGMA optimize")
