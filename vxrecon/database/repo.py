"""Repository helpers: persist scan facts into the local database.

These functions are the only place that writes targets, dns_records, ips,
certificates and relationships. They are called by the storage layer after a
pipeline run, and are no-ops when ``ctx.no_save`` is set.

Everything runs in a single transaction so a partial run cannot leave the
database in an inconsistent state.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult
from vxrecon.utils.timeutil import now_iso


def upsert_target(conn: sqlite3.Connection, kind: str, value: str) -> int:
    """Insert or touch a target and return its id."""

    ts = now_iso()
    conn.execute(
        """
        INSERT INTO targets(kind, value, first_seen, last_seen)
        VALUES (?,?,?,?)
        ON CONFLICT(kind, value) DO UPDATE SET last_seen=excluded.last_seen
        """,
        (kind, value, ts, ts),
    )
    row = conn.execute(
        "SELECT id FROM targets WHERE kind=? AND value=?", (kind, value)
    ).fetchone()
    return int(row["id"])


def upsert_domain(conn: sqlite3.Connection, name: str) -> int:
    """Insert or touch a domain and return its id."""

    ts = now_iso()
    tld = name.rsplit(".", 1)[-1] if "." in name else None
    conn.execute(
        """
        INSERT INTO domains(name, tld, first_seen, last_seen)
        VALUES (?,?,?,?)
        ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen
        """,
        (name, tld, ts, ts),
    )
    row = conn.execute("SELECT id FROM domains WHERE name=?", (name,)).fetchone()
    return int(row["id"])


def record_dns(conn: sqlite3.Connection, domain_id: int, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO dns_records(domain_id, record_type, name, value, ttl, observed_at, source)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            domain_id,
            record.get("record_type"),
            record.get("name"),
            record.get("value"),
            record.get("ttl"),
            now_iso(),
            record.get("source"),
        ),
    )


def record_certificate(conn: sqlite3.Connection, cert: dict[str, Any]) -> None:
    fp = cert.get("fingerprint_sha256") or cert.get("der_sha256")
    if not fp:
        return
    conn.execute(
        """
        INSERT INTO certificates(
            fingerprint_sha256, subject_cn, issuer_cn, serial, not_before,
            not_after, sig_alg, key_type, key_bits, san, chain, source, observed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(fingerprint_sha256) DO NOTHING
        """,
        (
            fp,
            cert.get("subject_cn"),
            cert.get("issuer_cn"),
            cert.get("serial"),
            cert.get("not_before"),
            cert.get("not_after"),
            cert.get("sig_alg"),
            cert.get("key_type"),
            cert.get("key_bits"),
            json.dumps(cert.get("san", [])),
            json.dumps(cert.get("chain", [])),
            cert.get("source", "tls"),
            now_iso(),
        ),
    )


def upsert_ip(
    conn: sqlite3.Connection,
    address: str,
    *,
    version: int | None = None,
    asn: str | None = None,
    as_name: str | None = None,
    country: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO ips(address, version, asn, as_name, country, first_seen)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(address) DO UPDATE SET
            asn=COALESCE(excluded.asn, ips.asn),
            as_name=COALESCE(excluded.as_name, ips.as_name),
            country=COALESCE(excluded.country, ips.country)
        """,
        (address, version, asn, as_name, country, now_iso()),
    )


def record_relationships(conn: sqlite3.Connection, graph: Any, scan_id: int | None = None) -> None:
    """Persist graph edges into the relationships table."""

    if graph is None or not hasattr(graph, "edges"):
        return
    for edge in graph.edges:
        conn.execute(
            """
            INSERT INTO relationships(
                src_kind, src_value, dst_kind, dst_value, relation, confidence,
                evidence, scan_id, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                edge.src_kind,
                edge.src_value,
                edge.dst_kind,
                edge.dst_value,
                edge.relation,
                edge.confidence,
                edge.evidence,
                scan_id,
                now_iso(),
            ),
        )


def record_timeline(
    conn: sqlite3.Connection,
    target_id: int,
    event_type: str,
    message: str,
    scan_id: int | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO timeline_events(target_id, scan_id, ts, event_type, message, data)
        VALUES (?,?,?,?,?,?)
        """,
        (
            target_id,
            scan_id,
            now_iso(),
            event_type,
            message,
            json.dumps(data) if data else None,
        ),
    )


def persist_scan(
    ctx: RunContext,
    target: str,
    results: list[ScanResult],
    graph: Any = None,
    raw_outputs: dict[str, Any] | None = None,
    mode: str = "online",
    status: str = "ok",
) -> None:
    """Persist a completed scan into the database.

    No-op when ``ctx.no_save`` is set. Wrapped in a single transaction; any
    failure is swallowed so persistence never crashes a scan (the caller logs).
    """

    if ctx.no_save:
        return

    from vxrecon.database import db as dbmod

    conn = dbmod.connect(ctx.database_file)
    try:
        dbmod.initialize(conn)
        with conn:
            target_id = upsert_target(conn, "domain", target)
            started = now_iso()
            cur = conn.execute(
                """
                INSERT INTO scans(target_id, started_at, finished_at, tool_version, mode, status)
                VALUES (?,?,?,?,?,?)
                """,
                (target_id, started, started, ctx.tool_version, mode, status),
            )
            scan_id = int(cur.lastrowid)

            # DNS facts
            if raw_outputs and "dns" in raw_outputs:
                domain_id = upsert_domain(conn, target)
                for record in raw_outputs["dns"].get("records", []):
                    record_dns(conn, domain_id, record)
                    if record.get("record_type") in {"A", "AAAA"} and record.get("value"):
                        version = 4 if record.get("record_type") == "A" else 6
                        upsert_ip(conn, record["value"], version=version)

            # Certificate facts
            if raw_outputs and "tls" in raw_outputs:
                cert = raw_outputs["tls"].get("certificate")
                if cert:
                    record_certificate(conn, cert)

            # Relationships
            record_relationships(conn, graph, scan_id)

            # Timeline markers
            record_timeline(conn, target_id, "scan_started", f"scan of {target}", scan_id)
            for result in results:
                record_timeline(
                    conn,
                    target_id,
                    "module_completed",
                    f"{result.module}: {len(result.findings)} finding(s)",
                    scan_id,
                )

            # Snapshot
            payload = {
                "target": target,
                "results": [r.to_dict() for r in results],
                "graph": graph.to_dict() if graph and hasattr(graph, "to_dict") else None,
            }
            summary_hash = _payload_hash(payload)
            conn.execute(
                """
                INSERT INTO snapshots(scan_id, target_id, created_at, summary_hash, payload)
                VALUES (?,?,?,?,?)
                """,
                (scan_id, target_id, now_iso(), summary_hash, json.dumps(payload, default=str)),
            )
    finally:
        conn.close()


def _payload_hash(payload: dict[str, Any]) -> str:
    import hashlib

    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
