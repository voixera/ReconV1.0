"""Tests for Phase 6: snapshot diff and read-side repo helpers."""

from __future__ import annotations

from pathlib import Path

from vxrecon.correlators.diff import diff_snapshots
from vxrecon.database import db as dbmod
from vxrecon.database import repo, repo_read


def _payload(a_records, mx=None, tech=None) -> dict:
    findings = [{"key": "dns.a", "value": ip} for ip in a_records]
    if mx:
        findings.append({"key": "dns.mx", "value": mx})
    if tech:
        findings.append({"key": "tech.react", "value": {"name": tech}})
    return {"results": [{"module": "x", "findings": findings}]}


def test_diff_detects_added_and_removed() -> None:
    old = _payload(["1.1.1.1"])
    new = _payload(["1.1.1.1", "2.2.2.2"])
    result = diff_snapshots("example.com", old, new)
    added = [e.value for e in result.added]
    assert "2.2.2.2" in added


def test_diff_detects_removed() -> None:
    old = _payload(["1.1.1.1", "2.2.2.2"])
    new = _payload(["1.1.1.1"])
    result = diff_snapshots("example.com", old, new)
    removed = [e.value for e in result.removed]
    assert "2.2.2.2" in removed


def test_diff_no_changes() -> None:
    old = _payload(["1.1.1.1"])
    new = _payload(["1.1.1.1"])
    result = diff_snapshots("example.com", old, new)
    assert result.entries == []


def test_diff_is_order_independent() -> None:
    a = _payload(["1.1.1.1", "2.2.2.2"])
    b = _payload(["2.2.2.2", "1.1.1.1"])
    assert diff_snapshots("x", a, b).entries == []


def test_repo_persist_and_read_snapshots(tmp_path: Path) -> None:
    from vxrecon.core.context import RunContext

    ctx = RunContext(quiet=True, home=tmp_path / ".vxrecon", no_save=False)
    from vxrecon.core.result import Confidence, Finding, ScanResult

    result = ScanResult(target="example.com", module="dns")
    result.add_finding(Finding(key="dns.a", value="1.2.3.4", confidence=Confidence.HIGH))

    repo.persist_scan(ctx, "example.com", [result], graph=None, raw_outputs={})

    conn = dbmod.connect(ctx.database_file)
    dbmod.initialize(conn)
    snaps = repo_read.latest_snapshots(conn, "example.com")
    events = repo_read.timeline_events(conn, "example.com")
    conn.close()
    assert len(snaps) == 1
    assert snaps[0]["payload"]["results"][0]["findings"][0]["value"] == "1.2.3.4"
    assert events


def test_repo_read_missing_target(tmp_path: Path) -> None:
    conn = dbmod.connect(tmp_path / "v.db")
    dbmod.initialize(conn)
    assert repo_read.latest_snapshots(conn, "nope.com") == []
    assert repo_read.timeline_events(conn, "nope.com") == []
    conn.close()
