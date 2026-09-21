"""Case management (local, filesystem-based).

A case is a self-contained investigation folder plus a row in the local
database. Layout::

    cases/
      investigation-001/
        case.json
        targets.json
        evidence/
        snapshots/
        reports/
        screenshots/

Everything is user-owned and portable: zipping a case folder captures the whole
investigation (minus the central database, which can be exported).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vxrecon.core.context import RunContext
from vxrecon.core.errors import ValidationError

_CASE_SUBDIRS = ("evidence", "snapshots", "reports", "screenshots")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_name(name: str) -> str:
    if not name or any(c in name for c in "\\/:*?\"<>| "):
        raise ValidationError(f"invalid case name: {name!r}")
    return name


def create_case(ctx: RunContext, name: str) -> Path:
    """Create a case folder and register it in the database."""

    _validate_name(name)
    case_dir = ctx.cases_dir / name
    if case_dir.exists():
        raise ValidationError(f"case already exists: {name}")
    for sub in _CASE_SUBDIRS:
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    case_json = {
        "name": name,
        "created_at": _now(),
        "tool_version": ctx.tool_version,
        "targets": [],
    }
    (case_dir / "case.json").write_text(
        json.dumps(case_json, indent=2), encoding="utf-8"
    )
    (case_dir / "targets.json").write_text("[]", encoding="utf-8")

    if not ctx.no_save:
        from vxrecon.database import db as dbmod

        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        conn.execute(
            "INSERT OR IGNORE INTO cases(name, created_at, path) VALUES (?,?,?)",
            (name, case_json["created_at"], str(case_dir)),
        )
        conn.commit()
        conn.close()
    return case_dir


def add_target(ctx: RunContext, case_name: str, target: str) -> None:
    """Add a target to an existing case."""

    _validate_name(case_name)
    case_dir = ctx.cases_dir / case_name
    targets_file = case_dir / "targets.json"
    if not targets_file.exists():
        raise ValidationError(f"case not found: {case_name}")

    targets = json.loads(targets_file.read_text(encoding="utf-8"))
    if target not in targets:
        targets.append(target)
        targets_file.write_text(json.dumps(targets, indent=2), encoding="utf-8")

    case_json_file = case_dir / "case.json"
    case_json = json.loads(case_json_file.read_text(encoding="utf-8"))
    if target not in case_json.get("targets", []):
        case_json.setdefault("targets", []).append(target)
        case_json_file.write_text(json.dumps(case_json, indent=2), encoding="utf-8")


def list_cases(ctx: RunContext) -> list[dict[str, object]]:
    """Return a summary list of cases on disk."""

    root = ctx.cases_dir
    if not root.exists():
        return []
    cases: list[dict[str, object]] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        case_file = entry / "case.json"
        targets = []
        if case_file.exists():
            try:
                data = json.loads(case_file.read_text(encoding="utf-8"))
                targets = data.get("targets", [])
            except json.JSONDecodeError:
                pass
        cases.append({"name": entry.name, "path": str(entry), "targets": len(targets)})
    return cases


def case_targets(ctx: RunContext, case_name: str) -> list[str]:
    """Return the list of targets registered in a case."""

    _validate_name(case_name)
    case_dir = ctx.cases_dir / case_name
    targets_file = case_dir / "targets.json"
    if not targets_file.exists():
        raise ValidationError(f"case not found: {case_name}")
    return json.loads(targets_file.read_text(encoding="utf-8"))


def write_case_report(ctx: RunContext, case_name: str, content: str, filename: str = "report.html") -> Path:
    """Write a generated report into the case's reports/ directory."""

    _validate_name(case_name)
    case_dir = ctx.cases_dir / case_name
    if not case_dir.exists():
        raise ValidationError(f"case not found: {case_name}")
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / filename
    out.write_text(content, encoding="utf-8")
    return out
