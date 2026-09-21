"""Intelligence Diff correlator (feature 16).

Compares two snapshot payloads for the same target and produces a structured
change list:

* ``added``   - facts present now but not before
* ``removed`` - facts present before but not now
* ``changed`` - facts whose value changed (e.g. an A record's IP)

Only *observed* differences are reported. VXRecon never infers history it did
not witness; a diff is strictly between two stored snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Finding keys whose values we compare for change detection.
_TRACKED_PREFIXES = (
    "dns.",
    "tech.",
    "tls.",
    "rdap.",
    "subdomains.",
    "http.",
    "dna.",
    "net.",
)


@dataclass
class DiffEntry:
    """A single difference between two snapshots."""

    kind: str  # added | removed | changed
    category: str
    value: str
    old: str | None = None
    new: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "category": self.category, "value": self.value, "old": self.old, "new": self.new}


@dataclass
class DiffResult:
    """Aggregate diff between two snapshots."""

    target: str
    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def added(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.kind == "added"]

    @property
    def removed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.kind == "removed"]

    @property
    def changed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.kind == "changed"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "added": [e.to_dict() for e in self.added],
            "removed": [e.to_dict() for e in self.removed],
            "changed": [e.to_dict() for e in self.changed],
            "total_changes": len(self.entries),
        }


def _extract_facts(payload: dict[str, Any]) -> dict[str, set[str]]:
    """Flatten a snapshot payload into {key -> set(values)} of tracked facts."""

    facts: dict[str, set[str]] = {}
    for result in payload.get("results", []):
        for finding in result.get("findings", []):
            key = finding.get("key", "")
            if not key.startswith(_TRACKED_PREFIXES):
                continue
            value = finding.get("value")
            facts.setdefault(key, set()).add(_stringify(value))
    return facts


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in sorted(value.items()))
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def diff_snapshots(target: str, old_payload: dict, new_payload: dict) -> DiffResult:
    """Compute the difference between two snapshot payloads."""

    old = _extract_facts(old_payload)
    new = _extract_facts(new_payload)
    result = DiffResult(target=target)

    all_keys = set(old) | set(new)
    for key in sorted(all_keys):
        old_vals = old.get(key, set())
        new_vals = new.get(key, set())
        for value in sorted(new_vals - old_vals):
            result.entries.append(DiffEntry("added", key, value))
        for value in sorted(old_vals - new_vals):
            result.entries.append(DiffEntry("removed", key, value, old=value))
    return result
