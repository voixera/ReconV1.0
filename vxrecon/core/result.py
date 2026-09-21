"""Structured result contracts shared across every VXRecon layer.

These dataclasses are the *lingua franca* of the framework:

* Collectors produce raw dicts (facts).
* Analyzers consume raw dicts and produce :class:`Finding` objects.
* Correlators consume findings and produce graph nodes/edges.
* Storage persists findings, evidence and relationships.
* Reporters render findings and evidence for humans/machines.

Every :class:`Finding` MUST carry human-readable evidence. This is enforced by
convention and by tests: there is no such thing as a confident detection
without a stated reason.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    """Confidence level attached to a detection or relationship."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> float:
        """Numeric weight useful for scoring/similarity math."""

        return {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}[self.value]


class Status(str, Enum):
    """Execution status of a module run."""

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Evidence:
    """Integrity metadata for an acquired artifact (feature 19).

    Every stored artifact must be traceable: where it came from, when, its
    content type, HTTP status and a SHA256 over its bytes.
    """

    source_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    sha256: str | None = None
    bytes: int | None = None
    acquired_at: str = ""
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single analyzed signal, always accompanied by evidence.

    Parameters
    ----------
    key:
        Stable identifier, e.g. ``"technology.react"`` or ``"dns.a"``.
    value:
        The signal payload. Must be JSON-serializable.
    confidence:
        How strongly the evidence supports this finding.
    evidence:
        Human-readable evidence lines displayed to the user.
    evidence_ref:
        Optional pointer to the raw artifact that backs this finding.
    source_module:
        Name of the analyzer that produced this finding.
    """

    key: str
    value: Any
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[str] = field(default_factory=list)
    evidence_ref: Evidence | None = None
    source_module: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
            "evidence_ref": self.evidence_ref.to_dict() if self.evidence_ref else None,
            "source_module": self.source_module,
        }


@dataclass
class ScanResult:
    """The result of running one module against one target."""

    target: str
    module: str
    status: Status = Status.OK
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def add_finding(self, finding: Finding) -> None:
        if not finding.source_module:
            finding.source_module = self.module
        self.findings.append(finding)

    def summary_hash(self) -> str:
        """Deterministic hash over the canonical content of this result.

        Used for snapshot change detection (feature 5). Sorting keys ensures
        the hash depends only on content, never on insertion order.
        """

        canonical = {
            "target": self.target,
            "module": self.module,
            "findings": sorted(
                (f.to_dict() for f in self.findings),
                key=lambda d: json.dumps(d, sort_keys=True, default=str),
            ),
        }
        blob = json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": self.artifacts,
            "raw": self.raw,
            "errors": list(self.errors),
            "notes": list(self.notes),
            "duration_ms": self.duration_ms,
            "summary_hash": self.summary_hash(),
        }
