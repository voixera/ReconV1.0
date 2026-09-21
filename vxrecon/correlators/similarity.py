"""Infrastructure Similarity Engine (feature 14).

Compares two hosts and produces similarity percentages across independent
dimensions: DNS, infrastructure (ASN/network), technology, certificate overlap,
nameservers, HTTP DNA and favicon.

Terminology matters: a high score means **shared infrastructure indicators**.
It is NOT a statement of ownership. Two unrelated sites can share a CDN,
hosting provider or managed platform, which raises infrastructure similarity
without any common owner.

The engine is a pure function over findings collected for each target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from vxrecon.core.result import ScanResult


def _values(results: list[ScanResult], key: str) -> set[str]:
    out: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.key == key:
                out.add(_stringify(finding.value))
    return out


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return _stringify(value.get("name", value))
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _jaccard(a: set[str], b: set[str]) -> float | None:
    """Jaccard similarity in [0,1]; ``None`` when both sets are empty."""

    if not a and not b:
        return None
    union = a | b
    if not union:
        return None
    return len(a & b) / len(union)


def _ratio_similar(a: str, b: str) -> float:
    """Cheap string similarity for a single value pair."""

    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    from difflib import SequenceMatcher

    return SequenceMatcher(None, a, b).ratio()


@dataclass
class SimilarityDimension:
    """One comparison dimension."""

    name: str
    score: float | None  # percentage 0..100, or None when not comparable
    shared: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "score": self.score, "shared": self.shared, "note": self.note}


@dataclass
class SimilarityResult:
    """Aggregate similarity between two targets."""

    target_a: str
    target_b: str
    dimensions: list[SimilarityDimension] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        comparable = [d.score for d in self.dimensions if d.score is not None]
        overall = sum(comparable) / len(comparable) if comparable else None
        return {
            "target_a": self.target_a,
            "target_b": self.target_b,
            "overall": round(overall, 1) if overall is not None else None,
            "disclaimer": "Scores indicate shared infrastructure indicators, not ownership.",
            "dimensions": [d.to_dict() for d in self.dimensions],
        }


def compare(a_results: list[ScanResult], b_results: list[ScanResult], target_a: str, target_b: str) -> SimilarityResult:
    """Compare findings from two targets across multiple dimensions."""

    result = SimilarityResult(target_a=target_a, target_b=target_b)

    result.dimensions.append(
        _set_dimension("DNS (A/AAAA)", _values(a_results, "dns.a") | _values(a_results, "dns.aaaa"), _values(b_results, "dns.a") | _values(b_results, "dns.aaaa"))
    )
    result.dimensions.append(
        _set_dimension("Nameservers", _values(a_results, "rdap.nameserver") | _values(a_results, "dns.ns"), _values(b_results, "rdap.nameserver") | _values(b_results, "dns.ns"))
    )
    result.dimensions.append(
        _set_dimension("Mail servers (MX)", _values(a_results, "dns.mx"), _values(b_results, "dns.mx"))
    )
    result.dimensions.append(
        _set_dimension("Certificate", _values(a_results, "tls.fingerprint_sha256"), _values(b_results, "tls.fingerprint_sha256"))
    )
    result.dimensions.append(
        _set_dimension("Technology", _tech_names(a_results), _tech_names(b_results))
    )
    result.dimensions.append(
        _set_dimension("Network (ASN)", _values(a_results, "net.asn"), _values(b_results, "net.asn"))
    )
    result.dimensions.append(
        _single_dimension("HTTP DNA", _values(a_results, "http.dna"), _values(b_results, "http.dna"))
    )
    result.dimensions.append(
        _single_dimension("Website DNA", _values(a_results, "dna.fingerprint"), _values(b_results, "dna.fingerprint"))
    )
    result.dimensions.append(
        _single_dimension("Favicon (SHA-256)", _values(a_results, "favicon.sha256"), _values(b_results, "favicon.sha256"))
    )
    return result


def _tech_names(results: list[ScanResult]) -> set[str]:
    out: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.key.startswith("tech."):
                value = finding.value
                if isinstance(value, dict):
                    out.add(str(value.get("name", finding.key)))
                else:
                    out.add(str(value))
    return out


def _set_dimension(name: str, a: set[str], b: set[str]) -> SimilarityDimension:
    score = _jaccard(a, b)
    shared = sorted(a & b)
    return SimilarityDimension(
        name=name,
        score=round(score * 100, 1) if score is not None else None,
        shared=shared,
        note="" if score is not None else "no comparable data",
    )


def _single_dimension(name: str, a: set[str], b: set[str]) -> SimilarityDimension:
    if not a or not b:
        return SimilarityDimension(name=name, score=None, note="no comparable data")
    best = max((_ratio_similar(x, y) for x in a for y in b), default=0.0)
    shared = sorted(a & b)
    return SimilarityDimension(name=name, score=round(best * 100, 1), shared=shared)
