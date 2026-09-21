"""SARIF report renderer.

Emits SARIF 2.1.0 so findings can be consumed by GitHub Code Scanning, IDEs and
SIEM/SOAR platforms. Each finding becomes a SARIF ``result`` with the target as
an artifact location and the evidence lines as message text.

VXRecon findings are *informational intelligence*, not vulnerabilities, so every
rule is emitted at a neutral ``note`` level by default; the confidence is carried
in ``properties`` so consumers can filter on it.
"""

from __future__ import annotations

from typing import Any

from vxrecon import __program__, __version__
from vxrecon.core.context import RunContext
from vxrecon.reporters.base import BaseReporter

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


class SarifReporter(BaseReporter):
    """Render a scan payload as SARIF 2.1.0."""

    name = "sarif"

    def render(self, data: dict[str, Any]) -> str:
        import json

        target = str(data.get("target", "unknown"))
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for result in data.get("results", []):
            module = result.get("module", "unknown")
            for finding in result.get("findings", []):
                key = str(finding.get("key", "unknown"))
                rule_id = f"vxrecon/{key}"
                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": key,
                        "shortDescription": {"text": f"{__program__}: {key}"},
                        "properties": {"module": module},
                    }
                evidence = finding.get("evidence", [])
                message = "; ".join(str(e) for e in evidence) or _stringify(finding.get("value"))
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "note",
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": target},
                                }
                            }
                        ],
                        "properties": {
                            "confidence": finding.get("confidence"),
                            "value": _stringify(finding.get("value")),
                        },
                    }
                )

        sarif = {
            "$schema": SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": __program__,
                            "version": __version__,
                            "informationUri": "https://github.com/vxrecon/vxrecon",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "note": "Passive OSINT indicators; not ownership claims.",
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2, default=str)


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
