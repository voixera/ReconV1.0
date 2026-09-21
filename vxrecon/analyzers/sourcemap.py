"""Source Map Awareness (feature 11).

Detects ``//# sourceMappingURL=`` references in public JavaScript and, when the
referenced ``.map`` file is publicly available, fetches it read-only to confirm
availability. We never attempt to *derive* a source map that is not referenced
or not present.

Source maps can reveal original source structure; reporting their public
availability is a legitimate defensive finding (it is often an unintended
exposure). We only read what the server already serves.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

# Matches //# sourceMappingURL=... or /*# sourceMappingURL=... */ with optional quotes.
_MAP_REF = re.compile(r"""[#@]\s*sourceMappingURL=([^\s'"]+)""")


class SourceMapAnalyzer(BaseAnalyzer):
    """Detect and (read-only) verify publicly available source maps."""

    name = "sourcemap"
    consumes = ("javascript",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("javascript")
        if not data:
            result.errors.append("no JavaScript collected")
            return result

        scripts = data.get("scripts", [])
        refs: list[dict[str, str]] = []
        for script in scripts:
            code = script.get("code")
            base = script.get("url", "")
            if not code or not base:
                continue
            for match in _MAP_REF.findall(code):
                map_url = urljoin(base, match)
                refs.append({"script": base, "source_map": map_url})

        if not refs:
            result.add_finding(
                Finding(
                    key="sourcemap.references",
                    value=0,
                    confidence=Confidence.MEDIUM,
                    evidence=["no sourceMappingURL references found in public JS"],
                )
            )
            return result

        result.add_finding(
            Finding(
                key="sourcemap.references",
                value=len(refs),
                confidence=Confidence.HIGH,
                evidence=[f"{len(refs)} sourceMappingURL reference(s) in public JS"],
            )
        )

        for ref in refs:
            result.add_finding(
                Finding(
                    key="sourcemap.reference",
                    value=ref["source_map"],
                    confidence=Confidence.HIGH,
                    evidence=[f"referenced by {ref['script']}"],
                )
            )
            self._check_availability(result, ref["source_map"], ctx)
        return result

    def _check_availability(self, result: ScanResult, map_url: str, ctx: RunContext) -> None:
        """Read-only GET to confirm the map is public. Never raises."""

        if ctx.offline:
            result.add_finding(
                Finding(
                    key="sourcemap.availability",
                    value="unknown (offline)",
                    confidence=Confidence.LOW,
                    evidence=[f"{map_url}: not checked (offline mode)"],
                )
            )
            return

        from vxrecon.utils import net

        try:
            response = net.http_get(map_url, ctx, max_bytes=500_000)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{map_url}: {exc}")
            return

        if response.ok and _looks_like_sourcemap(response.text):
            sources = _source_count(response.text)
            result.add_finding(
                Finding(
                    key="sourcemap.publicly_available",
                    value=map_url,
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"{map_url} is publicly retrievable (HTTP {response.status})",
                        f"references {sources} original source file(s)",
                        "consider whether this exposure is intended",
                    ],
                )
            )
        else:
            result.add_finding(
                Finding(
                    key="sourcemap.not_available",
                    value=map_url,
                    confidence=Confidence.LOW,
                    evidence=[f"{map_url} not publicly retrievable (HTTP {response.status})"],
                )
            )


def _looks_like_sourcemap(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and "mappings" in data


def _source_count(text: str) -> int:
    try:
        data = json.loads(text)
        return len(data.get("sources", []))
    except (ValueError, TypeError):
        return 0
