"""JavaScript endpoint intelligence (feature 10).

Analyses *public* JavaScript source (already fetched by the collector) and
extracts interesting strings: URLs, API paths, websocket endpoints, domains,
asset references and source-map pointers.

Critical safety rule: VXRecon **never** automatically requests any endpoint it
discovers. This module is read-only analysis of code that was already served
publicly. Discovered endpoints are reported as strings, not contacted.
"""

from __future__ import annotations

import re
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

# Conservative, high-signal patterns. We avoid catching every string to keep
# noise (and report size) manageable.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"""https?://[\w\-./?%&=:@~+#]+"""),
    "api_path": re.compile(r"""["'`](/(?:api|v\d+|graphql|rest|rpc)[\w\-./{}:]*?)["'`]"""),
    "path": re.compile(r"""["'`](/[\w\-]+(?:/[\w\-{}.]+)+?)["'`]"""),
    "ws": re.compile(r"""wss?://[\w\-./?%&=:@~+#]+"""),
    "domain": re.compile(r"""["'`]([\w-]+(?:\.[\w-]+){1,4}\.(?:com|net|org|io|dev|co|app|cloud|ai))["'`]"""),
    "sourcemap": re.compile(r"""sourceMappingURL=([^\s'"]+)"""),
    "email": re.compile(r"""[\w.+-]+@[\w-]+\.[\w.-]+"""),
}

# Strings that are almost always framework noise rather than real endpoints.
_IGNORE_HOSTS = ("w3.org", "schema.org", "reactjs.org", "localhost")


class JsEndpointAnalyzer(BaseAnalyzer):
    """Extract endpoints and references from public JavaScript."""

    name = "js_endpoints"
    consumes = ("javascript",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("javascript")
        if not data:
            result.errors.append("no JavaScript collected")
            return result

        scripts = data.get("scripts", [])
        if not scripts:
            result.add_finding(
                Finding(
                    key="js.scripts",
                    value=0,
                    confidence=Confidence.LOW,
                    evidence=["no page-referenced same-origin scripts found"],
                )
            )
            return result

        result.add_finding(
            Finding(
                key="js.scripts",
                value=len(scripts),
                confidence=Confidence.HIGH,
                evidence=[f"{len(scripts)} public script(s) analysed"],
            )
        )

        seen: dict[str, set[str]] = {k: set() for k in _PATTERNS}
        for script in scripts:
            code = script.get("code")
            if not code or script.get("_error"):
                if script.get("_error"):
                    result.errors.append(f"{script.get('url')}: {script['_error']}")
                continue
            for kind, regex in _PATTERNS.items():
                for match in regex.findall(code):
                    value = match if isinstance(match, str) else match[0]
                    if _is_ignored(value, kind):
                        continue
                    seen[kind].add(value)

        for kind, values in seen.items():
            if not values:
                continue
            for value in sorted(values)[:100]:
                result.add_finding(
                    Finding(
                        key=f"js.{kind}",
                        value=value,
                        confidence=Confidence.MEDIUM,
                        evidence=[
                            f"found in public JavaScript source ({kind})",
                            "note: not contacted - reported only",
                        ],
                    )
                )
        return result


def _is_ignored(value: str, kind: str) -> bool:
    if kind in {"url", "ws", "domain"}:
        lowered = value.lower()
        return any(host in lowered for host in _IGNORE_HOSTS)
    return False
