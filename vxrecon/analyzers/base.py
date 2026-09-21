"""Base class for analyzers.

Analyzers are **pure**: they take raw collector output and return a
:class:`~vxrecon.core.result.ScanResult` full of evidence-backed findings.
They must not perform I/O, must not mutate their inputs, and must not raise for
bad/partial data — a missing collector output simply means fewer findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult


class BaseAnalyzer(ABC):
    """Abstract base for all analyzers."""

    name: str = "analyzer"
    #: Collector names this analyzer reads from (informational/diagnostic).
    consumes: tuple[str, ...] = ()

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        """Turn raw facts into findings. Pure function."""

    def _result(self, target: str) -> ScanResult:
        return ScanResult(target=target, module=self.name)
