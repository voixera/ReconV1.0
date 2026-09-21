"""Base class for correlators."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult
from vxrecon.correlators.graph import Graph


class BaseCorrelator(ABC):
    """Abstract base for correlators. Pure functions over findings."""

    name: str = "correlator"

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def correlate(self, target: str, results: list[ScanResult], ctx: RunContext) -> Graph:
        """Build a relationship graph from analyzer findings."""
