"""Base class for reporters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vxrecon.core.context import RunContext


class BaseReporter(ABC):
    """Abstract base for output reporters."""

    name: str = "reporter"

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def render(self, data: dict[str, Any]) -> str:
        """Render ``data`` to a string. Pure function."""
