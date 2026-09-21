"""RunContext: the single source of truth for runtime policy.

Every network-capable helper reads ``ctx.offline`` before touching the
network. Every storage helper reads ``ctx.no_save`` before writing. This makes
the ``--offline`` and ``--no-save`` guarantees *architectural* instead of
per-module discipline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from vxrecon import DEFAULT_USER_AGENT, __version__
from vxrecon.core.errors import ConfigError

# Default on-disk locations. Everything lives under the user's home directory
# by default so VXRecon never writes into the current working directory
# without being asked.
DEFAULT_HOME = Path(os.environ.get("VXRECON_HOME", Path.home() / ".vxrecon"))


@dataclass
class RunContext:
    """Immutable-ish runtime policy bag passed through every layer."""

    target: str = ""
    offline: bool = False
    no_save: bool = False
    json: bool = False
    quiet: bool = False
    verbose: int = 0
    no_color: bool = False
    timeout: float = 10.0
    rate_rps: float = 2.0
    user_agent: str = DEFAULT_USER_AGENT
    home: Path = field(default_factory=lambda: DEFAULT_HOME)
    db_path: Path | None = None
    out_dir: Path | None = None
    tool_version: str = __version__
    action: str = ""
    extra: dict = field(default_factory=dict)

    # -- derived paths ---------------------------------------------------

    @property
    def database_file(self) -> Path:
        """Resolved database path (``--db`` overrides the default home)."""

        return self.db_path if self.db_path else self.home / "vxrecon.db"

    @property
    def evidence_dir(self) -> Path:
        return self.home / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.out_dir if self.out_dir else self.home / "reports"

    @property
    def cases_dir(self) -> Path:
        return self.home / "cases"

    # -- validation ------------------------------------------------------

    def validate(self) -> None:
        """Guard against contradictory or unsafe configuration."""

        if self.offline and self.extra.get("force_online"):
            raise ConfigError("--offline conflicts with --force-online")
        if self.timeout <= 0:
            raise ConfigError("--timeout must be greater than zero")
        if self.rate_rps <= 0:
            raise ConfigError("--rate must be greater than zero")
        if self.no_save and self.extra.get("force_save"):
            raise ConfigError("--no-save conflicts with --force-save")
        if self.verbose < 0:
            raise ConfigError("--verbose level must be >= 0")

    def ensure_home(self) -> None:
        """Create the local workspace directories (respects ``--no-save``)."""

        if self.no_save:
            return
        for directory in (self.home, self.evidence_dir, self.reports_dir, self.cases_dir):
            directory.mkdir(parents=True, exist_ok=True)
