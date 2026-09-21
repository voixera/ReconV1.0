"""Configuration file loading.

VXRecon accepts an optional config file (``--config path``) in JSON or TOML.
Precedence, highest first:

1. Explicit CLI flags
2. Environment variables (``VXRECON_*``)
3. Config file values
4. Built-in defaults

The file is plain data with no executable content. Unknown keys are ignored so a
config written for a newer version never breaks an older one. TOML uses the
stdlib ``tomllib`` (Python 3.11+); JSON always works.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from vxrecon.core.errors import ConfigError

# Keys we understand. Anything else is ignored (forward compatible).
_KNOWN_KEYS = {
    "timeout",
    "rate_rps",
    "user_agent",
    "offline",
    "no_save",
    "no_color",
    "json",
    "quiet",
    "verbose",
    "db_path",
    "out_dir",
    "home",
}


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a JSON or TOML config file into a normalized dict.

    Raises :class:`ConfigError` for missing/unreadable/invalid files.
    """

    file = Path(path)
    if not file.exists():
        raise ConfigError(f"config file not found: {file}")
    text = file.read_text(encoding="utf-8")

    suffix = file.suffix.lower()
    try:
        if suffix == ".toml":
            data = _load_toml(text)
        elif suffix == ".json":
            data = json.loads(text)
        else:
            # Try TOML first for extensionless files, then JSON.
            try:
                data = _load_toml(text)
            except Exception:  # noqa: BLE001
                data = json.loads(text)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"could not parse config file: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("config file must contain an object/table at the top level")
    return {k: v for k, v in data.items() if k in _KNOWN_KEYS}


def _load_toml(text: str) -> dict[str, Any]:
    try:
        import tomllib  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ConfigError("TOML support requires Python 3.11+") from exc
    return tomllib.loads(text)


def merge_config(ctx_data: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Merge config values into a context kwargs dict.

    ``ctx_data`` is treated as authoritative: config only fills values that are
    still at their sentinel/default. Because argparse defaults are always
    present, callers should pass only *user-specified* keys here. For the CLI we
    therefore apply config to a fresh dict and let explicit flags win via the
    caller passing sentinel ``None`` for unset flags.
    """

    merged = dict(ctx_data)
    for key, value in config.items():
        if key not in merged or merged[key] is None:
            merged[key] = value
    return merged


def env_overrides() -> dict[str, Any]:
    """Read ``VXRECON_*`` environment variables into config keys."""

    overrides: dict[str, Any] = {}
    mapping = {
        "VXRECON_TIMEOUT": ("timeout", float),
        "VXRECON_RATE": ("rate_rps", float),
        "VXRECON_USER_AGENT": ("user_agent", str),
        "VXRECON_HOME": ("home", str),
        "VXRECON_DB": ("db_path", str),
        "VXRECON_OFFLINE": ("offline", _to_bool),
        "VXRECON_NO_SAVE": ("no_save", _to_bool),
    }
    for env_name, (key, caster) in mapping.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        try:
            overrides[key] = caster(raw)
        except (ValueError, TypeError):
            continue
    return overrides


def _to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
