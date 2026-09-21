"""Formatting helpers for terminal and report output."""

from __future__ import annotations


def human_bytes(size: int | float, precision: int = 1) -> str:
    """Format a byte count like ``"1.4 KB"``."""

    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.{precision}f} {unit}"
        value /= 1024.0
    return f"{value:.{precision}f} PB"


def human_ms(milliseconds: int) -> str:
    """Format a duration in milliseconds."""

    if milliseconds < 1000:
        return f"{milliseconds} ms"
    return f"{milliseconds / 1000:.2f} s"


def truncate(text: str, length: int = 80, ellipsis: str = "...") -> str:
    """Truncate a string to ``length`` characters."""

    if len(text) <= length:
        return text
    return text[: max(0, length - len(ellipsis))] + ellipsis


def kv_table(rows: list[tuple[str, str]], key_width: int = 20) -> str:
    """Render a two-column key/value block without external dependencies."""

    return "\n".join(f"{key.ljust(key_width)}: {value}" for key, value in rows)
