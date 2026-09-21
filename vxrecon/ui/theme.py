"""Terminal theme: ANSI colors and status glyphs.

Professional security-framework look, not "hacker movie". Colors degrade
gracefully when disabled or when the terminal lacks support.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

# Raw ANSI SGR codes. Nothing exotic; these are supported by Windows Terminal,
# PowerShell 5.1+ (with VT enabled), and every modern *nix terminal.
_RESET = "\x1b[0m"
_CODES = {
    "reset": _RESET,
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "grey": "\x1b[90m",
    # 256-color bright variants for a cleaner green-accented theme.
    "bright_green": "\x1b[38;5;46m",
    "lime": "\x1b[38;5;118m",
    "spring": "\x1b[38;5;48m",
    "teal": "\x1b[38;5;44m",
    "dim_green": "\x1b[38;5;28m",
}

# The VXRecon accent color. Green, per the project's visual identity.
ACCENT = "spring"
ACCENT_STRONG = "bright_green"

# Status glyphs use plain ASCII so output survives copy/paste and log files.
GLYPHS = {
    "ok": "[+]",
    "warn": "[!]",
    "err": "[-]",
    "info": "[*]",
    "skip": "[~]",
    "new": "[+]",
    "removed": "[-]",
    "changed": "[~]",
}


@dataclass
class Theme:
    """Color/glyph rendering facade honoring ``--no-color``."""

    enabled: bool = True
    unicode: bool | None = None

    def __post_init__(self) -> None:
        if self.unicode is None:
            self.unicode = _supports_unicode()

    def color(self, text: str, *styles: str) -> str:
        if not self.enabled:
            return text
        prefix = "".join(_CODES.get(s, "") for s in styles)
        return f"{prefix}{text}{_RESET}"

    def glyph(self, name: str, label: str, style: str = "bold") -> str:
        symbol = GLYPHS.get(name, "[*]")
        color_name = {
            "ok": "bright_green",
            "warn": "yellow",
            "err": "red",
            "info": "spring",
            "skip": "grey",
        }.get(name, "spring")
        return f"{self.color(symbol, color_name, style)} {label}"

    def accent(self, text: str, *, strong: bool = False) -> str:
        """Render ``text`` in the project accent color (green)."""

        return self.color(text, ACCENT_STRONG if strong else ACCENT, "bold")

    def divider(self, width: int = 60, char: str = "─") -> str:
        if not self.unicode and char == "─":
            char = "-"
        return self.color(char * width, "dim_green")

    def rule(self, width: int = 56) -> str:
        """Return horizontal rule characters for framed banners."""

        return "=" * width if not self.unicode else "═" * width


def _supports_unicode() -> bool:
    """Heuristically decide whether the active stdout can encode box glyphs."""

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "─═│╔╗╚╝".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False
