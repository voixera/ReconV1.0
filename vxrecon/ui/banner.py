"""ASCII banner for VXRecon.

Rendered once at startup (interactive mode) or suppressed with ``--quiet``.
Deliberately restrained: a framed wordmark and tagline, not ASCII art. Falls
back to plain box-drawing-free ASCII when the terminal encoding cannot render
Unicode.

Set the environment variable ``VXRECON_ASCII=1`` to force the ASCII banner.
"""

from __future__ import annotations

import os

from vxrecon import __version__
from vxrecon.ui.theme import Theme

_WIDTH = 56


def render_banner(theme: Theme | None = None) -> str:
    theme = theme or Theme()
    if os.environ.get("VXRECON_ASCII") or not theme.unicode:
        return _ascii_banner(theme)
    return _unicode_banner(theme)


def _unicode_banner(theme: Theme) -> str:
    lines = [
        theme.color("╔" + "═" * _WIDTH + "╗", "dim_green"),
        _urow("VXRECON", theme),
        _urow("PASSIVE OSINT INTELLIGENCE FRAMEWORK", theme, dim=True),
        theme.color("╚" + "═" * _WIDTH + "╝", "dim_green"),
        "  " + theme.color(f"v{__version__}", "grey"),
    ]
    return "\n".join(lines)


def _ascii_banner(theme: Theme) -> str:
    lines = [
        theme.color("+" + "=" * _WIDTH + "+", "dim_green"),
        _arow("VXRECON", theme),
        _arow("PASSIVE OSINT INTELLIGENCE FRAMEWORK", theme, dim=True),
        theme.color("+" + "=" * _WIDTH + "+", "dim_green"),
        "  " + theme.color(f"v{__version__}", "grey"),
    ]
    return "\n".join(lines)


def _urow(text: str, theme: Theme, dim: bool = False) -> str:
    styles = ("grey",) if dim else ("bright_green", "bold")
    return theme.color("║", "dim_green") + theme.color(text.center(_WIDTH), *styles) + theme.color("║", "dim_green")


def _arow(text: str, theme: Theme, dim: bool = False) -> str:
    styles = ("grey",) if dim else ("bright_green", "bold")
    return theme.color("|", "dim_green") + theme.color(text.center(_WIDTH), *styles) + theme.color("|", "dim_green")


MENU_ITEMS = [
    ("1", "recon", "Full passive reconnaissance pipeline"),
    ("2", "domain", "Domain / registration intelligence"),
    ("3", "dns", "DNS records and resolver behaviour"),
    ("4", "cert", "TLS certificate intelligence"),
    ("5", "dna", "Website DNA fingerprint"),
    ("6", "tech", "Technology confidence breakdown"),
    ("7", "email", "Email infrastructure map"),
    ("8", "files", "Public file exposure map"),
    ("9", "js", "JavaScript endpoint intelligence"),
    ("10", "compare", "Infrastructure similarity"),
    ("11", "graph", "Digital footprint graph"),
    ("12", "diff", "Intelligence diff"),
    ("13", "timeline", "Investigation timeline"),
    ("14", "case", "Case management"),
    ("15", "db", "Local database"),
]


def render_menu(theme: Theme | None = None) -> str:
    theme = theme or Theme()
    width = max(len(label) for _, _, label in MENU_ITEMS) + 6
    rows: list[str] = []
    for num, _cmd, label in MENU_ITEMS:
        left = theme.color(f"[{num.rjust(2)}]", "spring", "bold")
        rows.append(f"{left} {label.ljust(width)}")
    return "\n".join(rows)
