"""Human-facing progress reporting.

The UI reporter draws step lines like::

    [+] Resolving target ............ OK

It is a pure *sink*: modules never print directly. When ``--quiet`` is set the
reporter becomes a no-op so automation output stays clean. When ``--json`` is
set, human progress is suppressed to keep stdout machine-parseable.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field

from vxrecon.core.result import Status
from vxrecon.ui.theme import Theme


@dataclass
class UIReporter:
    """Renders step-by-step progress to stderr/stdout."""

    theme: Theme = field(default_factory=Theme)
    quiet: bool = False
    json_mode: bool = False
    verbose: int = 0
    width: int = 42
    _start: float = field(default_factory=time.perf_counter)

    # -- primitives ------------------------------------------------------

    def _emit(self, text: str) -> None:
        if self.quiet or self.json_mode:
            return
        print(text, file=sys.stderr)

    def section(self, title: str) -> None:
        if self.quiet or self.json_mode:
            return
        self._emit("")
        self._emit(self.theme.color(title.upper(), "bold", "white"))
        self._emit(self.theme.divider(len(title) + 4))

    def step(self, label: str, status: Status | str = Status.OK, detail: str = "") -> None:
        """Render a single progress line.

        Examples
        --------
        ``[+] Resolving target ............ OK``
        """

        if isinstance(status, Status):
            mapping = {
                Status.OK: "ok",
                Status.PARTIAL: "warn",
                Status.FAILED: "err",
                Status.SKIPPED: "skip",
            }
            glyph = mapping[status]
            tail = status.value.upper()
        else:
            glyph = status
            tail = status.upper()

        dots = "." * max(2, self.width - len(label))
        line = f"{self.theme.glyph(glyph, label)} {self.theme.color(dots, 'grey')} {tail}"
        if detail and self.verbose:
            line += f" {self.theme.color(detail, 'grey')}"
        self._emit(line)

    def info(self, message: str) -> None:
        self._emit(self.theme.glyph("info", message))

    def warn(self, message: str) -> None:
        self._emit(self.theme.glyph("warn", message, style="bold"))

    def error(self, message: str) -> None:
        self._emit(self.theme.glyph("err", message, style="bold"))

    def success(self, message: str) -> None:
        self._emit(self.theme.glyph("ok", message))

    def detail(self, message: str, level: int = 1) -> None:
        """Indented detail, shown only when verbose >= ``level``."""

        if self.verbose >= level:
            self._emit("    " + self.theme.color(message, "grey"))

    def summary(self, *, duration_ms: int, ok: bool, findings: int) -> None:
        if self.quiet or self.json_mode:
            return
        verdict = self.theme.color("COMPLETE", "green", "bold") if ok else self.theme.color(
            "PARTIAL", "yellow", "bold"
        )
        self._emit("")
        self._emit(
            f"{verdict}  ({duration_ms} ms, {findings} finding(s))"
        )
