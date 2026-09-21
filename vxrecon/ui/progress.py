"""Human-facing progress reporting with a live spinner.

The UI reporter draws animated step lines while modules run, e.g.::

    [+] collector:dns ⠹ working...
    [+] collector:dns ............................. OK

It is a pure *sink*: modules never print directly. When ``--quiet`` is set the
reporter becomes a no-op so automation output stays clean. When ``--json`` is
set, human progress is suppressed to keep stdout machine-parseable.

The spinner only animates on an interactive TTY (and when output is not being
redirected); otherwise it falls back to plain lines so logs stay readable.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field

from vxrecon.core.result import Status
from vxrecon.ui.theme import Theme

# Braille spinner frames (widely supported). ASCII fallback used when the
# terminal cannot render them.
_SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_ASCII = "|/-\\"

_STATUS_MAP = {
    Status.OK: ("ok", "OK"),
    Status.PARTIAL: ("warn", "PARTIAL"),
    Status.FAILED: ("err", "FAILED"),
    Status.SKIPPED: ("skip", "SKIPPED"),
}


@dataclass
class UIReporter:
    """Renders step-by-step progress to stderr/stdout."""

    theme: Theme = field(default_factory=Theme)
    quiet: bool = False
    json_mode: bool = False
    verbose: int = 0
    width: int = 42
    animate: bool | None = None
    _start: float = field(default_factory=time.perf_counter)
    # Live-spinner state.
    _spinner_thread: threading.Thread | None = None
    _spinner_stop: threading.Event = field(default_factory=threading.Event)
    _spinner_label: str = ""

    def __post_init__(self) -> None:
        if self.animate is None:
            self.animate = self._detect_tty()

    # -- primitives ------------------------------------------------------

    def _active(self) -> bool:
        return not (self.quiet or self.json_mode)

    def _emit(self, text: str) -> None:
        if not self._active():
            return
        print(text, file=sys.stderr)

    @staticmethod
    def _detect_tty() -> bool:
        try:
            return sys.stderr.isatty()
        except (AttributeError, ValueError):
            return False

    # -- live spinner ----------------------------------------------------

    def spin(self, label: str) -> None:
        """Start a live spinner for ``label`` (no-op when not animating)."""

        if not self._active():
            return
        self.stop_spin(clear=True)
        if not self.animate:
            # Non-interactive: show a plain "working" line so output is not
            # silent for the whole scan.
            self._emit(f"{self.theme.glyph('info', label)} {self.theme.color('working...', 'grey')}")
            return

        self._spinner_label = label
        self._spinner_stop = threading.Event()

        def _run() -> None:
            frames = _SPINNER_UNICODE if self.theme.unicode else _SPINNER_ASCII
            idx = 0
            glyph = self.theme.color(GLYPHS_PLUS, "spring", "bold")
            while not self._spinner_stop.is_set():
                frame = frames[idx % len(frames)]
                line = (
                    f"\r{glyph} {label} "
                    f"{self.theme.color(frame, 'bright_green', 'bold')} "
                    f"{self.theme.color('working...', 'grey')}"
                )
                sys.stderr.write(line)
                sys.stderr.flush()
                idx += 1
                self._spinner_stop.wait(0.08)

        self._spinner_thread = threading.Thread(target=_run, daemon=True)
        self._spinner_thread.start()

    def stop_spin(self, *, clear: bool = True) -> None:
        """Stop any running spinner (optionally clearing its line)."""

        if self._spinner_thread is None:
            return
        self._spinner_stop.set()
        self._spinner_thread.join(timeout=0.5)
        self._spinner_thread = None
        if clear and self._active():
            # Clear the spinner line before printing the final status.
            sys.stderr.write("\r" + " " * 80 + "\r")
            sys.stderr.flush()

    # -- structured output ----------------------------------------------

    def section(self, title: str) -> None:
        if not self._active():
            return
        self.stop_spin()
        self._emit("")
        self._emit(self.theme.accent(title.upper(), strong=True))
        self._emit(self.theme.divider(len(title) + 4))

    def step(self, label: str, status: Status | str = Status.OK, detail: str = "") -> None:
        """Render a single completed progress line.

        Examples
        --------
        ``[+] Resolving target ............ OK``
        """

        if isinstance(status, Status):
            glyph, tail = _STATUS_MAP.get(status, ("info", status.value.upper()))
        else:
            glyph = status
            tail = str(status).upper()

        dots = "." * max(2, self.width - len(label))
        tail_color = {
            "OK": "bright_green",
            "PARTIAL": "yellow",
            "FAILED": "red",
            "SKIPPED": "grey",
        }.get(tail, "spring")
        line = (
            f"{self.theme.glyph(glyph, label)} "
            f"{self.theme.color(dots, 'dim_green')} "
            f"{self.theme.color(tail, tail_color, 'bold')}"
        )
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
        self._emit(self.theme.glyph("ok", message, style="bold"))

    def detail(self, message: str, level: int = 1) -> None:
        """Indented detail, shown only when verbose >= ``level``."""

        if self.verbose >= level:
            self._emit("    " + self.theme.color(message, "grey"))

    def summary(self, *, duration_ms: int, ok: bool, findings: int) -> None:
        if not self._active():
            return
        self.stop_spin()
        verdict = (
            self.theme.color("COMPLETE", "bright_green", "bold")
            if ok
            else self.theme.color("PARTIAL", "yellow", "bold")
        )
        self._emit("")
        self._emit(f"{verdict}  {self.theme.color(f'({duration_ms} ms, {findings} finding(s))', 'grey')}")


# '+' glyph reused by the spinner; declared here to avoid importing GLYPHS.
GLYPHS_PLUS = "[+]"
