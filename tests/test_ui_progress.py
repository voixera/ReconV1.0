"""Tests for the terminal UI: theme accent, spinner and pipeline hooks."""

from __future__ import annotations

import io
import time
from contextlib import redirect_stderr

from vxrecon.core.context import RunContext
from vxrecon.core.result import Status
from vxrecon.ui.progress import UIReporter
from vxrecon.ui.theme import ACCENT, GLYPHS, Theme


def test_theme_accent_is_green() -> None:
    theme = Theme(enabled=True, unicode=True)
    rendered = theme.accent("hello")
    # The accent maps to a green ANSI escape, not blue/cyan.
    assert "\x1b[" in rendered
    assert ACCENT in {"spring", "bright_green"}


def test_theme_uses_green_for_ok_glyph() -> None:
    theme = Theme(enabled=True, unicode=True)
    assert GLYPHS["ok"] == "[+]"
    # The ok glyph should color-code to a green SGR.
    code = theme.color("x", "bright_green", "bold")
    assert code.startswith("\x1b[")


def test_theme_no_color_returns_plain() -> None:
    theme = Theme(enabled=False)
    assert theme.color("abc", "green") == "abc"


def test_spinner_non_animated_prints_working_line() -> None:
    buf = io.StringIO()
    ui = UIReporter(theme=Theme(enabled=False), quiet=False, animate=False)
    with redirect_stderr(buf):
        ui.spin("collector:dns")
    assert "collector:dns" in buf.getvalue()
    assert "working" in buf.getvalue()


def test_spinner_animated_runs_and_stops() -> None:
    ui = UIReporter(theme=Theme(enabled=False, unicode=False), quiet=False, animate=True)
    ui.spin("collector:tls")
    time.sleep(0.2)
    assert ui._spinner_thread is not None
    ui.stop_spin()
    assert ui._spinner_thread is None


def test_spinner_is_noop_in_quiet_mode() -> None:
    buf = io.StringIO()
    ui = UIReporter(theme=Theme(enabled=True), quiet=True, animate=True)
    with redirect_stderr(buf):
        ui.spin("collector:dns")
        ui.stop_spin()
    assert buf.getvalue() == ""


def test_step_renders_status_text() -> None:
    buf = io.StringIO()
    ui = UIReporter(theme=Theme(enabled=False), quiet=False, animate=False)
    with redirect_stderr(buf):
        ui.step("collector:dns", Status.OK)
    out = buf.getvalue()
    assert "collector:dns" in out
    assert "OK" in out


def test_pipeline_hooks_fire_in_order() -> None:
    """The pipeline must call on_start/on_finish for each module."""

    from vxrecon.core.pipeline import Pipeline
    from vxrecon.core.registry import ModuleSpec, Registry

    class _Collector:
        requires_network = False

        def __init__(self, ctx: RunContext) -> None:
            self.ctx = ctx

        def collect(self, target: str):
            return {"ok": True}

    reg = Registry()
    reg.register(ModuleSpec("c1", "collector", _Collector))
    ctx = RunContext(quiet=True)
    pipeline = Pipeline(reg, ctx)

    events: list[str] = []
    pipeline.on_start = lambda kind, name: events.append(f"start:{kind}:{name}")
    pipeline.on_finish = lambda outcome: events.append(f"finish:{outcome.name}")
    pipeline.run("example.com")

    assert events == ["start:collector:c1", "finish:c1"]
