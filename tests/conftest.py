"""Shared pytest fixtures for the VXRecon test-suite.

All tests run fully offline: they must never perform network I/O. The
``isolated_home`` fixture redirects the workspace into a tmp dir so tests never
touch the developer's real ``~/.vxrecon``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vxrecon.core.context import RunContext


@pytest.fixture()
def isolated_home(tmp_path: Path) -> Path:
    home = tmp_path / ".vxrecon"
    home.mkdir(parents=True, exist_ok=True)
    return home


@pytest.fixture()
def ctx(isolated_home: Path) -> RunContext:
    context = RunContext(
        target="example.com",
        home=isolated_home,
        no_color=True,
        quiet=True,
    )
    context.validate()
    return context
