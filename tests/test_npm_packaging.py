"""Tests for the npm wrapper packaging (offline, no Node required)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _package_json() -> dict:
    return json.loads((ROOT / "package.json").read_text(encoding="utf-8"))


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_package_json_exists_and_valid() -> None:
    pkg = _package_json()
    assert pkg["name"] == "vxrecon"
    assert pkg["bin"]["vxrecon"] == "npm/cli.js"


def test_npm_wrapper_script_exists() -> None:
    assert (ROOT / "npm" / "cli.js").is_file()


def test_npm_version_matches_python_version() -> None:
    pkg = _package_json()
    py = _pyproject()
    assert pkg["version"] == py["project"]["version"]


def test_npm_license_matches() -> None:
    pkg = _package_json()
    assert "MIT" in pkg["license"]


def test_npm_files_include_source_and_wrapper() -> None:
    pkg = _package_json()
    files = pkg["files"]
    assert "npm/" in files
    assert "vxrecon.py" in files
    assert "vxrecon/" in files


def test_npmignore_excludes_caches_and_tests() -> None:
    text = (ROOT / ".npmignore").read_text(encoding="utf-8")
    assert "__pycache__" in text
    assert "tests/" in text


def test_wrapper_guards_minimum_python() -> None:
    script = (ROOT / "npm" / "cli.js").read_text(encoding="utf-8")
    # The wrapper must check for Python 3.11+ and forward to the CLI.
    assert "MIN_MINOR" in script
    assert "11" in script
    assert "vxrecon.py" in script
