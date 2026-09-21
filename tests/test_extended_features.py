"""Tests for the extended features: config, export, SARIF/Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vxrecon.core.config import env_overrides, load_config
from vxrecon.core.context import RunContext
from vxrecon.core.errors import ConfigError
from vxrecon.reporters.markdown_report import MarkdownReporter
from vxrecon.reporters.sarif_report import SarifReporter
from vxrecon.utils.export import to_csv, write_export


# -- config -----------------------------------------------------------------


def test_load_json_config(tmp_path: Path) -> None:
    cfg = tmp_path / "vx.json"
    cfg.write_text(json.dumps({"timeout": 3.0, "rate_rps": 1.0}), encoding="utf-8")
    data = load_config(cfg)
    assert data["timeout"] == 3.0
    assert data["rate_rps"] == 1.0


def test_load_toml_config(tmp_path: Path) -> None:
    cfg = tmp_path / "vx.toml"
    cfg.write_text('timeout = 4.5\nrate_rps = 2.5\n', encoding="utf-8")
    data = load_config(cfg)
    assert data["timeout"] == 4.5


def test_config_ignores_unknown_keys(tmp_path: Path) -> None:
    cfg = tmp_path / "vx.json"
    cfg.write_text(json.dumps({"timeout": 5.0, "bogus": 1}), encoding="utf-8")
    data = load_config(cfg)
    assert "bogus" not in data


def test_config_missing_file_raises() -> None:
    with pytest.raises(ConfigError):
        load_config("does-not-exist.json")


def test_config_invalid_json_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.json"
    cfg.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VXRECON_TIMEOUT", "8.0")
    monkeypatch.setenv("VXRECON_OFFLINE", "true")
    overrides = env_overrides()
    assert overrides["timeout"] == 8.0
    assert overrides["offline"] is True


def test_cli_overrides_config(tmp_path: Path) -> None:
    cfg = tmp_path / "vx.toml"
    cfg.write_text("timeout = 3.0\n", encoding="utf-8")
    from vxrecon.ui.cli import build_parser, context_from_args

    args = build_parser().parse_args(["version", "--config", str(cfg), "--timeout", "20"])
    ctx = context_from_args(args)
    assert ctx.timeout == 20.0


def test_config_applies_when_no_cli_flag(tmp_path: Path) -> None:
    cfg = tmp_path / "vx.toml"
    cfg.write_text("timeout = 7.5\nrate_rps = 0.5\n", encoding="utf-8")
    from vxrecon.ui.cli import build_parser, context_from_args

    args = build_parser().parse_args(["version", "--config", str(cfg)])
    ctx = context_from_args(args)
    assert ctx.timeout == 7.5
    assert ctx.rate_rps == 0.5


# -- export -----------------------------------------------------------------


def test_to_csv_has_header_and_rows() -> None:
    rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
    csv_text = to_csv(rows)
    lines = csv_text.strip().splitlines()
    assert lines[0] == "a,b"
    assert lines[1] == "1,x"
    assert len(lines) == 3


def test_to_csv_handles_nested_and_none() -> None:
    rows = [{"a": None, "b": {"k": "v"}}]
    csv_text = to_csv(rows)
    assert '"{""k"": ""v""}"' in csv_text or "k" in csv_text


def test_write_export_json(tmp_path: Path) -> None:
    path = write_export(tmp_path, "data", [{"x": 1}], fmt="json")
    assert path.exists() and path.suffix == ".json"
    assert json.loads(path.read_text(encoding="utf-8")) == [{"x": 1}]


def test_write_export_csv(tmp_path: Path) -> None:
    path = write_export(tmp_path, "data", [{"x": 1}], fmt="csv")
    assert path.exists() and path.suffix == ".csv"


# -- reports ----------------------------------------------------------------


def _payload() -> dict:
    return {
        "target": "example.com",
        "action": "recon",
        "results": [
            {
                "module": "dns",
                "findings": [
                    {
                        "key": "dns.a",
                        "value": "1.2.3.4",
                        "confidence": "HIGH",
                        "evidence": ["A record"],
                    }
                ],
                "errors": [],
            }
        ],
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "src_kind": "domain",
                    "src_value": "example.com",
                    "dst_kind": "ip",
                    "dst_value": "1.2.3.4",
                    "relation": "resolves_to",
                    "confidence": "HIGH",
                }
            ],
        },
    }


def test_markdown_report_structure() -> None:
    ctx = RunContext(quiet=True)
    md = MarkdownReporter(ctx).render(_payload())
    assert md.startswith("# VXRecon report")
    assert "| Confidence | Key | Value |" in md
    assert "resolves_to" in md
    assert "not ownership" in md.lower()


def test_sarif_report_valid_shape() -> None:
    ctx = RunContext(quiet=True)
    sarif = json.loads(SarifReporter(ctx).render(_payload()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VXRecon"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"].startswith("vxrecon/")


def test_sarif_carries_confidence() -> None:
    ctx = RunContext(quiet=True)
    sarif = json.loads(SarifReporter(ctx).render(_payload()))
    assert sarif["runs"][0]["results"][0]["properties"]["confidence"] == "HIGH"
