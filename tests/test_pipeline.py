"""Tests for the pipeline's error-isolation behaviour.

A failing collector/analyzer must never abort the run; the pipeline records the
failure and continues.
"""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.core.pipeline import Pipeline
from vxrecon.core.registry import ModuleSpec, Registry
from vxrecon.core.result import Finding, ScanResult, Status


class _BoomCollector:
    requires_network = False

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def collect(self, target: str):
        raise RuntimeError("simulated failure")


class _GoodCollector:
    requires_network = False

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def collect(self, target: str):
        return {"value": 1}


class _NetCollector:
    requires_network = True

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def collect(self, target: str):
        return {"net": True}


class _Analyzer:
    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def analyze(self, target: str, raw: dict, ctx: RunContext) -> ScanResult:
        result = ScanResult(target=target, module="good")
        # ``raw`` is keyed by collector name; pull facts from the "good" one.
        value = raw.get("good", {}).get("value", 0)
        result.add_finding(Finding(key="x", value=value))
        return result


def _build_registry() -> Registry:
    reg = Registry()
    reg.register(ModuleSpec("boom", "collector", _BoomCollector))
    reg.register(ModuleSpec("good", "collector", _GoodCollector))
    reg.register(ModuleSpec("net", "collector", _NetCollector, requires_network=True))
    reg.register(ModuleSpec("analyzer", "analyzer", _Analyzer))
    return reg


def test_failing_module_is_isolated() -> None:
    ctx = RunContext(quiet=True)
    report = Pipeline(_build_registry(), ctx).run("example.com")
    statuses = {o.name: o.status for o in report.outcomes}
    assert statuses["boom"] is Status.FAILED
    assert statuses["good"] is Status.OK


def test_offline_skips_network_collector() -> None:
    ctx = RunContext(offline=True, quiet=True)
    report = Pipeline(_build_registry(), ctx).run("example.com")
    net = next(o for o in report.outcomes if o.name == "net")
    assert net.status is Status.SKIPPED


def test_analyzer_receives_raw_facts() -> None:
    ctx = RunContext(quiet=True)
    report = Pipeline(_build_registry(), ctx).run("example.com")
    results = report.results()
    assert results
    assert results[0].findings[0].value == 1
