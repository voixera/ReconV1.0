"""Pipeline: orchestrate collectors, analyzers and correlators.

The pipeline is deliberately simple and synchronous. Its responsibilities:

1. Build an ordered list of modules for a given action.
2. Skip network modules when ``ctx.offline`` is set.
3. Execute each module inside an isolation boundary so a single failure never
   aborts the run.
4. Record per-module duration and status for the timeline/report.

Async or multiprocessing may be added later, but correctness and
observability come first.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from vxrecon.core.context import RunContext
from vxrecon.core.logging import get_logger
from vxrecon.core.registry import ModuleSpec, Registry
from vxrecon.core.result import ScanResult, Status

logger = get_logger()


@dataclass
class ModuleOutcome:
    """Bookkeeping record for one module execution."""

    name: str
    kind: str
    status: Status
    duration_ms: int
    error: str | None = None
    output: Any = None


@dataclass
class PipelineReport:
    """Aggregate result of a pipeline run."""

    target: str
    outcomes: list[ModuleOutcome] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def ok(self) -> bool:
        return all(o.status in {Status.OK, Status.SKIPPED} for o in self.outcomes)

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    @property
    def failures(self) -> list[ModuleOutcome]:
        return [o for o in self.outcomes if o.status is Status.FAILED]

    def results(self) -> list[ScanResult]:
        """Return the analyzer results that carry findings."""

        return [o.output for o in self.outcomes if isinstance(o.output, ScanResult)]

    def graph(self) -> Any:
        """Return the first correlator graph produced, if any."""

        for outcome in self.outcomes:
            if outcome.kind == "correlator" and outcome.output is not None:
                return outcome.output
        return None


class Pipeline:
    """Executes registered modules against a single target."""

    def __init__(self, registry: Registry, ctx: RunContext) -> None:
        self.registry = registry
        self.ctx = ctx
        # Optional per-kind allow-list of module names. ``None`` means "all".
        self.select: dict[str, set[str] | None] = {"collector": None, "analyzer": None, "correlator": None}

    def _names(self, kind: str) -> list[str]:
        allow = self.select.get(kind)
        names = [s.name for s in self.registry.all(kind)]
        if allow is not None:
            names = [n for n in names if n in allow]
        return names

    def run(self, target: str) -> PipelineReport:
        """Run the full collector -> analyzer -> correlator flow."""

        report = PipelineReport(target=target, started_at=time.time())

        collectors = self.registry.resolve_order("collector", self._names("collector"))

        raw_outputs: dict[str, Any] = {}
        for spec in collectors:
            outcome, raw = self._run_collector(spec, target)
            report.outcomes.append(outcome)
            if raw is not None:
                raw_outputs[spec.name] = raw

        analyzers = self.registry.resolve_order("analyzer", self._names("analyzer"))
        findings_by_analyzer: dict[str, ScanResult] = {}
        for spec in analyzers:
            outcome, result = self._run_analyzer(spec, target, raw_outputs)
            report.outcomes.append(outcome)
            if result is not None:
                findings_by_analyzer[spec.name] = result

        correlators = self.registry.resolve_order("correlator", self._names("correlator"))
        results = list(findings_by_analyzer.values())
        for spec in correlators:
            outcome, _ = self._run_correlator(spec, target, results)
            report.outcomes.append(outcome)

        report.finished_at = time.time()
        return report

    # -- executors -------------------------------------------------------

    def _run_collector(self, spec: ModuleSpec, target: str) -> tuple[ModuleOutcome, Any]:
        if spec.requires_network and self.ctx.offline:
            return (
                ModuleOutcome(spec.name, "collector", Status.SKIPPED, 0, "offline mode"),
                None,
            )
        start = time.perf_counter()
        try:
            instance = spec.factory(self.ctx)
            raw = instance.collect(target)  # type: ignore[attr-defined]
            duration = int((time.perf_counter() - start) * 1000)
            return (
                ModuleOutcome(spec.name, "collector", Status.OK, duration, output=raw),
                raw,
            )
        except Exception as exc:  # noqa: BLE001 - isolation boundary is intentional
            duration = int((time.perf_counter() - start) * 1000)
            logger.debug("collector %s failed: %s", spec.name, exc)
            return (
                ModuleOutcome(
                    spec.name, "collector", Status.FAILED, duration, error=str(exc)
                ),
                None,
            )

    def _run_analyzer(
        self, spec: ModuleSpec, target: str, raw_outputs: dict[str, Any]
    ) -> tuple[ModuleOutcome, ScanResult | None]:
        start = time.perf_counter()
        try:
            instance = spec.factory(self.ctx)
            result: ScanResult = instance.analyze(target, raw_outputs, self.ctx)  # type: ignore[attr-defined]
            duration = int((time.perf_counter() - start) * 1000)
            result.duration_ms = duration
            # In offline mode, "no data collected" is expected, not a failure.
            if self.ctx.offline and self._only_missing_data(result):
                result.notes.append("input unavailable in offline mode")
                status = Status.SKIPPED
            else:
                status = Status.PARTIAL if result.errors else Status.OK
            return (
                ModuleOutcome(spec.name, "analyzer", status, duration, output=result),
                result,
            )
        except Exception as exc:  # noqa: BLE001
            duration = int((time.perf_counter() - start) * 1000)
            logger.debug("analyzer %s failed: %s", spec.name, exc)
            return (
                ModuleOutcome(
                    spec.name, "analyzer", Status.FAILED, duration, error=str(exc)
                ),
                None,
            )

    @staticmethod
    def _only_missing_data(result: ScanResult) -> bool:
        """True if every error is a 'no data available' condition."""

        markers = ("no data", "no http", "no dns", "no tls", "no ct", "no javascript", "no rdap", "no public", "no favicon")
        for err in result.errors:
            if not any(marker in err.lower() for marker in markers):
                return False
        return bool(result.errors)

    def _run_correlator(
        self, spec: ModuleSpec, target: str, results: list[ScanResult]
    ) -> tuple[ModuleOutcome, Any]:
        start = time.perf_counter()
        try:
            instance = spec.factory(self.ctx)
            output = instance.correlate(target, results, self.ctx)  # type: ignore[attr-defined]
            duration = int((time.perf_counter() - start) * 1000)
            return (
                ModuleOutcome(spec.name, "correlator", Status.OK, duration, output=output),
                output,
            )
        except Exception as exc:  # noqa: BLE001
            duration = int((time.perf_counter() - start) * 1000)
            logger.debug("correlator %s failed: %s", spec.name, exc)
            return (
                ModuleOutcome(
                    spec.name, "correlator", Status.FAILED, duration, error=str(exc)
                ),
                None,
            )
