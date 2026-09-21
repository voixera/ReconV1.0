"""CLI action handlers.

Each ``cmd_<action>`` function receives the parsed ``args`` namespace and the
validated :class:`RunContext`, and returns an exit code. Handlers stay thin:
they validate the target, build a pipeline, and hand results to a reporter.

Phase 1 implements the structural actions (``version``, ``doctor``, ``db``,
``case``, ``menu``). Reconnaissance actions are wired to the pipeline but
report a clear "module not yet available" status until later phases land the
collectors/analyzers.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys

from vxrecon import __program__, __url__, __version__
from vxrecon.core.context import RunContext
from vxrecon.core.errors import ValidationError
from vxrecon.core.pipeline import Pipeline
from vxrecon.core.registry import DEFAULT_REGISTRY
from vxrecon.core.result import Confidence, Evidence, Finding, ScanResult, Status
from vxrecon.ui.banner import render_banner, render_menu
from vxrecon.ui.progress import UIReporter
from vxrecon.ui.theme import Theme

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _reporter(ctx: RunContext) -> UIReporter:
    return UIReporter(
        theme=Theme(enabled=not ctx.no_color),
        quiet=ctx.quiet,
        json_mode=ctx.json,
        verbose=ctx.verbose,
    )


def _emit_json(payload: object) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")


def _require_target(ctx: RunContext) -> str:
    if not ctx.target:
        raise ValidationError("this action requires a target argument")
    return ctx.target.strip()


# ---------------------------------------------------------------------------
# meta actions
# ---------------------------------------------------------------------------


def cmd_version(args: argparse.Namespace, ctx: RunContext) -> int:
    """Print version and build information."""

    info = {
        "program": __program__,
        "version": __version__,
        "url": __url__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "modules": {
            kind: [s.name for s in DEFAULT_REGISTRY.all(kind)]
            for kind in ("collector", "analyzer", "correlator")
        },
    }
    if ctx.json:
        _emit_json(info)
    else:
        ui = _reporter(ctx)
        ui._emit(f"{__program__} {__version__}")
        ui._emit(f"  python  : {info['python']}")
        ui._emit(f"  platform: {info['platform']}")
        total = sum(len(v) for v in info["modules"].values())
        ui._emit(f"  modules : {total} registered")
    return 0


def cmd_doctor(args: argparse.Namespace, ctx: RunContext) -> int:
    """Environment and capability self-check."""

    ui = _reporter(ctx)
    ui.section("environment check")

    checks: list[dict[str, object]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})
        ui.step(name, Status.OK if ok else Status.FAILED, detail)

    check("Python >= 3.11", sys.version_info >= (3, 11), platform.python_version())
    check("SQLite available", _has_sqlite(), "stdlib sqlite3")
    check("SSL context", _has_ssl(), "stdlib ssl")
    check("dnspython (optional)", _has_module("dns"), "TXT/MX support")
    check("Pillow (optional)", _has_module("PIL"), "image metadata")
    check("offline mode", True, "enabled" if ctx.offline else "disabled")

    ui.section("workspace")
    ui.info(f"home       : {ctx.home}")
    ui.info(f"database   : {ctx.database_file}")
    ui.info(f"reports    : {ctx.reports_dir}")

    if ctx.json:
        _emit_json({"checks": checks, "home": str(ctx.home)})
    return 0


def _has_module(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def _has_sqlite() -> bool:
    return _has_module("sqlite3")


def _has_ssl() -> bool:
    return _has_module("ssl")


# ---------------------------------------------------------------------------
# database actions
# ---------------------------------------------------------------------------


def cmd_db(args: argparse.Namespace, ctx: RunContext) -> int:
    """Database subcommands: init, stats, targets, relationships, dns, certs, export, vacuum."""

    parts = getattr(args, "db_args", None) or ["stats"]
    sub = parts[0] if parts else "stats"
    from vxrecon.database import db as dbmod
    from vxrecon.database import repo_read

    ui = _reporter(ctx)

    if sub == "init":
        ctx.ensure_home()
        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        conn.close()
        ui.success(f"database initialized at {ctx.database_file}")
        return 0

    if sub == "stats":
        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        stats = dbmod.stats(conn)
        conn.close()
        if ctx.json:
            _emit_json(stats)
        else:
            ui.section("database statistics")
            for table, count in stats.items():
                ui.info(f"{table:<20} {count}")
        return 0

    if sub in {"targets", "relationships", "dns", "certs"}:
        listing = {
            "targets": repo_read.list_targets,
            "relationships": repo_read.list_relationships,
            "dns": repo_read.list_dns_records,
            "certs": repo_read.list_certificates,
        }[sub]
        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        rows = listing(conn)
        conn.close()
        if ctx.json:
            _emit_json(rows)
        else:
            ui.section(f"database: {sub}")
            if not rows:
                ui.info("no rows")
            for row in rows[:100]:
                ui._emit("  " + " | ".join(f"{k}={v}" for k, v in row.items()))
            if len(rows) > 100:
                ui.info(f"... {len(rows) - 100} more row(s)")
        return 0

    if sub == "export":
        fmt = parts[1] if len(parts) > 1 else "json"
        if fmt not in {"json", "csv"}:
            ui.error(f"unsupported export format: {fmt} (use json or csv)")
            return 3
        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        payload = {
            "targets": repo_read.list_targets(conn),
            "relationships": repo_read.list_relationships(conn),
            "dns_records": repo_read.list_dns_records(conn),
            "certificates": repo_read.list_certificates(conn),
        }
        conn.close()

        from vxrecon.utils.export import write_export

        out_dir = ctx.reports_dir / "db-export"
        written: list[str] = []
        for name, rows in payload.items():
            path = write_export(out_dir, name, rows, fmt=fmt)
            written.append(str(path))
        ui.section("database export")
        for path in written:
            ui.success(path)
        if ctx.json:
            _emit_json({"exported": written, "counts": {k: len(v) for k, v in payload.items()}})
        return 0

    if sub == "vacuum":
        conn = dbmod.connect(ctx.database_file)
        dbmod.initialize(conn)
        repo_read.vacuum(conn)
        conn.close()
        ui.success("database vacuumed and optimized")
        return 0

    ui.error(f"unknown db subcommand: {sub}")
    ui.info("available: init stats targets relationships dns certs export vacuum")
    return 3


# ---------------------------------------------------------------------------
# case actions
# ---------------------------------------------------------------------------


def cmd_case(args: argparse.Namespace, ctx: RunContext) -> int:
    """Case subcommands: create, add, list."""

    from vxrecon.cases import manager

    parts = getattr(args, "case_args", None) or ["list"]
    sub = parts[0]
    ui = _reporter(ctx)

    if sub == "create":
        if len(parts) < 2:
            ui.error("usage: case create <name>")
            return 3
        path = manager.create_case(ctx, parts[1])
        ui.success(f"case created: {path}")
        return 0

    if sub == "add":
        if len(parts) < 3:
            ui.error("usage: case add <name> <target>")
            return 3
        manager.add_target(ctx, parts[1], parts[2])
        ui.success(f"target {parts[2]} added to case {parts[1]}")
        return 0

    if sub == "list":
        cases = manager.list_cases(ctx)
        if ctx.json:
            _emit_json({"cases": cases})
        else:
            ui.section("cases")
            if not cases:
                ui.info("no cases yet")
            for case in cases:
                ui.info(f"{case['name']}  ({case['targets']} target(s))")
        return 0

    if sub == "report":
        if len(parts) < 2:
            ui.error("usage: case report <name>")
            return 3
        return _case_report(ctx, parts[1])

    ui.error(f"unknown case subcommand: {sub}")
    ui.info("available: create add list report")
    return 3


def _case_report(ctx: RunContext, case_name: str) -> int:
    """Aggregate all targets in a case into a single HTML report."""

    from vxrecon.cases import manager
    from vxrecon.database import db as dbmod
    from vxrecon.database import repo_read
    from vxrecon.reporters.html_report import HtmlReporter

    ui = _reporter(ctx)
    try:
        targets = manager.case_targets(ctx, case_name)
    except Exception as exc:  # noqa: BLE001
        ui.error(str(exc))
        return 3

    conn = dbmod.connect(ctx.database_file)
    dbmod.initialize(conn)

    aggregate_results: list[dict] = []
    for target in targets:
        snapshots = repo_read.latest_snapshots(conn, target, limit=1)
        if snapshots:
            for result in snapshots[0]["payload"].get("results", []):
                aggregate_results.append(result)
    conn.close()

    payload = {
        "target": f"case:{case_name}",
        "action": "case-report",
        "results": aggregate_results,
        "graph": None,
    }
    html = HtmlReporter(ctx).render(payload)
    out = manager.write_case_report(ctx, case_name, html, filename="report.html")

    ui.section(f"case report: {case_name}")
    ui.info(f"targets aggregated: {len(targets)}")
    ui.info(f"result blocks: {len(aggregate_results)}")
    ui.success(str(out))
    if ctx.json:
        _emit_json({"case": case_name, "targets": targets, "report": str(out)})
    return 0


# ---------------------------------------------------------------------------
# interactive shell
# ---------------------------------------------------------------------------


def cmd_menu(args: argparse.Namespace, ctx: RunContext) -> int:
    """Interactive menu shell."""

    from vxrecon.ui.menu import run_shell

    return run_shell(ctx)


ACTIONS = [
    "recon", "domain", "dns", "cert", "dna", "tech", "http", "files", "js",
    "email", "subdomains", "username", "image", "metadata", "compare",
    "correlate", "graph", "diff", "timeline", "report", "case", "db",
    "doctor", "version", "completions", "menu",
]


def cmd_completions(args: argparse.Namespace, ctx: RunContext) -> int:
    """Print a shell completion script for the requested shell."""

    shell = getattr(args, "shell", "powershell")
    actions = " ".join(ACTIONS)
    template = {
        "powershell": _PS_COMPLETION,
        "bash": _BASH_COMPLETION,
        "zsh": _ZSH_COMPLETION,
    }[shell]
    print(template.replace("__ACTIONS__", actions))
    return 0


_PS_COMPLETION = """
Register-ArgumentCompleter -Native -CommandName vxrecon -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $actions = "__ACTIONS__".Split(' ')
    $actions | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
"""

_BASH_COMPLETION = """
_vxrecon_completions() {
    local actions="__ACTIONS__"
    COMPREPLY=($(compgen -W "$actions" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _vxrecon_completions vxrecon
"""

_ZSH_COMPLETION = """
#compdef vxrecon
_vxrecon() {
    local -a actions
    actions=(__ACTIONS__)
    _describe 'action' actions
}
compdef _vxrecon vxrecon
"""


# ---------------------------------------------------------------------------
# reconnaissance actions (Phase 1: wired but empty pipelines)
# ---------------------------------------------------------------------------


# Per-action module selection. Each entry maps a kind to the module names that
# should run. ``None`` means "all registered modules of that kind".
_ACTION_MODULES: dict[str, dict[str, set[str] | None]] = {
    "recon": {
        "collector": {"dns", "tls", "rdap", "http", "ct", "javascript", "files"},
        "analyzer": {
            "dns", "tls", "rdap", "http", "technology", "website_dna",
            "subdomains", "js_endpoints", "sourcemap", "files",
        },
        "correlator": {"infra_mapper", "cert_explorer"},
    },
    "domain": {
        "collector": {"rdap", "dns", "ct"},
        "analyzer": {"rdap", "dns", "subdomains"},
        "correlator": {"infra_mapper"},
    },
    "dns": {"collector": {"dns"}, "analyzer": {"dns"}, "correlator": None},
    "cert": {"collector": {"tls"}, "analyzer": {"tls"}, "correlator": {"cert_explorer"}},
    "email": {"collector": {"dns"}, "analyzer": {"dns"}, "correlator": {"infra_mapper"}},
    "http": {"collector": {"http"}, "analyzer": {"http"}, "correlator": None},
    "tech": {"collector": {"http"}, "analyzer": {"technology"}, "correlator": None},
    "dna": {"collector": {"http"}, "analyzer": {"http", "technology", "website_dna"}, "correlator": None},
    "files": {"collector": {"files"}, "analyzer": {"files"}, "correlator": None},
    "js": {
        "collector": {"javascript"},
        "analyzer": {"js_endpoints", "sourcemap"},
        "correlator": None,
    },
    "subdomains": {"collector": {"ct"}, "analyzer": {"subdomains"}, "correlator": None},
    "graph": {
        "collector": {"dns", "tls", "rdap", "http"},
        "analyzer": {"dns", "tls", "rdap", "http", "technology"},
        "correlator": {"infra_mapper", "cert_explorer"},
    },
    "correlate": {
        "collector": {"dns", "tls", "rdap", "http"},
        "analyzer": {"dns", "tls", "rdap", "http", "technology"},
        "correlator": {"infra_mapper", "cert_explorer"},
    },
    "compare": {
        "collector": {"dns", "tls", "rdap", "http"},
        "analyzer": {"dns", "tls", "rdap", "http", "technology"},
        "correlator": {"infra_mapper"},
    },
}


def _run_recon(action: str, ctx: RunContext) -> int:
    target = _require_target(ctx)
    ui = _reporter(ctx)

    # Validate the target shape up-front for a clear, fast failure.
    from vxrecon.utils.validators import classify_target

    kind = classify_target(target)
    if kind == "unknown":
        ui.error(f"'{target}' is not a valid domain, URL or IP address")
        if ctx.json:
            _emit_json({"target": target, "action": action, "ok": False, "error": "invalid target"})
        return 3

    # Some actions are domain-oriented; an IP target cannot produce DNS/RDAP
    # domain facts, so explain rather than run a pointless scan.
    if kind == "ip" and action in {"dns", "domain", "email", "subdomains"}:
        ui.error(f"'{target}' is an IP address; the '{action}' action expects a domain")
        if ctx.json:
            _emit_json({"target": target, "action": action, "ok": False, "error": "domain required"})
        return 3

    ui.section(f"{action}: {target}")

    pipeline = Pipeline(DEFAULT_REGISTRY, ctx)
    selection = _ACTION_MODULES.get(action)
    if selection:
        pipeline.select = selection

    # Live progress: spin while a module runs, resolve to a status line.
    # The UI never affects execution — hooks are pure side-effects.
    def _on_start(kind: str, name: str) -> None:
        if kind != "correlator":
            ui.spin(f"{kind}:{name}")

    def _on_finish(outcome) -> None:
        if outcome.kind == "correlator":
            return
        ui.stop_spin()
        ui.step(f"{outcome.kind}:{outcome.name}", outcome.status, outcome.error or "")

    pipeline.on_start = _on_start
    pipeline.on_finish = _on_finish

    # Progress hook: report each module as it completes.
    report = pipeline.run(target)
    ui.stop_spin()

    findings = 0
    for outcome in report.outcomes:
        if isinstance(outcome.output, ScanResult):
            findings += len(outcome.output.findings)
        if outcome.status is Status.FAILED and outcome.error:
            ui.warn(f"{outcome.name} module failed: {outcome.error}")

    if not report.outcomes:
        ui.warn(
            "no modules registered for this layer yet "
            "(collectors/analyzers land in later phases)"
        )

    payload = _build_payload(action, target, report)

    # Human-readable rendering (skipped in --json / --quiet).
    from vxrecon.reporters.terminal import TerminalReporter

    rendered = TerminalReporter(ctx).render(payload)
    if rendered and not (ctx.json or ctx.quiet):
        print(rendered)

    ui.summary(duration_ms=report.duration_ms, ok=report.ok, findings=findings)

    # Persist to the local intelligence database (respects --no-save).
    if not ctx.no_save and not ctx.offline and report.results():
        _persist_scan(ctx, target, report, ui)

    # Persist JSON report unless --no-save.
    if not ctx.no_save and not ctx.offline:
        _write_reports(ctx, target, payload)

    if ctx.json:
        _emit_json(payload)

    return 0 if report.ok else 1


def _persist_scan(ctx: RunContext, target: str, report, ui) -> None:
    """Save scan facts to SQLite, logging (never raising) on failure."""

    from vxrecon.database import repo

    raw_outputs = {
        o.name: o.output
        for o in report.outcomes
        if o.kind == "collector" and o.output is not None
    }
    try:
        repo.persist_scan(
            ctx,
            target,
            report.results(),
            graph=report.graph(),
            raw_outputs=raw_outputs,
            mode="offline" if ctx.offline else "online",
            status="ok" if report.ok else "partial",
        )
    except Exception as exc:  # noqa: BLE001 - persistence must not crash a scan
        ui.warn(f"could not save scan: {exc}")


def _build_payload(action: str, target: str, report) -> dict:
    """Assemble the canonical report payload from a pipeline run."""

    graph = report.graph()
    payload: dict = {
        "target": target,
        "action": action,
        "ok": report.ok,
        "duration_ms": report.duration_ms,
        "results": [r.to_dict() for r in report.results()],
    }
    if graph is not None and hasattr(graph, "to_dict"):
        payload["graph"] = graph.to_dict()
    return payload


def _write_reports(ctx: RunContext, target: str, payload: dict) -> None:
    from vxrecon.reporters.html_report import HtmlReporter
    from vxrecon.reporters.json_report import report_dir, write_json_report
    from vxrecon.reporters.markdown_report import MarkdownReporter
    from vxrecon.reporters.sarif_report import SarifReporter

    try:
        write_json_report(ctx, target, payload)
    except OSError as exc:  # noqa: BLE001 - report writing must not crash a scan
        _reporter(ctx).warn(f"could not write JSON report: {exc}")
    try:
        directory = report_dir(ctx, target)
        (directory / "report.html").write_text(HtmlReporter(ctx).render(payload), encoding="utf-8")
        (directory / "report.md").write_text(MarkdownReporter(ctx).render(payload), encoding="utf-8")
        (directory / "report.sarif").write_text(SarifReporter(ctx).render(payload), encoding="utf-8")
    except OSError as exc:  # noqa: BLE001
        _reporter(ctx).warn(f"could not write report: {exc}")


def cmd_recon(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("recon", ctx)


def cmd_domain(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("domain", ctx)


def cmd_dns(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("dns", ctx)


def cmd_cert(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("cert", ctx)


def cmd_dna(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("dna", ctx)


def cmd_tech(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("tech", ctx)


def cmd_http(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("http", ctx)


def cmd_files(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("files", ctx)


def cmd_js(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("js", ctx)


def cmd_email(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("email", ctx)


def cmd_subdomains(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("subdomains", ctx)


def cmd_username(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("username", ctx)


def cmd_image(args: argparse.Namespace, ctx: RunContext) -> int:
    """Fingerprint a local image file or a target's favicon."""

    target = _require_target(ctx)
    ui = _reporter(ctx)

    from pathlib import Path

    from vxrecon.analyzers.favicon_analyzer import FaviconAnalyzer
    from vxrecon.collectors.favicon_collector import FaviconCollector, LocalImageCollector

    is_local = Path(target).exists()
    if is_local:
        raw = {"local_image": LocalImageCollector(ctx, target).collect(target)}
    else:
        raw = {"favicon": FaviconCollector(ctx).collect(target)}

    ui.section(f"image: {target}")
    result = FaviconAnalyzer(ctx).analyze(target, raw, ctx)
    payload = _build_payload("image", target, _SingleReport(result))
    from vxrecon.reporters.terminal import TerminalReporter

    rendered = TerminalReporter(ctx).render(payload)
    if rendered and not (ctx.json or ctx.quiet):
        print(rendered)
    if ctx.json:
        _emit_json(payload)
    return 0 if not result.errors else 1


def cmd_metadata(args: argparse.Namespace, ctx: RunContext) -> int:
    """Extract metadata from a local file (offline)."""

    target = _require_target(ctx)
    ui = _reporter(ctx)
    ui.section(f"metadata: {target}")

    from vxrecon.analyzers.metadata_analyzer import MetadataAnalyzer

    result = MetadataAnalyzer(ctx).analyze(target, {}, ctx)
    payload = _build_payload("metadata", target, _SingleReport(result))
    from vxrecon.reporters.terminal import TerminalReporter

    rendered = TerminalReporter(ctx).render(payload)
    if rendered and not (ctx.json or ctx.quiet):
        print(rendered)
    if ctx.json:
        _emit_json(payload)
    return 0 if not result.errors else 1


class _SingleReport:
    """Adapter so a lone ScanResult can flow through the payload builder."""

    def __init__(self, result: ScanResult) -> None:
        self._result = result

    def results(self) -> list[ScanResult]:
        return [self._result]

    def graph(self):
        return None

    @property
    def outcomes(self):
        return []

    @property
    def duration_ms(self) -> int:
        return self._result.duration_ms

    @property
    def ok(self) -> bool:
        return not self._result.errors


def cmd_compare(args: argparse.Namespace, ctx: RunContext) -> int:
    """Compare two targets' infrastructure similarity."""

    target_a = _require_target(ctx)
    target_b = ctx.extra.get("second")
    ui = _reporter(ctx)
    if not target_b:
        ui.error("usage: compare <a> <b>")
        return 3

    from vxrecon.correlators.similarity import compare

    def _scan(target: str) -> list:
        sub = RunContext(**{**ctx.__dict__, "target": target})
        pipeline = Pipeline(DEFAULT_REGISTRY, sub)
        selection = _ACTION_MODULES.get("compare")
        if selection:
            pipeline.select = selection
        report = pipeline.run(target)
        return report.results()

    ui.section(f"compare: {target_a} vs {target_b}")
    ui.step("scanning target A", Status.OK)
    results_a = _scan(target_a)
    ui.step("scanning target B", Status.OK)
    results_b = _scan(target_b)

    result = compare(results_a, results_b, target_a, target_b)
    data = result.to_dict()

    ui.section("similarity analysis")
    for dim in result.dimensions:
        score = f"{dim.score:>5.1f}%" if dim.score is not None else "   n/a "
        ui.info(f"{dim.name:<22} {score}  {dim.note}")
    if data["overall"] is not None:
        ui.section("overall")
        ui.info(f"composite similarity : {data['overall']}%")
    ui.warn("scores indicate SHARED INFRASTRUCTURE INDICATORS, not ownership")

    if ctx.json:
        _emit_json(data)
    return 0


def cmd_correlate(args: argparse.Namespace, ctx: RunContext) -> int:
    """Build the artifact correlation graph."""

    target = _require_target(ctx)
    ui = _reporter(ctx)
    pipeline = Pipeline(DEFAULT_REGISTRY, ctx)
    selection = _ACTION_MODULES.get("correlate")
    if selection:
        pipeline.select = selection
    report = pipeline.run(target)

    from vxrecon.correlators.artifact import ArtifactCorrelator

    graph = ArtifactCorrelator(ctx).correlate(target, report.results(), ctx)
    ui.section(f"artifact correlation: {target}")
    for edge in graph.edges:
        src = f"{edge.src_kind}:{edge.src_value}"
        dst = f"{edge.dst_kind}:{edge.dst_value}"
        ui._emit(f"  {src} --{edge.relation}--> {dst} [{edge.confidence}]")

    if not ctx.no_save and not ctx.offline and report.results():
        _persist_scan(ctx, target, report, ui)
    if ctx.json:
        _emit_json(graph.to_dict())
    return 0


def cmd_graph(args: argparse.Namespace, ctx: RunContext) -> int:
    """Build and display the digital footprint graph."""

    target = _require_target(ctx)
    ui = _reporter(ctx)
    pipeline = Pipeline(DEFAULT_REGISTRY, ctx)
    selection = _ACTION_MODULES.get("graph")
    if selection:
        pipeline.select = selection
    report = pipeline.run(target)

    graph = report.graph()
    ui.section(f"footprint graph: {target}")
    if graph is None or not graph.edges:
        ui.warn("no relationships found")
    else:
        for edge in graph.edges:
            src = f"{edge.src_kind}:{edge.src_value}"
            dst = f"{edge.dst_kind}:{edge.dst_value}"
            conf = f"[{edge.confidence}]"
            ui._emit(f"  {src} --{edge.relation}--> {dst} {ui.theme.color(conf, 'grey')}")

    payload = _build_payload("graph", target, report)
    if not ctx.no_save and not ctx.offline:
        _write_reports(ctx, target, payload)
        graph_data = payload.get("graph")
        if graph_data:
            try:
                from vxrecon.reporters.graph_html import render_graph_html
                from vxrecon.reporters.json_report import report_dir

                out = report_dir(ctx, target) / "graph.html"
                out.write_text(render_graph_html(graph_data, target), encoding="utf-8")
            except OSError as exc:  # noqa: BLE001
                ui.warn(f"could not write graph HTML: {exc}")
    if ctx.json:
        _emit_json(payload)
    return 0


def cmd_diff(args: argparse.Namespace, ctx: RunContext) -> int:
    """Compare the two most recent snapshots for a target."""

    target = _require_target(ctx)
    ui = _reporter(ctx)

    from vxrecon.correlators.diff import diff_snapshots
    from vxrecon.database import db as dbmod
    from vxrecon.database import repo_read

    conn = dbmod.connect(ctx.database_file)
    dbmod.initialize(conn)
    snapshots = repo_read.latest_snapshots(conn, target, limit=2)
    conn.close()

    if len(snapshots) < 2:
        ui.section(f"diff: {target}")
        ui.warn(
            f"need at least 2 snapshots to diff; found {len(snapshots)}. "
            "run a scan again later."
        )
        if ctx.json:
            _emit_json({"target": target, "snapshots": len(snapshots), "entries": []})
        return 1

    newest, previous = snapshots[0], snapshots[1]
    result = diff_snapshots(target, previous["payload"], newest["payload"])

    ui.section(f"diff: {target}")
    ui.info(f"previous scan: {previous['created_at']}")
    ui.info(f"latest scan  : {newest['created_at']}")
    if not result.entries:
        ui.success("no changes detected")
    else:
        for entry in result.added:
            ui._emit(f"  {ui.theme.glyph('new', 'added')}   {entry.category} = {entry.value}")
        for entry in result.removed:
            ui._emit(f"  {ui.theme.glyph('removed', 'removed')} {entry.category} = {entry.value}")
        for entry in result.changed:
            ui._emit(f"  {ui.theme.glyph('changed', 'changed')} {entry.category} = {entry.value}")

    if ctx.json:
        _emit_json(result.to_dict())
    return 0


def cmd_timeline(args: argparse.Namespace, ctx: RunContext) -> int:
    """Render the investigation timeline for a target."""

    target = _require_target(ctx)
    ui = _reporter(ctx)

    from vxrecon.database import db as dbmod
    from vxrecon.database import repo_read

    conn = dbmod.connect(ctx.database_file)
    dbmod.initialize(conn)
    events = repo_read.timeline_events(conn, target)
    conn.close()

    ui.section(f"timeline: {target}")
    if not events:
        ui.info("no timeline events recorded yet")
    for event in events:
        ts = event["ts"].split(".")[0]
        ui._emit(f"  {ui.theme.color(ts, 'grey')}  {event['message']}")

    if not ctx.no_save and not ctx.offline and events:
        try:
            from vxrecon.reporters.graph_html import render_timeline_html
            from vxrecon.reporters.json_report import report_dir

            out = report_dir(ctx, target) / "timeline.html"
            out.write_text(render_timeline_html(events, target), encoding="utf-8")
            ui.info(f"timeline export: {out}")
        except OSError as exc:  # noqa: BLE001
            ui.warn(f"could not write timeline HTML: {exc}")

    if ctx.json:
        _emit_json({"target": target, "events": events})
    return 0


def cmd_report(args: argparse.Namespace, ctx: RunContext) -> int:
    return _run_recon("report", ctx)


def cmd_unimplemented(args: argparse.Namespace, ctx: RunContext) -> int:
    _reporter(ctx).error(f"action not implemented: {ctx.action}")
    return 3
