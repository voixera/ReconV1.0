"""Command-line interface router.

Parses arguments, builds a :class:`RunContext`, enforces global policy flags
and dispatches to the appropriate action. Actions are thin: they assemble a
pipeline and hand off to reporters. This keeps the CLI free of business logic.
"""

from __future__ import annotations

import argparse
import signal
import sys
from typing import Callable

from vxrecon import __program__, __version__
from vxrecon.core.context import RunContext
from vxrecon.core.errors import ConfigError, ValidationError, VXReconError
from vxrecon.core.logging import configure

# Exit codes (documented in README and consumed by automation).
EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
EXIT_USAGE = 3

# Actions that do not require a target argument.
_TARGETLESS = {"version", "doctor", "db", "case", "menu"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__program__.lower(),
        description="Advanced Passive OSINT & Digital Footprint Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument("--version", action="version", version=f"{__program__} {__version__}")

    # A shared parent so global flags work either before OR after the action,
    # e.g. both "vxrecon --json dns x" and "vxrecon dns x --json".
    common = argparse.ArgumentParser(add_help=False)
    _add_global_flags(common)
    _add_global_flags(parser)

    sub = parser.add_subparsers(dest="action", metavar="<action>")

    def action(name: str, help_text: str, target_metavar: str | None = "target") -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, parents=[common])
        if target_metavar:
            p.add_argument("target", metavar=target_metavar, help="target value")
        return p

    action("recon", "Run the full passive reconnaissance pipeline", "<target>")
    action("domain", "Domain and registration intelligence", "<domain>")
    action("dns", "DNS records and resolver behaviour", "<domain>")
    action("cert", "TLS certificate intelligence", "<host>")
    action("dna", "Website DNA fingerprint", "<url>")
    action("tech", "Technology confidence breakdown", "<url>")
    action("http", "HTTP behaviour fingerprint", "<url>")
    action("files", "Public file exposure map", "<url>")
    action("js", "JavaScript endpoint intelligence", "<url>")
    action("email", "Email infrastructure map", "<domain>")
    action("subdomains", "Passive subdomain discovery (CT logs)", "<domain>")
    action("username", "Passive username footprint", "<handle>")
    action("image", "Favicon/logo hash and dimensions", "<file|url>")
    action("metadata", "Local file/image metadata", "<file>")
    compare = action("compare", "Infrastructure similarity between two targets", "<a>")
    compare.add_argument("second", metavar="<b>", help="second target")
    action("correlate", "Artifact correlation graph", "<target>")
    action("graph", "Build and export the footprint graph", "<target>")
    action("diff", "Latest vs previous snapshot", "<target>")
    action("timeline", "Investigation timeline", "<target>")
    action("report", "Generate JSON + HTML report", "<target>")

    case = sub.add_parser("case", help="Local case management", parents=[common])
    case.add_argument("case_args", nargs="*", default=[], help="case subcommand")

    db = sub.add_parser("db", help="Local database operations", parents=[common])
    db.add_argument("db_args", nargs="*", default=[], help="db subcommand")

    sub.add_parser("doctor", help="Environment and connectivity self-check", parents=[common])
    sub.add_parser("version", help="Show version and module inventory", parents=[common])
    sub.add_parser("menu", help="Interactive menu shell", parents=[common])
    comp = sub.add_parser("completions", help="Print shell completion script", parents=[common])
    comp.add_argument("shell", nargs="?", default="powershell", choices=["powershell", "bash", "zsh"])
    return parser


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    # Defaults are ``None`` so config/env can fill them; final resolution
    # happens in ``context_from_args`` with precedence CLI > env > config > default.
    parser.add_argument("--json", action="store_true", default=None, help="machine-readable stdout")
    parser.add_argument("--quiet", action="store_true", default=None, help="suppress banners/progress")
    parser.add_argument("-v", "--verbose", action="count", default=None, help="increase verbosity")
    parser.add_argument("--offline", action="store_true", default=None, help="forbid all network access")
    parser.add_argument("--no-save", action="store_true", default=None, help="do not write to disk")
    parser.add_argument("--timeout", type=float, default=None, help="per-request timeout seconds")
    parser.add_argument("--rate", type=float, default=None, help="max requests/second per host")
    parser.add_argument("--user-agent", dest="user_agent", default=None, help="override User-Agent")
    parser.add_argument("--db", dest="db_path", default=None, help="custom database path")
    parser.add_argument("--out", dest="out_dir", default=None, help="report output directory")
    parser.add_argument("--no-color", action="store_true", default=None, help="disable ANSI colors")
    parser.add_argument("--no-banner", action="store_true", default=None, help="suppress the banner")
    parser.add_argument("--config", default=None, help="path to a JSON/TOML config file")


# Built-in defaults, applied only when no CLI/env/config value is present.
_DEFAULTS = {
    "timeout": 10.0,
    "rate_rps": 2.0,
    "verbose": 0,
    "offline": False,
    "no_save": False,
    "json": False,
    "quiet": False,
    "no_color": False,
}


def _resolve(args: argparse.Namespace) -> dict:
    """Resolve effective settings with precedence CLI > env > config > default."""

    from vxrecon.core import config as configmod

    file_config: dict = {}
    if args.config:
        file_config = configmod.load_config(args.config)
    env_config = configmod.env_overrides()

    resolved: dict = {}
    cli_values = {
        "timeout": args.timeout,
        "rate_rps": args.rate,
        "verbose": args.verbose,
        "offline": args.offline,
        "no_save": args.no_save,
        "json": args.json,
        "quiet": args.quiet,
        "no_color": args.no_color,
        "user_agent": args.user_agent,
        "db_path": args.db_path,
        "out_dir": args.out_dir,
        "home": None,
        "no_banner": args.no_banner,
    }
    for key, cli_value in cli_values.items():
        if cli_value is not None:
            resolved[key] = cli_value
        elif key in env_config:
            resolved[key] = env_config[key]
        elif key in file_config:
            resolved[key] = file_config[key]
        elif key in _DEFAULTS:
            resolved[key] = _DEFAULTS[key]
    return resolved


def context_from_args(args: argparse.Namespace) -> RunContext:
    """Translate parsed args into a validated :class:`RunContext`."""

    from pathlib import Path

    r = _resolve(args)

    ctx = RunContext(
        target=getattr(args, "target", "") or "",
        offline=bool(r.get("offline", False)),
        no_save=bool(r.get("no_save", False)),
        json=bool(r.get("json", False)),
        quiet=bool(r.get("quiet", False)),
        verbose=int(r.get("verbose", 0)),
        no_color=bool(r.get("no_color", False)),
        timeout=float(r.get("timeout", 10.0)),
        rate_rps=float(r.get("rate_rps", 2.0)),
        action=args.action or "",
        out_dir=Path(r["out_dir"]) if r.get("out_dir") else None,
        db_path=Path(r["db_path"]) if r.get("db_path") else None,
    )
    if r.get("user_agent"):
        ctx.user_agent = r["user_agent"]
    if r.get("home"):
        ctx.home = Path(r["home"])
    if r.get("no_banner"):
        ctx.extra["no_banner"] = True
    # ``compare`` carries a second positional target.
    second = getattr(args, "second", None)
    if second:
        ctx.extra["second"] = second
    ctx.validate()
    return ctx


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns a process exit code."""

    # Make Ctrl+C behave like a normal interrupt, not a stack trace.
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, AttributeError):
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.action is None:
        # No action -> launch interactive shell.
        args.action = "menu"

    # Build the context first (resolves CLI > env > config > default), then
    # configure logging from the resolved settings.
    try:
        ctx = context_from_args(args)
    except ConfigError as exc:
        print(f"{__program__.lower()}: configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    configure(quiet=ctx.quiet, verbose=ctx.verbose)

    # Register the built-in modules before any action runs.
    from vxrecon.core.bootstrap import register_core_modules

    register_core_modules()

    from vxrecon.ui import actions

    handler: Callable[[argparse.Namespace, RunContext], int] = getattr(
        actions, f"cmd_{args.action}", actions.cmd_unimplemented
    )
    try:
        return handler(args, ctx)
    except ValidationError as exc:
        print(f"{__program__.lower()}: invalid target: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print(f"\n{__program__.lower()}: interrupted", file=sys.stderr)
        return EXIT_FAILURE
    except VXReconError as exc:
        print(f"{__program__.lower()}: {exc}", file=sys.stderr)
        return EXIT_FAILURE
