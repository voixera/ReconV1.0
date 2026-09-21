"""Interactive menu shell.

A thin REPL over the same action handlers used by the command mode. It maps
menu selections and typed commands to ``actions.cmd_*`` so there is exactly one
implementation of each behavior.

Usage inside the shell::

    <number> <target>     e.g.   3 example.com
    <command> <target>    e.g.   dns example.com
    help | menu | exit

If a number or target-requiring command is entered without a target, the shell
prompts for it instead of failing.
"""

from __future__ import annotations

import argparse
import shlex

from vxrecon.core.context import RunContext
from vxrecon.ui import actions
from vxrecon.ui.banner import MENU_ITEMS, render_banner, render_menu
from vxrecon.ui.theme import Theme

_MENU_INDEX = {num: cmd for num, cmd, _ in MENU_ITEMS}

# Commands that can run without a target.
_TARGETLESS = {"doctor", "version", "completions", "menu", "case", "db"}
# Actions that carry two positional targets.
_TWO_TARGET = {"compare"}


def run_shell(ctx: RunContext) -> int:
    """Run the interactive shell until the user exits."""

    theme = Theme(enabled=not ctx.no_color)
    if not ctx.extra.get("no_banner"):
        print(render_banner(theme))
        print()
    print(render_menu(theme))
    print()
    print(
        theme.color(
            "how to use:  <number> <target>   e.g.  '3 example.com'   "
            "or  '<command> <target>'   e.g.  'dns example.com'",
            "grey",
        )
    )
    print(theme.color("commands:    help  (show menu)   exit  (quit)", "grey"))

    while True:
        try:
            raw = input(theme.color("vxrecon > ", "spring", "bold")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw in {"exit", "quit", ":q"}:
            return 0
        if raw in {"help", "menu", "?"}:
            print(render_menu(theme))
            continue

        try:
            tokens = shlex.split(raw)
        except ValueError:
            print("[-] could not parse input (check your quotes)")
            continue
        if not tokens:
            continue

        # A leading number selects a menu item; otherwise treat as a command.
        if tokens[0] in _MENU_INDEX:
            action = _MENU_INDEX[tokens[0]]
            args = tokens[1:]
        else:
            action = tokens[0]
            args = tokens[1:]

        if action not in _TARGETLESS:
            args = _ensure_targets(theme, action, args)
            if args is None:
                continue  # user cancelled; return to the prompt

        _dispatch(action, args, ctx)


def _ensure_targets(theme: Theme, action: str, args: list[str]) -> list[str] | None:
    """Prompt for missing target(s). Returns None if the user cancels.

    Prompting is robust to users who paste the whole command; on cancel we
    simply return ``None`` so the shell shows the prompt again.
    """

    needed = 2 if action in _TWO_TARGET else 1
    while len(args) < needed:
        label = "target" if len(args) == 0 else "second target"
        try:
            entered = input(theme.color(f"  {label} (or 'cancel'): ", "grey")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if entered.lower() in {"cancel", ":q"}:
            return None
        if not entered:
            continue
        try:
            args.extend(shlex.split(entered))
        except ValueError:
            args.append(entered)
    return args


def _dispatch(action: str, args: list[str], ctx: RunContext) -> None:
    handler = getattr(actions, f"cmd_{action}", None)
    if handler is None:
        print(f"[!] unknown command: {action}")
        print("    type 'help' to see the menu, or 'exit' to quit")
        return

    target = args[0] if args else ""
    sub_ctx = RunContext(**{**ctx.__dict__, "action": action, "target": target})
    if len(args) > 1:
        sub_ctx.extra["second"] = args[1]
    ns = argparse.Namespace(
        target=target,
        action=action,
        second=args[1] if len(args) > 1 else None,
        case_args=args if action == "case" else [],
        db_args=args if action == "db" else [],
    )
    try:
        handler(ns, sub_ctx)
    except Exception as exc:  # noqa: BLE001 - interactive shell must never die
        print(f"[-] {action} failed: {exc}")
