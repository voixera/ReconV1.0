"""Interactive menu shell.

A thin REPL over the same action handlers used by the command mode. It maps
menu selections and typed commands to ``actions.cmd_*`` so there is exactly one
implementation of each behavior.
"""

from __future__ import annotations

import argparse
import shlex

from vxrecon.core.context import RunContext
from vxrecon.ui import actions
from vxrecon.ui.banner import MENU_ITEMS, render_banner, render_menu
from vxrecon.ui.theme import Theme

_MENU_INDEX = {num: cmd for num, cmd, _ in MENU_ITEMS}


def run_shell(ctx: RunContext) -> int:
    """Run the interactive shell until the user exits."""

    theme = Theme(enabled=not ctx.no_color)
    if not ctx.extra.get("no_banner"):
        print(render_banner(theme))
        print()
    print(render_menu(theme))
    print()
    print(theme.color("type a number or command, 'help' or 'exit'", "grey"))

    while True:
        try:
            raw = input(theme.color("vxrecon > ", "cyan", "bold")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw in {"exit", "quit", ":q"}:
            return 0
        if raw == "help":
            print(render_menu(theme))
            continue

        # A leading number selects a menu item; otherwise treat as a command.
        tokens = shlex.split(raw)
        if tokens[0] in _MENU_INDEX:
            action = _MENU_INDEX[tokens[0]]
            target = tokens[1] if len(tokens) > 1 else ""
            _dispatch(action, target, ctx)
        elif raw.startswith("menu"):
            print(render_menu(theme))
        else:
            _dispatch(tokens[0], tokens[1] if len(tokens) > 1 else "", ctx)


def _dispatch(action: str, target: str, ctx: RunContext) -> None:
    handler = getattr(actions, f"cmd_{action}", None)
    if handler is None:
        print(f"[!] unknown command: {action}")
        return
    sub_ctx = RunContext(**{**ctx.__dict__, "action": action, "target": target})
    ns = argparse.Namespace(target=target, action=action, case_args=[], db_args=[])
    try:
        handler(ns, sub_ctx)
    except Exception as exc:  # noqa: BLE001 - interactive shell must never die
        print(f"[-] {action} failed: {exc}")
