"""The ``verfy`` command. An agent's hook runs on every tool call, so ``verfy hook <event>`` takes a short path that loads
only the hook (hookenv.py); every other command goes to cli.main."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "hook" and not args[1].startswith("-"):
        from . import hookenv
        code = hookenv.run(args[1])
        if code is not None:
            return code
    from .cli import main as cli_main
    return cli_main(args)
