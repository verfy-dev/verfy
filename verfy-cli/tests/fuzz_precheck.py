"""Fuzz the rule engine and the script reader with Atheris: no input may make them raise.

The guard answers for every tool call, and a crash there becomes the fail mode (ask) for that call, so a command or a
file an attacker shaped to break the parser must not. Run it on Linux with Python 3.11 or 3.12:

    pip install atheris && python verfy-cli/tests/fuzz_precheck.py -max_total_time=300

tests/test_fuzz_smoke.py runs the same targets on random inputs in every test run, without Atheris.
"""

from __future__ import annotations

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

with atheris.instrument_imports():
    from verfy import scripts
    from verfy.policy import load_policy
    from verfy.precheck import check, parse_shell

POLICY = load_policy({"home": "/home/you", "workspace": "/home/you/project"})


def targets(text: str) -> None:
    parse_shell(text)
    check({"server": "fuzz", "tool": "run_command", "arguments": {"command": text}}, POLICY)
    check({"server": "fuzz", "tool": "write_file", "arguments": {"file_path": text[:200], "content": text}}, POLICY)
    scripts.shell_units(text)
    for lang in ("py", "js", "rb", "pl", "php"):
        scripts.literals(text, lang)
    scripts.lang_of("x", text)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    targets(fdp.ConsumeUnicodeNoSurrogates(4096))


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
