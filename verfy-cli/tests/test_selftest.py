"""Tests for `verfy doctor --live` (verfy.selftest): each agent's hook command, run as the agent runs it.
Run from verfy-cli/: ``python -m unittest tests.test_selftest``."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import hook, selftest  # noqa: E402

PY = sys.executable.replace("\\", "/")
EVENTS = {"claude-code": "pre-tool-use", "cursor": "cursor", "codex": "codex", "gemini": "gemini", "copilot": "copilot",
          "windsurf": "windsurf", "devin": "devin"}


class Live(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"PYTHONPATH": str(ROOT / "src")})
        p.start()
        self.addCleanup(p.stop)

    def test_every_agent_format_passes_with_this_verfy(self):
        self.assertEqual(set(EVENTS), set(hook.INSTALL))  # a new agent needs a sample here
        for agent, event in EVENTS.items():
            res = selftest.check_agent(agent, f"{PY} -m verfy hook {event}")
            self.assertTrue(res["ok"], (agent, res["problems"]))

    def test_a_hook_that_lets_everything_through_is_reported(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        script = Path(d.name) / "allow.py"
        script.write_text("import sys; sys.stdin.read(); print('{\"permission\": \"allow\"}')\n", "utf-8")
        res = selftest.check_agent("cursor", f"{PY} {script.as_posix()}")
        self.assertFalse(res["ok"])
        self.assertIn("let `rm -rf ~` through", res["problems"][0])

    def test_a_hook_the_agent_cannot_start(self):
        res = selftest.check_agent("cursor", "verfy-not-installed-anywhere hook cursor")
        self.assertFalse(res["ok"])
        self.assertIn("not on this PATH", res["problems"][0])

    def test_reading_answers(self):
        self.assertIs(selftest.blocked("", 0), False)
        self.assertIs(selftest.blocked('{"permission": "allow"}', 0), False)
        self.assertIs(selftest.blocked('{"permission": "deny"}', 0), True)
        self.assertIs(selftest.blocked('{"hookSpecificOutput": {"permissionDecision": "deny"}}', 0), True)
        self.assertIs(selftest.blocked('{"decision": "block"}', 0), True)
        self.assertIs(selftest.blocked("", 2), True)
        self.assertIsNone(selftest.blocked("not json", 0))
        self.assertIsNone(selftest.blocked("", 1))


if __name__ == "__main__":
    unittest.main()
