"""Verfy's GitHub Copilot and Devin hooks against their own references, read 21 November 2026:
https://docs.github.com/en/copilot/reference/hooks-configuration (Copilot CLI, VS Code and the cloud agent share it) and
https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks (Devin Desktop, formerly Windsurf, and Devin CLI).
Run from verfy-cli/: ``python -m unittest tests.test_copilot_devin_spec``."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import hook  # noqa: E402
from verfy.policy import load_policy  # noqa: E402

POLICY = load_policy({"home": "/home/you", "workspace": "/home/you/project"})
META = ".".join(["169", "254", "169", "254"])


def run(event: str, payload: dict) -> tuple[int, dict | None, str]:
    out, err = io.StringIO(), io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode("utf-8")), encoding="cp1252")
    with redirect_stderr(err):
        code = hook.run_hook(event, stdin=stdin, stdout=out, get_policy=lambda cwd: POLICY, record=lambda **kw: None)
    text = out.getvalue().strip()
    return code, (json.loads(text) if text else None), err.getvalue()


def copilot(tool: str, args: dict) -> dict:
    """camelCase preToolUse input: toolArgs is a JSON string, as in the reference's own example."""
    return {"sessionId": "s1", "timestamp": 1704614400000, "cwd": "/home/you/project", "toolName": tool, "toolArgs": json.dumps(args)}


def copilot_claude(tool: str, args: dict) -> dict:
    """PascalCase PreToolUse input (the VS Code compatible format, also what Copilot sends through .claude/settings.json)."""
    return {"hook_event_name": "PreToolUse", "session_id": "s1", "timestamp": "2026-11-21T10:00:00Z", "cwd": "/home/you/project",
            "tool_name": tool, "tool_input": args}


def devin(tool: str, args: dict) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args, "session_id": "d1", "prompt_id": "p1"}


COPILOT_KEYS = {"permissionDecision", "permissionDecisionReason", "modifiedArgs"}


class CopilotSpec(unittest.TestCase):
    def test_answers_are_what_copilot_reads(self):
        cases = [
            (copilot("bash", {"command": "ls -la"}), None),
            (copilot("bash", {"command": "rm -rf ~"}), "deny"),
            (copilot("powershell", {"command": "Remove-Item -Recurse -Force ~"}), "deny"),
            (copilot("bash", {"command": "git push --force origin main"}), "ask"),
            (copilot("create", {"path": "/home/you/.claude/settings.json", "file_text": "{}"}), "deny"),
            (copilot("edit", {"path": "/home/you/project/a.py", "old_str": "a", "new_str": "b"}), None),
            (copilot("str_replace_editor", {"command": "view", "path": "/home/you/.ssh/id_rsa"}), "ask"),
            (copilot("view", {"path": "/home/you/.verfy/key.json"}), "deny"),
            (copilot("web_fetch", {"url": f"http://{META}/latest/meta-data/"}), "deny"),
        ]
        for payload, want in cases:
            code, answer, _ = run("copilot", payload)
            self.assertEqual(code, 0, payload)  # a decision is JSON on exit 0; a crash would deny anyway (preToolUse fails closed)
            if want is None:
                self.assertIsNone(answer, payload)  # no output: Copilot's own permission flow decides
                continue
            self.assertLessEqual(set(answer), COPILOT_KEYS, answer)
            self.assertEqual(answer["permissionDecision"], want, payload)
            self.assertTrue(answer["permissionDecisionReason"], payload)  # required with deny

    def test_the_pascal_case_format_is_read_too(self):
        code, answer, _ = run("copilot", copilot_claude("Bash", {"command": "rm -rf ~"}))
        self.assertEqual((code, answer["permissionDecision"]), (0, "deny"))

    def test_copilot_running_claude_codes_hook_gets_an_answer_it_reads(self):
        # Copilot reads .claude/settings.json and runs `verfy hook pre-tool-use`; it reads no hookSpecificOutput
        code, answer, _ = run("pre-tool-use", copilot_claude("Bash", {"command": "rm -rf ~"}))
        self.assertEqual(code, 0)
        self.assertEqual(answer["permissionDecision"], "deny")
        self.assertNotIn("hookSpecificOutput", answer)
        # Claude Code itself still gets its own format
        claude = {"session_id": "c1", "transcript_path": "/tmp/t.jsonl", "cwd": "/home/you/project", "hook_event_name": "PreToolUse",
                  "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}
        self.assertEqual(run("pre-tool-use", claude)[1]["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_the_hooks_file_has_the_documented_shape(self):
        config, changed = hook.with_copilot_hook({})
        self.assertTrue(changed)
        self.assertEqual(config["version"], 1)
        [entry] = config["hooks"]["preToolUse"]
        self.assertEqual(entry["type"], "command")
        for k in ("bash", "powershell", "command"):
            self.assertEqual(entry[k], "verfy hook copilot")
        self.assertLessEqual(entry["timeoutSec"], 30)  # a timeout lets the call through, so Verfy must answer well inside it
        self.assertFalse(hook.with_copilot_hook(config)[1])

    def test_copilot_home_moves_the_hooks_folder(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"COPILOT_HOME": d}):
            self.assertEqual(hook.copilot_hooks_path(False), Path(d) / "hooks" / "verfy.json")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("COPILOT_HOME", None)
            self.assertEqual(hook.copilot_hooks_path(False), Path.home() / ".copilot" / "hooks" / "verfy.json")
        self.assertEqual(hook.copilot_hooks_path(True, Path("/repo")), Path("/repo") / ".github" / "hooks" / "verfy.json")


class DevinSpec(unittest.TestCase):
    def test_a_block_is_exit_2_with_the_reason_where_devin_reads_it(self):
        code, answer, err = run("devin", devin("exec", {"command": "rm -rf ~", "shell_id": "main"}))
        self.assertEqual(code, 2)
        self.assertEqual(answer["decision"], "block")
        self.assertIn("VFY-SH-001", answer["reason"])
        self.assertIn("VFY-SH-001", err)

    def test_what_passes_has_no_output(self):
        self.assertEqual(run("devin", devin("exec", {"command": "ls -la", "shell_id": "main"}))[:2], (0, None))

    def test_ask_becomes_a_block_that_says_why(self):
        code, answer, _ = run("devin", devin("exec", {"command": "git push --force origin main", "shell_id": "main"}))
        self.assertEqual((code, answer["decision"]), (2, "block"))
        self.assertIn("cannot wait for a person", answer["reason"])

    def test_files_and_mcp_tools(self):
        self.assertEqual(run("devin", devin("edit", {"file_path": "/home/you/.claude/settings.json", "new_string": "{}"}))[0], 2)
        self.assertEqual(run("devin", devin("read", {"file_path": "/home/you/.verfy/key.json"}))[0], 2)
        code, answer, _ = run("devin", devin("mcp__db__query", {"sql": "drop table users"}))
        self.assertEqual(code, 2)
        self.assertIn("VFY-SQL", answer["reason"])

    def test_the_config_has_the_documented_shape(self):
        config, changed = hook.with_devin_hook({})
        self.assertTrue(changed)
        [entry] = config["hooks"]["PreToolUse"]
        self.assertEqual(entry["matcher"], "")  # every tool
        self.assertEqual(entry["hooks"], [{"type": "command", "command": "verfy hook devin", "timeout": 30}])


if __name__ == "__main__":
    unittest.main()
