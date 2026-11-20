"""Verfy's Cursor hook against Cursor's hook reference (https://cursor.com/docs/agent/hooks, read 20 November 2026):
the input of every event Verfy registers, with every common field Cursor sends, and the exact answer each event accepts.
Run from verfy-cli/: ``python -m unittest tests.test_cursor_spec``."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import hook  # noqa: E402
from verfy.policy import load_policy  # noqa: E402

POLICY = load_policy({"home": "/home/you", "workspace": "/home/you/project"})
TOKEN = "ghp_" + "a1B2" * 9

# what the reference lists as common to every hook's input
COMMON = {
    "conversation_id": "668320d2-2fd8-4888-b33c-2a466fec86e7", "generation_id": "490b90b7-a2ce-4c2c-bb76-cb77b125df2f",
    "model": "claude-sonnet", "model_id": "claude-sonnet-x", "model_params": [{"id": "thinking", "value": "on"}],
    "cursor_version": "2.4.0", "workspace_roots": ["/home/you/project"], "user_email": "dev@example.com",
    "transcript_path": None,
}
# the answer keys each event accepts, and the permission values it enforces
ACCEPTS = {
    "beforeShellExecution": ({"permission", "user_message", "agent_message", "continue"}, {"allow", "deny", "ask"}),
    "beforeMCPExecution": ({"permission", "user_message", "agent_message", "continue"}, {"allow", "deny", "ask"}),
    "beforeReadFile": ({"permission", "user_message"}, {"allow", "deny"}),
    "preToolUse": ({"permission", "user_message", "agent_message", "updated_input"}, {"allow", "deny"}),
    "beforeSubmitPrompt": ({"continue", "user_message"}, None),
    "postToolUse": ({"updated_mcp_tool_output", "additional_context"}, None),
}


def event(name: str, **fields) -> dict:
    return {**COMMON, "hook_event_name": name, **fields}


def run(payload: dict | None = None, raw: bytes | None = None) -> tuple[int, dict]:
    data = raw if raw is not None else json.dumps(payload).encode("utf-8")

    class Stdin(io.TextIOWrapper):
        pass
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="cp1252")  # what a Windows pipe looks like to Python
    out = io.StringIO()
    code = hook.run_hook("cursor", stdin=stdin, stdout=out, get_policy=lambda cwd: POLICY, record=lambda **kw: None)
    return code, json.loads(out.getvalue())


class CursorSpec(unittest.TestCase):
    def assertConforms(self, name: str, answer: dict) -> None:
        keys, values = ACCEPTS[name]
        self.assertLessEqual(set(answer), keys, f"{name} answered keys Cursor does not read: {answer}")
        if values is not None:
            self.assertIn(answer.get("permission"), values, f"{name}: {answer}")

    def test_every_answer_is_one_cursor_accepts_and_the_exit_code_is_0(self):
        cases = [
            event("beforeShellExecution", command="ls -la", cwd="/home/you/project", sandbox=False),
            event("beforeShellExecution", command="rm -rf ~", cwd="/home/you/project", sandbox=True),
            event("beforeShellExecution", command="git push --force origin main", cwd="/home/you/project", sandbox=False),
            event("beforeMCPExecution", tool_name="query", tool_input=json.dumps({"sql": "select 1"}), mcp_server_name="db", command="npx db-mcp"),
            event("beforeMCPExecution", tool_name="query", tool_input=json.dumps({"sql": "drop table users"}), mcp_server_name="db",
                  url="https://db.example/mcp", mcp_server_url="https://db.example/mcp"),
            event("beforeReadFile", file_path="/home/you/project/README.md", content="# hi", attachments=[]),
            event("beforeReadFile", file_path="/home/you/.ssh/id_rsa", content="-----BEGIN", attachments=[]),
            event("preToolUse", tool_name="Write", tool_input={"file_path": "/home/you/project/a.py", "contents": "print(1)"},
                  tool_use_id="t1", cwd="/home/you/project", agent_message=""),
            event("preToolUse", tool_name="Delete", tool_input={"path": "/home/you"}, tool_use_id="t2", cwd="/home/you/project"),
            event("preToolUse", tool_name="Shell", tool_input={"command": "rm -rf ~", "working_directory": "/home/you/project"},
                  tool_use_id="t3", cwd="/home/you/project"),
            event("beforeSubmitPrompt", prompt="fix the tests", attachments=[]),
            event("beforeSubmitPrompt", prompt=f"use {TOKEN}", attachments=[]),
            event("postToolUse", tool_name="MCP:get", tool_input={}, tool_output=json.dumps({"content": [{"type": "text", "text": TOKEN}]}),
                  tool_use_id="t4", cwd="/home/you/project", duration=12),
        ]
        for payload in cases:
            code, answer = run(payload)
            self.assertEqual(code, 0, payload)
            self.assertConforms(payload["hook_event_name"], answer)

    def test_the_answers_mean_what_they_should(self):
        self.assertEqual(run(event("beforeShellExecution", command="ls", cwd="/home/you/project", sandbox=False))[1], {"permission": "allow"})
        deny = run(event("beforeShellExecution", command="rm -rf ~", cwd="/home/you/project", sandbox=False))[1]
        self.assertEqual(deny["permission"], "deny")
        self.assertIn("VFY-SH-001", deny["user_message"])
        self.assertIn("VFY-SH-001", deny["agent_message"])
        self.assertEqual(run(event("beforeShellExecution", command="git push --force origin main", cwd="/home/you/project"))[1]["permission"], "ask")
        # a file read and a tool call cannot wait for a person: what would ask is denied, and says so
        read = run(event("beforeReadFile", file_path="/home/you/.ssh/id_rsa", content="", attachments=[]))[1]
        self.assertEqual(read["permission"], "deny")
        self.assertIn("cannot wait for a person", read["user_message"])
        # Write and Delete through preToolUse: the edit is checked before it is made
        w = run(event("preToolUse", tool_name="Write", tool_input={"file_path": "/home/you/.claude/settings.json", "contents": "{}"},
                      tool_use_id="t", cwd="/home/you/project"))[1]
        self.assertEqual(w["permission"], "deny")
        d = run(event("preToolUse", tool_name="Delete", tool_input={"path": "/home/you"}, tool_use_id="t", cwd="/home/you/project"))[1]
        self.assertEqual(d["permission"], "deny")
        # a secret in the content Cursor's Write tool sends under "contents"
        s = run(event("preToolUse", tool_name="Write", tool_input={"file_path": "/home/you/project/.env.local", "contents": f"T={TOKEN}"},
                      tool_use_id="t", cwd="/home/you/project"))[1]
        self.assertEqual(s["permission"], "deny")
        self.assertIn("VFY-SEC-001", s["user_message"])
        # Shell, Read and MCP in preToolUse are left to their own hooks, so nothing is checked twice
        self.assertEqual(run(event("preToolUse", tool_name="Shell", tool_input={"command": "rm -rf ~"}, tool_use_id="t"))[1], {"permission": "allow"})
        self.assertEqual(run(event("beforeSubmitPrompt", prompt=f"use {TOKEN}", attachments=[]))[1]["continue"], False)

    def test_an_attached_file_is_checked_like_the_file_read(self):
        a = run(event("beforeReadFile", file_path="/home/you/project/notes.md", content="",
                      attachments=[{"type": "file", "file_path": "/home/you/.ssh/id_rsa"}, {"type": "rule", "file_path": "/home/you/project/.cursor/rules/x.mdc"}]))[1]
        self.assertEqual(a["permission"], "deny")
        self.assertIn("id_rsa", a["user_message"])

    def test_utf8_input_on_a_windows_pipe(self):
        # Python would read this pipe as cp1252 and garble the path, or fail on bytes cp1252 does not map
        for raw in (json.dumps(event("beforeShellExecution", command="cat ~/.ssh/id_rsa", cwd="/home/Жавохир/проект"), ensure_ascii=False).encode("utf-8"),
                    b"\xef\xbb\xbf" + json.dumps(event("beforeShellExecution", command="rm -rf ~", cwd="/x")).encode("utf-8"),
                    json.dumps(event("beforeShellExecution", command="rm -rf ~", cwd="/x")).encode("utf-16")):
            code, answer = run(raw=raw)
            self.assertEqual(code, 0)
            self.assertIn(answer["permission"], ("ask", "deny"), answer)
            self.assertNotIn("could not check", answer.get("user_message", ""))
        ok = run(raw=json.dumps(event("beforeShellExecution", command="ls", cwd="/home/Жавохир/проект"), ensure_ascii=False).encode("utf-8"))[1]
        self.assertEqual(ok, {"permission": "allow"})

    def test_what_verfy_cannot_read_never_lets_the_action_through(self):
        for raw in (b"", b"not json", json.dumps(event("beforeShellExecution")).encode()):
            code, answer = run(raw=raw)
            self.assertEqual(code, 0)
            self.assertIn(answer["permission"], ("ask", "deny"))

    def test_hooks_json_has_the_documented_shape(self):
        config, changed = hook.with_cursor_hook({})
        self.assertTrue(changed)
        self.assertEqual(config["version"], 1)
        for name, entries in config["hooks"].items():
            self.assertIn(name, ACCEPTS)
            for e in entries:
                self.assertEqual(e["command"], "verfy hook cursor")
                self.assertLessEqual(set(e), {"command", "failClosed", "matcher", "timeout", "type"})
        # the hooks that decide fail closed; the prompt guard and the output filter must not stop Cursor when they break
        for name in ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse"):
            self.assertTrue(config["hooks"][name][0]["failClosed"], name)
        self.assertFalse(config["hooks"]["beforeSubmitPrompt"][0]["failClosed"])
        self.assertEqual(hook.with_cursor_hook(config)[1], False)  # a second run changes nothing


if __name__ == "__main__":
    unittest.main()
