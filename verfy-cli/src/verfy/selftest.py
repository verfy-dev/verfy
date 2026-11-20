"""`verfy doctor --live`: run each agent's Verfy hook the way the agent runs it, and check the answers.

Support for an agent is written from its published hook format. Whether it works on this machine depends on things
no unit test sees: whether the agent finds `verfy` on its PATH, whether the command starts in time, and whether the
installed Verfy answers in the format the agent reads. This runs the very command each agent's settings name, with
two calls in that agent's own format: a harmless one (`ls`) that must pass and a destructive one (`rm -rf ~`) that must
be stopped. It runs them with a throwaway VERFY_HOME, so it leaves no receipt, learns nothing and changes nothing.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

SAFE, RISKY = "ls", "rm -rf ~"
TIMEOUT = 30.0


def _shell_payload(agent: str, cmd: str, cwd: str) -> dict:
    sid = "verfy-selftest"
    if agent == "cursor":
        return {"hook_event_name": "beforeShellExecution", "command": cmd, "cwd": cwd, "workspace_roots": [cwd], "conversation_id": sid}
    if agent == "windsurf":
        return {"agent_action_name": "pre_run_command", "trajectory_id": sid, "tool_info": {"command_line": cmd, "cwd": cwd}}
    if agent == "copilot":
        return {"toolName": "bash", "toolArgs": json.dumps({"command": cmd}), "cwd": cwd, "sessionId": sid}
    if agent == "gemini":
        return {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": cmd}, "cwd": cwd, "session_id": sid}
    # Claude Code, Codex and Devin send the Claude Code shape
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd, "session_id": sid}


def blocked(stdout: str, code: int) -> bool | None:
    """True when the hook's answer stops the call in any agent's format, False when it lets it through, None when the
    answer cannot be read."""
    if code == 2:
        return True
    text = stdout.strip()
    if code != 0:
        return None
    if not text:
        return False
    try:
        data = json.loads(text.splitlines()[-1])
    except ValueError:
        return None

    def walk(v: Any) -> bool:
        if isinstance(v, dict):
            for k, x in v.items():
                if k in ("permission", "permissionDecision", "decision") and x in ("deny", "block", "ask"):
                    return True
                if k == "continue" and x is False:
                    return True
                if walk(x):
                    return True
        return False
    return walk(data)


def run(command: str, payload: dict, env: dict, timeout: float = TIMEOUT) -> tuple[str, int, float]:
    argv = shlex.split(command, posix=os.name != "nt")
    exe = shutil.which(argv[0])
    if exe is None:
        raise FileNotFoundError(f"`{argv[0]}` is not on this PATH, so the agent cannot start the hook")
    t = time.monotonic()
    # UTF-8 as the agents send it, not \u escapes, so a path with non-ASCII letters is tested as it arrives
    p = subprocess.run([exe, *argv[1:]], input=json.dumps(payload, ensure_ascii=False), capture_output=True, text=True, encoding="utf-8",
                       timeout=timeout, env=env)  # noqa: S603 - the command the agent's own settings name
    return p.stdout, p.returncode, time.monotonic() - t


def _extra_calls(agent: str, cwd: str) -> list[tuple[str, dict, bool]]:
    """Calls beyond the shell pair, for agents whose other hooks Verfy answers: (what, payload, must be stopped)."""
    if agent != "cursor":
        return []
    home = os.path.expanduser("~")
    common = {"conversation_id": "verfy-selftest", "generation_id": "verfy-selftest", "workspace_roots": [cwd], "cwd": cwd}
    return [
        ("a read of a project file", {**common, "hook_event_name": "beforeReadFile", "file_path": os.path.join(cwd, "README.md"),
                                      "content": "", "attachments": []}, False),
        ("a read of ~/.ssh/id_rsa", {**common, "hook_event_name": "beforeReadFile", "file_path": os.path.join(home, ".ssh", "id_rsa"),
                                     "content": "", "attachments": []}, True),
        ("a write to Claude Code's settings", {**common, "hook_event_name": "preToolUse", "tool_name": "Write", "tool_use_id": "verfy-selftest",
                                              "tool_input": {"file_path": os.path.join(home, ".claude", "settings.json"), "contents": "{}"}}, True),
    ]


def check_agent(agent: str, command: str, cwd: str | None = None) -> dict:
    """``{"agent", "ok", "problems", "seconds"}`` for one agent's hook command."""
    cwd = cwd or os.getcwd()
    problems: list[str] = []
    seconds = 0.0
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "VERFY_HOME": tmp}
        calls = [(f"`{cmd}`", _shell_payload(agent, cmd, cwd), want) for cmd, want in ((SAFE, False), (RISKY, True))]
        for what, payload, want in [*calls, *_extra_calls(agent, cwd)]:
            cmd = what.strip("`")
            try:
                out, code, took = run(command, payload, env)
            except FileNotFoundError as e:
                problems.append(str(e))
                break
            except subprocess.TimeoutExpired:
                problems.append(f"`{command}` did not answer within {TIMEOUT:g} s; the agent may give up and run the call unchecked")
                break
            seconds = max(seconds, took)
            got = blocked(out, code)
            if got is None:
                problems.append(f"`{command}` answered `{cmd}` with something the agent cannot read (exit {code})")
            elif got != want:
                problems.append(f"`{command}` {'let' if want else 'stopped'} `{cmd}` {'through' if want else ''}".strip() +
                                ("; the installed Verfy may be older than this one: run `verfy update`" if want else ""))
    return {"agent": agent, "ok": not problems, "problems": problems, "seconds": round(seconds, 2)}
