"""``verfy policy simulate NEW.json``: try a policy on actions agents already took, before turning it on.

The actions come from Claude Code's own transcripts on this computer (``~/.claude/projects/**/*.jsonl``, the tool
calls it made), or from a JSON or JSONL file of ``{"tool", "arguments"}`` objects (``--from FILE``). Verfy's
receipts hold only hashes of arguments, so they cannot be replayed. Nothing leaves this computer; each action is
checked twice, under the policy in force and under the new one, and only the differences are listed.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

from ._util import redact
from .hook import action_from_payload
from .precheck import check

MAX_FILE = 64 * 1024 * 1024


def claude_actions(root: Path | None = None, days: int = 7, limit: int = 20000) -> Iterator[dict]:
    """Tool calls from Claude Code transcripts changed in the last ``days`` days, newest files first."""
    root = root or Path.home() / ".claude" / "projects"
    if not root.is_dir():
        return
    cutoff = time.time() - days * 86400
    files = sorted((p for p in root.rglob("*.jsonl") if p.stat().st_mtime >= cutoff and p.stat().st_size <= MAX_FILE),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    n = 0
    for p in files:
        try:
            lines = p.read_text("utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            msg = entry.get("message") if isinstance(entry, dict) else None
            content = msg.get("content") if isinstance(msg, dict) else None
            if entry.get("type") != "assistant" or not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use" and isinstance(block.get("name"), str):
                    action = action_from_payload({"tool_name": block["name"], "tool_input": block.get("input"), "cwd": entry.get("cwd")})
                    action["_cwd"] = entry.get("cwd") if isinstance(entry.get("cwd"), str) else None
                    yield action
                    n += 1
                    if n >= limit:
                        return


def file_actions(path: Path) -> list[dict]:
    text = path.read_text("utf-8")
    try:
        data = json.loads(text)
        items = data if isinstance(data, list) else data.get("actions", []) if isinstance(data, dict) else []
    except ValueError:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    out = []
    for it in items:
        if isinstance(it, dict) and isinstance(it.get("tool") or it.get("name"), str):
            out.append({"server": str(it.get("server") or ""), "tool": it.get("tool") or it["name"],
                        "arguments": it.get("arguments", it.get("args", {})) if isinstance(it.get("arguments", it.get("args", {})), dict) else {}})
    return out


def simulate(actions: list[dict], current: dict, new: dict) -> dict:
    """Each action under both policies: counts of allow/ask/deny before and after, and the actions whose answer changed."""
    before, after, changed = Counter(), Counter(), []
    for a in actions:
        action = {k: v for k, v in a.items() if not k.startswith("_")}
        old_r, new_r = check(action, current), check(action, new)
        before[old_r["verdict"]] += 1
        after[new_r["verdict"]] += 1
        if old_r["verdict"] != new_r["verdict"]:
            changed.append({"tool": new_r["tool"], "kind": new_r["kind"], "before": old_r["verdict"], "after": new_r["verdict"],
                            "rules": sorted({f["rule"] for f in new_r["findings"]} - {f["rule"] for f in old_r["findings"]})
                            or sorted({f["rule"] for f in old_r["findings"]}), "summary": _summary(action)})
    return {"v": "verfy.simulate/1", "total": len(actions), "before": dict(before), "after": dict(after), "changed": changed}


def _summary(action: dict) -> str:
    """A short line naming the action, with keys and tokens in it replaced (a command can carry one)."""
    args = action.get("arguments") or {}
    for k in ("command", "file_path", "path", "url", "query", "sql"):
        if isinstance(args.get(k), str):
            v = redact(args[k]).replace("\n", " ")
            return v if len(v) <= 100 else v[:97] + "..."
    return ", ".join(sorted(map(str, args)))[:100]
