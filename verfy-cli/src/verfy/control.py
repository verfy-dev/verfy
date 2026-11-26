"""Stop, resume and emergency access: ``verfy stop``, ``verfy resume`` and ``verfy breakglass``.

``verfy stop`` blocks every action of every agent on this computer (or of one agent with ``--agent``) until a person
runs ``verfy resume``: hooks, the MCP gateway and the SDK's ``Recorder.guard`` all answer VFY-STOP-001. A team can
stop all its devices from Verfy Cloud: the team policy then carries ``"stop"`` and each device picks it up with its
next policy pull.

``verfy breakglass`` is for an emergency: for a few minutes (at most four hours) the rules that ask are waived, or
only the rules named with ``--rule`` (which may also be rules that block). What guards Verfy itself, a stop and
protected paths are never waived. Every action in that time is recorded with ``decision.breakglass`` set to the
window's id, and opening and closing the window are receipts too, so emergency access is never silent.

Agents cannot run ``resume``, ``breakglass`` or ``policy observe`` (VFY-SELF-003); the commands also refuse to run
without a terminal. The files live in Verfy's folder, which the rules protect from agents.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .fileio import atomic_write

STOP = "stop.json"
BREAKGLASS = "breakglass.json"
MAX_MINUTES = 240
AGENT_NAMES = ("claude-code", "cursor", "codex", "gemini", "copilot", "windsurf", "devin", "cline", "kiro", "opencode")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds").replace("+00:00", "Z")


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write(path: Path, data: dict | None) -> None:
    if data is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps(data, indent=2) + "\n")


def _record(home: Path, tool: str, args: dict, verdict: str = "allow") -> dict | None:
    """A receipt for the stop, resume or emergency access itself, so the ledger shows who opened what and when."""
    kp = home / "key.json"
    if not kp.exists():
        return None
    from .receipts import Key, Ledger
    led = Ledger(home / "ledger.jsonl", Key.load(kp))
    return led.append(agent="person", session="control", action={"server": "verfy", "tool": tool, "arguments": args},
                      decision={"verdict": verdict, "kind": "other", "findings": []}, outcome={"status": "ok", "result_sha256": None},
                      policy_sha256="sha256:" + "0" * 64)


def state(home: Path) -> dict:
    """What is in force on this computer: ``{"stop": ... or None, "breakglass": ... or None}`` (a window that ended is None)."""
    from .precheck import active_breakglass
    return {"stop": _read(home / STOP), "breakglass": active_breakglass(_read(home / BREAKGLASS))}


def inject(pol: dict, home: Path) -> dict:
    """``pol`` with this computer's stop and open emergency access added. A team's stop in the policy stays; a local
    stop is added to it. Emergency access only ever comes from this computer's file, never from a policy."""
    pol.pop("breakglass", None)
    now = state(home)
    local = now["stop"]
    team_stop = _read(home / "team-stop.json")  # Verfy Cloud: the team stopped every agent (team.check_stop)
    if team_stop and team_stop.get("all"):
        local = {**(local or {}), "all": (local or {}).get("all") or team_stop["all"]}
    if local:
        team = pol.get("stop") if isinstance(pol.get("stop"), dict) else {}
        agents = {**(team.get("agents") if isinstance(team.get("agents"), dict) else {}),
                  **(local.get("agents") if isinstance(local.get("agents"), dict) else {})}
        merged: dict[str, Any] = {}
        if team.get("all") or local.get("all"):
            merged["all"] = team.get("all") or local.get("all")
        if agents:
            merged["agents"] = agents
        pol["stop"] = merged
    if now["breakglass"]:
        pol["breakglass"] = now["breakglass"]
    return pol


def stop(home: Path, agent: str | None = None, reason: str = "") -> dict:
    data = _read(home / STOP) or {}
    entry = {"at": _iso(_now()), **({"reason": reason[:200]} if reason else {})}
    if agent:
        data.setdefault("agents", {})[agent] = entry
    else:
        data["all"] = entry
    _write(home / STOP, data)
    _record(home, "stop", {"agent": agent or "*", "reason": reason[:200]})
    return data


def resume(home: Path, agent: str | None = None) -> dict | None:
    data = _read(home / STOP) or {}
    if agent:
        (data.get("agents") or {}).pop(agent, None)
        if not data.get("agents"):
            data.pop("agents", None)
    else:
        data = {}
    _write(home / STOP, data or None)
    _record(home, "resume", {"agent": agent or "*"})
    return data or None


def open_breakglass(home: Path, minutes: int, reason: str, rules: list[str] | None = None) -> dict:
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= MAX_MINUTES:
        raise ValueError(f"minutes must be from 1 to {MAX_MINUTES}")
    reason = reason.strip()
    if len(reason) < 5:
        raise ValueError("say why in a few words (--reason); it is recorded")
    start = _now()
    bg = {"id": "bg_" + secrets.token_hex(6), "opened_at": _iso(start), "until": _iso(start + timedelta(minutes=minutes)),
          "reason": reason[:200], "rules": list(dict.fromkeys(rules or ["*"]))}
    _write(home / BREAKGLASS, bg)
    _record(home, "breakglass_open", {"id": bg["id"], "until": bg["until"], "reason": bg["reason"], "rules": bg["rules"]})
    return bg


def close_breakglass(home: Path) -> dict | None:
    bg = _read(home / BREAKGLASS)
    _write(home / BREAKGLASS, None)
    if bg:
        _record(home, "breakglass_close", {"id": str(bg.get("id", ""))})
    return bg


def waived_receipts(receipts: list[dict], bg_id: str | None = None) -> list[dict]:
    """The receipts of actions emergency access let through (``decision.breakglass``), for one window or all."""
    return [r for r in receipts if (r.get("decision") or {}).get("breakglass") and (bg_id is None or r["decision"]["breakglass"] == bg_id)]
