"""Verfy policy: what an agent may do without asking.

A policy is plain JSON. Anything you leave out falls back to the defaults in
``data/default_policy.json``, so a two-line policy file is a complete policy.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from .canonical import digest

DEFAULT_POLICY: dict[str, Any] = json.loads((Path(__file__).parent / "data" / "default_policy.json").read_text("utf-8"))
TEMPLATES: dict[str, dict] = json.loads((Path(__file__).parent / "data" / "templates.json").read_text("utf-8"))


def merge(base: Any, over: Any) -> Any:
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = merge(base.get(k), v) if k in base else copy.deepcopy(v)
        return out
    return copy.deepcopy(over)


def load_policy(source: str | os.PathLike | dict | None = None, *, workspace: str | None = None, home: str | None = None) -> dict:
    """Merge a policy (path, dict or None) over the defaults and fill in paths."""
    user: dict = {}
    if isinstance(source, dict):
        user = source
    elif source:
        user = json.loads(Path(source).read_text("utf-8"))
    if not isinstance(user, dict):
        raise ValueError("a policy must be a JSON object")
    pol = merge(DEFAULT_POLICY, user)
    if not pol.get("home"):
        pol["home"] = home or os.path.expanduser("~")
    if not pol.get("workspace"):
        pol["workspace"] = workspace or os.getcwd()
    if pol["on_ask"] not in ("deny", "allow", "elicit", "team"):
        raise ValueError("on_ask must be deny, allow, elicit or team")
    wait = pol.get("approval_timeout", 120)
    if not isinstance(wait, int) or isinstance(wait, bool) or not 10 <= wait <= 900:
        raise ValueError("approval_timeout must be a whole number of seconds from 10 to 900")
    if pol.get("fail_mode") not in ("ask", "deny"):
        raise ValueError("fail_mode must be ask or deny (Verfy never fails open)")
    if (pol.get("session") or {}).get("after_outside_text") not in ("off", "hooks", "ask", "deny"):
        raise ValueError("session.after_outside_text must be off, hooks, ask or deny")
    shell_allow = (pol.get("shell") or {}).get("allow", []) if isinstance(pol.get("shell", {}), dict) else None
    if not isinstance(shell_allow, list) or not all(isinstance(x, str) for x in shell_allow):
        raise ValueError("shell.allow must be a list of program names")
    pkg_allow = (pol.get("packages") or {}).get("allow", []) if isinstance(pol.get("packages", {}), dict) else None
    if not isinstance(pkg_allow, list) or not all(isinstance(x, str) for x in pkg_allow):
        raise ValueError("packages.allow must be a list of package names")
    if (pol.get("session") or {}).get("include_network", False) not in (True, False):
        raise ValueError("session.include_network must be true or false")
    # read with the default "ask" where it is used, and left out of the default policy (see prompt_secrets below)
    if not isinstance(pol.get("messages", {}), dict) or (pol.get("messages") or {}).get("send", "ask") not in ("ask", "deny", "allow"):
        raise ValueError("messages.send must be ask, deny or allow")
    if pol.get("mode", "enforce") not in ("enforce", "observe"):
        raise ValueError("mode must be enforce or observe")
    _check_extras(pol)
    if (pol.get("lock") or {}).get("on_new") not in ("ask", "deny", "allow"):
        raise ValueError("lock.on_new must be ask, deny or allow")
    # read with the default "block" where it is used; left out of the policy so its hash, and receipts, stay the same
    if pol.get("prompt_secrets", "block") not in ("block", "off"):
        raise ValueError("prompt_secrets must be block or off")
    # also read with its defaults where used (adaptive.settings), and left out of the default policy for the same reason
    if "adaptive" in pol:
        from .adaptive import settings
        if not isinstance(pol["adaptive"], dict):
            raise ValueError("adaptive must be an object")
        settings(pol)
    if "scripts" in pol:
        from .scripts import settings as script_settings
        if not isinstance(pol["scripts"], dict):
            raise ValueError("scripts must be an object")
        script_settings(pol)
    return pol


def _limit(where: str, v: Any) -> None:
    if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0):
        raise ValueError(f"{where} must be a number of at least 0")


def _check_extras(pol: dict) -> None:
    """The parts 0.29.0 added; each is read with its default where used and left out of the default policy, so the
    policy's hash, and the receipts of anyone who does not use them, stay the same."""
    pay = pol.get("payments") or {}
    _limit("payments.monthly_budget", pay.get("monthly_budget"))
    if pay.get("unknown_recipient", "ask") not in ("ask", "deny"):
        raise ValueError("payments.unknown_recipient must be ask or deny")
    for part, fields in (("merchants", ("max_per_call", "daily")), ("categories", ("max_per_call", "daily", "monthly"))):
        table = pay.get(part, {})
        if not isinstance(table, dict) or not all(isinstance(v, dict) for v in table.values()):
            raise ValueError(f"payments.{part} must map a name or * pattern to its limits")
        for name, lim in table.items():
            for f in fields:
                _limit(f"payments.{part}.{name}.{f}", lim.get(f))
            if part == "categories" and lim.get("then", "deny") not in ("ask", "deny"):
                raise ValueError(f"payments.categories.{name}.then must be ask or deny")
    dlp = pol.get("dlp", {})
    if not isinstance(dlp, dict) or dlp.get("personal", "ask") not in ("ask", "deny", "off"):
        raise ValueError("dlp.personal must be ask, deny or off")
    bulk = dlp.get("bulk", 5)
    if isinstance(bulk, bool) or not isinstance(bulk, int) or bulk < 0:
        raise ValueError("dlp.bulk must be a whole number (0 turns it off)")
    pats = dlp.get("patterns", [])
    if not isinstance(pats, list) or not all(isinstance(p, dict) and isinstance(p.get("pattern"), str) and p.get("then", "ask") in ("ask", "deny") for p in pats):
        raise ValueError('dlp.patterns must be a list of {"pattern": "...", "label": "...", "then": "ask" or "deny"}')
    for key in ("stop", "breakglass"):
        if key in pol and not isinstance(pol[key], dict):
            raise ValueError(f"{key} must be an object")


# "hooks" asks where an agent can put the question to a person (its hooks) and leaves the MCP gateway alone
STRICTNESS = {"off": 0, "allow": 0, "hooks": 0.5, "ask": 1, "deny": 2, "block": 2}


def _stricter(a: Any, b: Any) -> Any:
    return b if STRICTNESS.get(b, -1) > STRICTNESS.get(a, 0) else a


def _strings(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def tighten(base: dict, project: Any) -> dict:
    """``base`` with what a repository's policy adds. A policy that arrives with a clone is not yours, so it can make Verfy
    stricter and nothing else: what would loosen it (trust, disabled rules, allow lists, raw receipts) is left out."""
    if not isinstance(project, dict):
        raise ValueError("a policy must be a JSON object")
    out = copy.deepcopy(base)

    def part(name: str) -> dict:
        v = project.get(name)
        return v if isinstance(v, dict) else {}

    files, net, tools, pay = part("files"), part("network"), part("tools"), part("payments")
    for key in ("sensitive", "deny_write"):
        out["files"][key] = list(dict.fromkeys([*out["files"][key], *_strings(files.get(key))]))
    out["network"]["deny"] = list(dict.fromkeys([*out["network"]["deny"], *_strings(net.get("deny"))]))
    for key in ("deny", "ask"):
        out["tools"][key] = list(dict.fromkeys([*out["tools"].get(key, []), *_strings(tools.get(key))]))
    out["files"]["outside_workspace"] = _stricter(out["files"].get("outside_workspace", "ask"), files.get("outside_workspace"))
    out["network"]["unknown"] = _stricter(out["network"].get("unknown", "ask"), net.get("unknown"))
    out["lock"]["on_new"] = _stricter(out["lock"].get("on_new", "ask"), part("lock").get("on_new"))
    out["fail_mode"] = _stricter(out["fail_mode"], project.get("fail_mode"))
    if project.get("prompt_secrets") == "block":
        out["prompt_secrets"] = "block"
    out["session"]["after_outside_text"] = _stricter(out["session"].get("after_outside_text", "off"), part("session").get("after_outside_text"))
    if part("session").get("include_network") is True:
        out["session"]["include_network"] = True
    sends = part("messages").get("send")
    if sends in ("ask", "deny"):
        out["messages"] = {**(out.get("messages") or {}), "send": _stricter((out.get("messages") or {}).get("send", "ask"), sends)}
    if project.get("on_ask") == "deny":
        out["on_ask"] = "deny"
    if project.get("mode") == "enforce":  # a cloned policy can end observe mode, never start it
        out["mode"] = "enforce"
    project_dlp = part("dlp")
    if project_dlp.get("personal") in ("ask", "deny") or isinstance(project_dlp.get("patterns"), list):
        mine = dict(out.get("dlp") or {})
        mine["personal"] = _stricter(mine.get("personal", "ask"), project_dlp.get("personal"))
        mine["patterns"] = [*(mine.get("patterns") or []), *[p for p in project_dlp.get("patterns") or []
                                                              if isinstance(p, dict) and isinstance(p.get("pattern"), str) and p.get("then", "ask") in ("ask", "deny")]]
        out["dlp"] = mine
    adaptive = part("adaptive")
    if adaptive:
        mine = dict(out.get("adaptive") or {})
        if adaptive.get("escalate") == "on":
            mine["escalate"] = "on"
        if adaptive.get("novelty") == "ask":
            mine["novelty"] = "ask"
        if adaptive.get("packages") == "ask":
            mine["packages"] = "ask"
        w = adaptive.get("warmup")
        if isinstance(w, int) and not isinstance(w, bool) and 0 <= w < mine.get("warmup", 50):
            mine["warmup"] = w
        out["adaptive"] = mine
    if part("scripts").get("read") == "on":
        out["scripts"] = {**(out.get("scripts") or {}), "read": "on"}
    for key in ("max_per_call", "ask_above", "daily_budget", "monthly_budget"):
        v = pay.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and (out["payments"].get(key) is None or v < out["payments"][key]):
            out["payments"][key] = v
    rules = project.get("rules")
    if isinstance(rules, list):
        out["rules"] = [*out.get("rules", []), *[r for r in rules if isinstance(r, dict) and isinstance(r.get("pattern"), str) and r.get("verdict", "ask") in ("ask", "deny")]]
    return out


def policy_digest(policy: dict) -> str:
    return digest(policy)
