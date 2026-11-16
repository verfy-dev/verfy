"""Rules that stop an agent's action before it runs: ``Recorder(rules=[...])`` and ``rec.guard(...)``.

A rule names which actions it covers and what happens to them::

    {"id": "big-refund", "kind": "payment", "amount": "amount", "over": 500, "then": "ask"}
    {"id": "refund-day", "kind": "payment", "amount": "amount", "daily": 2000, "then": "deny"}
    {"id": "no-drop", "action": "drop_table", "then": "deny"}
    {"system": "prod-*", "kind": "delete", "then": "ask"}

* ``kind``, ``system`` and ``action`` select actions; each is a name, a ``*`` pattern or a list of them. A rule
  without any of them covers every action.
* ``amount`` is the dotted path of a number in the arguments ("amount", "payment.total"). ``over`` covers an action
  whose amount is above it; ``daily`` an action that would take today's total (UTC) above it. An action a rule with
  a limit covers but whose amount is missing or not a number counts as over the limit: a guard fails closed.
* ``then`` is "ask" (a person must approve it, in Verfy Cloud or by a callback) or "deny".

Rules come from the recorder, ``~/.verfy/policy.json`` and the team policy ``verfy team pull`` saves
(``"actions": [...]`` in either). Together they can only make an action stricter: the strictest rule that covers it
decides. Daily totals are kept on this machine (``limits.json``, amounts only) and count every action the guard let
through, also one that failed afterwards.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import math
import re
from pathlib import Path
from typing import Any

from .canonical import digest
from .fileio import FileLock, atomic_write

THEN = ("ask", "deny")
SEVERITY = {"allow": 0, "ask": 1, "deny": 2}
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_FIELDS = {"id", "kind", "system", "action", "amount", "over", "daily", "then", "message"}


class RuleError(ValueError):
    """A rule that cannot be used."""


def _names(rule: dict, key: str) -> list[str] | None:
    v = rule.get(key)
    if v is None:
        return None
    vals = [v] if isinstance(v, str) else v
    if not isinstance(vals, list) or not vals or not all(isinstance(x, str) and x for x in vals):
        raise RuleError(f"rule {rule.get('id', '?')}: {key} must be a name, a * pattern or a list of them")
    return vals


def normalize(rule: Any) -> dict:
    """Check one rule and give it an id (from its content when it has none)."""
    if not isinstance(rule, dict):
        raise RuleError("a rule is a JSON object")
    extra = set(rule) - _FIELDS
    if extra:
        raise RuleError(f"rule {rule.get('id', '?')}: unknown field(s) {', '.join(sorted(extra))}")
    if rule.get("then") not in THEN:
        raise RuleError(f"rule {rule.get('id', '?')}: then must be ask or deny")
    for key in ("kind", "system", "action"):
        _names(rule, key)
    for key in ("over", "daily"):
        v = rule.get(key)
        if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0):
            raise RuleError(f"rule {rule.get('id', '?')}: {key} must be a number of at least 0")
    has_limit = rule.get("over") is not None or rule.get("daily") is not None
    if has_limit and not isinstance(rule.get("amount"), str):
        raise RuleError(f"rule {rule.get('id', '?')}: over and daily need amount, the path of the number in the arguments")
    if rule.get("amount") is not None and not has_limit:
        raise RuleError(f"rule {rule.get('id', '?')}: amount needs over or daily")
    if rule.get("message") is not None and not isinstance(rule["message"], str):
        raise RuleError(f"rule {rule.get('id', '?')}: message must be text")
    out = {k: v for k, v in rule.items() if v is not None}
    if "id" in out:
        if not isinstance(out["id"], str) or not _ID.match(out["id"]):
            raise RuleError("a rule id is 1 to 64 letters, digits or . _ : -")
    else:
        out["id"] = "rule-" + digest({k: v for k, v in out.items() if k != "message"})[7:15]
    return out


def load_rules(rules: list | None) -> list[dict]:
    seen: set[str] = set()
    out = []
    for r in rules or []:
        n = normalize(r)
        if n["id"] in seen:
            raise RuleError(f"two rules have the id {n['id']}")
        seen.add(n["id"])
        out.append(n)
    return out


def rules_from_policies(home: Path) -> list[dict]:
    """The "actions" rules in ~/.verfy/policy.json and in the team policy saved by `verfy team pull`."""
    found: list[dict] = []
    for path in (home / "team" / "policy.json", home / "policy.json"):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise RuleError(f"{path} cannot be read: {e}") from None
        acts = data.get("actions") if isinstance(data, dict) else None
        if acts is None:
            continue
        if not isinstance(acts, list):
            raise RuleError(f'{path}: "actions" must be a list of rules')
        for r in acts:
            n = normalize(r)
            n["id"] = n["id"] if path.parent.name != "team" or n["id"].startswith("team:") else "team:" + n["id"]
            found.append(n)
    return found


def _matches(patterns: list[str] | None, value: str) -> bool:
    return patterns is None or any(fnmatch.fnmatchcase(value, p) for p in patterns)


def amount_at(args: Any, path: str) -> float | None:
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    if isinstance(cur, bool):
        return None
    if isinstance(cur, (int, float)) and math.isfinite(cur):
        return float(cur)
    if isinstance(cur, str):
        try:
            v = float(cur)
        except ValueError:
            return None
        return v if math.isfinite(v) else None
    return None


def today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def evaluate(rules: list[dict], *, action: str, system: str, kind: str, args: Any, spent: dict[str, float],
             agent: str) -> dict:
    """``{"verdict", "findings", "amounts"}``. ``amounts`` maps each daily rule that covered the action to the amount
    to add to its total when the action goes ahead."""
    findings: list[dict] = []
    amounts: dict[str, float] = {}
    for r in rules:
        if not (_matches(_names(r, "kind"), kind) and _matches(_names(r, "system"), system) and _matches(_names(r, "action"), action)):
            continue
        hit, why = True, None
        if "amount" in r:
            value = amount_at(args, r["amount"])
            if value is None:
                why = f"no number at {r['amount']} in the arguments, so the limit cannot be checked"
            else:
                hit = False
                if "over" in r and value > r["over"]:
                    hit, why = True, f"{value:g} is over {r['over']:g}"
                if "daily" in r:
                    key = f"{agent}|{r['id']}"
                    total = spent.get(key, 0.0) + value
                    amounts[key] = value
                    if total > r["daily"]:
                        hit, why = True, f"today's total would be {total:g}, over {r['daily']:g}"
        if hit:
            findings.append({"rule": r["id"], "verdict": r["then"], "message": r.get("message") or why or f"{action} needs {'approval' if r['then'] == 'ask' else 'to be stopped'}"})
    verdict = max((f["verdict"] for f in findings), key=lambda v: SEVERITY[v], default="allow")
    return {"verdict": verdict, "findings": findings, "amounts": amounts}


class Totals:
    """Today's totals per agent and daily rule, in ``limits.json``, read and written under a lock."""

    def __init__(self, path: Path):
        self.path = path

    def _read(self) -> dict[str, float]:
        try:
            data = json.loads(self.path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict) or data.get("date") != today() or not isinstance(data.get("totals"), dict):
            return {}
        return {k: float(v) for k, v in data["totals"].items() if isinstance(v, (int, float)) and not isinstance(v, bool)}

    def current(self) -> dict[str, float]:
        return self._read()

    def decide(self, fn):
        """Run ``fn(totals) -> (result, amounts_to_add)`` under the lock and add the amounts it returns, so two
        processes never both spend the last of a daily limit."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(self.path, timeout=30.0):
            totals = self._read()
            result, add = fn(totals)
            if add:
                for k, v in add.items():
                    totals[k] = totals.get(k, 0.0) + v
                atomic_write(self.path, json.dumps({"date": today(), "totals": totals}, indent=2, sort_keys=True) + "\n", mode=0o600)
            return result


def rules_digest(rules: list[dict]) -> str:
    return digest({"actions": rules})
