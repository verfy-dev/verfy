"""Rules written in plain English: ``verfy rule add "ask before payments over 50"``.

The sentence is turned into an exact policy change by fixed patterns below, shown to the person with what it does,
and written only after they say yes. Nothing here guesses with a model: a sentence the patterns do not cover is
refused with the forms that work, and the decision on each action is made by the written rule, never by this text.

Also here: rule packs (``verfy policy pack add github``), ready policy parts for common tools, kept in
``data/packs.json``.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

PACKS: dict[str, dict] = json.loads((Path(__file__).parent / "data" / "packs.json").read_text("utf-8"))

DENY = r"(?:block|deny|never\s+allow|don'?t\s+allow|do\s+not\s+allow|forbid|prevent|stop|no)"
ASK = r"(?:ask(?:\s+me)?(?:\s+(?:before|for|when|about))?|require\s+(?:my\s+)?approval\s+(?:for|before)|confirm\s+before|check\s+with\s+me\s+before)"
ALLOW = r"(?:always\s+allow|allow|trust|let\s+(?:the\s+)?agents?)"
NUM = r"(\d+(?:[.,]\d+)?)"
CUR = r"(?:\s*(?:\$|usd|dollars?|eur|euros?|€|gbp|£|uzs|so'?m))?"

FORMS = [
    'block deleting files outside the project',
    'ask before changes outside the project',
    'block reading .env files            (any glob: "~/secrets/**", "*.pem")',
    'block writing to ~/Documents/**',
    'ask before payments over 50',
    'block payments over 500',
    'block spending more than 200 per day      (or per month)',
    'allow payments to acme                   (then: block payments to anyone else)',
    'block calls to example.com               (ask before ..., allow ...)',
    'block the tool delete_repository          (ask before the tool ..., trust the tool ...)',
    'block commands starting with terraform    (allow commands starting with npm)',
    'ask before sending messages               (block sending emails)',
    'block sending personal data               (ask before ...)',
    'ask before installing packages',
    'block pushing to main                     (ask before pushing to main)',
]


class PlainRuleError(ValueError):
    pass


def _verb(s: str) -> tuple[str, str] | None:
    for verdict, pat in (("ask", ASK), ("deny", DENY), ("allow", ALLOW)):
        m = re.match(r"^\s*" + pat + r"\b\s*(?:to\s+|any\s+|all\s+)?(.*)$", s, re.I)
        if m:
            return verdict, m.group(1).strip()
    return None


def _num(v: str) -> float:
    x = float(v.replace(",", "."))
    return int(x) if x == int(x) else x


def _slug(s: str) -> str:
    return "plain-" + (re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "rule")


def compile_rule(text: str) -> dict:
    """``{"patch": {...policy part...}, "says": "what it does, in words", "text": text}``; PlainRuleError if not covered."""
    s = re.sub(r"\s+", " ", text.strip().rstrip(".!")).strip()
    if not s:
        raise PlainRuleError("write the rule as a sentence")
    vb = _verb(s)
    if vb is None:
        raise PlainRuleError(_help(s))
    verdict, rest = vb
    rest = re.sub(r"^(?:the\s+agent\s+(?:from\s+)?)", "", rest, flags=re.I)
    rid = _slug(s)
    low = rest.lower()

    # payments
    m = re.match(r"^(?:any\s+)?payments?\s+(?:over|above|of\s+more\s+than|bigger\s+than|larger\s+than)\s+" + NUM + CUR + r"$", low)
    if m and verdict in ("ask", "deny"):
        key = "ask_above" if verdict == "ask" else "max_per_call"
        return _out({"payments": {key: _num(m.group(1))}}, f"{'Asks a person about' if verdict == 'ask' else 'Blocks'} any payment above {m.group(1)}.", text)
    m = re.match(r"^(?:spending|payments?|paying)\s+(?:of\s+)?(?:more\s+than|over|above)\s+" + NUM + CUR + r"\s+(?:per|a|each|every)\s+(day|month)$", low)
    if m and verdict == "deny":
        key = "daily_budget" if m.group(2) == "day" else "monthly_budget"
        return _out({"payments": {key: _num(m.group(1))}}, f"Blocks a payment that would take spending above {m.group(1)} in one {m.group(2)}.", text)
    m = re.match(r"^payments?\s+to\s+(anyone\s+else|unknown\s+(?:recipients|payees|merchants)|strangers)$", low)
    if m and verdict in ("ask", "deny"):
        return _out({"payments": {"unknown_recipient": verdict}}, f"{'Asks about' if verdict == 'ask' else 'Blocks'} a payment to anyone not on payments.recipients.", text)
    m = re.match(r"^payments?\s+to\s+([a-z0-9_.@*-]+)$", rest, re.I)
    if m and verdict == "allow":
        return _out({"payments": {"recipients": [m.group(1)]}}, f"Adds `{m.group(1)}` to the known recipients (payments.recipients).", text)

    # where changes go
    if re.match(r"^(?:any\s+)?(?:changes?|writes?|writing|edits?|editing|anything)\s+(?:to\s+files\s+)?outside\s+(?:of\s+)?the\s+(?:project|workspace|repo(?:sitory)?)$", low) and verdict in ("ask", "deny"):
        return _out({"files": {"outside_workspace": verdict}}, f"{'Asks about' if verdict == 'ask' else 'Blocks'} a change to a file outside the project.", text)
    m = re.match(r"^(?:deleting|removing|deletion\s+of)\s+(?:any\s+)?files?(\s+outside\s+(?:of\s+)?the\s+(?:project|workspace|repo(?:sitory)?))?$", low)
    if m and verdict in ("ask", "deny"):
        if m.group(1):
            rules = [{"id": rid, "kind": "file_delete", "pattern": ".", "verdict": verdict, "message": "Deletes a file (your plain-language rule)."}]
            return _out({"files": {"outside_workspace": verdict}, "rules": rules}, f"{'Asks about' if verdict == 'ask' else 'Blocks'} deleting a file outside the project (and any change there).", text)
        rules = [{"id": rid, "kind": "file_delete", "pattern": ".", "verdict": verdict, "message": "Deletes a file (your plain-language rule)."},
                 {"id": rid + "-sh", "kind": "shell", "pattern": r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:rm|rmdir|del|erase|unlink|shred|Remove-Item)\b", "flags": "i",
                  "verdict": verdict, "message": "Deletes files with a command (your plain-language rule)."}]
        return _out({"rules": rules}, f"{'Asks about' if verdict == 'ask' else 'Blocks'} every file delete, by a tool or a command.", text)
    m = re.match(r"^(reading|opening|viewing|writing(?:\s+to)?|changing|editing|modifying)\s+(.+?)(?:\s+files?)?$", rest, re.I)
    if m and verdict in ("ask", "deny"):
        glob = _glob(m.group(2))
        if glob:
            if m.group(1).lower() in ("reading", "opening", "viewing"):
                if verdict == "ask":
                    return _out({"files": {"sensitive": [glob]}}, f"Asks before an agent reads `{glob}` (files.sensitive).", text)
                return _out({"rules": [{"id": rid, "kind": "file_read", "pattern": _glob_rx(glob), "flags": "i", "verdict": "deny",
                                        "message": f"Reads `{glob}` (your plain-language rule)."}],
                             "files": {"sensitive": [glob]}}, f"Blocks reading `{glob}` with a file tool, and asks when a command reads it.", text)
            if verdict == "deny":
                return _out({"files": {"deny_write": [glob]}}, f"Blocks every change to `{glob}` (files.deny_write).", text)
            return _out({"rules": [{"id": rid, "kind": "file_write", "pattern": _glob_rx(glob), "flags": "i", "verdict": "ask",
                                    "message": f"Changes `{glob}` (your plain-language rule)."}]}, f"Asks before a file tool changes `{glob}`.", text)

    # network
    m = re.match(r"^(?:calls?|requests?|connections?|access|going|traffic|uploads?)\s+to\s+([a-z0-9*][a-z0-9.*-]*\.[a-z*]{2,})$", low)
    if m:
        host = m.group(1)
        if verdict == "deny":
            return _out({"network": {"deny": [host]}}, f"Blocks requests to `{host}` (network.deny).", text)
        if verdict == "allow":
            return _out({"network": {"allow": [host]}}, f"Lets agents reach `{host}` without asking (network.allow).", text)
        return _out({"rules": [{"id": rid, "pattern": r"(?:^|[/@.])" + re.escape(host).replace(r"\*", "[a-z0-9-]*") + r"(?:[:/?#]|$)",
                                "flags": "i", "verdict": "ask", "message": f"Reaches `{host}` (your plain-language rule)."}]},
                    f"Asks before any action that names `{host}`.", text)

    # tools
    m = re.match(r"^(?:using\s+|calling\s+)?(?:the\s+)?tool\s+([A-Za-z0-9_./*-]+)$|^(?:using\s+|calling\s+)?(?:the\s+)?([A-Za-z0-9_./*-]+)\s+tool$", rest, re.I)
    if m:
        name = m.group(1) or m.group(2)
        key = {"deny": "deny", "ask": "ask", "allow": "trust"}[verdict]
        says = {"deny": f"Blocks the tool `{name}`.", "ask": f"Asks before every call of `{name}`.",
                "allow": f"Trusts `{name}`: the rules skip it (what guards Verfy still applies)."}[verdict]
        return _out({"tools": {key: [name]}}, says, text)

    # commands
    m = re.match(r"^(?:running\s+)?(?:commands?|programs?)\s+(?:starting\s+with|like|named|called)\s+([A-Za-z0-9_.+-]+)$|^running\s+([A-Za-z0-9_.+-]+)$", rest, re.I)
    if m:
        prog = m.group(1) or m.group(2)
        if verdict == "allow":
            return _out({"shell": {"allow": [prog]}}, f"Adds `{prog}` to the programs that run without a person in allowlist mode (shell.allow).", text)
        return _out({"rules": [{"id": rid, "kind": "shell", "pattern": r"(?:^|[;&|(]\s*)(?:sudo\s+|env\s+\S+\s+)*" + re.escape(prog) + r"(?:\.exe)?\b",
                                "flags": "i", "verdict": verdict, "message": f"Runs `{prog}` (your plain-language rule)."}]},
                    f"{'Asks before' if verdict == 'ask' else 'Blocks'} running `{prog}`.", text)

    # messages, personal data, packages, pushes
    if re.match(r"^(?:sending\s+)?(?:messages?|emails?|e-mails?|dms?|chat\s+messages?)$", re.sub(r"^sending\s+", "sending ", low)) or re.match(r"^sending\s+(?:messages?|emails?|e-mails?|dms?)$", low):
        return _out({"messages": {"send": verdict}}, {"ask": "Asks before an agent sends a message.", "deny": "Blocks every message an agent sends.",
                                                      "allow": "Lets agents send messages without asking."}[verdict], text)
    if re.match(r"^(?:sending|sharing|leaking|uploading)\s+(?:personal\s+data|personal\s+information|pii|card\s+numbers?|customer\s+data)$", low) and verdict in ("ask", "deny"):
        return _out({"dlp": {"personal": verdict}}, f"{'Asks before' if verdict == 'ask' else 'Blocks'} sending card numbers, IBANs, social security numbers or many email addresses out.", text)
    if re.match(r"^(?:installing|downloading|running)\s+(?:new\s+)?(?:packages?|npx\s+packages?|dependencies)$", low) and verdict == "ask":
        return _out({"adaptive": {"packages": "ask"}}, "Asks the first time an agent runs a package with npx, uvx, pipx run or dlx.", text)
    m = re.match(r"^(force[\s-]pushing|force[\s-]pushes|pushing|pushes)\s+(?:to\s+)?(main|master|production|prod|release)$", low)
    if m and verdict in ("ask", "deny"):
        force = m.group(1).startswith("force")
        pat = r"\bgit\b[^\n;&|]*\bpush\b" + (r"[^\n;&|]*(?:--force|-f\b|\+)" if force else "") + r"[^\n;&|]*\b" + m.group(2) + r"\b"
        return _out({"rules": [{"id": rid, "kind": "shell", "pattern": pat, "flags": "i", "verdict": verdict,
                                "message": f"{'Force-pushes' if force else 'Pushes'} to {m.group(2)} (your plain-language rule)."}]},
                    f"{'Asks before' if verdict == 'ask' else 'Blocks'} {'a force push' if force else 'a push'} to {m.group(2)}.", text)
    raise PlainRuleError(_help(s))


def _glob(s: str) -> str | None:
    s = s.strip().strip("`'\"")
    s = re.sub(r"^(?:any\s+|all\s+|the\s+)", "", s, flags=re.I)
    if re.fullmatch(r"\.env", s, re.I):
        return "**/.env*"
    if re.fullmatch(r"\*?\.[A-Za-z0-9]{1,8}", s):  # ".pem" or "*.pem"
        return "**/*" + s.lstrip("*")
    if re.fullmatch(r"[~/.A-Za-z0-9_*:\\ -]*[/*.~][~/.A-Za-z0-9_*:\\ -]*", s) and len(s) <= 200:
        return s.replace("\\", "/")
    return None


def _glob_rx(glob: str) -> str:
    """A pattern that finds the glob in a path argument (the rules match argument text)."""
    out = ""
    i = 0
    g = glob.lstrip("~").lstrip("/") if glob.startswith(("~/", "**/")) else glob
    if g.startswith("**/"):
        g = g[3:]
    while i < len(g):
        if g.startswith("**", i):
            out += ".*"
            i += 2
        elif g[i] == "*":
            out += "[^/\\\\]*"
            i += 1
        else:
            out += re.escape(g[i])
            i += 1
    return r"(?:^|[/\\])" + out + "$"


def _out(patch: dict, says: str, text: str) -> dict:
    return {"patch": patch, "says": says, "text": text}


def _help(s: str) -> str:
    return (f'Verfy does not turn "{s}" into a rule; it understands these forms (no AI decides what a sentence means):\n  '
            + "\n  ".join(FORMS) + "\nAnything else: edit the policy JSON (verfy policy show).")


# ---------------------------------------------------------------- applying a patch

LISTS = {("files", "sensitive"), ("files", "deny_write"), ("network", "deny"), ("network", "allow"), ("tools", "deny"), ("tools", "ask"),
         ("tools", "trust"), ("shell", "allow"), ("payments", "recipients"), ("packages", "allow")}


def apply_patch(policy: dict, patch: dict) -> dict:
    """``policy`` (the user's own JSON, not merged with the defaults) with ``patch`` added: lists get new entries, numbers
    and words are replaced, rules are appended (a rule with the same id is replaced)."""
    out = copy.deepcopy(policy)
    for top, val in patch.items():
        if top == "rules":
            mine = [r for r in out.get("rules", []) if r.get("id") not in {x.get("id") for x in val}]
            out["rules"] = mine + copy.deepcopy(val)
            continue
        if not isinstance(val, dict):
            out[top] = copy.deepcopy(val)
            continue
        part = out.setdefault(top, {})
        for k, v in val.items():
            if (top, k) in LISTS:
                part[k] = list(dict.fromkeys([*(part.get(k) or []), *v]))
            elif isinstance(v, dict):
                part[k] = {**(part.get(k) or {}), **copy.deepcopy(v)}
            else:
                part[k] = v
    return out


def remove_rule(policy: dict, rule_id: str) -> tuple[dict, bool]:
    out = copy.deepcopy(policy)
    before = len(out.get("rules", []))
    out["rules"] = [r for r in out.get("rules", []) if r.get("id") != rule_id and not str(r.get("id", "")).startswith(rule_id + "-sh")]
    return out, len(out["rules"]) != before


# ---------------------------------------------------------------- packs

def pack_patch(name: str) -> dict:
    if name not in PACKS:
        raise PlainRuleError(f"no pack named {name!r}; packs: {', '.join(sorted(PACKS))}")
    patch = copy.deepcopy(PACKS[name]["policy"])
    for r in patch.get("rules", []):
        r["id"] = f"pack-{name}-{r['id']}"
    return patch


def add_pack(policy: dict, name: str) -> dict:
    out = apply_patch(policy, pack_patch(name))
    out["packs"] = list(dict.fromkeys([*(out.get("packs") or []), name]))
    return out


def remove_pack(policy: dict, name: str) -> dict:
    """Takes out what the pack added: its rules, and list entries no other pack in use also adds."""
    patch = pack_patch(name)
    out = copy.deepcopy(policy)
    out["rules"] = [r for r in out.get("rules", []) if not str(r.get("id", "")).startswith(f"pack-{name}-")]
    others = [pack_patch(p) for p in out.get("packs") or [] if p != name and p in PACKS]
    for top, val in patch.items():
        if top == "rules" or not isinstance(val, dict):
            continue
        for k, v in val.items():
            if (top, k) in LISTS and isinstance(out.get(top, {}).get(k), list):
                kept = {x for o in others for x in (o.get(top, {}).get(k) or [])}
                out[top][k] = [x for x in out[top][k] if x not in v or x in kept]
    out["packs"] = [p for p in out.get("packs") or [] if p != name]
    return out
