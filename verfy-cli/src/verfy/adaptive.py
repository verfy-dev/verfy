"""Catching what no rule names yet: a guard that adapts to the session and to this machine.

Verfy's rules (precheck.py) name known attacks and risky shapes of commands. An attack nobody has written a rule for
can still slip past those. Two checks here need no rule for the attack itself:

1. **Escalation, per session.** An agent that tried something Verfy blocked, or several suspicious things, may be
   steered by text an attacker wrote. Someone who does not know Verfy's rules has to try variants until one passes,
   and every try that is caught counts against the session. From 3 points in the last hour (one blocked action, or
   three suspicious ones) every risky action in that session needs a person (VFY-AD-001); from 9 points it is blocked
   (VFY-AD-002). Risky means: a shell command other than plain reading, anything that reaches the network, a message,
   a payment, a delete, or a change outside the project. Reading and editing inside the project go on.

2. **Novelty, per machine.** Verfy learns which programs that reach the network or run inline code this machine's
   agents use, and which hosts they contact from the shell. After a warm-up (50 actions by default), the first time a
   program or host appears that was never seen, a person is asked once (VFY-AD-003); then it is learned. Nothing is
   learned from a session under escalation, so an attacker cannot teach the baseline.

3. **Packages, per machine.** ``npx``, ``bunx``, ``npm exec``, ``pnpm dlx``, ``yarn dlx``, ``uvx``, ``uv tool run`` and
   ``pipx run`` download a package and run it in one step. The first time a package appears, a person is asked once
   (VFY-AD-004), with no warm-up; then it is learned. A local bin of the project (``node_modules/.bin``) and a package
   on ``packages.allow`` (``"npm:prettier"``, ``"pypi:ruff"`` or a bare name; ``*`` works) are not asked about.

Policy: ``"adaptive": {"escalate": "on" | "off", "novelty": "ask" | "off", "packages": "ask" | "off", "warmup": 50}``. The state, in
``~/.verfy/adaptive.json``, holds program names, host names, counts and times, never arguments. A state file that
cannot be read starts over: this layer only ever adds findings, so losing it never lets anything through that the
rules stop.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .fileio import FileLock, atomic_write
from ._util import VERDICT_RANK, name_match
from .precheck import NETWORK_CMDS, _url_parts, _urls, parse_shell

VERSION = 1
WINDOW = 3600.0
ASK_AT, DENY_AT = 3, 9
FEATURES_MAX = 5000
SESSIONS_MAX = 500
#: rules whose "ask" says the agent tried something an attacker would; each counts one point
SUSPICIOUS = ("VFY-SH-005", "VFY-SH-008", "VFY-SH-020", "VFY-SH-021", "VFY-SH-024", "VFY-SH-025", "VFY-SH-026", "VFY-SH-039",
              "VFY-SH-040", "VFY-SH-011", "VFY-SEC-001", "VFY-SELF-", "VFY-TOOL-003", "VFY-TOOL-004",
              "VFY-TOOL-005", "VFY-NET-001", "VFY-NET-003", "VFY-FS-001", "VFY-IMP-001", "VFY-SCRIPT-003")
INTERPRETERS = re.compile(r"^(?:python[0-9.]*|py|node|deno|bun|perl|ruby|php|pwsh|powershell)(?:\.exe)?$", re.I)
INLINE_FLAG = re.compile(r"^-(?:c|e|r|command|encodedcommand|ec|enc)$", re.I)
EXEC_PROGS = {"ssh", "sshpass", "base64", "certutil", "bitsadmin", "osascript", "launchctl", "crontab", "schtasks", "reg",
              "mshta", "rundll32", "regsvr32", "wmic", "xxd", "openssl"}
READ_ONLY = {"ls", "dir", "cat", "head", "tail", "less", "more", "grep", "rg", "find", "fd", "wc", "sort", "uniq", "pwd",
             "echo", "printf", "which", "where", "type", "file", "stat", "du", "df", "tree", "diff", "cut", "tr", "jq", "date",
             "whoami", "uname", "env", "true", "false", "test", "["}
SAFE_GIT = re.compile(r"^git\s+(?:status|diff|log|show|branch|rev-parse|ls-files|blame|remote\s+-v)\b")


def settings(policy: dict) -> dict:
    a = policy.get("adaptive") if isinstance(policy.get("adaptive"), dict) else {}
    escalate = a.get("escalate", "on")
    novelty = a.get("novelty", "ask")
    packages = a.get("packages", "ask")
    warmup = a.get("warmup", 50)
    if escalate not in ("on", "off"):
        raise ValueError("adaptive.escalate must be on or off")
    if novelty not in ("ask", "off"):
        raise ValueError("adaptive.novelty must be ask or off")
    if packages not in ("ask", "off"):
        raise ValueError("adaptive.packages must be ask or off")
    if isinstance(warmup, bool) or not isinstance(warmup, int) or not 0 <= warmup <= 100000:
        raise ValueError("adaptive.warmup must be a whole number from 0 to 100000")
    return {"escalate": escalate, "novelty": novelty, "packages": packages, "warmup": warmup}


def _f(rule: str, verdict: str, message: str) -> dict:
    return {"rule": rule, "verdict": verdict, "message": message}


def _shell_text(action: dict) -> str:
    args = action.get("arguments", action.get("args", {}))
    if isinstance(args, dict):
        for k in ("command", "cmd", "script", "commandLine", "command_line", "input"):
            if isinstance(args.get(k), str):
                return args[k]
    return ""


def features(action: dict, decision: dict) -> list[str]:
    """The risky things in one action this machine may not have seen: programs that reach the network or run code
    (``prog:<name>``) and hosts contacted from the shell (``host:<name>``)."""
    if decision.get("kind") != "shell":
        return []
    cmd = _shell_text(action)
    if not cmd:
        return []
    out: list[str] = []
    for s in parse_shell(cmd):
        name = str(s.get("name") or "")
        base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if not base:
            continue
        if name in NETWORK_CMDS or base in EXEC_PROGS or (INTERPRETERS.match(base) and any(INLINE_FLAG.match(a) for a in s.get("args", []))):
            out.append("prog:" + base)
    if decision.get("reaches_network"):
        for u in _urls(cmd):
            parts = _url_parts(u)
            if parts and parts[0]:
                out.append("host:" + parts[0].lower())
    return list(dict.fromkeys(out))


NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "-w", "--workspace", "--cache", "--registry", "--userconfig"}
UVX_VALUE_FLAGS = {"--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index", "--index-url",
                   "--extra-index-url", "--default-index", "-i", "--find-links", "-f", "--constraint", "-c", "--override",
                   "--spec", "--pip-args", "--directory", "--project", "--config-file", "--cache-dir"}


def _spec_args(args: list[str], value_flags: set[str], spec_flags: tuple[str, ...]) -> tuple[list[str], str | None]:
    """(packages named by a flag, the first plain argument) after the flags of a package runner."""
    named: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return named, args[i + 1] if i + 1 < len(args) else None
        if a.startswith("--") and "=" in a:
            flag, value = a.split("=", 1)
            if flag in spec_flags:
                named.append(value)
            i += 1
            continue
        if a in value_flags:
            if a in spec_flags and i + 1 < len(args):
                named.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return named, a
    return named, None


def _npm_name(spec: str) -> str:
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith(("git+", "github:", "file:")):
        return spec
    spec = spec.removeprefix("npm:")
    m = re.match(r"^(@[^/@\s]+/[^@\s]+)", spec) or re.match(r"^([^@\s]+)", spec)
    return (m.group(1) if m else spec).lower()


def _pypi_name(spec: str) -> str:
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith("git+"):
        return spec
    return re.split(r"[\[<>=!~@ ;]", spec, maxsplit=1)[0].lower().replace("_", "-")


def packages_run(cmd: str) -> list[tuple[str, str, bool]]:
    """Packages a command downloads and runs: (registry, name, could be a local bin of the project)."""
    out: list[tuple[str, str, bool]] = []
    for s in parse_shell(cmd):
        base = re.sub(r"\.(?:exe|cmd|bat|ps1)$", "", str(s.get("name") or "").replace("\\", "/").rsplit("/", 1)[-1].lower())
        a = [str(x) for x in s.get("args", [])]
        if base in ("npx", "bunx", "pnpx") or (base == "npm" and a[:1] in (["exec"], ["x"])) or (base == "bun" and a[:1] == ["x"]):
            rest = a[1:] if base in ("npm", "bun") else a
            named, first = _spec_args(rest, NPX_VALUE_FLAGS, ("-p", "--package"))
            local = not named and base != "pnpx"
            out += [("npm", _npm_name(x), False) for x in named] + ([("npm", _npm_name(first), local)] if first and not named else [])
        elif base in ("pnpm", "yarn") and a[:1] == ["dlx"]:
            named, first = _spec_args(a[1:], NPX_VALUE_FLAGS, ("-p", "--package"))
            out += [("npm", _npm_name(x), False) for x in named] + ([("npm", _npm_name(first), False)] if first and not named else [])
        elif base == "uvx" or (base == "uv" and a[:2] == ["tool", "run"]):
            named, first = _spec_args(a[2:] if base == "uv" else a, UVX_VALUE_FLAGS, ("--from",))
            out += [("pypi", _pypi_name(x), False) for x in named] + ([("pypi", _pypi_name(first), False)] if first and not named else [])
        elif base == "pipx" and a[:1] == ["run"]:
            named, first = _spec_args(a[1:], UVX_VALUE_FLAGS, ("--spec",))
            out += [("pypi", _pypi_name(x), False) for x in named] + ([("pypi", _pypi_name(first), False)] if first and not named else [])
    return [x for x in dict.fromkeys(out) if x[1]]


def _local_bin(cwd: str | None, name: str) -> bool:
    if not cwd:
        return False
    root = Path(cwd)
    return (root / "node_modules" / ".bin" / name.rsplit("/", 1)[-1]).exists() or (root / "node_modules" / name / "package.json").exists()


def package_features(action: dict, decision: dict, policy: dict, cwd: str | None = None) -> list[str]:
    """``pkg:<registry>:<name>`` for each package this action downloads and runs, leaving out a local bin of the project
    and what ``packages.allow`` lists."""
    if decision.get("kind") != "shell":
        return []
    cmd = _shell_text(action)
    if not cmd:
        return []
    allow = [str(x) for x in ((policy.get("packages") or {}).get("allow") or []) if isinstance(x, str)]
    out = []
    for registry, name, maybe_local in packages_run(cmd):
        if maybe_local and _local_bin(cwd, name):
            continue
        if any(name_match(p.lower(), f"{registry}:{name}") or name_match(p.lower(), name) for p in allow):
            continue
        out.append(f"pkg:{registry}:{name}")
    return out


def risky(action: dict, decision: dict) -> bool:
    kind = decision.get("kind")
    if kind in ("network", "message", "payment", "file_delete"):
        return True
    if kind == "file_write":
        return any(f["rule"] == "VFY-FS-002" for f in decision.get("findings", []))
    if kind == "shell":
        cmd = _shell_text(action).strip()
        if decision.get("reaches_network") or not cmd:
            return True
        if SAFE_GIT.match(cmd):
            return False
        segs = parse_shell(cmd)
        return not segs or any(s.get("sudo") or s.get("out") or str(s.get("name") or "") not in READ_ONLY for s in segs)
    return kind not in ("file_read", "file_write", "other", "read")


def points(decision: dict) -> int:
    """How much one decision counts against its session."""
    if decision.get("verdict") == "deny" and any(not f["rule"].startswith("VFY-AD-") for f in decision.get("findings", [])):
        return 3
    n = sum(1 for f in decision.get("findings", []) if f["verdict"] == "ask" and f["rule"].startswith(SUSPICIOUS))
    return min(n, 2)


class State:
    """``~/.verfy/adaptive.json``, read and written under a lock."""

    def __init__(self, home: Path):
        self.path = Path(home) / "adaptive.json"

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            if isinstance(data, dict) and data.get("v") == VERSION and isinstance(data.get("features"), dict) and isinstance(data.get("sessions"), dict):
                return data
        except (OSError, ValueError):
            pass
        return {"v": VERSION, "learned": 0, "features": {}, "sessions": {}}

    def update(self, fn):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(self.path, timeout=10.0):
            data = self._read()
            result = fn(data)
            atomic_write(self.path, json.dumps(data, separators=(",", ":")) + "\n", mode=0o600)
            return result

    def snapshot(self) -> dict:
        return self._read()


def _score(data: dict, session: str, now: float) -> int:
    events = data["sessions"].get(session) or []
    return sum(int(e[1]) for e in events if isinstance(e, list) and len(e) >= 2 and now - float(e[0]) < WINDOW)


def _prune(data: dict, now: float) -> None:
    sessions = data["sessions"]
    for sid in list(sessions):
        kept = [e for e in sessions[sid] if isinstance(e, list) and len(e) >= 2 and now - float(e[0]) < WINDOW]
        if kept:
            sessions[sid] = kept[-200:]
        else:
            del sessions[sid]
    if len(sessions) > SESSIONS_MAX:
        for sid in sorted(sessions, key=lambda s: sessions[s][-1][0])[: len(sessions) - SESSIONS_MAX]:
            del sessions[sid]
    feats = data["features"]
    if len(feats) > FEATURES_MAX:
        for k in sorted(feats, key=lambda k: feats[k].get("last", 0))[: len(feats) - FEATURES_MAX]:
            del feats[k]


def _verdict(findings: list[dict]) -> str:
    return max((f["verdict"] for f in findings), key=lambda v: VERDICT_RANK[v], default="allow")


def apply(home: Path | None, session: str, checked: list[tuple[dict, dict]], policy: dict, now: float | None = None,
          cwd: str | None = None) -> list[tuple[dict, dict]]:
    """Add escalation and novelty findings to the rules' decisions for one tool call (several actions for a patch), then
    count the call against its session and learn from it. Returns the decisions, changed in place."""
    if home is None or not checked:
        return checked
    cfg = settings(policy)
    if cfg["escalate"] == "off" and cfg["novelty"] == "off" and cfg["packages"] == "off":
        return checked
    now = time.time() if now is None else now

    def step(data: dict) -> None:
        _prune(data, now)
        score = _score(data, session, now)
        warm = int(data.get("learned", 0)) >= cfg["warmup"]
        for action, decision in checked:
            added: list[dict] = []
            if cfg["escalate"] == "on" and score >= ASK_AT and risky(action, decision):
                if score >= DENY_AT:
                    added.append(_f("VFY-AD-002", "deny", f"This session already tried {score // 3 or 1}+ blocked or suspicious actions in the last hour, "
                                                          "so Verfy blocks anything risky in it. Start a new session if this was a mistake."))
                else:
                    added.append(_f("VFY-AD-001", "ask", "This session already tried something Verfy blocked or found suspicious, "
                                                         "so a person has to approve anything risky in it for the next hour."))
            feats = features(action, decision)
            if cfg["novelty"] == "ask" and warm and decision.get("verdict") != "deny":
                new = [k for k in feats if k not in data["features"]]
                if new:
                    names = ", ".join(f"`{k.split(':', 1)[1]}`" for k in new[:3])
                    what = "program" if all(k.startswith("prog:") for k in new) else ("host" if all(k.startswith("host:") for k in new) else "program or host")
                    added.append(_f("VFY-AD-003", "ask", f"This machine's agents have never used the {what} {names} before; Verfy asks the first time."))
            pkgs = package_features(action, decision, policy, cwd) if cfg["packages"] == "ask" else []
            fresh = [k for k in pkgs if k not in data["features"]]
            if fresh and decision.get("verdict") != "deny":
                names = ", ".join(f"`{k.split(':', 2)[2]}` from {'npm' if k.split(':')[1] == 'npm' else 'PyPI'}" for k in fresh[:3])
                added.append(_f("VFY-AD-004", "ask", f"Downloads and runs {names}, which this machine's agents have not run before; "
                                                     "Verfy asks the first time. List packages you trust under packages.allow."))
            if added:
                decision["findings"] = sorted([*decision.get("findings", []), *added], key=lambda f: -VERDICT_RANK[f["verdict"]])
                decision["verdict"] = _verdict(decision["findings"])
        # count the call, then learn from it unless it was blocked or the session is under escalation
        worst = max(checked, key=lambda ad: points(ad[1]))[1]
        p = points(worst)
        if p:
            rule = next((f["rule"] for f in worst.get("findings", []) if not f["rule"].startswith("VFY-AD-")), "")
            data["sessions"].setdefault(session, []).append([round(now, 3), p, rule])
        if score < ASK_AT and p == 0 and all(d.get("verdict") != "deny" for _, d in checked):
            data["learned"] = int(data.get("learned", 0)) + 1
            for action, decision in checked:
                for k in features(action, decision) + (package_features(action, decision, policy, cwd) if cfg["packages"] == "ask" else []):
                    e = data["features"].setdefault(k, {"first": round(now), "count": 0})
                    e["count"] = int(e.get("count", 0)) + 1
                    e["last"] = round(now)

    State(home).update(step)
    return checked


def status(home: Path, policy: dict, now: float | None = None) -> dict:
    """What ``verfy adaptive`` shows: settings, how much has been learned, and sessions under escalation."""
    cfg = settings(policy)
    data = State(home).snapshot()
    now = time.time() if now is None else now
    sessions = {sid: _score(data, sid, now) for sid in data["sessions"]}
    return {
        **cfg,
        "learned": int(data.get("learned", 0)),
        "warm": int(data.get("learned", 0)) >= cfg["warmup"],
        "programs": sorted(k[5:] for k in data["features"] if k.startswith("prog:")),
        "hosts": sorted(k[5:] for k in data["features"] if k.startswith("host:")),
        "packages": sorted(k[4:] for k in data["features"] if k.startswith("pkg:")),
        "packages_mode": cfg["packages"],
        "escalated": {sid: s for sid, s in sorted(sessions.items(), key=lambda x: -x[1]) if s >= ASK_AT},
    }


def forget(home: Path, what: str) -> int:
    """Remove a learned program (``prog:NAME``), host (``host:NAME``), package (``pkg:npm:NAME``) or session score (``session:ID``); ``all``
    clears everything. Returns how many entries went."""
    def step(data: dict) -> int:
        if what == "all":
            n = len(data["features"]) + len(data["sessions"])
            data.update({"learned": 0, "features": {}, "sessions": {}})
            return n
        if what.startswith("session:"):
            return 1 if data["sessions"].pop(what[8:], None) is not None else 0
        return 1 if data["features"].pop(what, None) is not None else 0
    return State(home).update(step)
