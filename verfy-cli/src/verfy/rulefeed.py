"""Verfy's rule feed: new rules between releases, signed by Verfy.

When a new kind of attack appears, a rule for it can reach every machine within a day instead of waiting for the next
release. Verfy Cloud publishes the feed at ``/api/v1/rules/feed`` as a ``verfy.witness/1`` statement of type
"rules", signed with its witness key:

    {"type": "rules", "subject": {"version": 3, "shell": [[id, verdict, pattern, flags, message], ...],
                                  "network_deny": ["exfil.example", "*.bad.example"]}}

``verfy rules update`` fetches it, checks the signature, and keeps it in ``~/.verfy/rule-feed.json``. The policy in force
then has the feed's rules added (as ``VFY-FEED-*`` rules on every tool's arguments, and hosts on the network deny list),
so receipts name the policy with them in it.

A feed can only make Verfy stricter: every rule is ``ask`` or ``deny``, and nothing in it removes or loosens a rule.
The first key that signs it is remembered; a feed signed by any other key is refused until you accept that key
(``--trust-key KID``), and an older version than the one kept is refused, so a stale or replayed feed cannot take
rules away. A rule whose pattern does not compile, or that could take long to match, is refused with the whole feed.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from . import witness
from .fileio import FileLock, atomic_write

DEFAULT_URL = "https://verfy.dev"
FEED_PATH = "/api/v1/rules/feed"
REFRESH_EVERY = 24 * 3600
_ID = re.compile(r"^VFY-FEED-\d{3}$")
_HOST = re.compile(r"^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$|^[0-9a-f:.]+$")
MAX_RULES, MAX_HOSTS, MAX_PATTERN = 500, 1000, 600
# nested quantifiers such as (a+)+ can take exponential time on some inputs
_NESTED = re.compile(r"\([^()]*[+*][^()]*\)[+*{]")


class FeedError(ValueError):
    pass


def feed_file(home: Path) -> Path:
    return Path(home) / "rule-feed.json"


def check_feed(statement: Any, keys: dict[str, bytes], pinned: list[str] | None = None) -> dict:
    """The feed's subject when the statement is a signed rule feed whose rules can only make Verfy stricter."""
    if not isinstance(statement, dict) or statement.get("type") != "rules":
        raise FeedError("not a Verfy rule feed")
    kid = statement.get("kid")
    if pinned and kid not in pinned:
        raise FeedError(f"the feed is signed by {kid!r}, not by the key this machine accepted before ({', '.join(pinned)}); "
                        "if Verfy changed its key, run `verfy rules update --trust-key KID`")
    key = keys.get(kid)  # type: ignore[arg-type]
    if key is None or not witness.verify_statement(statement, key):
        raise FeedError("the feed's signature does not check with Verfy's published witness keys")
    sub = statement.get("subject")
    if not isinstance(sub, dict) or isinstance(sub.get("version"), bool) or not isinstance(sub.get("version"), int) or sub["version"] < 1:
        raise FeedError("the feed has no version")
    shell, hosts = sub.get("shell", []), sub.get("network_deny", [])
    if not isinstance(shell, list) or len(shell) > MAX_RULES or not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise FeedError("the feed's lists are not lists, or are too long")
    seen: set[str] = set()
    for r in shell:
        if not (isinstance(r, list) and len(r) == 5 and all(isinstance(x, str) for x in r)):
            raise FeedError("a feed rule is [id, verdict, pattern, flags, message]")
        rid, verdict, pattern, flags, message = r
        if not _ID.match(rid) or verdict not in ("ask", "deny") or flags not in ("", "i") or not 1 <= len(message) <= 200:
            raise FeedError(f"feed rule {rid!r} is not a VFY-FEED-NNN rule that asks or denies")
        if len(pattern) > MAX_PATTERN or _NESTED.search(pattern):
            raise FeedError(f"feed rule {rid} has a pattern that is too long or could take too long to match")
        try:
            re.compile(pattern, re.I if flags else 0)
        except re.error as e:
            raise FeedError(f"feed rule {rid} has a pattern that does not compile: {e}") from None
        seen.add(rid)
    for h in hosts:
        if not isinstance(h, str) or not _HOST.match(h.lower()):
            raise FeedError(f"{h!r} is not a host name")
    return {"version": sub["version"], "shell": shell, "network_deny": [h.lower() for h in hosts]}


def load(home: Path) -> dict | None:
    """The feed kept on this machine, or None."""
    try:
        data = json.loads(feed_file(home).read_text("utf-8"))
    except (OSError, ValueError):
        return None
    sub = data.get("feed") if isinstance(data, dict) else None
    return data if isinstance(sub, dict) and isinstance(sub.get("shell"), list) else None


def merge(policy: dict, home: Path) -> dict:
    """``policy`` with the kept feed's rules added. A feed that cannot be read adds nothing."""
    data = load(home)
    if not data:
        return policy
    feed = data["feed"]
    rules = [{"id": rid, "tool": "*", "kind": "shell", "pattern": pattern, "flags": flags, "verdict": verdict, "message": message}
             for rid, verdict, pattern, flags, message in feed["shell"]]
    out = dict(policy)
    if rules:
        out["rules"] = [*policy.get("rules", []), *rules]
    if feed.get("network_deny"):
        net = dict(policy.get("network") or {})
        net["deny"] = list(dict.fromkeys([*net.get("deny", []), *feed["network_deny"]]))
        out["network"] = net
    return out


def update(home: Path, url: str = DEFAULT_URL, *, transport: Any = None, trust_key: str | None = None, now: float | None = None) -> dict:
    """Fetch the feed, check it and keep it. Returns ``{"version", "rules", "hosts", "changed", "kid"}``."""
    from .team import TeamClient, TeamError
    try:
        client = TeamClient(url, None, transport=transport, retries=2)
        keys = witness.keys_from(client.call("GET", "/.well-known/verfy-witness.json"))
        res = client.call("GET", FEED_PATH)
    except TeamError as e:
        raise FeedError(f"could not read the rule feed: {e}") from None
    statement = res.get("feed") if isinstance(res, dict) else None
    if statement is None:
        raise FeedError("Verfy Cloud publishes no rule feed (it has no witness key set up)")
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    with FileLock(feed_file(home), timeout=30.0):
        kept = load(home) or {}
        pinned = list(kept.get("keys") or [])
        if trust_key:
            pinned = list(dict.fromkeys([*pinned, trust_key]))
        feed = check_feed(statement, keys, pinned or None)
        old = (kept.get("feed") or {}).get("version", 0)
        if feed["version"] < old:
            raise FeedError(f"the feed is version {feed['version']}, older than version {old} kept here; it was not taken")
        data = {"url": client.url, "keys": pinned or [statement["kid"]], "fetched_at": round(time.time() if now is None else now),
                "issued_at": statement.get("issued_at"), "feed": feed}
        atomic_write(feed_file(home), json.dumps(data, indent=1) + "\n", mode=0o600)
    return {"version": feed["version"], "rules": len(feed["shell"]), "hosts": len(feed["network_deny"]),
            "changed": feed["version"] != old, "kid": statement["kid"]}


def set_auto(home: Path, on: bool) -> None:
    """Turn the daily background refresh on or off for this machine (kept in rule-feed-auto.json)."""
    atomic_write(Path(home) / "rule-feed-auto.json", json.dumps({"auto": bool(on)}) + "\n")


def auto(home: Path) -> bool | None:
    try:
        v = json.loads((Path(home) / "rule-feed-auto.json").read_text("utf-8")).get("auto")
    except (OSError, ValueError, AttributeError):
        return None
    return v if isinstance(v, bool) else None


def refresh_soon(home: Path, now: float | None = None, start: Any = None) -> bool:
    """Start `verfy rules update` in the background when the kept feed is a day old, on a machine that turned the
    refresh on (`verfy rules auto on`), or that is enrolled in Verfy Cloud with automatic upload and did not turn it
    off. Called by the hook after each receipt, so it never goes online itself and never raises."""
    try:
        home = Path(home)
        team = None
        if (home / "team.json").exists():  # the team module (and its HTTP client) only for an enrolled device
            from .team import load_team
            team = load_team(home)
        on = auto(home)
        if on is False or (on is None and not (team and team.get("auto_sync") is True)):
            return False
        now = time.time() if now is None else now
        if not due(home, now):
            return False
        mark = home / "rule-feed-soon.json"
        try:
            last: float | None = float(json.loads(mark.read_text("utf-8")).get("started_at"))
        except (OSError, ValueError, AttributeError, TypeError):
            last = None
        if last is not None and 0 <= now - last < 3600:
            return False
        atomic_write(mark, json.dumps({"started_at": now}) + "\n")
        url = (team or {}).get("url") or DEFAULT_URL
        return (start or _start_update)(home, url)
    except Exception:  # noqa: BLE001 (a failed refresh must never break the guard)
        return False


def _start_update(home: Path, url: str) -> bool:
    import os
    import subprocess
    import sys
    kw: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                "env": {**os.environ, "VERFY_HOME": str(home)}}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        subprocess.Popen([sys.executable, "-m", "verfy", "rules", "update", "--quiet", "--url", url], **kw)  # noqa: S603
    except OSError:
        return False
    return True


def due(home: Path, now: float | None = None) -> bool:
    data = load(home)
    now = time.time() if now is None else now
    # a minute of slack: the time kept is rounded, and clocks move a little
    return data is None or not -60 <= now - float(data.get("fetched_at", 0)) < REFRESH_EVERY
