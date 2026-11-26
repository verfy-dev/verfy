"""Agent keys and hand-overs between agents.

**Agent keys** (``verfy agent create NAME``): each agent gets its own Ed25519 key, and the owner's Verfy key signs a
certificate for it (``verfy.agentcert/1``: the agent's name and key, the owner's key id, when it was made and until
when it is good). Receipts the agent signs then prove "this agent, which belongs to that owner, did it": check the
agent's ledger with its key, and the certificate with the owner's public key. ``verfy agent revoke`` writes a signed
revocation, so a certificate can be withdrawn before it ends.

**Hand-overs** (``Recorder.delegate``): when one agent gives work to another, it signs a delegation
(``verfy.delegation/1``) naming the other agent's key, what it may do (rules that can only be stricter than its own)
and until when, and it records the hand-over as a receipt. The other agent's receipts name the delegation, so the
chain of permission and of receipts runs from the first agent to the last. ``verify_chain`` checks each link.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import ed25519
from .canonical import canonical_bytes, digest
from .receipts import Key, b64u, key_id, unb64u

CERT = "verfy.agentcert/1"
REVOCATION = "verfy.agentrevoke/1"
DELEGATION = "verfy.delegation/1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds").replace("+00:00", "Z")


def _sign(body: dict, key: Key) -> dict:
    body = {k: v for k, v in body.items() if k != "sig"}
    return {**body, "sig": b64u(ed25519.sign(key.secret, canonical_bytes(body)))}


def _verify(doc: dict, public: bytes) -> bool:
    try:
        return ed25519.verify(public, canonical_bytes({k: v for k, v in doc.items() if k != "sig"}), unb64u(doc["sig"]))
    except (KeyError, TypeError, ValueError):
        return False


def _time(v: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------- agent keys

def create_agent(owner: Key, name: str, days: int = 365) -> tuple[Key, dict]:
    if not name or len(name) > 100 or not all(c.isalnum() or c in "-_." for c in name):
        raise ValueError("the agent name is letters, digits, - _ or ., at most 100 characters")
    if not 1 <= days <= 3650:
        raise ValueError("days must be from 1 to 3650")
    agent = Key.generate()
    start = _now()
    cert = _sign({"v": CERT, "agent": name, "agent_kid": agent.kid, "agent_public": b64u(agent.public), "owner_kid": owner.kid,
                  "owner_public": b64u(owner.public), "issued_at": _iso(start), "expires_at": _iso(start + timedelta(days=days)),
                  "serial": secrets.token_hex(8)}, owner)
    return agent, cert


def revoke(owner: Key, cert: dict, reason: str = "") -> dict:
    return _sign({"v": REVOCATION, "serial": cert.get("serial"), "agent_kid": cert.get("agent_kid"), "owner_kid": owner.kid,
                  "revoked_at": _iso(_now()), **({"reason": reason[:200]} if reason else {})}, owner)


def verify_cert(cert: dict, owner_public: bytes, revocations: list[dict] | None = None, at: str | None = None) -> dict:
    problems = []
    if not isinstance(cert, dict) or cert.get("v") != CERT:
        return {"ok": False, "problems": ["not a Verfy agent certificate"]}
    if cert.get("owner_kid") != key_id(owner_public):
        problems.append("the certificate names another owner key")
    if not _verify(cert, owner_public):
        problems.append("the owner's signature does not check out")
    try:
        if key_id(unb64u(cert["agent_public"])) != cert.get("agent_kid"):
            problems.append("the agent key and its id do not match")
    except (KeyError, ValueError):
        problems.append("the agent key is missing")
    when = _time(at) if at else _now()
    start, end = _time(cert.get("issued_at")), _time(cert.get("expires_at"))
    if when is None or start is None or end is None or not start <= when <= end:
        problems.append(f"not valid at {at or 'this time'} (good from {cert.get('issued_at')} to {cert.get('expires_at')})")
    for rv in revocations or []:
        if rv.get("v") == REVOCATION and rv.get("serial") == cert.get("serial") and _verify(rv, owner_public):
            rt = _time(rv.get("revoked_at"))
            if rt is not None and (when is None or rt <= when):
                problems.append(f"revoked at {rv.get('revoked_at')}" + (f" ({rv['reason']})" if rv.get("reason") else ""))
    return {"ok": not problems, "problems": problems, "agent": cert.get("agent"), "agent_kid": cert.get("agent_kid"), "owner_kid": cert.get("owner_kid")}


def verify_agent_ledger(receipts: list[dict], cert: dict, owner_public: bytes, revocations: list[dict] | None = None) -> dict:
    """The ledger is signed by the agent's key, and the certificate was good when each receipt was signed."""
    from .receipts import verify_ledger
    res = verify_ledger(receipts, unb64u(cert["agent_public"]))
    problems = list(res.get("errors", []))
    for r in receipts:
        c = verify_cert(cert, owner_public, revocations, at=r.get("issued_at"))
        if not c["ok"]:
            problems.append(f"#{r.get('seq')}: " + "; ".join(c["problems"]))
            break
    return {"ok": res.get("ok", False) and not problems, "count": len(receipts), "problems": problems, "agent": cert.get("agent")}


# ---------------------------------------------------------------- hand-overs

def delegate(parent: Key, *, to_public: bytes, to_agent: str, rules: list[dict] | None = None, tools: list[str] | None = None,
             minutes: int = 60, parent_receipt: str | None = None, parent_delegation: dict | None = None) -> dict:
    """A signed hand-over from ``parent`` to the agent with ``to_public``. ``rules`` use the guard's rule format
    (limits.py); ``tools`` limits which actions it may take (``*`` patterns). A hand-over made under another one
    (``parent_delegation``) can only narrow it: its time ends no later, its tools are a subset, and its rules add to
    the parent's."""
    if not 1 <= minutes <= 7 * 24 * 60:
        raise ValueError("minutes must be from 1 to 10080")
    start = _now()
    end = start + timedelta(minutes=minutes)
    chain_rules = list(rules or [])
    if parent_delegation is not None:
        pend = _time(parent_delegation.get("expires_at"))
        if pend is not None and end > pend:
            end = pend
        chain_rules = [*parent_delegation.get("rules", []), *chain_rules]
        ptools = parent_delegation.get("tools")
        if ptools is not None:
            tools = [t for t in (tools or ptools) if any(_glob(p, t) for p in ptools)]
    return _sign({"v": DELEGATION, "id": "dlg_" + secrets.token_hex(8), "from_kid": parent.kid, "from_public": b64u(parent.public),
                  "to_agent": to_agent, "to_kid": key_id(to_public), "issued_at": _iso(start), "expires_at": _iso(end),
                  "rules": chain_rules, **({"tools": tools} if tools is not None else {}),
                  **({"parent_receipt": parent_receipt} if parent_receipt else {}),
                  **({"parent": digest(parent_delegation)} if parent_delegation is not None else {})}, parent)


def _glob(pat: str, name: str) -> bool:
    from ._util import name_match
    return name_match(pat, name)


def allows(delegation: dict, action: str, at: str | None = None) -> str | None:
    """Why ``action`` is outside the hand-over (None when it is inside)."""
    when = _time(at) if at else _now()
    end = _time(delegation.get("expires_at"))
    if end is None or when is None or when > end:
        return f"the hand-over {delegation.get('id')} ended at {delegation.get('expires_at')}"
    tools = delegation.get("tools")
    if tools is not None and not any(_glob(p, action) for p in tools):
        return f"`{action}` is not among the actions the hand-over {delegation.get('id')} allows ({', '.join(tools)})"
    return None


def verify_chain(delegations: list[dict], receipts_by_kid: dict[str, list[dict]] | None = None) -> dict:
    """Each hand-over is signed by the key the one before it handed to, narrows it, and (when ledgers are given)
    each receipt that names a hand-over was signed by its receiving key within its time and tools."""
    problems = []
    prev = None
    for i, d in enumerate(delegations):
        try:
            pub = unb64u(d["from_public"])
        except (KeyError, ValueError):
            problems.append(f"#{i}: no signing key")
            continue
        if key_id(pub) != d.get("from_kid") or not _verify(d, pub):
            problems.append(f"#{i}: the signature does not check out")
        if prev is not None:
            if d.get("from_kid") != prev.get("to_kid"):
                problems.append(f"#{i}: signed by {d.get('from_kid')}, but the hand-over before it went to {prev.get('to_kid')}")
            if d.get("parent") != digest(prev):
                problems.append(f"#{i}: does not name the hand-over before it")
            pe, de = _time(prev.get("expires_at")), _time(d.get("expires_at"))
            if pe and de and de > pe:
                problems.append(f"#{i}: lasts longer than the hand-over before it")
            if prev.get("tools") is not None and not all(any(_glob(p, t) for p in prev["tools"]) for t in d.get("tools") or ["*"]):
                problems.append(f"#{i}: allows actions the hand-over before it did not")
            if d.get("rules", [])[:len(prev.get("rules", []))] != prev.get("rules", []):
                problems.append(f"#{i}: drops rules the hand-over before it set")
        for r in (receipts_by_kid or {}).get(d.get("to_kid", ""), []):
            if r.get("delegation") != d.get("id") or (r.get("decision") or {}).get("verdict") == "deny"                     or (r.get("outcome") or {}).get("status") in ("blocked", "declined"):
                continue  # a refusal is the hand-over working, not a breach of it
            why = allows(d, (r.get("action") or {}).get("tool", ""), at=r.get("issued_at"))
            if why:
                problems.append(f"receipt #{r.get('seq')} of {d.get('to_kid')}: {why}")
        prev = d
    return {"ok": not problems, "links": len(delegations), "problems": problems}


def save_json(path: Path, data: dict) -> None:
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
