"""``verfy claim``: one signed file with everything an insurer or an arbitrator needs about one disputed action.

A claim (``verfy.claim/1``) carries the dispute record (``verfy dispute open``), the ledger's check at the time,
the passkey approvals in the receipt checked offline, whether the tool matched the lock, the decision of Verfy's
open responsibility rules (liability.py) and, when there is one, the arbitrator's verdict (``verfy.verdict/1``
from Verfy Cloud). It is signed with this computer's key. ``verify`` checks all of it again, offline.

Nothing is sent anywhere: Verfy has no insurance or arbitration partner yet.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from . import dispute, ed25519, liability, passkeys
from .canonical import canonical_bytes
from .receipts import Key, b64u, key_id, receipt_hash, unb64u, verify_ledger

VERSION = "verfy.claim/1"


def _tool_check(receipt: dict, lock: dict | None) -> dict:
    act = receipt.get("action") or {}
    if lock is None:
        return {"checked": False}
    entry = ((lock.get("servers") or {}).get(act.get("server", "")) or {}).get("tools", {}).get(act.get("tool", ""))
    if not entry:
        return {"checked": True, "locked": False, "changed": None}
    got = receipt.get("tool_sha256")
    return {"checked": True, "locked": True, "pin": entry.get("digest"), "seen": got, "changed": bool(got) and got != entry.get("digest")}


def _verdict_check(verdict: dict | None, dispute_sha: str) -> list[str]:
    if verdict is None:
        return []
    problems = []
    if verdict.get("v") != "verfy.verdict/1":
        problems.append("the verdict is not a Verfy verdict (verfy.verdict/1)")
    if verdict.get("dispute_sha256") != dispute_sha:
        problems.append("the verdict is about another dispute record")
    body = {k: v for k, v in verdict.items() if k != "sha256"}
    if receipt_hash(body) != verdict.get("sha256"):
        problems.append("the verdict was changed after it was recorded")
    return problems


def build(doc: dict, receipts: list[dict], key: Key, *, verdict: dict | None = None, lock: dict | None = None) -> dict:
    check = dispute.verify_dispute(doc, key.public)
    if not check["ok"]:
        raise ValueError("the dispute record does not check out: " + "; ".join(check["problems"]))
    target = doc["receipt"]
    dispute_sha = receipt_hash(doc)
    vproblems = _verdict_check(verdict, dispute_sha)
    if vproblems:
        raise ValueError("; ".join(vproblems))
    ledger = verify_ledger(receipts, key.public) if receipts else {"ok": None, "count": 0, "head": None}
    in_ledger = any(isinstance(r, dict) and receipt_hash(r) == doc.get("receipt_sha256") for r in receipts)
    pk = passkeys.check_ledger([target])
    tool = _tool_check(target, lock)
    decision = liability.decide(doc["finding"], passkey_ok=(pk["checked"] > 0 and not pk["errors"]), tool_changed=tool.get("changed"))
    body: dict[str, Any] = {
        "v": VERSION,
        "id": "clm_" + secrets.token_hex(8),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "dispute": doc,
        "dispute_sha256": dispute_sha,
        "ledger": {"ok": ledger.get("ok"), "count": ledger.get("count"), "head": ledger.get("head"), "receipt_in_ledger": in_ledger},
        "passkeys": {"checked": pk["checked"], "problems": [e["error"] for e in pk["errors"]]},
        "tool": tool,
        "liability": decision,
        "verdict": verdict,
        "note": "Evidence for people who decide. Verfy did not judge, and nothing was sent to an insurer or arbitrator.",
        "kid": key.kid,
        "public": b64u(key.public),
    }
    return {**body, "sig": b64u(ed25519.sign(key.secret, canonical_bytes(body)))}


def verify(claim: Any) -> dict:
    """Check a claim again, offline: its signature, the dispute inside, the passkeys, the verdict and the rules."""
    if not isinstance(claim, dict) or claim.get("v") != VERSION:
        return {"ok": False, "problems": ["not a Verfy claim (verfy.claim/1)"]}
    problems: list[str] = []
    try:
        pub = unb64u(claim["public"])
    except (KeyError, ValueError):
        return {"ok": False, "problems": ["the claim has no public key"]}
    if key_id(pub) != claim.get("kid"):
        problems.append("signed by another key")
    body = {k: v for k, v in claim.items() if k != "sig"}
    try:
        if not ed25519.verify(pub, canonical_bytes(body), unb64u(claim["sig"])):
            problems.append("the claim's signature does not check out")
    except (KeyError, ValueError):
        problems.append("the claim has no signature")
    doc = claim.get("dispute") or {}
    d = dispute.verify_dispute(doc, pub)
    problems += ["dispute: " + p for p in d["problems"]]
    if receipt_hash(doc) != claim.get("dispute_sha256"):
        problems.append("the dispute record does not match its hash")
    pk = passkeys.check_ledger([doc.get("receipt") or {}])
    problems += [e["error"] for e in pk["errors"]]
    problems += _verdict_check(claim.get("verdict"), claim.get("dispute_sha256", ""))
    want = liability.decide(doc.get("finding", ""), passkey_ok=(pk["checked"] > 0 and not pk["errors"]), tool_changed=(claim.get("tool") or {}).get("changed"))
    got = claim.get("liability") or {}
    if (got.get("rule"), got.get("party")) != (want["rule"], want["party"]):
        problems.append(f"the responsibility rule is not what the evidence shows ({want['rule']}, {want['party']})")
    return {"ok": not problems, "problems": problems, "party": want["party"], "rule": want["rule"]}
