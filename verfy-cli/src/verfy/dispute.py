"""``verfy dispute open``: a signed dispute record built from the receipts, with a first finding made by fixed rules.

When someone says "the agent should not have done that", the receipt already answers the first questions: did it
run, did a rule let it through, did a person approve it, was it under emergency access or observe mode, is the
receipt chain intact. ``open_dispute`` writes those answers into ``verfy.dispute/1`` and signs it with this
computer's key, so the other side, an insurer or an arbitrator gets one file they can check offline.

The finding is not a judgement. Verfy has no arbitration or insurance partner yet: a decision about who pays is
made by people, outside Verfy, with this file as evidence.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from . import ed25519
from .canonical import canonical_bytes
from .receipts import Key, b64u, key_id, receipt_hash, unb64u, verify_ledger, verify_receipt

VERSION = "verfy.dispute/1"

FINDINGS = {
    "blocked": "Verfy blocked this action; it did not run.",
    "person_approved": "A person approved this action before it ran.",
    "emergency_access": "This action ran under emergency access a person opened, past rules that would have stopped it.",
    "observe_mode": "Verfy was in observe mode: the rules would have stopped this action, but nothing was blocked.",
    "policy_allowed": "The policy in force allowed this action; no rule asked for a person.",
    "asked_not_approved": "A rule asked for a person and no approval is recorded; the agent's own prompt may have been answered outside Verfy.",
    "chain_broken": "The receipt chain does not check out, so this receipt alone proves little.",
}


def finding(receipt: dict, chain_ok: bool) -> str:
    d, o = receipt.get("decision") or {}, receipt.get("outcome") or {}
    if not chain_ok:
        return "chain_broken"
    if d.get("verdict") == "deny" or o.get("status") in ("blocked", "declined"):
        return "blocked"
    if d.get("breakglass"):
        return "emergency_access"
    if d.get("would"):
        return "observe_mode"
    if d.get("approved_by"):
        return "person_approved"
    if d.get("verdict") == "ask":
        return "asked_not_approved"
    return "policy_allowed"


def open_dispute(receipts: list[dict], seq: int, claim: str, key: Key, opened_by: str = "") -> dict:
    claim = claim.strip()
    if len(claim) < 10:
        raise ValueError("say what went wrong in a sentence (--claim)")
    target = next((r for r in receipts if r.get("seq") == seq), None)
    if target is None:
        raise ValueError(f"there is no receipt #{seq} in this ledger")
    ver = verify_ledger(receipts, key.public)
    code = finding(target, bool(ver.get("ok")))
    args = (target.get("action") or {}).get("args") or {}
    facts: list[str] = [FINDINGS[code]]
    d = target.get("decision") or {}
    if d.get("rules"):
        facts.append("Rules that matched: " + ", ".join(d["rules"]) + ".")
    if d.get("approved_by"):
        facts.append(f"Approved by: {d['approved_by']}.")
    if d.get("breakglass"):
        facts.append(f"Emergency access window: {d['breakglass']}.")
    if isinstance(args, dict) and args.get("mandate_sha256"):
        facts.append(f"The payment names mandate {args['mandate_sha256']}; compare the mandate the person signed.")
    facts.append(f"Policy in force: {d.get('policy_sha256')}.")
    body: dict[str, Any] = {
        "v": VERSION, "id": "dsp_" + secrets.token_hex(8),
        "opened_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "opened_by": opened_by[:100], "claim": claim[:2000], "receipt": target, "receipt_sha256": receipt_hash(target),
        "chain": {"ok": bool(ver.get("ok")), "count": ver.get("count"), "head": ver.get("head")},
        "finding": code, "facts": facts,
        "next": "This finding comes from fixed rules, not a judgement. A person decides who is responsible; send them this file.",
        "kid": key.kid, "public": b64u(key.public),
    }
    return {**body, "sig": b64u(ed25519.sign(key.secret, canonical_bytes(body)))}


def verify_dispute(doc: dict, public: bytes | None = None) -> dict:
    problems = []
    if not isinstance(doc, dict) or doc.get("v") != VERSION:
        return {"ok": False, "problems": ["not a Verfy dispute record"]}
    try:
        pub = public or unb64u(doc["public"])
    except (KeyError, ValueError):
        return {"ok": False, "problems": ["no public key"]}
    if key_id(pub) != doc.get("kid"):
        problems.append("signed by another key")
    body = {k: v for k, v in doc.items() if k != "sig"}
    try:
        if not ed25519.verify(pub, canonical_bytes(body), unb64u(doc["sig"])):
            problems.append("the record's signature does not check out")
    except (KeyError, ValueError):
        problems.append("the record has no signature")
    if not verify_receipt(doc.get("receipt"), pub):
        problems.append("the receipt inside does not check out with this key")
    elif receipt_hash(doc["receipt"]) != doc.get("receipt_sha256"):
        problems.append("the receipt hash does not match")
    elif finding(doc["receipt"], bool((doc.get("chain") or {}).get("ok"))) != doc.get("finding"):
        problems.append("the finding is not what the receipt shows")
    return {"ok": not problems, "problems": problems, "finding": doc.get("finding"), "claim": doc.get("claim")}
