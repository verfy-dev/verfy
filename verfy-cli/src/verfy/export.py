"""``verfy export``: the receipt ledger in formats other tools read.

* ``ocsf``: OCSF 1.3.0 API Activity events (class_uid 6003), one JSON object per line, for a SIEM. Not signed; each
  event carries the Verfy receipt id and hash, so it can be checked against the signed ledger.
* ``acta``: receipts in the envelope of the IETF draft "Acta Signed Receipts" (draft-farley-acta-signed-receipts-04):
  ``{"payload": {...}, "signature": {"alg": "EdDSA", "kid", "sig"}}``, the payload canonicalized with JCS (RFC 8785)
  and signed with Ed25519 directly.
* ``aar``: the IETF draft "Agent Action Receipts" (draft-sahu-agent-action-receipts-00): NDJSON, fixed member order,
  ``prev_hash`` over the previous line, Ed25519 over the canonical bytes, keys in hex.

The two signed formats are signed again with this computer's Verfy key (the same Ed25519 key, so the same public
key verifies both and the Verfy ledger). They carry only what Verfy receipts hold: tool names, verdicts, rule ids
and hashes, never arguments. Both drafts are individual Internet-Drafts and may change; ``verify_acta`` and
``verify_aar`` check exactly what this module writes against the text of those revisions.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime
from typing import Any

from . import ed25519
from .canonical import canonical_bytes
from .receipts import Key, key_id, receipt_hash

ACTA_DRAFT = "draft-farley-acta-signed-receipts-04"
AAR_DRAFT = "draft-sahu-agent-action-receipts-00"
OCSF_VERSION = "1.3.0"
ACTIVITY = {"file_read": 2, "file_write": 3, "file_delete": 4, "network": 2, "sql": 99, "shell": 99, "payment": 1, "message": 1}


def _ms(ts: str) -> int:
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


def _decision(r: dict) -> str:
    return {"allow": "allow", "deny": "deny", "ask": "require_approval"}.get((r.get("decision") or {}).get("verdict"), "deny")


def _name(r: dict) -> str:
    a = r.get("action") or {}
    return f"{a.get('server')}/{a.get('tool')}" if a.get("server") else str(a.get("tool", ""))


# ---------------------------------------------------------------- OCSF

def ocsf(receipts: list[dict], version: str, host: str | None = None) -> list[dict]:
    host = host or platform.node() or "localhost"
    out = []
    for r in receipts:
        a, d, o = r.get("action") or {}, r.get("decision") or {}, r.get("outcome") or {}
        act = ACTIVITY.get(a.get("kind", ""), 99)
        verdict = d.get("verdict", "allow")
        status_id = 1 if o.get("status") == "ok" else 2 if o.get("status") in ("error", "blocked", "declined") else 99
        ev = {
            "activity_id": act, "category_uid": 6, "class_uid": 6003, "type_uid": 600300 + act,
            "category_name": "Application Activity", "class_name": "API Activity",
            "time": _ms(r["issued_at"]), "severity_id": 4 if verdict == "deny" else 3 if verdict == "ask" else 1,
            "status_id": status_id, "status": o.get("status"),
            "message": f"{_name(r)}: {verdict}" + (f" ({', '.join(d.get('rules', []))})" if d.get("rules") else ""),
            "api": {"operation": a.get("tool", ""), "service": {"name": a.get("server") or "local"}},
            "actor": {"app_name": r.get("agent", ""), "session": {"uid": r.get("session", "")}},
            "src_endpoint": {"hostname": host},
            "cloud": {"provider": "none"},
            "metadata": {"version": OCSF_VERSION, "uid": r.get("id"), "sequence": r.get("seq"), "log_name": "verfy-ledger",
                         "product": {"name": "Verfy", "vendor_name": "Verfy", "version": version}},
            "unmapped": {"verfy_receipt_sha256": receipt_hash(r), "verfy_kid": r.get("kid"), "verdict": verdict,
                         "rules": d.get("rules", []), "args_sha256": a.get("args_sha256"),
                         **({"would": d["would"]} if d.get("would") else {}), **({"breakglass": d["breakglass"]} if d.get("breakglass") else {})},
        }
        out.append(ev)
    return out


# ---------------------------------------------------------------- Acta (draft-farley-acta-signed-receipts-04)

def acta(receipts: list[dict], key: Key) -> list[dict]:
    out, prev = [], None
    for r in receipts:
        d = r.get("decision") or {}
        payload: dict[str, Any] = {"type": "verfy:decision", "tool_name": _name(r), "decision": _decision(r),
                                   "issued_at": r["issued_at"], "issuer_id": key.kid, "agent_id": r.get("agent", ""),
                                   "session_id": r.get("session", ""), "action_ref": r.get("id")}
        if d.get("rules"):
            payload["reason"] = ",".join(d["rules"])
        if str(d.get("policy_sha256", "")).startswith("sha256:") and len(d["policy_sha256"]) == 71:
            payload["policy_digest"] = d["policy_sha256"]
        if r.get("sandbox"):
            payload["sandbox_state"] = "enabled"
        if prev is not None:
            payload["previousReceiptHash"] = prev
        sig = ed25519.sign(key.secret, canonical_bytes(payload))
        rec = {"payload": payload, "signature": {"alg": "EdDSA", "kid": key.kid, "sig": sig.hex()}}
        prev = hashlib.sha256(canonical_bytes(rec)).hexdigest()
        out.append(rec)
    return out


def verify_acta(items: list[dict], public: bytes) -> dict:
    errors, prev = [], None
    kid = key_id(public)
    for i, rec in enumerate(items):
        p, s = rec.get("payload"), rec.get("signature")
        if not isinstance(p, dict) or not isinstance(s, dict):
            errors.append(f"#{i}: not an Acta envelope")
            continue
        if s.get("alg") != "EdDSA" or s.get("kid") != kid or p.get("issuer_id") != kid:
            errors.append(f"#{i}: signed by another key")
        for f in ("type", "issued_at", "issuer_id", "tool_name", "decision"):
            if f not in p:
                errors.append(f"#{i}: {f} is missing")
        try:
            ok = ed25519.verify(public, canonical_bytes(p), bytes.fromhex(str(s.get("sig", ""))))
        except ValueError:
            ok = False
        if not ok:
            errors.append(f"#{i}: bad signature")
        if p.get("previousReceiptHash") != prev:
            errors.append(f"#{i}: previousReceiptHash does not match the receipt before it")
        prev = hashlib.sha256(canonical_bytes(rec)).hexdigest()
    return {"ok": not errors, "count": len(items), "errors": errors, "draft": ACTA_DRAFT}


# ---------------------------------------------------------------- Agent Action Receipts (draft-sahu-agent-action-receipts-00)

def _sorted_json(v: Any) -> str:
    """Compact JSON with object keys sorted by code point, recursively (the draft's rule for ``params``)."""
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _sorted_json(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_sorted_json(x) for x in v) + "]"
    if isinstance(v, bool) or v is None:
        return json.dumps(v)
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return json.dumps(v, ensure_ascii=False)


def aar_signed_bytes(rec: dict) -> bytes:
    parts = [f'"step_id":{json.dumps(rec["step_id"], ensure_ascii=False)}', f'"action_id":{json.dumps(rec["action_id"], ensure_ascii=False)}',
             f'"params":{_sorted_json(rec["params"])}', f'"success":{"true" if rec["success"] else "false"}', f'"ts_ms":{int(rec["ts_ms"])}']
    if "actor" in rec:
        actor = rec["actor"]
        inner = ",".join(f'"{k}":{json.dumps(actor[k], ensure_ascii=False)}' for k in ("agent", "user") if k in actor)
        parts.append('"actor":{' + inner + "}")
    if "prev_hash" in rec:
        parts.append(f'"prev_hash":{json.dumps(rec["prev_hash"])}')
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def aar_line(rec: dict) -> str:
    """The transmitted line: signed members in order, then public_key and signature."""
    body = aar_signed_bytes(rec).decode("utf-8")[:-1]
    return body + f',"public_key":"{rec["public_key"]}","signature":"{rec["signature"]}"' + "}"


def aar(receipts: list[dict], key: Key) -> list[str]:
    lines, prev = [], None
    pub = key.public.hex()
    for r in receipts:
        d, a = r.get("decision") or {}, r.get("action") or {}
        rec: dict[str, Any] = {"step_id": r["id"], "action_id": _name(r),
                               "params": {"verdict": d.get("verdict"), "rules": d.get("rules", []), "kind": a.get("kind"),
                                          "args_sha256": a.get("args_sha256"), "verfy_seq": r.get("seq")},
                               "success": (r.get("outcome") or {}).get("status") == "ok", "ts_ms": _ms(r["issued_at"]),
                               "actor": {"agent": str(r.get("agent", ""))}}
        if prev is not None:
            rec["prev_hash"] = prev
        rec["public_key"] = pub
        rec["signature"] = ed25519.sign(key.secret, aar_signed_bytes(rec)).hex()
        line = aar_line(rec)
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        lines.append(line)
    return lines


def verify_aar(lines: list[str], public_hex: str | None = None) -> dict:
    errors, prev = [], None
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            errors.append(f"line {i + 1}: not JSON")
            prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
            continue
        missing = [f for f in ("step_id", "action_id", "params", "success", "ts_ms", "public_key", "signature") if f not in rec]
        if missing:
            errors.append(f"line {i + 1}: missing {', '.join(missing)}")
        else:
            pk, sig = str(rec["public_key"]), str(rec["signature"])
            hexok = len(pk) == 64 and len(sig) == 128 and all(c in "0123456789abcdef" for c in pk + sig)
            if not hexok:
                errors.append(f"line {i + 1}: public_key or signature is not lowercase hex of the right length")
            elif not ed25519.verify(bytes.fromhex(pk), aar_signed_bytes(rec), bytes.fromhex(sig)):
                errors.append(f"line {i + 1}: bad signature")
            if public_hex and pk != public_hex:
                errors.append(f"line {i + 1}: signed by another key")
            if (i == 0 and "prev_hash" in rec) or (i > 0 and rec.get("prev_hash") != prev):
                errors.append(f"line {i + 1}: prev_hash does not match the line before it")
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return {"ok": not errors, "count": len(lines), "errors": errors, "draft": AAR_DRAFT}
