"""Verfy Cloud's witness statements (format ``verfy.witness/1``) and how to check them offline.

A receipt is signed by the device that wrote it, so it shows who wrote it and that nobody changed it, but its time is
the device's own clock. When Verfy Cloud receives a receipt it keeps the time it arrived, and on a share link or the
verification API it signs a statement about it with its own Ed25519 key: this receipt, with this hash, from this
chain, first reached Verfy at this time, and the chain had this many receipts when the statement was made. An agent
statement does the same for a whole chain: how many receipts, of which kinds and outcomes, from when to when.

The statement is canonical JSON signed like a receipt (every field except ``sig``). The key is published at
https://verfy.dev/.well-known/verfy-witness.json; its id is ``vw_`` and the first 16 hex characters of its SHA-256.

    statement = proof["witness"]
    ok = verify_statement(statement, public_key_bytes)
    report = check_proof(proof, {"vw_...": public_key_bytes})
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from . import ed25519
from .canonical import canonical_bytes, sha256_hex
from .receipts import public_from, receipt_hash, unb64u, verify_receipt

VERSION = "verfy.witness/1"
DEFAULT_KEY_URL = "https://verfy.dev/.well-known/verfy-witness.json"
TIMEOUT = 15.0


def witness_kid(public: bytes) -> str:
    return "vw_" + sha256_hex(public)[:16]


def verify_statement(statement: Any, public: bytes) -> bool:
    """True when ``statement`` is a ``verfy.witness/1`` statement signed by ``public``."""
    if not isinstance(statement, dict) or statement.get("v") != VERSION or not isinstance(statement.get("sig"), str):
        return False
    if statement.get("kid") != witness_kid(public):
        return False
    try:
        sig = unb64u(statement["sig"])
    except Exception:  # noqa: BLE001
        return False
    if len(sig) != 64:
        return False
    body = {k: v for k, v in statement.items() if k != "sig"}
    try:
        return ed25519.verify(public, canonical_bytes(body), sig)
    except Exception:  # noqa: BLE001
        return False


def fetch_keys(url: str = DEFAULT_KEY_URL) -> dict[str, bytes]:
    """The witness keys published at ``url`` (HTTPS only): ``{kid: public key bytes}``."""
    u = urlparse(url)
    if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("the witness key URL must use https")
    import urllib.request
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "verfy-cli"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - scheme checked above
        data = json.loads(resp.read(256 * 1024) or b"null")
    return keys_from(data)


def keys_from(data: Any) -> dict[str, bytes]:
    """Read ``{"keys": [{"kid", "public", "alg": "Ed25519"}]}``; a key whose id does not match its bytes is skipped."""
    out: dict[str, bytes] = {}
    for k in (data or {}).get("keys", []) if isinstance(data, dict) else []:
        if not isinstance(k, dict) or k.get("alg", "Ed25519") != "Ed25519" or not isinstance(k.get("public"), str):
            continue
        try:
            raw = unb64u(k["public"])
        except Exception:  # noqa: BLE001
            continue
        if len(raw) == 32 and k.get("kid") == witness_kid(raw):
            out[k["kid"]] = raw
    return out


def check_proof(doc: Any, keys: dict[str, bytes]) -> dict:
    """Check what a share link or the verification API returned (or a bare statement).

    Returns ``{"ok", "kind", "witness", "receipt", "errors", "statement"}``: ``witness`` is True when the statement is
    signed by one of ``keys``; ``receipt`` is True when the document also carries the receipt, it is the one the
    statement names, and its own signature checks with the device key the statement names (None when there is no
    receipt to check)."""
    errors: list[str] = []
    statement = doc.get("witness") if isinstance(doc, dict) and "witness" in doc else doc
    out: dict[str, Any] = {"ok": False, "kind": None, "witness": False, "receipt": None, "errors": errors, "statement": statement}
    if not isinstance(statement, dict):
        errors.append("there is no witness statement in this file (Verfy Cloud may not have a witness key set up)")
        return out
    out["kind"] = statement.get("type")
    public = keys.get(statement.get("kid", ""))
    if public is None:
        errors.append(f"the statement is signed by {statement.get('kid')!r}, which is not one of the witness keys given")
    elif not verify_statement(statement, public):
        errors.append("the witness signature does not verify: the statement was changed or not signed by Verfy")
    else:
        out["witness"] = True
    receipt = doc.get("receipt") if isinstance(doc, dict) else None
    subject = statement.get("subject") if isinstance(statement.get("subject"), dict) else {}
    if receipt is not None:
        named = (subject.get("receipt") or {}).get("hash")
        device = (subject.get("chain") or {}).get("public_key")
        if not isinstance(receipt, dict):
            errors.append("the receipt in this file is not a JSON object")
            out["receipt"] = False
        elif receipt_hash(receipt) != named:
            errors.append("the receipt in this file is not the one the statement names (its hash differs)")
            out["receipt"] = False
        elif not isinstance(device, str):
            errors.append("the statement does not name the device key")
            out["receipt"] = False
        else:
            try:
                ok = verify_receipt(receipt, public_from(device))
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                errors.append("the receipt's own signature does not verify with the device key the statement names")
            out["receipt"] = ok
    out["ok"] = out["witness"] and out["receipt"] is not False
    return out
