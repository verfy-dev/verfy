"""Check a passkey approval offline: the proof Verfy Cloud keeps when an owner or admin approves a call with a passkey
(Face ID, a fingerprint, a security key), as the gateway writes it into the call's receipt (``decision.approval``).

A proof is a WebAuthn assertion. The passkey signed ``authenticatorData || SHA-256(clientDataJSON)``, and
clientDataJSON carries the challenge Verfy Cloud asked for:

    base64url(SHA-256("verfy-approval/1\\n{approval id}\\n{args_sha256}\\n{approve|reject}\\n{user id}"))

so the signature covers this one request, the hash of its arguments (the same ``action.args_sha256`` the receipt
holds) and the decision. Checked here: the challenge, the origin and relying party, that the person was verified (the
UV flag) and the signature, for ES256 (P-256), EdDSA (Ed25519) and RS256 keys, with no dependency.

What it does not show: that the public key belongs to a given person. Verfy Cloud registered it to the account named by
``user_id``; the receipt, signed by the device that asked, carries it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from . import ed25519

PROOF_VERSION = "verfy.approval-proof/1"
ALGS = {-7: "ES256", -8: "EdDSA", -257: "RS256"}
MAX_PROOFS = 2
_FIELD_MAX = {"client_data_json": 2048, "authenticator_data": 1024, "signature": 1024, "credential_id": 1400}


class ProofError(ValueError):
    pass


def _b64u(s: Any) -> bytes:
    if not isinstance(s, str) or not s or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in s):
        raise ProofError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def approval_challenge(approval_id: str, args_sha256: str, approve: bool, user_id: str) -> str:
    text = f"verfy-approval/1\n{approval_id}\n{args_sha256}\n{'approve' if approve else 'reject'}\n{user_id}"
    return b64u(hashlib.sha256(text.encode()).digest())


# ---------------------------------------------------------------- P-256 (ES256), verification only

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _on_curve(pt: tuple[int, int]) -> bool:
    x, y = pt
    return 0 <= x < _P and 0 <= y < _P and (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def _der_ints(sig: bytes) -> tuple[int, int]:
    """r and s from an ASN.1 DER ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }, short lengths only."""
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ProofError("the ES256 signature is not DER")
    out, i = [], 2
    for _ in range(2):
        if i + 2 > len(sig) or sig[i] != 0x02:
            raise ProofError("the ES256 signature is not DER")
        n = sig[i + 1]
        if n == 0 or n > 33 or i + 2 + n > len(sig):
            raise ProofError("the ES256 signature is not DER")
        out.append(int.from_bytes(sig[i + 2:i + 2 + n], "big"))
        i += 2 + n
    if i != len(sig):
        raise ProofError("the ES256 signature has trailing bytes")
    return out[0], out[1]


def verify_es256(jwk: dict, msg: bytes, sig: bytes) -> bool:
    try:
        q = (int.from_bytes(_b64u(jwk["x"]), "big"), int.from_bytes(_b64u(jwk["y"]), "big"))
        r, s = _der_ints(sig)
    except (KeyError, TypeError, ProofError):
        return False
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not _on_curve(q) or not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(e * w % _N, _G), _mul(r * w % _N, q))
    return pt is not None and pt[0] % _N == r


# ---------------------------------------------------------------- RS256 (PKCS #1 v1.5 with SHA-256)

_SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def verify_rs256(jwk: dict, msg: bytes, sig: bytes) -> bool:
    try:
        n = int.from_bytes(_b64u(jwk["n"]), "big")
        e = int.from_bytes(_b64u(jwk["e"]), "big")
    except (KeyError, TypeError, ProofError):
        return False
    k = (n.bit_length() + 7) // 8
    if jwk.get("kty") != "RSA" or n.bit_length() < 2048 or e < 3 or len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    t = _SHA256_INFO + hashlib.sha256(msg).digest()
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t
    return pow(s, e, n).to_bytes(k, "big") == want


def verify_eddsa(jwk: dict, msg: bytes, sig: bytes) -> bool:
    try:
        pub = _b64u(jwk["x"])
    except (KeyError, TypeError, ProofError):
        return False
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or len(pub) != 32 or len(sig) != 64:
        return False
    try:
        return ed25519.verify(pub, msg, sig)
    except Exception:  # noqa: BLE001 (a malformed key is a failed check)
        return False


# ---------------------------------------------------------------- one proof

def verify_proof(proof: Any, *, approval_id: str, args_sha256: str, origin: str) -> list[str]:
    """Problems with one proof; an empty list means the passkey signed this approval of these arguments."""
    if not isinstance(proof, dict) or proof.get("v") != PROOF_VERSION or proof.get("method") != "passkey":
        return ["not a Verfy passkey proof"]
    problems: list[str] = []
    decision = proof.get("decision")
    if decision not in ("approve", "reject"):
        return ["the proof names no decision"]
    try:
        client_raw = _b64u(proof.get("client_data_json"))
        auth = _b64u(proof.get("authenticator_data"))
        sig = _b64u(proof.get("signature"))
        client = json.loads(client_raw)
    except (ProofError, ValueError):
        return ["the proof is not readable"]
    want = approval_challenge(approval_id, args_sha256, decision == "approve", str(proof.get("user_id", "")))
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        problems.append("the browser answered a different WebAuthn call")
    elif client.get("challenge") != want:
        problems.append("the passkey signed a different request, arguments or decision")
    if isinstance(client, dict) and client.get("origin") != origin:
        problems.append(f"the passkey was used on {client.get('origin')!r}, not {origin!r}")
    if isinstance(client, dict) and client.get("crossOrigin") is True:
        problems.append("the passkey was used inside another site's frame")
    rp = urlsplit(origin).hostname or ""
    if len(auth) < 37 or auth[:32] != hashlib.sha256(rp.encode()).digest():
        problems.append("the passkey belongs to another site")
    elif not auth[32] & 0x01:
        problems.append("nobody touched the passkey")
    elif not auth[32] & 0x04:
        problems.append("the passkey did not verify the person (Face ID, fingerprint or PIN)")
    jwk = proof.get("public_key") if isinstance(proof.get("public_key"), dict) else {}
    alg = proof.get("alg")
    signed = auth + hashlib.sha256(client_raw).digest()
    check = {-7: verify_es256, -8: verify_eddsa, -257: verify_rs256}.get(alg) if isinstance(alg, int) else None
    if check is None:
        problems.append(f"unknown key type {alg!r}")
    elif not check(jwk, signed, sig):
        problems.append("the passkey's signature does not check out")
    return problems


# ---------------------------------------------------------------- what the gateway writes, and checking a ledger

def approval_record(approval_id: str, state: dict, origin: str) -> dict:
    """``decision.approval`` for a receipt: the request's id, how many people it needed, and the passkey proofs Verfy
    Cloud returned (at most two, only the fields a check needs, each bounded)."""
    rec: dict[str, Any] = {"id": str(approval_id)[:64], "origin": str(origin)[:200]}
    if isinstance(state.get("required"), int) and state["required"] in (1, 2):
        rec["required"] = state["required"]
    proofs = []
    for p in state.get("proofs") or []:
        if not isinstance(p, dict) or p.get("method") != "passkey" or p.get("v") != PROOF_VERSION:
            continue
        item = {k: p.get(k) for k in ("v", "method", "decision", "user_id", "credential_id", "alg", "public_key",
                                       "client_data_json", "authenticator_data", "signature")}
        if not all(isinstance(item[k], str) and len(item[k]) <= _FIELD_MAX[k] for k in _FIELD_MAX) or not isinstance(item["public_key"], dict):
            continue
        if len(json.dumps(item["public_key"])) > 1024 or not isinstance(item["alg"], int):
            continue
        proofs.append(item)
        if len(proofs) == MAX_PROOFS:
            break
    if proofs:
        rec["proofs"] = proofs
    return rec


def check_ledger(receipts: list[dict]) -> dict:
    """Every passkey proof in a ledger, checked. ``checked`` counts receipts with at least one proof."""
    checked, errors = 0, []
    for i, r in enumerate(receipts):
        appr = ((r or {}).get("decision") or {}).get("approval") if isinstance(r, dict) else None
        if not isinstance(appr, dict) or not appr.get("proofs"):
            continue
        checked += 1
        args = ((r.get("action") or {}).get("args_sha256")) or ""
        for p in appr["proofs"]:
            for problem in verify_proof(p, approval_id=str(appr.get("id", "")), args_sha256=str(args), origin=str(appr.get("origin", ""))):
                errors.append({"index": i, "seq": r.get("seq"), "error": "passkey approval: " + problem})
    return {"checked": checked, "errors": errors}
