"""Check a payment against the mandate a person gave for it: AP2 mandates and x402 payment requirements.

An agent that pays should pay only what the person agreed to. ``check`` compares the payment (amount, currency,
payee) with:

* an AP2 IntentMandate (``intent_expiry``, ``merchants``, ``user_cart_confirmation_required``),
* an AP2 CartMandate (``contents.payment_request.details.total.amount``, ``contents.merchant_name``, ``contents.cart_expiry``),
* an AP2 PaymentMandate (``payment_mandate_contents.payment_details_total.amount``, ``merchant_agent``),
* x402 PaymentRequirements (``maxAmountRequired`` in the asset's smallest unit, ``payTo``, ``asset``).

It checks the fields; with the signer's public key (``--key``), ``check_authorization`` also checks the signature
inside an AP2 cart or payment mandate (the merchant's or the user's JWT). The x402 payment signature (EIP-712 on
secp256k1) and on-chain settlement are left to the payment network. ``Recorder.record_payment(..., mandate=...)`` then ties the
receipt to the mandate by its hash.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any


def _dec(v: Any) -> Decimal | None:
    if isinstance(v, bool):
        return None
    try:
        return Decimal(str(v))
    except (InvalidOperation, ValueError):
        return None


def _f(rule: str, verdict: str, message: str) -> dict:
    return {"rule": rule, "verdict": verdict, "message": message}


def kind_of(m: dict) -> str:
    if "maxAmountRequired" in m and "payTo" in m:
        return "x402"
    if "payment_mandate_contents" in m:
        return "ap2-payment"
    if "contents" in m and isinstance(m.get("contents"), dict) and "payment_request" in m["contents"]:
        return "ap2-cart"
    if "intent_expiry" in m or "natural_language_description" in m:
        return "ap2-intent"
    return "unknown"


def _expired(value: Any, now: datetime, what: str) -> dict | None:
    if not value:
        return None
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return _f("VFY-MDT-004", "deny", f"The {what} has an expiry Verfy cannot read ({value}).")
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return _f("VFY-MDT-004", "deny", f"The {what} expired at {value}.") if now > t else None


def check(mandate: Any, *, amount: Any, currency: str | None = None, payee: str | None = None, now: datetime | None = None) -> dict:
    """``{"kind", "verdict", "findings"}`` for paying ``amount`` (in the mandate's units: the currency's for AP2,
    the asset's smallest unit for x402) to ``payee``."""
    now = now or datetime.now(timezone.utc)
    out: list[dict] = []
    if not isinstance(mandate, dict):
        return {"kind": "unknown", "verdict": "deny", "findings": [_f("VFY-MDT-000", "deny", "The mandate is not a JSON object.")]}
    kind = kind_of(mandate)
    amt = _dec(amount)
    if amt is None or amt < 0:
        out.append(_f("VFY-MDT-001", "deny", "The payment amount is not a number of at least 0."))
    limit: Decimal | None = None
    cur: str | None = None
    who: list[str] = []
    if kind == "x402":
        limit = _dec(mandate.get("maxAmountRequired"))
        who = [str(mandate.get("payTo"))]
        cur = str(mandate.get("asset")) if mandate.get("asset") else None
    elif kind == "ap2-cart":
        c = mandate["contents"]
        total = (((c.get("payment_request") or {}).get("details") or {}).get("total") or {}).get("amount") or {}
        limit, cur = _dec(total.get("value")), total.get("currency")
        who = [c["merchant_name"]] if c.get("merchant_name") else []
        e = _expired(c.get("cart_expiry"), now, "cart mandate")
        out += [e] if e else []
    elif kind == "ap2-payment":
        c = mandate["payment_mandate_contents"]
        total = (c.get("payment_details_total") or {}).get("amount") or {}
        limit, cur = _dec(total.get("value")), total.get("currency")
        who = [c["merchant_agent"]] if c.get("merchant_agent") else []
    elif kind == "ap2-intent":
        who = [str(x) for x in mandate.get("merchants") or []]
        e = _expired(mandate.get("intent_expiry"), now, "intent mandate")
        out += [e] if e else []
        if mandate.get("user_cart_confirmation_required", True):
            out.append(_f("VFY-MDT-005", "ask", "The intent mandate asks the person to confirm the cart before paying."))
    else:
        out.append(_f("VFY-MDT-000", "deny", "Verfy does not know this kind of mandate (AP2 intent, cart or payment mandate, or x402 payment requirements)."))
    if amt is not None and limit is not None and amt > limit:
        out.append(_f("VFY-MDT-001", "deny", f"The payment of {amt} is more than the mandate allows ({limit})."))
    if kind in ("ap2-cart", "ap2-payment", "x402") and limit is None:
        out.append(_f("VFY-MDT-001", "deny", "The mandate has no amount Verfy can read."))
    if currency and cur and currency.upper() != str(cur).upper():
        out.append(_f("VFY-MDT-002", "deny", f"The payment is in {currency.upper()}, the mandate in {str(cur).upper()}."))
    if payee is not None and who and payee not in who:
        out.append(_f("VFY-MDT-003", "deny", f"`{payee}` is not the payee the mandate names ({', '.join(who)})."))
    out.sort(key=lambda f: {"deny": 0, "ask": 1}[f["verdict"]])
    return {"kind": kind, "verdict": out[0]["verdict"] if out else "allow", "findings": out}


# ---------------------------------------------------------------- signatures inside AP2 mandates

def _b64u(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_to_der(sig: bytes) -> bytes:
    """A JWS ES256 signature (r || s, 32 bytes each) as the DER form passkeys.verify_es256 reads."""
    def part(b: bytes) -> bytes:
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = part(sig[:32]) + part(sig[32:])
    return b"\x30" + bytes([len(body)]) + body


def verify_jws(token: Any, jwk: dict, now: datetime | None = None) -> tuple[list[str], dict]:
    """Check a compact JWS (a merchant's or a user's authorization) with the signer's public JWK: the signature
    (ES256, EdDSA or RS256) and, when present, exp and nbf. Returns the problems and the payload."""
    import json as _json

    from . import passkeys
    if not isinstance(token, str):
        return ["the authorization is not a JWT"], {}
    jwt = token.split("~", 1)[0]  # an SD-JWT: the issuer-signed JWT comes first
    parts = jwt.split(".")
    if len(parts) != 3:
        return ["the authorization is not a compact JWT"], {}
    try:
        header = _json.loads(_b64u(parts[0]))
        payload = _json.loads(_b64u(parts[1]))
        sig = _b64u(parts[2])
    except ValueError:
        return ["the authorization cannot be read"], {}
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return ["the authorization cannot be read"], {}
    signed = (parts[0] + "." + parts[1]).encode()
    alg = header.get("alg")
    if alg == "ES256":
        ok = len(sig) == 64 and passkeys.verify_es256(jwk, signed, _raw_to_der(sig))
    elif alg in ("EdDSA", "Ed25519"):
        ok = passkeys.verify_eddsa(jwk, signed, sig)
    elif alg == "RS256":
        ok = passkeys.verify_rs256(jwk, signed, sig)
    else:
        return [f"the authorization uses {alg!r}; Verfy checks ES256, EdDSA and RS256"], payload
    problems = [] if ok else ["the signature does not check out with the key given"]
    t = (now or datetime.now(timezone.utc)).timestamp()
    if isinstance(payload.get("exp"), (int, float)) and t > payload["exp"]:
        problems.append("the authorization has expired")
    if isinstance(payload.get("nbf"), (int, float)) and t < payload["nbf"]:
        problems.append("the authorization is not valid yet")
    return problems, payload


def check_authorization(m: Any, jwk: dict, now: datetime | None = None) -> list[dict]:
    """VFY-MDT-006: the signature inside an AP2 mandate, checked with the signer's key: a CartMandate's
    ``merchant_authorization`` (the merchant) or a PaymentMandate's ``user_authorization`` (the person)."""
    if not isinstance(m, dict):
        return [_f("VFY-MDT-006", "deny", "The mandate is not a JSON object.")]
    kind = kind_of(m)
    field = {"ap2-cart": "merchant_authorization", "ap2-payment": "user_authorization"}.get(kind)
    if field is None:
        return [_f("VFY-MDT-006", "ask", f"A {kind} mandate carries no signature Verfy checks.")]
    if not m.get(field):
        return [_f("VFY-MDT-006", "deny", f"The mandate has no {field}.")]
    problems, _ = verify_jws(m[field], jwk, now)
    return [_f("VFY-MDT-006", "deny", f"{field}: {p}.") for p in problems]
