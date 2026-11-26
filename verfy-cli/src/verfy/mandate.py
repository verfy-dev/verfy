"""Check a payment against the mandate a person gave for it: AP2 mandates and x402 payment requirements.

An agent that pays should pay only what the person agreed to. ``check`` compares the payment (amount, currency,
payee) with:

* an AP2 IntentMandate (``intent_expiry``, ``merchants``, ``user_cart_confirmation_required``),
* an AP2 CartMandate (``contents.payment_request.details.total.amount``, ``contents.merchant_name``, ``contents.cart_expiry``),
* an AP2 PaymentMandate (``payment_mandate_contents.payment_details_total.amount``, ``merchant_agent``),
* x402 PaymentRequirements (``maxAmountRequired`` in the asset's smallest unit, ``payTo``, ``asset``).

It checks the fields, not the signatures inside them (a merchant's JWT, a user's authorization, an on-chain
settlement): those belong to the payment network. ``Recorder.record_payment(..., mandate=...)`` then ties the
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
