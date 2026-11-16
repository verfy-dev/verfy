"""Two-party records (``verfy.deal/1``) and payments tied to a mandate.

A deal is one action two agents agree on: a purchase, a booking, a hand-over. Each side signs it in its own ledger,
and the second receipt names the first, so neither side can later say the other agreed to something else::

    offer = seller.offer("sell", counterparty="buyer-bot", terms={"item": "sku-1", "price": 4999, "currency": "USD"})
    deal = buyer.accept(offer)                 # buyer checks the offer, signs its own receipt naming it
    verify_deal(deal)                          # anyone: both signatures, the terms, the link between them

The terms are never in a receipt. Each receipt carries ``terms_sha256``, the SHA-256 of the terms together with a
random deal id, so the hash says nothing to anyone who does not hold the deal document. These receipts store their
arguments, but only references: the deal id, hashes, the role and the other side's key id
(``REFERENCE_KEYS``), which ``verfy sync`` uploads without ``--allow-args``.

``Recorder.record_payment`` records a payment the same way: the amount, currency and payee only as a salted hash, and
the payment mandate it carried out (an agent payment mandate or a card network's signed intent, any JSON) as
``mandate_sha256``, so whoever holds the mandate can show this receipt carried it out.
"""

from __future__ import annotations

import secrets
from typing import Any

from .canonical import digest
from .receipts import public_from, receipt_hash, verify_receipt

VERSION = "verfy.deal/1"
#: argument names a receipt may store and still upload without --allow-args: identifiers and hashes, never values
REFERENCE_KEYS = frozenset({"deal", "terms_sha256", "role", "counterparty", "offer_receipt", "offer_kid",
                            "mandate_sha256", "mandate_type", "details_sha256"})


def is_reference(args: Any) -> bool:
    """True for stored arguments that hold only references (short strings under REFERENCE_KEYS)."""
    return (isinstance(args, dict) and bool(args) and set(args) <= REFERENCE_KEYS
            and all(isinstance(v, str) and len(v) <= 200 for v in args.values()))


def terms_hash(deal_id: str, terms: Any) -> str:
    return digest({"deal": deal_id, "terms": terms})


class DealError(ValueError):
    """A deal document that does not check out."""


def check_offer(offer: Any) -> dict:
    if not isinstance(offer, dict) or offer.get("v") != VERSION:
        raise DealError("not a verfy.deal/1 document")
    for k in ("deal", "terms", "offer", "offer_key"):
        if k not in offer:
            raise DealError(f"the deal has no {k}")
    a = offer["offer"]
    try:
        key = public_from(offer["offer_key"])
    except Exception:  # noqa: BLE001
        raise DealError("the offer key is not a public key") from None
    if not isinstance(a, dict) or not verify_receipt(a, key):
        raise DealError("the offer receipt's signature does not check with the offer key")
    args = (a.get("action") or {}).get("args")
    if not is_reference(args) or args.get("role") != "offer" or args.get("deal") != offer["deal"]:
        raise DealError("the offer receipt does not name this deal")
    if args.get("terms_sha256") != terms_hash(offer["deal"], offer["terms"]):
        raise DealError("the terms are not the ones the offer receipt was signed for")
    return a


def verify_deal(deal: Any) -> dict:
    """``{"ok", "errors", "deal", "offer_kid", "accept_kid"}``: both signatures, the terms, and that the accepting
    receipt names the offer receipt."""
    errors: list[str] = []
    out: dict[str, Any] = {"ok": False, "errors": errors, "deal": deal.get("deal") if isinstance(deal, dict) else None,
                           "offer_kid": None, "accept_kid": None}
    try:
        a = check_offer(deal)
        out["offer_kid"] = a.get("kid")
    except DealError as e:
        errors.append(str(e))
        return out
    b = deal.get("accept")
    if b is None:
        errors.append("nobody has accepted this offer yet")
        return out
    try:
        bkey = public_from(deal.get("accept_key", ""))
    except Exception:  # noqa: BLE001
        errors.append("the accepting key is not a public key")
        return out
    if not isinstance(b, dict) or not verify_receipt(b, bkey):
        errors.append("the accepting receipt's signature does not check with the accepting key")
        return out
    out["accept_kid"] = b.get("kid")
    args = (b.get("action") or {}).get("args")
    if not is_reference(args) or args.get("role") != "accept" or args.get("deal") != deal["deal"]:
        errors.append("the accepting receipt does not name this deal")
    elif args.get("terms_sha256") != terms_hash(deal["deal"], deal["terms"]):
        errors.append("the accepting receipt was signed for other terms")
    elif args.get("offer_receipt") != receipt_hash(a) or args.get("offer_kid") != a.get("kid"):
        errors.append("the accepting receipt names a different offer")
    if b.get("kid") == a.get("kid"):
        errors.append("both sides signed with the same key")
    out["ok"] = not errors
    return out


def new_deal_id() -> str:
    return "deal_" + secrets.token_hex(12)
