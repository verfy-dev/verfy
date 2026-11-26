"""Show one part of a receipt and keep the rest hidden: ``verfy disclose``.

With ``"receipts": {"field_hashes": true}`` in the policy (or ``Recorder(field_hashes=True)``), a receipt carries one
salted hash per argument (``action.args_fields``), next to the hash of all arguments. Each argument has its own salt,
derived from the key's secret salt, the receipt id and the argument's name. A disclosure hands over the signed
receipt (which holds only hashes) plus the value and salt of the arguments you choose; the reader checks the
signature and recomputes those hashes. The other arguments stay hidden: without their salts their hashes cannot be
guessed, even for short values.
"""

from __future__ import annotations

from typing import Any

from .receipts import b64u, field_digest, field_salt, unb64u, verify_receipt

VERSION = "verfy.disclosure/1"


class DisclosureError(ValueError):
    pass


def disclose(receipt: dict, args: dict, show: list[str], salt: bytes) -> dict:
    fields = (receipt.get("action") or {}).get("args_fields")
    if not isinstance(fields, dict):
        raise DisclosureError("this receipt has no per-argument hashes; turn on receipts.field_hashes for new receipts")
    out: dict[str, Any] = {}
    for name in show:
        if name not in fields:
            raise DisclosureError(f"the receipt has no hash for the argument {name!r} (it has: {', '.join(sorted(fields))})")
        if name not in args:
            raise DisclosureError(f"the arguments given do not include {name!r}")
        fs = field_salt(salt, receipt["id"], name)
        if field_digest(fs, name, args[name]) != fields[name]:
            raise DisclosureError(f"the value given for {name!r} is not the one this receipt recorded")
        out[name] = {"value": args[name], "salt": b64u(fs)}
    return {"v": VERSION, "receipt": receipt, "show": out}


def verify_disclosure(doc: dict, public: bytes) -> dict:
    problems = []
    if not isinstance(doc, dict) or doc.get("v") != VERSION:
        return {"ok": False, "problems": ["not a Verfy disclosure"], "shown": {}}
    r = doc.get("receipt")
    if not verify_receipt(r, public):
        problems.append("the receipt's signature does not check out with this key")
    fields = ((r or {}).get("action") or {}).get("args_fields") or {}
    shown = {}
    for name, item in (doc.get("show") or {}).items():
        try:
            ok = field_digest(unb64u(item["salt"]), name, item["value"]) == fields.get(name)
        except (KeyError, TypeError, ValueError):
            ok = False
        if ok:
            shown[name] = item["value"]
        else:
            problems.append(f"{name}: the value does not match the receipt's hash")
    hidden = sorted(set(fields) - set(shown))
    return {"ok": not problems, "problems": problems, "shown": shown, "hidden": hidden,
            "receipt": {k: (r or {}).get(k) for k in ("id", "seq", "issued_at", "agent")} | {"tool": ((r or {}).get("action") or {}).get("tool"),
                                                                                           "verdict": ((r or {}).get("decision") or {}).get("verdict")}}
