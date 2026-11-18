"""Incident packs (``verfy.incident/1``): the evidence for one stretch of an agent's work, in one file.

When something went wrong (a refund that should not have happened, a deleted table) the people looking into it need
what the agent did, in order, with nothing left out, in a form they can check without trusting whoever hands it over.
A pack holds:

- every receipt in the time window, as one unbroken run of the chain (seq n to m, each naming the one before), so a
  receipt cannot be left out of the middle without the gap showing;
- the device's public key, so each signature can be checked;
- the hash of the receipt that came after the window, when there is one, showing the chain went on;
- optionally (``prove=True``) Verfy's transparency-log proof for each receipt: signed by Verfy, it shows the receipt
  was in Verfy's public log no later than the time of that signed head, so it was not written after the fact.

``verify_pack`` checks all of it offline (log proofs against the witness keys given). The arguments of each action
are in a pack only if they were in the receipts (``include_args``); otherwise only their hashes.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

from .receipts import b64u, public_from, read_ledger, receipt_hash, verify_ledger, verify_receipt

VERSION = "verfy.incident/1"
MAX_RECEIPTS = 100_000


class IncidentError(ValueError):
    pass


def _time(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    try:
        t = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IncidentError(f"{name} is not an ISO 8601 time, such as 2026-11-16T09:00:00Z") from None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return t.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _issued(r: dict) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(r.get("issued_at", "")).replace("Z", "+00:00"))


def build_pack(ledger_path: str | Path, public: bytes, *, since: str | None = None, until: str | None = None,
               agent: str | None = None, note: str | None = None, log: Any = None, attest: Any = None) -> dict:
    """The pack for the receipts issued between ``since`` and ``until`` (either open), as one unbroken run of the
    chain. With ``agent``, the run spans that agent's first to last receipt in the window (other agents' receipts in
    between stay in, so nothing is cut out of the chain). With ``log`` (a ``verfy.tlog.Log``), each receipt's
    inclusion proof is added; a receipt Verfy does not hold yet is listed under ``not_in_log``. With ``attest`` (a
    function taking the receipt hashes in order, such as ``verfy.team.attest_incident`` bound to a home), Verfy
    Cloud's signed statement about them is added as ``attestation``."""
    since_s, until_s = _time(since, "since"), _time(until, "until")
    lo = _dt.datetime.fromisoformat(since_s.replace("Z", "+00:00")) if since_s else None
    hi = _dt.datetime.fromisoformat(until_s.replace("Z", "+00:00")) if until_s else None
    if lo and hi and lo > hi:
        raise IncidentError("since is after until")
    receipts = read_ledger(ledger_path)
    if not receipts:
        raise IncidentError("the ledger is empty")
    whole = verify_ledger(receipts, public)
    if not whole.get("ok"):
        first_bad = (whole.get("errors") or [{}])[0]
        raise IncidentError(f"the ledger does not verify ({first_bad.get('error')} at seq {first_bad.get('seq')}), so it cannot be packed; "
                            "run verfy ledger verify")
    picked = [i for i, r in enumerate(receipts)
              if (lo is None or _issued(r) >= lo) and (hi is None or _issued(r) <= hi) and (agent is None or r.get("agent") == agent)]
    if not picked:
        raise IncidentError("no receipts in that window")
    first, last = picked[0], picked[-1]
    run = receipts[first:last + 1]
    if len(run) > MAX_RECEIPTS:
        raise IncidentError(f"the window holds {len(run)} receipts; make it narrower (at most {MAX_RECEIPTS})")
    pack: dict[str, Any] = {
        "v": VERSION,
        "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "window": {"since": since_s, "until": until_s, "agent": agent},
        "public_key": b64u(public),
        "kid": run[0].get("kid"),
        "receipts": run,
        "next": receipt_hash(receipts[last + 1]) if last + 1 < len(receipts) else None,
        "ledger_length": len(receipts),
    }
    if note:
        pack["note"] = str(note)[:2000]
    if log is not None:
        proofs, missing = [], []
        for r in run:
            h = receipt_hash(r)
            try:
                proofs.append(log.prove(h)["proof"])
            except Exception as e:  # noqa: BLE001 - one receipt not yet uploaded must not lose the others' proofs
                missing.append({"hash": h, "reason": str(e)[:300]})
        pack["log"] = {"url": log.url, "proofs": proofs, "not_in_log": missing}
    if attest is not None:
        res = attest([receipt_hash(r) for r in run])
        pack["attestation"] = res.get("attestation") if isinstance(res, dict) and "attestation" in res else res
    return pack


def check_attestation(statement: Any, run: list[dict], keys: dict[str, bytes]) -> dict:
    """Check Verfy Cloud's attestation of a pack: its signature, and that it covers exactly these receipts in this
    order (the Merkle root of their hashes). Returns its ``receipts`` facts: count, known, in_log, first and last
    received_at. Raises IncidentError."""
    from . import merkle, witness
    if not isinstance(statement, dict) or statement.get("type") != "incident":
        raise IncidentError("the attestation is not a Verfy incident statement")
    key = keys.get(statement.get("kid"))  # type: ignore[arg-type]
    if key is None or not witness.verify_statement(statement, key):
        raise IncidentError("the attestation is not signed by one of Verfy's witness keys")
    facts = (statement.get("subject") or {}).get("receipts") if isinstance(statement.get("subject"), dict) else None
    if not isinstance(facts, dict):
        raise IncidentError("the attestation names no receipts")
    root = merkle.tree_root([merkle.receipt_hash_bytes(receipt_hash(r)) for r in run]).hex()
    if facts.get("count") != len(run) or facts.get("merkle_root") != root:
        raise IncidentError("the attestation is for a different list of receipts")
    return facts


def verify_pack(pack: Any, keys: dict[str, bytes] | None = None) -> dict:
    """Check a pack offline. ``keys`` are the witness keys for its log proofs (without them those are not checked).
    Returns ``{"ok", "errors", "receipts", "first_seq", "last_seq", "in_log", "log_checked", "earliest_head",
    "attested"}``; ``attested`` is Verfy Cloud's checked facts about the receipts, or None."""
    from . import tlog
    errors: list[str] = []
    out: dict[str, Any] = {"ok": False, "errors": errors, "receipts": 0, "first_seq": None, "last_seq": None,
                           "in_log": 0, "log_checked": False, "earliest_head": None, "attested": None}
    if not isinstance(pack, dict) or pack.get("v") != VERSION:
        errors.append("not a verfy.incident/1 pack")
        return out
    run = pack.get("receipts")
    if not isinstance(run, list) or not run or not all(isinstance(r, dict) for r in run):
        errors.append("the pack holds no receipts")
        return out
    try:
        public = public_from(pack.get("public_key", ""))
    except Exception:  # noqa: BLE001
        errors.append("the pack's public key is not a key")
        return out
    out.update(receipts=len(run), first_seq=run[0].get("seq"), last_seq=run[-1].get("seq"))
    bad = [r.get("seq") for r in run if not verify_receipt(r, public)]
    if bad:
        errors.append(f"{len(bad)} receipt(s) do not check with the pack's key (seq {', '.join(map(str, bad[:5]))})")
    chain = verify_ledger(run, public, start_prev=run[0].get("prev"), start_seq=run[0].get("seq", 0))
    if not chain.get("ok"):
        problems = [f"{e.get('error')} (seq {e.get('seq')})" for e in chain.get("errors", []) if isinstance(e, dict)]
        errors.append("the receipts are not one unbroken run of the chain: " + "; ".join(problems[:5]))
    log = pack.get("log")
    if isinstance(log, dict) and keys:
        hashes = {receipt_hash(r) for r in run}
        heads: list[str] = []
        for doc in log.get("proofs") or []:
            try:
                res = tlog.check_inclusion(doc, keys)
            except tlog.LogError as e:
                errors.append(f"a log proof does not check: {e}")
                continue
            if res["hash"] not in hashes:
                errors.append("a log proof is for a receipt that is not in the pack")
                continue
            out["in_log"] += 1
            if isinstance(res["head"].get("issued_at"), str):
                heads.append(res["head"]["issued_at"])
        out["log_checked"] = True
        out["earliest_head"] = min(heads) if heads else None
    if "attestation" in pack and keys:
        try:
            out["attested"] = check_attestation(pack["attestation"], run, keys)
        except IncidentError as e:
            errors.append(str(e))
    out["ok"] = not errors
    return out
