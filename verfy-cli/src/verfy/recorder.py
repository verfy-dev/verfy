"""Signed receipts for anything an agent or a program does: ``verfy.record()`` and ``verfy.Recorder``.

The hook and the gateway write a receipt for every tool call a coding agent makes. This module lets any program write
the same kind of receipt for any action it takes: a refund, an email sent, a row deleted, a deploy. Each record is a
``verfy.receipt/1`` receipt, signed with this machine's key and chained to the receipt before it in the same ledger,
so ``verfy ledger verify``, the check on verfy.dev/verify and Verfy Cloud check it like every other receipt.

    import verfy

    rec = verfy.Recorder(agent="refund-bot")
    rec.record("refund", system="stripe", kind="payment", args={"order": "A-1042", "amount": 4999})

    @rec.track("send_email", system="gmail", kind="message")
    def send(to, subject, body): ...

    with rec.action("delete_rows", system="postgres", kind="delete", args={"table": "carts"}) as act:
        act.result = db.execute(...)

What a record proves: the holder of this key wrote this record at this point in its ledger, and nothing in the ledger
was changed afterwards. It does not prove that the action happened as described: the program that records it says
so. Once the record is in Verfy Cloud, the cloud's signed witness statement adds when Verfy first saw it.

How a record fills the receipt:

    action.server        the system acted on ("stripe", "gmail", "postgres"; may be empty)
    action.tool          the action ("refund", "send_email")
    action.kind          one word for the kind of action ("payment", "message", "delete", ...)
    action.args_sha256   salted hash of the arguments; the arguments themselves only with include_args
    decision             verdict "allow", no rules, policy_sha256 "none": no Verfy policy decided this action
    outcome              "ok" or "error", and the salted hash of the result

Everything a record would carry is checked before anything is written, against the limits Verfy Cloud applies, so a
record never stops a later upload.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import decimal
import enum
import functools
import hashlib
import inspect
import json
import logging
import math
import numbers
import os
import re
import secrets
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, TypeVar

from . import team as teamlib
from .fileio import FileLock
from .receipts import Key, Ledger, read_ledger, receipt_hash, verify_ledger

log = logging.getLogger("verfy")

#: ``decision.policy_sha256`` of a record: no Verfy policy decided it.
RECORD_POLICY = "none"
#: kinds Verfy suggests; any lowercase word up to 40 characters is accepted
KINDS = ("payment", "message", "write", "delete", "read", "exec", "network", "deploy", "access", "data", "other")
STATUSES = ("ok", "error")
UPLOAD_MODES = ("auto", "now", "off")

TEXT_MAX = 200  # agent, session, system and action, in UTF-16 code units, the way Verfy Cloud counts them
APPROVER_MAX = 100
RECEIPT_MAX_BYTES = 12 * 1024  # Verfy Cloud refuses receipts over 16 KB; the rest is headroom
ARGS_NODES_MAX = 1000  # stored arguments: keeps the database's copy of a receipt under its 32 KB limit
DEPTH_MAX = 64
SAFE_INT = 2**53 - 1  # larger integers lose digits in JavaScript, which checks signatures in Verfy Cloud

_KIND = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
F = TypeVar("F", bound=Callable[..., Any])


class RecordError(ValueError):
    """A record was refused before anything was written."""


# ---------------------------------------------------------------- values

def jsonable(value: Any, *, strict: bool = True, _depth: int = 0) -> Any:
    """The JSON data a value is recorded (and hashed) as.

    dict, list, tuple, str, int, float, bool and None stay as they are. Decimal becomes its exact text ("49.99"), dates
    and times their ISO text, UUIDs and paths their text, an Enum its value, a set a sorted list, a dataclass or a
    pydantic model its fields, bytes ``{"$bytes": length, "sha256": ...}`` (never the bytes themselves). Integers
    outside JavaScript's safe range become text, and NaN and the infinities the text "NaN", "Infinity", "-Infinity",
    so every engine signs the same bytes.

    Anything else raises ``TypeError`` when ``strict``, and is recorded as ``{"$type": "module.Class"}`` otherwise."""
    if _depth > DEPTH_MAX:
        if strict:
            raise RecordError(f"the value is nested more than {DEPTH_MAX} levels deep")
        return {"$truncated": True}
    d = _depth + 1
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if -SAFE_INT <= value <= SAFE_INT else str(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, enum.Enum):
        return jsonable(value.value, strict=strict, _depth=d)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, _dt.timedelta):
        return value.total_seconds()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, os.PathLike):
        return os.fspath(value) if isinstance(os.fspath(value), str) else repr(os.fspath(value))
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"$bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if isinstance(value, dict):
        return {k if isinstance(k, str) else str(jsonable(k, strict=False, _depth=d)): jsonable(v, strict=strict, _depth=d)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v, strict=strict, _depth=d) for v in value]
    if isinstance(value, (set, frozenset)):
        from .canonical import canonical
        return sorted((jsonable(v, strict=strict, _depth=d) for v in value), key=canonical)
    if isinstance(value, numbers.Integral):
        return jsonable(int(value), strict=strict, _depth=d)
    if isinstance(value, numbers.Real):
        return jsonable(float(value), strict=strict, _depth=d)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return jsonable({f.name: getattr(value, f.name) for f in dataclasses.fields(value)}, strict=strict, _depth=d)
    dump = getattr(value, "model_dump", None)
    if callable(dump) and not isinstance(value, type):
        try:
            return jsonable(dump(), strict=strict, _depth=d)
        except Exception:  # noqa: BLE001 (a model that cannot dump itself falls through)
            pass
    if strict:
        raise RecordError(f"cannot record a value of type {type(value).__name__}: pass JSON-like data "
                          "(dict, list, str, int, float, bool, None, Decimal, datetime, UUID)")
    return {"$type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _text(name: str, value: Any, *, required: bool = False, limit: int = TEXT_MAX) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise RecordError(f"{name} must be text, not {type(value).__name__}")
    if required and not value.strip():
        raise RecordError(f"{name} must not be empty")
    if _utf16_len(value) > limit:
        raise RecordError(f"{name} is longer than {limit} characters")
    _check_text(name, value)
    return value


def _check_text(where: str, s: str, stored: bool = True) -> None:
    if stored and "\x00" in s:
        raise RecordError(f"{where} contains a NUL character, which Verfy Cloud cannot store")
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise RecordError(f"{where} is not valid Unicode (it has a lone surrogate)") from None


def _check_tree(where: str, value: Any, stored: bool) -> int:
    """Check every string in a JSON tree and return how many values it holds. A value that goes into the receipt
    (``stored``) may not hold a NUL character; one that is only hashed may."""
    if isinstance(value, str):
        _check_text(where, value, stored)
        return 1
    if isinstance(value, dict):
        n = 1
        for k, v in value.items():
            _check_text(where, k, stored)
            n += _check_tree(where, v, stored)
        return n
    if isinstance(value, list):
        return 1 + sum(_check_tree(where, v, stored) for v in value)
    return 1


# ---------------------------------------------------------------- the recorder

class Action:
    """What ``Recorder.action()`` yields. Set ``result`` before the block ends to record its hash."""

    __slots__ = ("result", "receipt")

    def __init__(self) -> None:
        self.result: Any = None
        self.receipt: dict | None = None


class Recorder:
    """Writes signed receipts for one agent into this machine's Verfy ledger.

    ``agent``         the agent's name in every receipt (default: $VERFY_AGENT, else "agent")
    ``home``          Verfy's folder (default: $VERFY_HOME, else ~/.verfy). Its key.json signs the receipts and is
                      created on first use; ledger.jsonl holds them. A separate home is a separate key and chain.
    ``session``       the session in every receipt unless a call gives its own (default: a new random id)
    ``include_args``  keep the arguments themselves in the receipt (secrets redacted), not only their hash
    ``upload``        "auto": on a machine enrolled in Verfy Cloud, upload in the background at most every 5 minutes,
                      as the hook does. "now": upload after every record (a failed upload is logged, not raised).
                      "off": never; call ``sync()`` yourself.
    ``on_error``      what ``track`` and ``action`` do when the record itself fails after the action ran:
                      "log" (default) logs it and lets the program carry on, "raise" raises it.
    """

    def __init__(self, agent: str | None = None, *, home: str | os.PathLike | None = None, session: str | None = None,
                 include_args: bool = False, upload: str = "auto", on_error: str = "log"):
        self.agent = _text("agent", agent if agent is not None else os.environ.get("VERFY_AGENT") or "agent", required=True)
        self.session = _text("session", session if session is not None else "sess_" + secrets.token_hex(8), required=True)
        if upload not in UPLOAD_MODES:
            raise RecordError(f"upload must be one of {', '.join(UPLOAD_MODES)}")
        if on_error not in ("log", "raise"):
            raise RecordError("on_error must be 'log' or 'raise'")
        self.home = Path(home) if home is not None else Path(os.environ.get("VERFY_HOME") or Path.home() / ".verfy")
        self.include_args = bool(include_args)
        self.upload = upload
        self.on_error = on_error
        self.key = _load_or_create_key(self.home / "key.json")
        self.ledger_path = self.home / "ledger.jsonl"
        self._ledger = Ledger(self.ledger_path, self.key)
        self._sync_lock = threading.Lock()
        self.last: dict | None = None

    # -------------------------------------------------- writing

    def record(self, action: str, *, system: str = "", kind: str = "other", args: Any = None, result: Any = None,
               status: str = "ok", session: str | None = None, approved_by: str | None = None,
               include_args: bool | None = None) -> dict:
        """Sign and append one receipt, and return it. Nothing is written when anything in it is refused."""
        receipt = self._write(action, system=system, kind=kind, args=jsonable(args if args is not None else {}),
                              result=None if result is None else jsonable(result), status=status, session=session,
                              approved_by=approved_by, include_args=self.include_args if include_args is None else bool(include_args))
        self._after_write()
        return receipt

    def track(self, action: str, *, system: str = "", kind: str = "other", args: Callable[..., Any] | None = None,
              record_result: bool = True, session: str | None = None) -> Callable[[F], F]:
        """A decorator that records every call of a function (plain or async).

        The arguments recorded are the call's named arguments (``self`` and ``cls`` left out), or what ``args`` returns
        when given, for example ``args=lambda order, amount, **_: {"order": order, "amount": amount}``. A call that
        raises is recorded with status "error", and the exception is raised again. Values that are not JSON-like are
        recorded as their type name."""
        return _tracker(lambda: self, action, system=system, kind=kind, args=args, record_result=record_result, session=session)

    def action(self, action: str, *, system: str = "", kind: str = "other", args: Any = None, session: str | None = None) -> "_ActionBlock":
        """A ``with`` block recorded when it ends: status "error" if it raised, else "ok" with the hash of ``.result``."""
        return _ActionBlock(self, action, system=system, kind=kind, args=args, session=session)

    def _write(self, action: str, *, system: str, kind: str, args: Any, result: Any, status: str, session: str | None,
               approved_by: str | None, include_args: bool) -> dict:
        action = _text("action", action, required=True)
        system = _text("system", system)
        if not isinstance(kind, str) or not _KIND.match(kind):
            raise RecordError("kind must be one lowercase word (letters, digits, - or _) of at most 40 characters, "
                              f"such as {', '.join(KINDS[:6])}")
        if status not in STATUSES:
            raise RecordError(f"status must be one of {', '.join(STATUSES)}")
        session = _text("session", session if session is not None else self.session, required=True)
        decision: dict[str, Any] = {"verdict": "allow", "kind": kind, "findings": []}
        if approved_by is not None:
            decision["approved_by"] = _text("approved_by", approved_by, required=True, limit=APPROVER_MAX)
        nodes = _check_tree("args", args, stored=include_args)
        if result is not None:
            _check_tree("result", result, stored=False)
        if include_args and nodes > ARGS_NODES_MAX:
            raise RecordError(f"the arguments hold more than {ARGS_NODES_MAX} values; record them without include_args "
                              "(only their hash), or pass fewer")
        outcome = {"status": status, "result_sha256": None if result is None else self._ledger.hash(result)}
        fields = dict(agent=self.agent, session=session, action={"server": system, "tool": action, "arguments": args},
                      decision=decision, outcome=outcome, policy_sha256=RECORD_POLICY, include_args=include_args)
        self._check_size(fields)
        receipt = self._ledger.append(**fields)
        self.last = receipt
        return receipt

    def _check_size(self, fields: dict) -> None:
        from .receipts import build_receipt
        body = build_receipt(seq=2**31 - 1, prev="sha256:" + "0" * 64, salt=self.key.hash_salt(), **fields)
        body.update({"kid": self.key.kid, "sig": "x" * 86})
        size = len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if size > RECEIPT_MAX_BYTES:
            raise RecordError(f"this receipt would be {size} bytes, over the {RECEIPT_MAX_BYTES} byte limit; "
                              "record the arguments without include_args (only their hash), or shorten the text")

    def _after_write(self) -> None:
        if self.upload == "off":
            return
        if self.upload == "now" and self._enrolled():
            try:
                self.sync()
                return
            except Exception as e:  # noqa: BLE001 (the receipt is written; the upload is retried later)
                log.warning("verfy: upload failed, will retry in the background: %s", e)
        self._sync_soon()

    def _enrolled(self) -> bool:
        try:
            return teamlib.load_team(self.home) is not None
        except Exception:  # noqa: BLE001
            return False

    def _sync_soon(self) -> None:
        # In a program frozen into one executable, `sys.executable -m verfy` would start that program again, not Verfy.
        if getattr(sys, "frozen", False) and Path(sys.executable).stem.lower() != "verfy":
            return
        teamlib.sync_soon(self.home)

    # -------------------------------------------------- Verfy Cloud

    def sync(self, *, transport: teamlib.Transport | None = None) -> dict:
        """Upload every receipt not uploaded yet. Raises ``TeamError`` when this machine is not enrolled or the upload fails."""
        with self._sync_lock:
            return teamlib.sync(self.home, self.ledger_path, self.key, allow_args=self.include_args, transport=transport)

    def share(self, receipt: dict | str | None = None, *, expires_in_days: int | None = None, label: str | None = None,
              transport: teamlib.Transport | None = None) -> str:
        """A link anyone can open to check one receipt: its signature, its place in the chain and Verfy's witness
        statement. Uploads what is waiting first. ``receipt`` is a receipt, its id (``rcpt_...``) or None for the
        last one this recorder wrote."""
        target = self._find(receipt)
        self.sync(transport=transport)
        res = teamlib.create_share(self.home, "receipt", receipt_hash=receipt_hash(target), expires_in_days=expires_in_days,
                                   label=label, transport=transport)
        return res["url"]

    def share_agent(self, *, expires_in_days: int | None = None, label: str | None = None,
                    transport: teamlib.Transport | None = None) -> str:
        """A link to this key's record as a whole: how many actions, of which kinds, since when, and whether the chain
        is intact, with Verfy's witness statement. No single action's details are shown. Uploads what is waiting first."""
        self.sync(transport=transport)
        return teamlib.create_share(self.home, "agent", expires_in_days=expires_in_days, label=label, transport=transport)["url"]

    def _find(self, receipt: dict | str | None) -> dict:
        if receipt is None:
            if self.last is None:
                raise RecordError("this recorder has not written a receipt yet; pass the receipt or its id")
            receipt = self.last
        if isinstance(receipt, str):
            found = [r for r in read_ledger(self.ledger_path) if isinstance(r, dict) and r.get("id") == receipt and r.get("kid") == self.key.kid]
            if not found:
                raise RecordError(f"no receipt {receipt} signed by {self.key.kid} in {self.ledger_path}")
            receipt = found[-1]
        if not isinstance(receipt, dict) or receipt.get("kid") != self.key.kid:
            raise RecordError("that receipt was not signed by this recorder's key")
        return receipt

    # -------------------------------------------------- checking

    def verify(self) -> dict:
        """Check every signature and link of this key's receipts in the ledger: ``{"ok", "count", "head", "errors"}``."""
        receipts = [r for r in read_ledger(self.ledger_path) if isinstance(r, dict) and r.get("kid") == self.key.kid]
        return verify_ledger(receipts, self.key.public)

    @property
    def kid(self) -> str:
        return self.key.kid

    @property
    def public_key(self) -> str:
        return self.key.to_json(include_secret=False)["public"]


class _ActionBlock:
    def __init__(self, rec: Recorder, action: str, *, system: str, kind: str, args: Any, session: str | None):
        self.rec, self.action_name, self.system, self.kind, self.session = rec, action, system, kind, session
        self.args = jsonable(args if args is not None else {})
        self.act = Action()

    def __enter__(self) -> Action:
        return self.act

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is None:
            outcome: dict[str, Any] = {"status": "ok", "result": None if self.act.result is None else jsonable(self.act.result, strict=False)}
        else:
            outcome = {"status": "error", "result": _error_value(exc)}
        self.act.receipt = _safe_write(self.rec, self.action_name, system=self.system, kind=self.kind, args=self.args,
                                       session=self.session, **outcome, raising=exc is None)
        return False


def _error_value(exc: BaseException) -> dict:
    return {"error": f"{type(exc).__module__}.{type(exc).__qualname__}", "message": str(exc)[:2000]}


def _safe_write(rec: Recorder, action: str, *, system: str, kind: str, args: Any, status: str, result: Any,
                session: str | None, raising: bool = True) -> dict | None:
    """Write a record for an action that already ran. A record that fails must not undo or repeat the action, so by
    default the failure is logged; an over-large record is written again with the hash of the arguments only."""
    kw = dict(system=system, kind=kind, args=args, result=result, status=status, session=session, approved_by=None)
    try:
        try:
            receipt = rec._write(action, include_args=rec.include_args, **kw)
        except RecordError as e:
            if not rec.include_args:
                raise
            log.warning("verfy: %s; recording %s with the hash of its arguments only", e, action)
            receipt = rec._write(action, include_args=False, **kw)
        rec._after_write()
        return receipt
    except Exception as e:  # noqa: BLE001
        if rec.on_error == "raise" and raising:
            raise
        log.error("verfy: could not record %s: %s", action, e)
        return None


def _tracker(get: Callable[[], Recorder], action: str, *, system: str, kind: str, args: Callable[..., Any] | None,
             record_result: bool, session: str | None) -> Callable[[F], F]:
    if not isinstance(action, str) or not action.strip():
        raise RecordError("action must not be empty")
    if not isinstance(kind, str) or not _KIND.match(kind):
        raise RecordError("kind must be one lowercase word (letters, digits, - or _) of at most 40 characters")

    def deco(fn: F) -> F:
        sig = inspect.signature(fn)

        def capture(a: tuple, kw: dict) -> Any:
            try:
                if args is not None:
                    return jsonable(args(*a, **kw), strict=False)
                bound = sig.bind_partial(*a, **kw)
                values = dict(bound.arguments)
                for name, p in sig.parameters.items():
                    if p.kind is inspect.Parameter.VAR_KEYWORD and name in values:
                        values.update(values.pop(name))
                values.pop("self", None)
                values.pop("cls", None)
                return jsonable(values, strict=False)
            except Exception as e:  # noqa: BLE001 (recording must not change how the function is called)
                return {"$unrecorded": type(e).__name__}

        def finish(rec: Recorder, a: Any, ok: bool, value: Any) -> None:
            if ok:
                result = jsonable(value, strict=False) if record_result and value is not None else None
                _safe_write(rec, action, system=system, kind=kind, args=a, status="ok", result=result, session=session)
            else:
                _safe_write(rec, action, system=system, kind=kind, args=a, status="error", result=_error_value(value),
                            session=session, raising=False)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def run_async(*a: Any, **kw: Any) -> Any:
                rec = get()
                recorded = capture(a, kw)
                try:
                    value = await fn(*a, **kw)
                except BaseException as e:
                    finish(rec, recorded, False, e)
                    raise
                finish(rec, recorded, True, value)
                return value
            return run_async  # type: ignore[return-value]

        @functools.wraps(fn)
        def run(*a: Any, **kw: Any) -> Any:
            rec = get()
            recorded = capture(a, kw)
            try:
                value = fn(*a, **kw)
            except BaseException as e:
                finish(rec, recorded, False, e)
                raise
            finish(rec, recorded, True, value)
            return value
        return run  # type: ignore[return-value]
    return deco


def _load_or_create_key(path: Path) -> Key:
    """This machine's signing key, created once. Two processes starting at the same moment get the same key: the
    first creates it under a lock and the second reads it, so a ledger never holds receipts from two keys."""
    if path.exists():
        return Key.load(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(path, timeout=30.0):
        if path.exists():
            return Key.load(path)
        key = Key.generate()
        key.save(path)
        key.path = path
        log.info("verfy: created signing key %s at %s", key.kid, path)
        return key


# ---------------------------------------------------------------- module level

_default: Recorder | None = None
_default_lock = threading.Lock()


def default_recorder() -> Recorder:
    """The recorder ``verfy.record`` and ``verfy.track`` use: agent $VERFY_AGENT (else "agent"), home $VERFY_HOME."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Recorder()
        return _default


def record(action: str, **kw: Any) -> dict:
    """``verfy.record("refund", system="stripe", kind="payment", args={...})``: one signed receipt, with the default recorder."""
    return default_recorder().record(action, **kw)


def track(action: str, *, system: str = "", kind: str = "other", args: Callable[..., Any] | None = None,
          record_result: bool = True, session: str | None = None) -> Callable[[F], F]:
    """``@verfy.track("send_email", system="gmail", kind="message")``: record every call, with the default recorder,
    which is created at the first call, not when the module is imported."""
    return _tracker(default_recorder, action, system=system, kind=kind, args=args, record_result=record_result, session=session)
