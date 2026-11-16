"""Checking Verfy's transparency log.

Verfy Cloud adds every receipt it accepts as the next leaf of one public, append-only RFC 6962 Merkle tree and signs
the tree's size and root (a ``verfy.witness/1`` statement of type "tree_head") with its witness key. With that:

- ``prove(hash)`` fetches a receipt's inclusion proof and checks it against a signed head: Verfy holds this receipt,
  at this position, in the log it signed;
- ``watch()`` fetches the newest head and checks it only added to the last head this machine saw (a consistency
  proof), so Verfy cannot quietly drop, change or reorder receipts it already accepted.

Every head this machine checked is kept in ``~/.verfy/log-heads.json``. A check fails closed: a signature that does not
check, a proof that does not lead to the signed root, or two heads that do not extend one another. The proof
documents ``prove`` returns can be checked again offline with ``check_inclusion`` (``verfy incident`` packs them).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlparse

from . import merkle, witness
from .fileio import FileLock, atomic_write

DEFAULT_LOG_URL = "https://verfy.dev/api/v1/log"
HEADS_KEPT = 200
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")

Transport = Callable[[str, str, Any, dict], tuple[int, Any]]


class LogError(RuntimeError):
    """The log could not be read, or what it returned does not check out."""


def check_log_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")):
        raise LogError("the log URL must use https")
    return url.rstrip("/")


def key_url_for(log_url: str) -> str:
    u = urlparse(log_url)
    return f"{u.scheme}://{u.netloc}/.well-known/verfy-witness.json"


def _get(transport: Transport, url: str) -> Any:
    status, body = transport("GET", url, None, {})
    if status != 200:
        title = body.get("title") if isinstance(body, dict) else None
        detail = body.get("detail") if isinstance(body, dict) else None
        raise LogError(f"{url}: {status} {title or ''}{': ' + detail if detail else ''}".strip())
    return body


def check_head(statement: Any, keys: dict[str, bytes]) -> tuple[int, bytes]:
    """The size and root of a signed tree head, or LogError."""
    if not isinstance(statement, dict) or statement.get("type") != "tree_head":
        raise LogError("not a signed tree head")
    key = keys.get(statement.get("kid"))  # type: ignore[arg-type]
    if key is None:
        raise LogError(f"the head is signed by {statement.get('kid')!r}, which is not one of the witness keys")
    if not witness.verify_statement(statement, key):
        raise LogError("the head's signature does not check")
    size, root = statement.get("tree_size"), statement.get("root_hash")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or not isinstance(root, str) or not _HEX.match(root):
        raise LogError("the head has no valid tree_size and root_hash")
    return size, bytes.fromhex(root)


def _hexes(path: Any) -> list[bytes]:
    if not isinstance(path, list) or not all(isinstance(p, str) and _HEX.match(p) for p in path) or len(path) > 64:
        raise LogError("the proof's path is not a list of SHA-256 hashes")
    return [bytes.fromhex(p) for p in path]


def check_inclusion(doc: Any, keys: dict[str, bytes], receipt_hash: str | None = None) -> dict:
    """Check an inclusion proof document (what /api/v1/log/proof returns) offline: the head is signed by a witness
    key and the path leads from the receipt hash to its root. Returns ``{"hash", "index", "tree_size", "head"}``."""
    if not isinstance(doc, dict):
        raise LogError("not an inclusion proof")
    h = doc.get("hash")
    if not isinstance(h, str) or not _HASH.match(h):
        raise LogError("the proof names no receipt hash")
    if receipt_hash is not None and h != receipt_hash:
        raise LogError("the proof is for a different receipt")
    size, root = check_head(doc.get("head"), keys)
    index = doc.get("index")
    if doc.get("tree_size") != size or not isinstance(index, int) or isinstance(index, bool):
        raise LogError("the proof does not match its head")
    if not merkle.verify_inclusion(merkle.receipt_hash_bytes(h), index, size, _hexes(doc.get("path")), root):
        raise LogError("the inclusion proof does not lead to the signed root")
    return {"hash": h, "index": index, "tree_size": size, "head": doc["head"]}


class Log:
    """A client for one log: its URL, the witness keys that sign its heads, and the heads this machine has seen."""

    def __init__(self, url: str = DEFAULT_LOG_URL, *, keys: dict[str, bytes] | None = None, home: str | os.PathLike | None = None,
                 transport: Transport | None = None):
        from .team import http_transport
        self.url = check_log_url(url)
        self.transport = transport or http_transport
        self._keys = keys
        self.home = Path(home) if home is not None else Path(os.environ.get("VERFY_HOME") or Path.home() / ".verfy")

    @property
    def keys(self) -> dict[str, bytes]:
        if self._keys is None:
            try:
                self._keys = witness.keys_from(_get(self.transport, key_url_for(self.url)))
            except LogError:
                raise
            except Exception as e:  # noqa: BLE001
                raise LogError(f"could not read the witness keys: {e}") from None
            if not self._keys:
                raise LogError("the log publishes no witness keys")
        return self._keys

    # -------------------------------------------------- heads seen
    @property
    def heads_path(self) -> Path:
        return self.home / "log-heads.json"

    def seen(self) -> list[dict]:
        try:
            data = json.loads(self.heads_path.read_text("utf-8"))
        except (OSError, ValueError):
            return []
        heads = data.get(self.url, []) if isinstance(data, dict) else []
        return [h for h in heads if isinstance(h, dict)]

    def _remember(self, statement: dict) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        with FileLock(self.heads_path, timeout=30.0):
            try:
                data = json.loads(self.heads_path.read_text("utf-8"))
                if not isinstance(data, dict):
                    data = {}
            except (OSError, ValueError):
                data = {}
            heads = [h for h in data.get(self.url, []) if isinstance(h, dict) and h.get("tree_size") != statement["tree_size"]]
            heads.append(statement)
            heads.sort(key=lambda h: h.get("tree_size", 0))
            data[self.url] = heads[-HEADS_KEPT:]
            atomic_write(self.heads_path, json.dumps(data, indent=1))

    # -------------------------------------------------- checks
    def consistent(self, old: dict, new: dict) -> None:
        """Raise LogError unless the log at head ``new`` only added leaves to the log at head ``old``."""
        s1, r1 = check_head(old, self.keys)
        s2, r2 = check_head(new, self.keys)
        if s1 > s2:
            s1, r1, s2, r2, old, new = s2, r2, s1, r1, new, old
        if s1 == s2:
            if r1 != r2:
                raise LogError(f"two signed heads of size {s1} have different roots: the log was forked")
            return
        if s1 == 0:
            return
        doc = _get(self.transport, f"{self.url}/consistency?from={s1}&to={s2}")
        if not isinstance(doc, dict) or doc.get("from") != s1 or doc.get("to") != s2:
            raise LogError("the consistency proof is for other sizes")
        if not merkle.verify_consistency(s1, s2, r1, r2, _hexes(doc.get("path"))):
            raise LogError(f"the log of size {s2} does not extend the log of size {s1} this machine saw: receipts were changed or removed")

    def _against_seen(self, head: dict) -> int:
        """Check ``head`` against the nearest heads seen before (one smaller, one larger) and remember it."""
        size, _ = check_head(head, self.keys)
        seen = []
        for h in self.seen():
            try:
                check_head(h, self.keys)
                seen.append(h)
            except LogError:
                continue  # a head signed by a key no longer published is not held against the log
        smaller = [h for h in seen if h["tree_size"] <= size]
        larger = [h for h in seen if h["tree_size"] > size]
        checked = 0
        for other in ([smaller[-1]] if smaller else []) + ([larger[0]] if larger else []):
            self.consistent(other, head)
            checked += 1
        self._remember(head)
        return checked

    def head(self) -> dict:
        doc = _get(self.transport, self.url)
        h = doc.get("head") if isinstance(doc, dict) else None
        if h is None:
            raise LogError("the log has no signed head yet")
        check_head(h, self.keys)
        return h

    def prove(self, receipt_hash: str, size: int | None = None) -> dict:
        """Fetch and check the inclusion proof for one receipt hash; also check its head against the heads seen."""
        if not isinstance(receipt_hash, str) or not _HASH.match(receipt_hash):
            raise LogError("a receipt hash is sha256: and 64 lowercase hex characters")
        url = f"{self.url}/proof?hash={quote(receipt_hash, safe=':')}" + (f"&size={int(size)}" if size else "")
        doc = _get(self.transport, url)
        res = check_inclusion(doc, self.keys, receipt_hash)
        res["consistency_checks"] = self._against_seen(res["head"])
        res["proof"] = doc
        return res

    def watch(self) -> dict:
        """Fetch the newest head and check it extends the heads this machine saw before."""
        head = self.head()
        checked = self._against_seen(head)
        return {"tree_size": head["tree_size"], "root_hash": head["root_hash"], "issued_at": head.get("issued_at"),
                "kid": head.get("kid"), "consistency_checks": checked, "head": head}
