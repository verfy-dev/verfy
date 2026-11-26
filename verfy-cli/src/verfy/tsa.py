"""Independent time stamps (RFC 3161) for the receipt ledger: ``verfy timestamp``.

A time stamp authority signs "this hash existed at this time". Verfy sends it only the SHA-256 head of the ledger
(the hash of the last receipt, which covers every receipt before it), never a receipt. The reply (a ``.tsr`` file)
is kept next to the ledger; anyone with it can show the ledger up to that receipt existed at that time, without
trusting Verfy or this computer's clock.

What this module checks itself, with no dependency: the reply was granted, the stamped hash is the ledger head, the
nonce is ours, and the time. The authority's signature and certificate chain are checked by ``openssl ts -verify``
when OpenSSL is installed (the command is printed otherwise), because checking X.509 chains needs a full PKI library.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TSA = "http://timestamp.digicert.com"
SHA256_OID = bytes.fromhex("0609608648016503040201")  # 2.16.840.1.101.3.4.2.1, with its tag and length
TSTINFO_OID = bytes.fromhex("060b2a864886f70d0109100104")  # 1.2.840.113549.1.9.16.1.4


class TimestampError(ValueError):
    pass


# ---------------------------------------------------------------- DER, the little that is needed

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, b)


def request(digest: bytes, nonce: int) -> bytes:
    """A TimeStampReq for a SHA-256 digest, asking for the authority's certificate in the reply."""
    if len(digest) != 32:
        raise TimestampError("the digest must be 32 bytes (SHA-256)")
    alg = _tlv(0x30, SHA256_OID + b"\x05\x00")
    imprint = _tlv(0x30, alg + _tlv(0x04, digest))
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + _tlv(0x01, b"\xff"))


def _read(buf: bytes, i: int) -> tuple[int, int, int]:
    """(tag, start of value, end of value) of the element at ``i``."""
    if i + 2 > len(buf):
        raise TimestampError("the reply is cut short")
    tag, n = buf[i], buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(buf):
            raise TimestampError("the reply has a length Verfy cannot read")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > len(buf):
        raise TimestampError("the reply is cut short")
    return tag, i, i + n


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, i = [], start
    while i < end:
        tag, s, e = _read(buf, i)
        out.append((tag, s, e))
        i = e
    return out


def parse_reply(reply: bytes) -> dict:
    """``{"status", "digest", "nonce", "gen_time", "serial", "token"}`` from a TimeStampResp."""
    tag, s, e = _read(reply, 0)
    if tag != 0x30:
        raise TimestampError("not a time stamp reply")
    parts = _children(reply, s, e)
    st = _children(reply, parts[0][1], parts[0][2])
    status = int.from_bytes(reply[st[0][1]:st[0][2]], "big")
    if status not in (0, 1) or len(parts) < 2:
        raise TimestampError(f"the authority did not grant the time stamp (status {status})")
    token = reply[parts[1][1] - _start_of(reply, parts[1]):parts[1][2]]
    ci = _children(reply, parts[1][1], parts[1][2])  # ContentInfo: contentType, [0] SignedData
    sd_wrap = _children(reply, ci[1][1], ci[1][2])
    sd = _children(reply, sd_wrap[0][1], sd_wrap[0][2])  # version, digestAlgorithms, encapContentInfo, ...
    encap = _children(reply, sd[2][1], sd[2][2])
    if reply[encap[0][1] - 2:encap[0][2]] != TSTINFO_OID:
        raise TimestampError("the reply does not carry TSTInfo")
    octets = _children(reply, encap[1][1], encap[1][2])[0]
    tst = reply[octets[1]:octets[2]]
    t = _children(tst, *_read(tst, 0)[1:])
    imprint = _children(tst, t[2][1], t[2][2])
    digest = tst[imprint[1][1]:imprint[1][2]]
    if tst[_children(tst, imprint[0][1], imprint[0][2])[0][1] - 2:_children(tst, imprint[0][1], imprint[0][2])[0][2]] != SHA256_OID:
        raise TimestampError("the stamped hash is not SHA-256")
    serial = int.from_bytes(tst[t[3][1]:t[3][2]], "big")
    gen = tst[t[4][1]:t[4][2]].decode("ascii")
    nonce = None
    for tag2, s2, e2 in t[5:]:
        if tag2 == 0x02:
            nonce = int.from_bytes(tst[s2:e2], "big", signed=True)
    return {"status": status, "digest": digest.hex(), "nonce": nonce, "gen_time": _gen_time(gen), "serial": serial, "token": token}


def _start_of(buf: bytes, el: tuple[int, int, int]) -> int:
    """Where the element (tag byte) starts, given its value range."""
    _, s, e = el
    for back in range(2, 7):
        try:
            tag, s2, e2 = _read(buf, s - back)
        except TimestampError:
            continue
        if (s2, e2) == (s, e):
            return back
    raise TimestampError("cannot find the token in the reply")


def _gen_time(g: str) -> str:
    g = g.rstrip("Z")
    main, _, frac = g.partition(".")
    t = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return t.isoformat().replace("+00:00", (("." + frac[:6]) if frac else "") + "Z")


# ---------------------------------------------------------------- stamping and checking

def stamp(head: str, tsa: str = DEFAULT_TSA, *, post=None, timeout: float = 20) -> dict:
    """Ask ``tsa`` to stamp the ledger head ``sha256:<hex>``. Returns the parsed reply plus the raw bytes (``reply``)."""
    if not (isinstance(head, str) and head.startswith("sha256:") and len(head) == 71):
        raise TimestampError("head must be sha256:<64 hex>")
    digest = bytes.fromhex(head[7:])
    nonce = secrets.randbits(63)
    body = request(digest, nonce)
    if post is None:
        if not tsa.startswith(("http://", "https://")):
            raise TimestampError("the time stamp authority must be an http(s) URL")
        req = urllib.request.Request(tsa, data=body, headers={"Content-Type": "application/timestamp-query", "User-Agent": "verfy"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - a URL the person chose, http(s) only
            reply = r.read(1_000_000)
    else:
        reply = post(tsa, body)
    info = parse_reply(reply)
    if info["digest"] != digest.hex():
        raise TimestampError("the authority stamped a different hash")
    if info["nonce"] != nonce:
        raise TimestampError("the reply's nonce is not the one sent (a replayed reply?)")
    return {**info, "head": head, "tsa": tsa, "reply": reply}


def save(home: Path, info: dict, seq: int | None) -> Path:
    d = home / "timestamps"
    d.mkdir(parents=True, exist_ok=True)
    name = f"{seq if seq is not None else 'x'}-{info['head'][7:19]}"
    (d / f"{name}.tsr").write_bytes(info["reply"])
    meta = {"v": "verfy.timestamp/1", "head": info["head"], "seq": seq, "tsa": info["tsa"], "gen_time": info["gen_time"], "serial": info["serial"]}
    (d / f"{name}.json").write_text(json.dumps(meta, indent=2) + "\n", "utf-8")
    return d / f"{name}.tsr"


def check_file(path: Path, receipts: list[dict] | None = None, ca: Path | None = None) -> dict:
    """What a ``.tsr`` proves: the hash, the time, whether that hash is a receipt in ``receipts``, and the signature
    (``signature``: "ok", "bad" or "not checked")."""
    from .receipts import receipt_hash
    reply = path.read_bytes()
    info = parse_reply(reply)
    head = "sha256:" + info["digest"]
    out = {"head": head, "gen_time": info["gen_time"], "serial": info["serial"], "seq": None, "signature": "not checked", "command": None}
    if receipts is not None:
        out["seq"] = next((r.get("seq") for r in receipts if receipt_hash(r) == head), None)
    cmd = ["openssl", "ts", "-verify", "-digest", info["digest"], "-in", str(path)] + (["-CAfile", str(ca)] if ca else [])
    out["command"] = " ".join(cmd)
    if ca and shutil.which("openssl"):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out["signature"] = "ok" if r.returncode == 0 and "Verification: OK" in (r.stdout + r.stderr) else "bad"
    return out
