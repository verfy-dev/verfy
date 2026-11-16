"""Tests for Verfy's transparency log client (verfy.merkle, verfy.tlog) and incident packs (verfy.incident).
Run from verfy-cli/: ``python -m unittest tests.test_log``."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import ed25519, incident, merkle, tlog, witness  # noqa: E402
from verfy.canonical import canonical_bytes  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.receipts import b64u, receipt_hash  # noqa: E402
from verfy.recorder import Recorder  # noqa: E402

URL = "https://verfy.example/api/v1/log"
SEED = b"\x09" * 32
PUB = ed25519.public_key(SEED)
KEYS = {witness.witness_kid(PUB): PUB}


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


def sign(body: dict, seed: bytes = SEED) -> dict:
    pub = ed25519.public_key(seed)
    body = {**body, "v": witness.VERSION, "kid": witness.witness_kid(pub)}
    return {**body, "sig": b64u(ed25519.sign(seed, canonical_bytes(body)))}


class FakeLog:
    """Verfy Cloud's log endpoints, built on verfy.merkle (the cloud's TypeScript code agrees with it on the shared
    vectors in tests/fixtures/merkle.json)."""

    def __init__(self):
        self.leaves: list[str] = []
        self.heads: dict[int, dict] = {}
        self.forged: dict[int, list[str]] = {}  # size -> a different history served for that size
        self.calls: list[str] = []

    def add(self, *hashes: str) -> None:
        self.leaves.extend(hashes)

    def data(self, n: int) -> list[bytes]:
        src = self.forged.get(n, self.leaves)
        return [merkle.receipt_hash_bytes(h) for h in src[:n]]

    def sign_head(self, seed: bytes = SEED) -> dict:
        n = len(self.leaves)
        st = sign({"issuer": "https://verfy.example", "issued_at": f"2026-11-16T10:{n:02d}:00Z", "type": "tree_head",
                   "tree_size": n, "root_hash": merkle.tree_root(self.data(n)).hex()}, seed)
        self.heads[n] = st
        return st

    def __call__(self, method, url, body, headers):
        self.calls.append(url)
        u = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/.well-known/verfy-witness.json":
            return 200, {"keys": [{"kid": witness.witness_kid(PUB), "alg": "Ed25519", "public": b64u(PUB)}]}
        if u.path == "/api/v1/log":
            latest = self.heads[max(self.heads)] if self.heads else None
            return 200, {"head": latest}
        if u.path == "/api/v1/log/proof":
            h = q["hash"]
            if h not in self.leaves:
                return 404, {"title": "Verfy's log does not hold a receipt with this hash."}
            i = self.leaves.index(h)
            size = int(q["size"]) if "size" in q else (max(self.heads) if self.heads else 0)
            if size <= i:
                self.sign_head()
                size = len(self.leaves)
            return 200, {"hash": h, "index": i, "tree_size": size, "path": [p.hex() for p in merkle.inclusion_path(i, self.data(size))],
                         "head": self.heads[size]}
        if u.path == "/api/v1/log/consistency":
            m, n = int(q["from"]), int(q.get("to", max(self.heads)))
            return 200, {"from": m, "to": n, "path": [p.hex() for p in merkle.consistency_path(m, self.data(n))], "head": self.heads[n]}
        return 404, {"title": "not found"}


def H(i: int) -> str:
    return "sha256:" + hashlib.sha256(f"leaf {i}".encode()).hexdigest()


class Merkle(unittest.TestCase):
    def test_shared_vectors_and_certificate_transparency_root(self):
        doc = json.loads((ROOT / "tests" / "fixtures" / "merkle.json").read_text("utf-8"))
        leaves = [bytes.fromhex(x) for x in doc["leaves"]]
        for v in doc["proofs"]:
            self.assertEqual(merkle.tree_root(leaves[:v["size"]]).hex(), v["root"])
            self.assertEqual([p.hex() for p in merkle.inclusion_path(v["index"], leaves[:v["size"]])], v["path"])
            self.assertTrue(merkle.verify_inclusion(leaves[v["index"]], v["index"], v["size"], [bytes.fromhex(p) for p in v["path"]], bytes.fromhex(v["root"])))
        for c in doc["consistency"]:
            path = [bytes.fromhex(p) for p in c["path"]]
            self.assertTrue(merkle.verify_consistency(c["from"], c["to"], bytes.fromhex(c["from_root"]), bytes.fromhex(c["to_root"]), path))
        ct = [bytes.fromhex(h) for h in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
        self.assertEqual(merkle.tree_root(ct).hex(), "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")

    def test_every_proof_of_small_trees(self):
        for n in range(1, 34):
            d = [hashlib.sha256(bytes([i])).digest() for i in range(n)]
            root = merkle.tree_root(d)
            for m in range(n):
                path = merkle.inclusion_path(m, d)
                self.assertTrue(merkle.verify_inclusion(d[m], m, n, path, root))
                if n > 1:
                    self.assertFalse(merkle.verify_inclusion(d[(m + 1) % n], m, n, path, root))
                    self.assertFalse(merkle.verify_inclusion(d[m], m, n, path[:-1], root))
            for m in range(1, n + 1):
                self.assertTrue(merkle.verify_consistency(m, n, merkle.tree_root(d[:m]), root, merkle.consistency_path(m, d)))
        self.assertFalse(merkle.verify_inclusion(b"x", 0, 0, [], b""))
        self.assertFalse(merkle.verify_consistency(0, 1, b"", b"", []))


class LogClient(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.cloud = FakeLog()
        self.cloud.add(*[H(i) for i in range(5)])
        self.cloud.sign_head()

    def log(self, **kw) -> tlog.Log:
        return tlog.Log(URL, home=self.home, transport=self.cloud, **kw)

    def test_prove_and_remember_heads(self):
        res = self.log().prove(H(3))
        self.assertEqual((res["index"], res["tree_size"], res["consistency_checks"]), (3, 5, 0))
        self.cloud.add(H(5), H(6))
        res = self.log().prove(H(6))  # after the newest head: a new one is signed and checked against the one seen
        self.assertEqual((res["tree_size"], res["consistency_checks"]), (7, 1))
        self.assertEqual([h["tree_size"] for h in self.log().seen()], [5, 7])
        again = tlog.check_inclusion(res["proof"], KEYS, H(6))  # the saved proof checks offline
        self.assertEqual(again["index"], 6)
        with self.assertRaises(tlog.LogError):
            tlog.check_inclusion(res["proof"], KEYS, H(5))

    def test_watch_catches_a_rewritten_log(self):
        self.assertEqual(self.log().watch()["consistency_checks"], 0)
        self.cloud.add(H(5))
        self.cloud.sign_head()
        self.assertEqual(self.log().watch()["consistency_checks"], 1)
        # the operator now serves a history where receipt 2 is replaced, and signs it
        self.cloud.add(H(6))
        self.cloud.forged[7] = [H(0), H(1), "sha256:" + "f" * 64, H(3), H(4), H(5), H(6)]
        self.cloud.sign_head()
        with self.assertRaisesRegex(tlog.LogError, "changed or removed"):
            self.log().watch()

    def test_a_fork_at_the_same_size_is_caught(self):
        self.log().watch()
        self.cloud.forged[5] = [H(0), H(1), H(2), H(3), "sha256:" + "e" * 64]
        self.cloud.sign_head()
        with self.assertRaisesRegex(tlog.LogError, "forked"):
            self.log().watch()

    def test_bad_heads_and_proofs_fail_closed(self):
        good = self.log().prove(H(1))["proof"]
        cases = {
            "other key": {**good, "head": FakeLog.sign_head.__get__(self.cloud)(b"\x01" * 32)},
            "tampered root": {**good, "head": {**good["head"], "root_hash": "0" * 64}},
            "wrong index": {**good, "index": 2},
            "short path": {**good, "path": good["path"][:-1]},
            "bad path": {**good, "path": ["zz"]},
            "size mismatch": {**good, "tree_size": 4},
            "no head": {**good, "head": None},
        }
        for name, doc in cases.items():
            with self.assertRaises(tlog.LogError, msg=name):
                tlog.check_inclusion(doc, KEYS)
        with self.assertRaises(tlog.LogError):
            self.log().prove(H(99))
        with self.assertRaises(tlog.LogError):
            self.log().prove("sha256:short")
        with self.assertRaises(tlog.LogError):
            tlog.Log("http://verfy.example/api/v1/log")
        tlog.Log("http://localhost:3000/api/v1/log")  # local development is allowed
        empty = FakeLog()
        with self.assertRaisesRegex(tlog.LogError, "no signed head"):
            tlog.Log(URL, home=self.home, transport=empty).watch()


class Incident(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.rec = Recorder(agent="refund-bot", home=self.home, upload="off")
        self.receipts = []
        for i in range(6):
            with mock.patch("verfy.receipts.now_iso", return_value=f"2026-11-16T09:0{i}:00.000Z"):
                self.receipts.append(self.rec.record("refund", kind="payment", args={"n": i}, session=f"s{i}"))

    def pack(self, **kw) -> dict:
        return incident.build_pack(self.rec.ledger_path, self.rec.key.public, **kw)

    def test_a_pack_checks_and_shows_gaps(self):
        p = self.pack(note="refund to the wrong customer")
        res = incident.verify_pack(p)
        self.assertTrue(res["ok"], res["errors"])
        self.assertEqual((res["receipts"], res["first_seq"], res["last_seq"], res["log_checked"]), (6, 0, 5, False))
        cut = {**p, "receipts": p["receipts"][:2] + p["receipts"][3:]}
        self.assertFalse(incident.verify_pack(cut)["ok"])  # one left out of the middle shows
        edited = json.loads(json.dumps(p))
        edited["receipts"][1]["agent"] = "someone-else"
        self.assertFalse(incident.verify_pack(edited)["ok"])
        other = Recorder(home=tmpdir(self), upload="off")
        self.assertFalse(incident.verify_pack({**p, "public_key": other.public_key})["ok"])
        self.assertFalse(incident.verify_pack({"v": "verfy.incident/1", "receipts": []})["ok"])

    def test_windows(self):
        times = [r["issued_at"] for r in self.receipts]
        p = self.pack(since=times[2], until=times[3])
        self.assertEqual([r["seq"] for r in p["receipts"]], [2, 3])
        self.assertEqual(p["next"], receipt_hash(self.receipts[4]))
        self.assertTrue(incident.verify_pack(p)["ok"])
        self.assertIsNone(self.pack(since=times[5])["next"])
        with self.assertRaises(incident.IncidentError):
            self.pack(since="2999-01-01T00:00:00Z")
        with self.assertRaises(incident.IncidentError):
            self.pack(since=times[3], until=times[1])
        with self.assertRaises(incident.IncidentError):
            self.pack(since="yesterday")

    def test_log_proofs_in_a_pack(self):
        cloud = FakeLog()
        cloud.add(*[receipt_hash(r) for r in self.receipts[:4]])
        cloud.sign_head()
        log = tlog.Log(URL, home=self.home, transport=cloud)
        p = self.pack(log=log)
        self.assertEqual((len(p["log"]["proofs"]), len(p["log"]["not_in_log"])), (4, 2))
        res = incident.verify_pack(json.loads(json.dumps(p)), KEYS)
        self.assertTrue(res["ok"], res["errors"])
        self.assertEqual((res["in_log"], res["log_checked"]), (4, True))
        self.assertEqual(res["earliest_head"], "2026-11-16T10:04:00Z")
        bad = json.loads(json.dumps(p))
        bad["log"]["proofs"][0]["path"] = bad["log"]["proofs"][1]["path"]
        self.assertFalse(incident.verify_pack(bad, KEYS)["ok"])
        stranger = json.loads(json.dumps(p))
        stranger["receipts"] = stranger["receipts"][4:]
        self.assertFalse(incident.verify_pack(stranger, KEYS)["ok"])  # proofs for receipts not in the pack


class Commands(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        p = mock.patch.dict("os.environ", {"VERFY_HOME": str(self.home), "NO_COLOR": "1"})
        p.start()
        self.addCleanup(p.stop)
        self.rec = Recorder(home=self.home, upload="off")
        for i in range(3):
            self.rec.record("step", args={"i": i})
        self.cloud = FakeLog()
        self.cloud.add(*[receipt_hash(r) for r in json.loads("[" + ",".join(self.rec.ledger_path.read_text("utf-8").splitlines()) + "]")])
        self.cloud.sign_head()
        t = mock.patch("verfy.team.http_transport", self.cloud)
        t.start()
        self.addCleanup(t.stop)

    def run_cli(self, *argv, stdin: str = "") -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()), mock.patch("sys.stdin", io.StringIO(stdin)):
            try:
                code = cli_main(list(argv))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue()

    def test_log_and_incident_commands(self):
        h = self.cloud.leaves[1]
        code, out = self.run_cli("log", "prove", h, "--url", URL)
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFIED", out)
        self.assertIn("leaf 1 of Verfy's log of 3", out)
        code, out = self.run_cli("log", "watch", "--url", URL, "--json")
        self.assertEqual(json.loads(out)["tree_size"], 3)
        code, out = self.run_cli("log", "prove", "sha256:" + "0" * 64, "--url", URL)
        self.assertEqual(code, 1)
        pack = self.home / "pack.json"
        code, out = self.run_cli("incident", "export", "--prove", "--url", URL, "-o", str(pack))
        self.assertEqual(code, 0, out)
        self.assertIn("3 with Verfy's log proof", out)
        code, out = self.run_cli("incident", "verify", str(pack))
        self.assertEqual(code, 0, out)
        self.assertIn("3 of them are in Verfy's signed log", out)
        code, out = self.run_cli("incident", "verify", str(pack), "--offline", "--json")
        self.assertEqual((code, json.loads(out)["log_checked"]), (0, False))
        doc = json.loads(pack.read_text("utf-8"))
        doc["receipts"].pop(1)
        code, out = self.run_cli("incident", "verify", "-", "--offline", stdin=json.dumps(doc))
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out)


if __name__ == "__main__":
    unittest.main()
