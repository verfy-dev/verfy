"""0.33.0: Verfy's open responsibility rules, verfy claim, signatures inside AP2 mandates."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import claim, dispute, ed25519, liability, mandate  # noqa: E402
from verfy.canonical import canonical_bytes  # noqa: E402
from verfy.receipts import Key, read_ledger, receipt_hash  # noqa: E402
from verfy.recorder import Recorder  # noqa: E402

FIX = json.loads((ROOT / "tests" / "fixtures" / "ap2_jws.json").read_text("utf-8"))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class LiabilityTests(unittest.TestCase):
    def test_each_finding_has_one_rule(self):
        cases = {
            ("blocked", None, None): ("R1", "nobody"),
            ("chain_broken", None, None): ("R2", "agent_operator"),
            ("emergency_access", None, None): ("R3", "agent_operator"),
            ("observe_mode", None, None): ("R4", "agent_operator"),
            ("person_approved", True, None): ("R5", "approver"),
            ("person_approved", False, None): ("R6", "agent_operator"),
            ("asked_not_approved", None, None): ("R7", "agent_operator"),
            ("policy_allowed", None, True): ("R8", "tool_author"),
            ("policy_allowed", None, False): ("R9", "agent_operator"),
        }
        for (finding, pk, tool), want in cases.items():
            d = liability.decide(finding, passkey_ok=pk, tool_changed=tool)
            self.assertEqual((d["rule"], d["party"]), want, finding)
            self.assertEqual(d["v"], "verfy.liability/1")

    def test_unchecked_tool_is_said_out_loud(self):
        self.assertIn("open", liability.decide("policy_allowed"))
        self.assertNotIn("open", liability.decide("policy_allowed", tool_changed=False))

    def test_every_finding_is_covered(self):
        for f in dispute.FINDINGS:
            self.assertIn(liability.decide(f)["rule"], liability.RULES)


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"VERFY_HOME": str(self.home)})
        self.env.start()
        self.rec = Recorder("bot", home=self.home)
        r = self.rec.record("pay", kind="payment", args={"amount": 12, "to": "acme"})
        self.receipts = read_ledger(self.home / "ledger.jsonl")
        self.doc = dispute.open_dispute(self.receipts, r["seq"], "The agent paid acme without asking me.", self.rec.key)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def verdict(self, **kw):
        body = {"v": "verfy.verdict/1", "dispute_sha256": receipt_hash(self.doc), "decision": "operator pays", "arbitrator": "a@example.test", **kw}
        return {**body, "sha256": receipt_hash(body)}

    def test_build_and_verify(self):
        c = claim.build(self.doc, self.receipts, self.rec.key, verdict=self.verdict())
        self.assertTrue(c["ledger"]["receipt_in_ledger"])
        self.assertEqual(c["liability"]["party"], liability.decide(self.doc["finding"])["party"])
        res = claim.verify(json.loads(json.dumps(c)))
        self.assertTrue(res["ok"], res["problems"])

    def test_changed_claim_fails(self):
        c = claim.build(self.doc, self.receipts, self.rec.key)
        c["liability"]["party"] = "approver"
        self.assertFalse(claim.verify(c)["ok"])

    def test_forged_rule_with_valid_signature_fails(self):
        c = claim.build(self.doc, self.receipts, self.rec.key)
        body = {k: v for k, v in c.items() if k != "sig"}
        body["liability"] = {**body["liability"], "rule": "R5", "party": "approver"}
        forged = {**body, "sig": b64u(ed25519.sign(self.rec.key.secret, canonical_bytes(body)))}
        res = claim.verify(forged)
        self.assertFalse(res["ok"])
        self.assertTrue(any("responsibility rule" in p for p in res["problems"]))

    def test_verdict_for_another_dispute_is_refused(self):
        with self.assertRaises(ValueError):
            claim.build(self.doc, self.receipts, self.rec.key, verdict=self.verdict(dispute_sha256="0" * 64))
        v = self.verdict()
        v["decision"] = "approver pays"
        with self.assertRaises(ValueError):
            claim.build(self.doc, self.receipts, self.rec.key, verdict=v)

    def test_lock_is_checked(self):
        act = self.doc["receipt"].get("action") or {}
        lock = {"servers": {act.get("server", ""): {"tools": {act.get("tool", ""): {"digest": "sha256:other"}}}}}
        c = claim.build(self.doc, self.receipts, self.rec.key, lock=lock)
        self.assertTrue(c["tool"]["checked"])
        self.assertTrue(claim.verify(c)["ok"])

    def test_cli(self):
        f = self.home / "d.json"
        f.write_text(json.dumps(self.doc), "utf-8")
        out = self.home / "c.json"
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

        def run(*a):
            return subprocess.run([sys.executable, "-m", "verfy", *a], capture_output=True, text=True, env=env)

        p = run("claim", "build", str(f), "--out", str(out))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Nothing was sent", p.stdout)
        p = run("claim", "verify", str(out))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("VERIFIED", p.stdout)
        self.assertIn("R8", run("claim", "rules").stdout)


class MandateSignatureTests(unittest.TestCase):
    def cart(self, token):
        return {"contents": {"payment_request": {"details": {"total": {"amount": {"currency": "USD", "value": 10}}}}, "merchant_name": "acme"}, "merchant_authorization": token}

    def test_es256_and_rs256(self):
        for t in FIX["tokens"]:
            problems, payload = mandate.verify_jws(t["token"], t["jwk"])
            self.assertEqual(problems, [], t["alg"])
            self.assertEqual(payload["iss"], "merchant.example")
            self.assertEqual(mandate.check_authorization(self.cart(t["token"]), t["jwk"]), [], t["alg"])

    def test_wrong_key_and_tampering(self):
        es, rs = FIX["tokens"]
        self.assertTrue(mandate.verify_jws(es["token"], rs["jwk"])[0])
        h, _, s = es["token"].split(".")
        evil = b64u(json.dumps({"iss": "merchant.example", "cart_hash": "evil", "exp": 4102444800}).encode())
        self.assertTrue(mandate.verify_jws(f"{h}.{evil}.{s}", es["jwk"])[0])
        found = mandate.check_authorization(self.cart(f"{h}.{evil}.{s}"), es["jwk"])
        self.assertEqual((found[0]["rule"], found[0]["verdict"]), ("VFY-MDT-006", "deny"))

    def test_eddsa_expiry_and_alg_none(self):
        k = Key.generate()
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(k.public)}

        def tok(payload, alg="EdDSA"):
            h = b64u(json.dumps({"alg": alg}).encode())
            p = b64u(json.dumps(payload).encode())
            return f"{h}.{p}." + b64u(ed25519.sign(k.secret, f"{h}.{p}".encode()))

        self.assertEqual(mandate.verify_jws(tok({"sub": "u", "exp": 4102444800}), jwk)[0], [])
        self.assertIn("the authorization has expired", mandate.verify_jws(tok({"exp": 1000}), jwk)[0])
        self.assertTrue(mandate.verify_jws(tok({}, alg="none"), jwk)[0])
        self.assertTrue(mandate.verify_jws("not-a-jwt", jwk)[0])

    def test_missing_authorization_and_intent(self):
        es = FIX["tokens"][0]
        self.assertEqual(mandate.check_authorization(self.cart(None), es["jwk"])[0]["verdict"], "deny")
        intent = {"natural_language_description": "shoes", "intent_expiry": "2099-01-01T00:00:00Z", "merchants": ["acme"]}
        self.assertEqual(mandate.check_authorization(intent, es["jwk"])[0]["verdict"], "ask")


if __name__ == "__main__":
    unittest.main()
