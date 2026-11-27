"""0.31.0: passkey approvals in the receipt and checked offline; personal data: phone lists and passport zones."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import ed25519, passkeys, recorder, team  # noqa: E402
from verfy.precheck import check  # noqa: E402
from verfy.recorder import Recorder  # noqa: E402
from verfy.receipts import read_ledger  # noqa: E402

VECTORS = json.loads((ROOT / "tests" / "fixtures" / "passkey_proofs.json").read_text("utf-8"))
ORIGIN = "https://verfy.example.com"
USER = "00000000-0000-4000-8000-0000000000a1"
BIG = {"id": "big-refund", "kind": "payment", "amount": "amount", "over": 500, "then": "ask"}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def eddsa_proof(approval_id: str, args_sha256: str, *, approve: bool = True, origin: str = ORIGIN, flags: int = 0x05) -> dict:
    """A passkey assertion made here with an Ed25519 key, as a browser would send it."""
    secret = ed25519.generate_secret()
    client = json.dumps({"type": "webauthn.get", "challenge": passkeys.approval_challenge(approval_id, args_sha256, approve, USER), "origin": origin}).encode()
    auth = hashlib.sha256(b"verfy.example.com").digest() + bytes([flags]) + (3).to_bytes(4, "big")
    sig = ed25519.sign(secret, auth + hashlib.sha256(client).digest())
    return {"v": passkeys.PROOF_VERSION, "method": "passkey", "decision": "approve" if approve else "reject", "user_id": USER,
            "credential_id": "cred-1", "alg": -8, "public_key": {"kty": "OKP", "crv": "Ed25519", "x": b64u(ed25519.public_key(secret))},
            "client_data_json": b64u(client), "authenticator_data": b64u(auth), "signature": b64u(sig)}


class ProofChecks(unittest.TestCase):
    def check(self, proof, **kw):
        args = {"approval_id": VECTORS["approval_id"], "args_sha256": VECTORS["args_sha256"], "origin": VECTORS["origin"], **kw}
        return passkeys.verify_proof(proof, **args)

    def test_vectors_from_node(self):
        algs = set()
        for p in VECTORS["proofs"]:
            self.assertEqual(self.check(p), [], p["alg"])
            algs.add(p["alg"])
        self.assertEqual(algs, {-7, -8, -257})

    def test_another_call_request_or_site(self):
        p = VECTORS["proofs"][0]
        self.assertIn("the passkey signed a different request, arguments or decision", self.check(p, args_sha256="sha256:" + "00" * 32))
        self.assertIn("the passkey signed a different request, arguments or decision", self.check(p, approval_id="other"))
        self.assertTrue(any("not 'https://evil.example'" in x for x in self.check(p, origin="https://evil.example")))
        flipped = dict(p, decision="reject")
        self.assertIn("the passkey signed a different request, arguments or decision", self.check(flipped))

    def test_forged_or_broken(self):
        for p in VECTORS["proofs"][:3]:
            sig = bytearray(base64.urlsafe_b64decode(p["signature"] + "=="))
            sig[-1] ^= 1
            self.assertIn("the passkey's signature does not check out", self.check(dict(p, signature=b64u(bytes(sig)))), p["alg"])
        es = VECTORS["proofs"][0]
        off = dict(es, public_key=dict(es["public_key"], y=es["public_key"]["x"]))  # not a point on P-256
        self.assertIn("the passkey's signature does not check out", self.check(off))
        rs = VECTORS["proofs"][2]
        small = dict(rs, public_key=dict(rs["public_key"], n=b64u((2**1023 + 1).to_bytes(128, "big"))))
        self.assertIn("the passkey's signature does not check out", self.check(small))
        self.assertIn("unknown key type -999", self.check(dict(es, alg=-999)))
        self.assertEqual(self.check(dict(es, client_data_json="!!")), ["the proof is not readable"])
        self.assertEqual(self.check({"v": "x"}), ["not a Verfy passkey proof"])
        self.assertFalse(passkeys.verify_es256(es["public_key"], b"m", b"\x30\x02\x02\x00"))

    def test_person_not_verified(self):
        p = eddsa_proof("apr_1", "sha256:" + "11" * 32, flags=0x01)
        self.assertIn("the passkey did not verify the person (Face ID, fingerprint or PIN)",
                      passkeys.verify_proof(p, approval_id="apr_1", args_sha256="sha256:" + "11" * 32, origin=ORIGIN))

    def test_record_keeps_only_what_a_check_needs(self):
        good = VECTORS["proofs"][0]
        state = {"required": 2, "proofs": [dict(good, extra="x"), {"method": "dashboard"}, dict(good, signature="A" * 5000), good, good]}
        rec = passkeys.approval_record("apr_9", state, "https://verfy.dev")
        self.assertEqual((rec["id"], rec["required"], rec["origin"], len(rec["proofs"])), ("apr_9", 2, "https://verfy.dev", 2))
        self.assertNotIn("extra", rec["proofs"][0])
        self.assertNotIn("proofs", passkeys.approval_record("apr_9", {"proofs": None}, "https://verfy.dev"))


class ApprovalCloud:
    """Verfy Cloud's approval queue, answering with a passkey proof made over what the device asked."""

    def __init__(self, proof_args=None):
        self.requests: list[dict] = []
        self.proof_args = proof_args

    def __call__(self, method, url, body, headers):
        if url.endswith("/api/v1/devices/enroll"):
            return 201, {"device_id": "dev_1", "token": "atd_secret_token", "org_name": "Acme"}
        if url.endswith("/api/v1/approvals") and method == "POST":
            self.requests.append(body)
            return 201, {"id": "apr_1", "status": "pending"}
        if "/api/v1/approvals/" in url:
            args = self.proof_args or self.requests[0]["args_sha256"]
            return 200, {"id": "apr_1", "status": "approved", "decided_by": "Alice", "required": 1, "passkey": True,
                         "proofs": [eddsa_proof("apr_1", args)]}
        return 404, {"title": "not found"}


class ReceiptCarriesTheProof(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"VERFY_HOME": str(self.home)})
        self.env.start()
        p = mock.patch.object(recorder, "POLL_SECONDS", 0.0)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_refund(self, cloud) -> dict:
        r = Recorder(agent="bot", home=self.home, upload="off", rules=[BIG], on_ask="team", approval_timeout=10)
        team.enroll(self.home, ORIGIN, "CODE", r.key, transport=cloud)
        r._team_transport = cloud
        args = {"amount": 900, "order": "A-1042"}
        d = r.guard("refund", system="stripe", kind="payment", args=args)
        return r.record("refund", system="stripe", kind="payment", args=args, decision=d)

    def verify(self) -> tuple[int, str]:
        from verfy import cli
        out = io.StringIO()
        ns = mock.Mock(ledger=str(self.home / "ledger.jsonl"), pub=None, key=None, kid=None, start_after=None, json=False)
        with redirect_stdout(out):
            code = cli.cmd_ledger_verify(ns)
        return code, out.getvalue()

    def test_proof_in_receipt_and_checked(self):
        receipt = self.run_refund(ApprovalCloud())
        appr = receipt["decision"]["approval"]
        self.assertEqual((appr["id"], appr["origin"], len(appr["proofs"])), ("apr_1", ORIGIN, 1))
        self.assertEqual(receipt["decision"]["approved_by"], "team:Alice")
        self.assertEqual(passkeys.check_ledger(read_ledger(self.home / "ledger.jsonl")), {"checked": 1, "errors": []})
        code, text = self.verify()
        self.assertEqual(code, 0, text)
        self.assertIn("1 team approval(s) signed with a passkey", text)

    def test_proof_for_other_arguments_fails_the_check(self):
        self.run_refund(ApprovalCloud(proof_args="sha256:" + "22" * 32))
        code, text = self.verify()
        self.assertEqual(code, 1)
        self.assertIn("passkey approval: the passkey signed a different request, arguments or decision", text)


class PersonalData(unittest.TestCase):
    MRZ = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"  # the ICAO 9303 specimen passport, not a real person

    def rules(self, body, policy=None):
        r = check({"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": body}}, {"home": "/h", "workspace": "/h/p", **(policy or {})})
        return [f["rule"] for f in r["findings"]]

    def test_passport_zone(self):
        self.assertIn("VFY-DLP-007", self.rules("P<UTOERIKSSON<<ANNA<MARIA\n" + self.MRZ))
        for i in (9, 19, 27, 43):  # each check digit matters
            bad = self.MRZ[:i] + str((int(self.MRZ[i]) + 1) % 10) + self.MRZ[i + 1:]
            self.assertNotIn("VFY-DLP-007", self.rules(bad), i)
        self.assertNotIn("VFY-DLP-007", self.rules(self.MRZ, {"dlp": {"personal": "off"}}))
        self.assertNotIn("VFY-DLP-007", self.rules("X" + self.MRZ))  # part of a longer token

    def test_phone_list(self):
        five = "+998 90 123 45 67, +1 (415) 555-0100, +44 20 7946 0958, +49 30 901820, (212) 555-0199"
        self.assertIn("VFY-DLP-006", self.rules(five))
        self.assertNotIn("VFY-DLP-006", self.rules(five, {"dlp": {"bulk": 6}}))
        self.assertNotIn("VFY-DLP-006", self.rules("+1 415 555 0100, (415) 555-0100, +14155550100, +1-415-555-0100, +1.415.555.0100"))
        self.assertNotIn("VFY-DLP-006", self.rules("call me on +1 415 555 0100"))  # one number is not a list
        self.assertNotIn("VFY-DLP-006", self.rules("build 20261128 1.2.3.4 port 8080", {"dlp": {"bulk": 1}}))


if __name__ == "__main__":
    unittest.main()
