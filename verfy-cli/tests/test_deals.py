"""Tests for two-party deals (verfy.deal/1) and payments tied to a mandate. Run from verfy-cli/:
``python -m unittest tests.test_deals``."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import deals, team  # noqa: E402
from verfy.canonical import digest  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.receipts import read_ledger, receipt_hash  # noqa: E402
from verfy.recorder import ActionDenied, Recorder, RecordError  # noqa: E402

TERMS = {"item": "sku-1", "price": 4999, "currency": "USD"}


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


class Deals(unittest.TestCase):
    def setUp(self):
        self.seller = Recorder(agent="seller-bot", home=tmpdir(self), upload="off")
        self.buyer = Recorder(agent="buyer-bot", home=tmpdir(self), upload="off")

    def test_both_sides_sign_the_same_terms(self):
        offer = self.seller.offer("sell", system="shop", kind="payment", counterparty="buyer-bot", terms=TERMS)
        self.assertNotIn("sku-1", json.dumps(offer["offer"]))  # the terms are not in the receipt
        deal = self.buyer.accept(json.loads(json.dumps(offer)))  # it travels as JSON
        res = deals.verify_deal(deal)
        self.assertTrue(res["ok"], res["errors"])
        self.assertEqual((res["offer_kid"], res["accept_kid"]), (self.seller.kid, self.buyer.kid))
        b = deal["accept"]["action"]
        self.assertEqual((b["tool"], b["server"], b["kind"]), ("sell", "shop", "payment"))
        self.assertEqual(b["args"]["offer_receipt"], receipt_hash(deal["offer"]))
        self.assertTrue(self.seller.verify()["ok"])
        self.assertTrue(self.buyer.verify()["ok"])

    def test_tampering_is_caught(self):
        deal = self.buyer.accept(self.seller.offer("sell", counterparty="b", terms=TERMS))
        cases = {
            "terms": {**deal, "terms": {**TERMS, "price": 1}},
            "deal id": {**deal, "deal": "deal_other"},
            "accept key": {**deal, "accept_key": self.seller.public_key},
            "offer receipt": {**deal, "offer": {**deal["offer"], "agent": "x"}},
            "not accepted": {k: v for k, v in deal.items() if k not in ("accept", "accept_key")},
            "junk": {"v": "verfy.deal/1"},
            "not a deal": [],
        }
        for name, doc in cases.items():
            self.assertFalse(deals.verify_deal(doc)["ok"], name)
        other = self.seller.offer("sell", counterparty="b", terms=TERMS)
        mixed = {**deal, "offer": other["offer"], "deal": other["deal"]}
        self.assertFalse(deals.verify_deal(mixed)["ok"])

    def test_an_offer_is_checked_before_accepting(self):
        offer = self.seller.offer("sell", counterparty="b", terms=TERMS)
        with self.assertRaises(deals.DealError):
            self.buyer.accept({**offer, "terms": {**TERMS, "price": 1}})
        with self.assertRaises(RecordError):
            self.seller.accept(offer)  # one cannot accept one's own offer
        self.assertEqual(len(read_ledger(self.buyer.ledger_path)), 0)

    def test_rules_guard_both_sides(self):
        careful = Recorder(agent="buyer", home=tmpdir(self), upload="off", rules=[{"kind": "payment", "amount": "price", "over": 1000, "then": "deny"}])
        with self.assertRaises(ActionDenied):
            careful.accept(self.seller.offer("sell", kind="payment", counterparty="b", terms=TERMS))

    def test_reference_receipts_upload_without_allow_args(self):
        home = self.buyer.home
        sent = []

        def cloud(method, url, body, headers):
            if url.endswith("/devices/enroll"):
                return 201, {"device_id": "d", "token": "atd_x"}
            sent.extend(body["receipts"])
            return 200, {"accepted": len(body["receipts"]), "duplicates": 0}

        team.enroll(home, "https://verfy.example.com", "C", self.buyer.key, transport=cloud)
        self.buyer.accept(self.seller.offer("sell", counterparty="b", terms=TERMS))
        self.buyer.record_payment(49.99, "USD", payee="shop-1", mandate={"intent": "m-1"})
        self.assertEqual(self.buyer.sync(transport=cloud)["uploaded"], 2)
        self.buyer.record("note", args={"secret": "x"}, include_args=True)
        with self.assertRaises(team.TeamError):
            self.buyer.sync(transport=cloud)  # real arguments still need --allow-args
        self.assertFalse(deals.is_reference({"deal": "d", "amount": "5"}))
        self.assertFalse(deals.is_reference({"deal": 5}))
        self.assertFalse(deals.is_reference({}))


class DealWitness(unittest.TestCase):
    """verfy.deals.witness_deal against Verfy Cloud's POST /api/v1/verify/deals (faked here; verfy-cloud tests the
    route with the deal in tests/fixtures/deal.json)."""

    def setUp(self):
        self.deal = json.loads((Path(__file__).parent / "fixtures" / "deal.json").read_text("utf-8"))["deal"]
        self.seed = b"\x05" * 32
        from verfy import ed25519, witness
        from verfy.canonical import canonical_bytes
        from verfy.receipts import b64u
        pub = ed25519.public_key(self.seed)
        self.kid = witness.witness_kid(pub)

        def sign(body):
            body = {**body, "v": witness.VERSION, "kid": self.kid}
            return {**body, "sig": b64u(ed25519.sign(self.seed, canonical_bytes(body)))}

        self.sign, self.keys_doc = sign, {"keys": [{"kid": self.kid, "alg": "Ed25519", "public": b64u(pub)}]}
        self.calls = []

    def cloud(self, answer):
        def transport(method, url, body, headers):
            self.calls.append((method, url, headers.get("Authorization")))
            if url.endswith("/.well-known/verfy-witness.json"):
                return 200, self.keys_doc
            return 200, answer
        return transport

    def test_a_signed_answer(self):
        answer = {"ok": True, "errors": [], "deal": self.deal["deal"], "offer": {"received_at": "2026-11-16T10:00:00.000Z", "log_index": 4},
                  "accept": {"received_at": None, "log_index": None}}
        answer["witness"] = self.sign({"type": "deal", "subject": {"deal": self.deal["deal"]}})
        res = deals.witness_deal(self.deal, verifier_key="vk_" + "a" * 43, url="https://verfy.example", transport=self.cloud(answer))
        self.assertEqual(res["offer"]["log_index"], 4)
        self.assertEqual(self.calls[0], ("POST", "https://verfy.example/api/v1/verify/deals", "Bearer vk_" + "a" * 43))

    def test_a_forged_or_misdirected_answer_fails(self):
        forged = {"ok": True, "deal": self.deal["deal"], "witness": {**self.sign({"type": "deal", "subject": {"deal": self.deal["deal"]}}), "issued_at": "x"}}
        other = {"ok": True, "deal": self.deal["deal"], "witness": self.sign({"type": "deal", "subject": {"deal": "deal_" + "0" * 24}})}
        for answer in (forged, other):
            with self.assertRaises(deals.DealError):
                deals.witness_deal(self.deal, verifier_key="vk_" + "a" * 43, url="https://verfy.example", transport=self.cloud(answer))
        with self.assertRaises(deals.DealError):
            deals.witness_deal(self.deal, verifier_key="sk_wrong", url="https://verfy.example", transport=self.cloud({}))

    def test_the_shared_fixture_checks(self):
        self.assertTrue(deals.verify_deal(self.deal)["ok"])


class Payments(unittest.TestCase):
    def test_a_payment_names_its_mandate_and_hides_the_details(self):
        r = Recorder(agent="pay-bot", home=tmpdir(self), upload="off")
        mandate = {"type": "cart", "merchant": "shop-1", "total": {"value": "49.99", "currency": "USD"}, "nonce": "n-1"}
        rec = r.record_payment("49.99", "USD", payee="shop-1", mandate=mandate, mandate_type="cart-mandate")
        args = rec["action"]["args"]
        self.assertEqual(args["mandate_sha256"], digest(mandate))
        self.assertEqual(args["mandate_type"], "cart-mandate")
        self.assertEqual(args["details_sha256"], r._ledger.hash({"amount": "49.99", "currency": "USD", "payee": "shop-1"}))
        self.assertNotIn("shop-1", json.dumps(rec))
        self.assertEqual(rec["action"]["kind"], "payment")
        for bad in ({"currency": ""}, {"payee": ""}, {"status": "maybe"}):
            kw = {"currency": "USD", "payee": "p", **bad}
            with self.assertRaises(RecordError):
                r.record_payment(1, kw.pop("currency"), **kw)

    def test_guard_then_record(self):
        r = Recorder(agent="pay-bot", home=tmpdir(self), upload="off", rules=[{"kind": "payment", "amount": "amount", "over": 100, "then": "ask"}],
                     on_ask=lambda req: "bob")
        d = r.guard("payment", kind="payment", args={"amount": 250})
        rec = r.record_payment(250, "USD", payee="p", decision=d)
        self.assertEqual(rec["decision"]["approved_by"], "bob")
        self.assertEqual(rec["decision"]["verdict"], "ask")


class Commands(unittest.TestCase):
    def run_cli(self, *argv, stdin: str = "") -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()), mock.patch("sys.stdin", io.StringIO(stdin)):
            try:
                code = cli_main(list(argv))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue()

    def test_deal_commands(self):
        seller = Recorder(agent="s", home=tmpdir(self), upload="off")
        buyer = Recorder(agent="b", home=tmpdir(self), upload="off")
        deal = buyer.accept(seller.offer("sell", counterparty="b", terms=TERMS))
        f = tmpdir(self) / "deal.json"
        f.write_text(json.dumps(deal), "utf-8")
        code, out = self.run_cli("deal", "verify", str(f))
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFIED", out)
        code, out = self.run_cli("deal", "verify", "-", "--json", stdin=json.dumps({**deal, "terms": {}}))
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])
        code, out = self.run_cli("deal", "hash", "-", stdin='{"b": 1, "a": 2}')
        self.assertEqual(out.strip(), digest({"a": 2, "b": 1}))


if __name__ == "__main__":
    unittest.main()
