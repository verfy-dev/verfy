"""Tests for receipts written by any program (verfy.record, @verfy.track, Recorder), share links and Verfy's witness
statements. Run from verfy-cli/: ``python -m unittest tests.test_record``."""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import decimal
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import verfy  # noqa: E402
from verfy import ed25519, recorder, team, witness  # noqa: E402
from verfy.canonical import canonical_bytes  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.receipts import Key, Ledger, b64u, read_ledger, receipt_hash, salted_digest, verify_ledger  # noqa: E402
from verfy.recorder import Recorder, RecordError, jsonable  # noqa: E402

TOKEN = "ghp_" + "a1B2c3D4e5" * 4  # looks like a GitHub token to the secret scanner
SHARE = "https://verfy.example.com/r/vs_" + "Ab3_" * 8


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


class FakeCloud:
    """Verfy Cloud's device API, as far as recording and sharing use it."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.received: list[dict] = []
        self.share_answer: dict | None = None

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body))
        if url.endswith("/api/v1/devices/enroll"):
            return 201, {"device_id": "dev_1", "token": "atd_secret_token", "org_name": "Acme"}
        if headers.get("Authorization") != "Bearer atd_secret_token":
            return 401, {"title": "unauthorized"}
        if url.endswith("/api/v1/receipts/batch"):
            new = [r for r in body["receipts"] if receipt_hash(r) not in {receipt_hash(x) for x in self.received}]
            self.received.extend(new)
            return 200, {"accepted": len(new), "duplicates": len(body["receipts"]) - len(new)}
        if url.endswith("/api/v1/shares"):
            if body.get("kind") == "receipt" and body.get("receipt_hash") not in {receipt_hash(x) for x in self.received}:
                return 404, {"title": "Receipt not found.", "code": "not_found"}
            return 201, self.share_answer or {"id": "sh_1", "kind": body["kind"], "url": SHARE if body["kind"] == "receipt" else SHARE.replace("/r/", "/a/"), "expires_at": None}
        return 404, {"title": "not found"}

    def paths(self) -> list[str]:
        return [u.split("/api/v1/", 1)[1] for _, u, _ in self.calls]


class RecordBasics(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.rec = Recorder(agent="refund-bot", home=self.home, upload="off", session="run-1")

    def test_a_record_is_a_signed_chained_receipt(self):
        r1 = self.rec.record("refund", system="stripe", kind="payment", args={"order": "A-1", "amount": 4999}, result={"id": "re_1"})
        r2 = self.rec.record("send_email", system="gmail", kind="message")
        self.assertEqual((r1["seq"], r2["seq"]), (0, 1))
        self.assertEqual(r2["prev"], receipt_hash(r1))
        self.assertEqual(r1["agent"], "refund-bot")
        self.assertEqual(r1["session"], "run-1")
        self.assertEqual(r1["action"]["server"], "stripe")
        self.assertEqual(r1["action"]["tool"], "refund")
        self.assertEqual(r1["action"]["kind"], "payment")
        self.assertNotIn("args", r1["action"])
        self.assertEqual(r1["decision"], {"verdict": "allow", "rules": [], "policy_sha256": "none"})
        self.assertEqual(r1["outcome"]["status"], "ok")
        self.assertEqual(r1["action"]["args_sha256"], salted_digest({"order": "A-1", "amount": 4999}, self.rec.key.hash_salt()))
        self.assertEqual(r1["outcome"]["result_sha256"], salted_digest({"id": "re_1"}, self.rec.key.hash_salt()))
        self.assertIsNone(r2["outcome"]["result_sha256"])
        self.assertEqual(r1["kid"], self.rec.kid)
        res = self.rec.verify()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["count"], 2)
        self.assertEqual(read_ledger(self.home / "ledger.jsonl"), [r1, r2])

    def test_the_key_is_made_once_and_kept_private(self):
        key_file = self.home / "key.json"
        self.assertTrue(key_file.exists())
        again = Recorder(home=self.home, upload="off")
        self.assertEqual(again.kid, self.rec.kid)
        self.assertEqual(again.public_key, self.rec.public_key)
        if os.name != "nt":
            self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)

    def test_arguments_are_kept_only_when_asked_and_secrets_are_hidden(self):
        r = self.rec.record("deploy", system="github", kind="deploy", args={"token": TOKEN, "ref": "main"}, include_args=True)
        self.assertEqual(r["action"]["args"]["ref"], "main")
        self.assertNotIn(TOKEN, json.dumps(r))
        self.assertTrue(self.rec.verify()["ok"])
        everyone = Recorder(home=self.home, upload="off", include_args=True)
        self.assertIn("args", everyone.record("x", args={"a": 1})["action"])
        self.assertNotIn("args", everyone.record("x", args={"a": 1}, include_args=False)["action"])

    def test_who_approved_is_kept(self):
        r = self.rec.record("refund", kind="payment", approved_by="alice@example.com")
        self.assertEqual(r["decision"]["approved_by"], "alice@example.com")

    def test_records_and_hook_receipts_share_one_chain(self):
        led = Ledger(self.home / "ledger.jsonl", self.rec.key)
        led.append(agent="claude-code", session="s", action={"server": "", "tool": "Bash", "arguments": {"command": "ls"}},
                   decision={"verdict": "allow", "kind": "read", "findings": []}, outcome={"status": "ok", "result_sha256": None},
                   policy_sha256="sha256:" + "0" * 64)
        self.rec.record("refund", kind="payment")
        led.append(agent="claude-code", session="s", action={"server": "", "tool": "Bash", "arguments": {"command": "pwd"}},
                   decision={"verdict": "allow", "kind": "read", "findings": []}, outcome={"status": "ok", "result_sha256": None},
                   policy_sha256="sha256:" + "0" * 64)
        res = verify_ledger(read_ledger(self.home / "ledger.jsonl"), self.rec.key.public)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["count"], 3)


class Refusals(unittest.TestCase):
    """Nothing Verfy Cloud would refuse is ever written: one refused receipt would stop every later upload."""

    def setUp(self):
        self.home = tmpdir(self)
        self.rec = Recorder(home=self.home, upload="off")
        self.ledger = self.home / "ledger.jsonl"

    def refused(self, **kw):
        before = self.ledger.read_bytes() if self.ledger.exists() else b""
        action = kw.pop("action", "act")
        with self.assertRaises(RecordError):
            self.rec.record(action, **kw)
        after = self.ledger.read_bytes() if self.ledger.exists() else b""
        self.assertEqual(before, after, "a refused record must not change the ledger")

    def test_bad_names(self):
        self.refused(action="")
        self.refused(action="   ")
        self.refused(kind="Payment")
        self.refused(kind="two words")
        self.refused(kind="x" * 41)
        self.refused(status="done")
        self.refused(system="a\x00b")
        self.refused(action="bad\ud800")
        self.refused(approved_by="x" * 101)
        self.refused(session="")

    def test_length_counts_like_the_cloud(self):
        self.rec.record("a" * 200)
        self.rec.record("é" * 200)
        self.refused(action="a" * 201)
        self.refused(action="😀" * 101)  # 202 UTF-16 code units
        self.rec.record("😀" * 100)

    def test_stored_arguments_are_checked_hashed_ones_only_for_unicode(self):
        self.refused(args={"note": "a\x00b"}, include_args=True)
        self.rec.record("act", args={"note": "a\x00b"})  # only hashed: fine
        self.refused(args={"note": "bad\udc80"})
        self.refused(result={"note": "bad\udc80"})

    def test_size_limits(self):
        self.refused(args={"blob": "x" * 20_000}, include_args=True)
        self.refused(args={"items": list(range(1001))}, include_args=True)
        self.rec.record("act", args={"blob": "x" * 20_000})  # hashed only
        self.rec.record("act", args={"items": list(range(500))}, include_args=True)
        for r in read_ledger(self.ledger):
            self.assertLessEqual(len(json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode()), 16 * 1024)

    def test_values_that_cannot_be_recorded(self):
        self.refused(args={"x": object()})
        self.refused(args={"x": compile("1", "s", "eval")})
        deep: dict = {}
        cur = deep
        for _ in range(70):
            cur["a"] = {}
            cur = cur["a"]
        self.refused(args=deep)

    def test_bad_settings(self):
        with self.assertRaises(RecordError):
            Recorder(home=self.home, upload="sometimes")
        with self.assertRaises(RecordError):
            Recorder(home=self.home, on_error="ignore")
        with self.assertRaises(RecordError):
            Recorder(agent="", home=self.home)


@dataclasses.dataclass
class Order:
    id: str
    amount: decimal.Decimal


class Values(unittest.TestCase):
    def test_conversions(self):
        when = dt.datetime(2026, 11, 16, 10, 0, tzinfo=dt.timezone.utc)
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        got = jsonable({"amount": decimal.Decimal("49.99"), "when": when, "day": dt.date(2026, 11, 16), "id": u,
                        "tags": {"b", "a"}, "pair": (1, 2), "raw": b"abc", "big": 2**60, "nan": float("nan"),
                        "inf": float("inf"), "order": Order("A-1", decimal.Decimal("5.00")), 3: "three", "path": Path("x")})
        self.assertEqual(got["amount"], "49.99")
        self.assertEqual(got["when"], "2026-11-16T10:00:00+00:00")
        self.assertEqual(got["day"], "2026-11-16")
        self.assertEqual(got["id"], str(u))
        self.assertEqual(got["tags"], ["a", "b"])
        self.assertEqual(got["pair"], [1, 2])
        self.assertEqual(got["raw"], {"$bytes": 3, "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"})
        self.assertEqual(got["big"], str(2**60))
        self.assertEqual((got["nan"], got["inf"]), ("NaN", "Infinity"))
        self.assertEqual(got["order"], {"id": "A-1", "amount": "5.00"})
        self.assertEqual(got["3"], "three")
        self.assertEqual(got["path"], "x")
        self.assertEqual(jsonable(2**53 - 1), 2**53 - 1)
        self.assertEqual(jsonable(-(2**53)), str(-(2**53)))
        self.assertEqual(jsonable(object(), strict=False), {"$type": "builtins.object"})
        with self.assertRaises(RecordError):
            jsonable(object())

    def test_the_same_data_gives_the_same_hash(self):
        rec = Recorder(home=tmpdir(self), upload="off")
        a = rec.record("x", args={"tags": {"b", "a"}, "n": decimal.Decimal("1.10")})
        b = rec.record("x", args={"n": decimal.Decimal("1.10"), "tags": {"a", "b"}})
        self.assertEqual(a["action"]["args_sha256"], b["action"]["args_sha256"])


class Concurrency(unittest.TestCase):
    def test_threads_never_fork_the_chain(self):
        home = tmpdir(self)
        rec = Recorder(home=home, upload="off")
        errors: list[BaseException] = []

        def work(n: int) -> None:
            try:
                for i in range(25):
                    rec.record("act", args={"thread": n, "i": i})
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        res = rec.verify()
        self.assertTrue(res["ok"], res["errors"][:3])
        self.assertEqual(res["count"], 200)

    def test_processes_share_one_key_and_one_chain(self):
        home = tmpdir(self)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from verfy import Recorder\n"
                "r = Recorder(home=sys.argv[2], upload='off')\n"
                "[r.record('act', args={'p': sys.argv[3], 'i': i}) for i in range(20)]\n")
        env = {**os.environ, "VERFY_PURE_PYTHON": os.environ.get("VERFY_PURE_PYTHON", "")}
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT / "src"), str(home), str(n)], env=env) for n in range(3)]
        for p in procs:
            self.assertEqual(p.wait(timeout=180), 0)
        receipts = read_ledger(home / "ledger.jsonl")
        self.assertEqual(len(receipts), 60)
        self.assertEqual(len({r["kid"] for r in receipts}), 1, "two processes made two keys")
        key = Key.load(home / "key.json")
        res = verify_ledger(receipts, key.public)
        self.assertTrue(res["ok"], res["errors"][:3])


class Tracking(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.rec = Recorder(agent="bot", home=self.home, upload="off")

    def receipts(self) -> list[dict]:
        return read_ledger(self.home / "ledger.jsonl")

    def test_a_tracked_call_records_its_arguments_and_result(self):
        class Mailer:
            @self.rec.track("send_email", system="gmail", kind="message")
            def send(self, to, subject, body="", **extra):
                return {"id": "m1", "to": to}

        out = Mailer().send("a@example.com", "hi", cc="b@example.com")
        self.assertEqual(out, {"id": "m1", "to": "a@example.com"})
        r = self.receipts()[-1]
        expected = {"to": "a@example.com", "subject": "hi", "cc": "b@example.com"}
        self.assertEqual(r["action"]["args_sha256"], salted_digest(expected, self.rec.key.hash_salt()))
        self.assertEqual(r["outcome"], {"status": "ok", "result_sha256": salted_digest(out, self.rec.key.hash_salt())})
        self.assertEqual(Mailer.send.__name__, "send")

    def test_chosen_arguments(self):
        @self.rec.track("refund", system="stripe", kind="payment", args=lambda order, amount, **_: {"order": order, "amount": amount})
        def refund(order, amount, client=None):
            return None

        refund("A-1", 4999, client=object())
        r = self.receipts()[-1]
        self.assertEqual(r["action"]["args_sha256"], salted_digest({"order": "A-1", "amount": 4999}, self.rec.key.hash_salt()))
        self.assertIsNone(r["outcome"]["result_sha256"])

    def test_a_failed_call_is_recorded_and_raised_again(self):
        @self.rec.track("charge", kind="payment")
        def charge(amount):
            raise RuntimeError("card declined")

        with self.assertRaisesRegex(RuntimeError, "card declined"):
            charge(10)
        r = self.receipts()[-1]
        self.assertEqual(r["outcome"]["status"], "error")
        self.assertIsNotNone(r["outcome"]["result_sha256"])

    def test_async_functions(self):
        @self.rec.track("fetch", system="api", kind="network")
        async def fetch(url):
            await asyncio.sleep(0)
            return {"status": 200}

        @self.rec.track("explode", kind="exec")
        async def explode():
            raise ValueError("nope")

        self.assertEqual(asyncio.run(fetch("https://example.com")), {"status": 200})
        with self.assertRaises(ValueError):
            asyncio.run(explode())
        self.assertEqual([r["outcome"]["status"] for r in self.receipts()], ["ok", "error"])

    def test_objects_that_are_not_data_do_not_stop_the_call(self):
        @self.rec.track("use", kind="other")
        def use(client):
            return client

        c = object()
        self.assertIs(use(c), c)
        self.assertEqual(len(self.receipts()), 1)

    def test_a_failed_record_does_not_undo_the_action(self):
        calls = []

        @self.rec.track("refund", kind="payment")
        def refund():
            calls.append(1)
            return "done"

        with mock.patch.object(Recorder, "_write", side_effect=OSError("disk full")), self.assertLogs("verfy", logging.ERROR):
            self.assertEqual(refund(), "done")
        self.assertEqual(calls, [1])
        strict = Recorder(home=self.home, upload="off", on_error="raise")

        @strict.track("refund", kind="payment")
        def refund2():
            return "done"

        with mock.patch.object(Recorder, "_write", side_effect=OSError("disk full")), self.assertRaises(OSError):
            refund2()

    def test_a_record_too_big_to_keep_falls_back_to_the_hash(self):
        rec = Recorder(home=self.home, upload="off", include_args=True)

        @rec.track("upload", kind="write")
        def upload(data):
            return len(data)

        with self.assertLogs("verfy", logging.WARNING):
            self.assertEqual(upload("x" * 50_000), 50_000)
        r = self.receipts()[-1]
        self.assertNotIn("args", r["action"])
        self.assertTrue(rec.verify()["ok"])

    def test_a_with_block(self):
        with self.rec.action("delete_rows", system="postgres", kind="delete", args={"table": "carts"}) as act:
            act.result = {"deleted": 3}
        self.assertEqual(act.receipt["outcome"]["result_sha256"], salted_digest({"deleted": 3}, self.rec.key.hash_salt()))
        with self.assertRaises(KeyError):
            with self.rec.action("delete_rows", kind="delete") as act2:
                raise KeyError("x")
        self.assertEqual(act2.receipt["outcome"]["status"], "error")
        with self.assertRaises(RecordError):
            self.rec.action("x", args={"o": object()})  # refused before the block runs

    def test_bad_decorator_settings_fail_at_once(self):
        with self.assertRaises(RecordError):
            self.rec.track("", kind="other")
        with self.assertRaises(RecordError):
            self.rec.track("x", kind="Not A Kind")

    def test_module_level_functions_use_one_recorder_made_on_first_use(self):
        home = tmpdir(self)
        with mock.patch.dict(os.environ, {"VERFY_HOME": str(home), "VERFY_AGENT": "env-bot"}), mock.patch.object(recorder, "_default", None):
            @verfy.track("ping", kind="network")
            def ping():
                return "pong"

            self.assertFalse((home / "key.json").exists(), "decorating must not create a key")
            self.assertEqual(ping(), "pong")
            r = verfy.record("refund", kind="payment")
            self.assertEqual(r["agent"], "env-bot")
            self.assertEqual(len(read_ledger(home / "ledger.jsonl")), 2)


class Uploads(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.cloud = FakeCloud()

    def enroll(self, rec: Recorder) -> None:
        team.enroll(self.home, "https://verfy.example.com", "CODE", rec.key, transport=self.cloud)

    def test_auto_upload_goes_through_sync_soon_and_off_never(self):
        auto = Recorder(home=self.home)
        with mock.patch("verfy.team.sync_soon") as soon:
            auto.record("x")
        soon.assert_called_once_with(self.home)
        off = Recorder(home=self.home, upload="off")
        with mock.patch("verfy.team.sync_soon") as soon:
            off.record("x")
        soon.assert_not_called()

    def test_now_uploads_at_once_and_falls_back_when_it_fails(self):
        rec = Recorder(home=self.home, upload="now")
        with mock.patch("verfy.team.sync_soon") as soon:
            rec.record("x")  # not enrolled: nothing to upload to
        soon.assert_called_once()
        self.enroll(rec)
        with mock.patch("verfy.team.http_transport", self.cloud):
            rec.record("y")
        self.assertEqual(len(self.cloud.received), 2)
        with mock.patch("verfy.team.http_transport", side_effect=team.TeamError("offline")), \
                mock.patch("verfy.team.sync_soon") as soon, mock.patch("time.sleep"), self.assertLogs("verfy", logging.WARNING):
            rec.record("z")  # the receipt is written; the upload waits
        soon.assert_called_once()
        self.assertEqual(len(read_ledger(self.home / "ledger.jsonl")), 3)

    def test_a_frozen_program_does_not_start_itself(self):
        rec = Recorder(home=self.home)
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(sys, "executable", "/opt/shop/shop-server"), \
                mock.patch("verfy.team.sync_soon") as soon:
            rec.record("x")
        soon.assert_not_called()

    def test_share_uploads_first_then_asks_for_a_link(self):
        rec = Recorder(home=self.home, upload="off")
        self.enroll(rec)
        r1 = rec.record("refund", kind="payment")
        rec.record("other")
        url = rec.share(r1, expires_in_days=30, label="for the customer", transport=self.cloud)
        self.assertEqual(url, SHARE)
        self.assertEqual(self.cloud.paths()[-2:], ["receipts/batch", "shares"])
        body = self.cloud.calls[-1][2]
        self.assertEqual(body, {"kind": "receipt", "receipt_hash": receipt_hash(r1), "expires_in_days": 30, "label": "for the customer"})
        self.assertEqual(rec.share(transport=self.cloud), SHARE)  # the last receipt by default
        self.assertEqual(self.cloud.calls[-1][2]["receipt_hash"], receipt_hash(read_ledger(self.home / "ledger.jsonl")[-1]))
        self.assertEqual(rec.share(r1["id"], transport=self.cloud), SHARE)
        agent_url = rec.share_agent(transport=self.cloud)
        self.assertIn("/a/vs_", agent_url)
        self.assertEqual(self.cloud.calls[-1][2], {"kind": "agent"})

    def test_share_refusals(self):
        rec = Recorder(home=self.home, upload="off")
        with self.assertRaises(RecordError):
            rec.share(transport=self.cloud)  # nothing recorded yet
        r = rec.record("x")
        with self.assertRaises(team.TeamError):
            rec.share(r, transport=self.cloud)  # not enrolled
        self.enroll(rec)
        other = Recorder(home=tmpdir(self), upload="off").record("y")
        with self.assertRaises(RecordError):
            rec.share(other, transport=self.cloud)
        with self.assertRaises(RecordError):
            rec.share("rcpt_missing", transport=self.cloud)
        for bad in (0, 3651, True, 1.5):
            with self.assertRaises(team.TeamError):
                rec.share(r, expires_in_days=bad, transport=self.cloud)
        for answer in ({"url": "http://verfy.example.com/r/vs_" + "a" * 32}, {"url": "https://evil.example/x"}, {"id": "x"}):
            self.cloud.share_answer = answer
            with self.assertRaises(team.TeamError):
                rec.share(r, transport=self.cloud)


def make_witness(seed: bytes = b"\x07" * 32):
    pub = ed25519.public_key(seed)

    def sign(body: dict) -> dict:
        body = {**body, "v": witness.VERSION, "kid": witness.witness_kid(pub)}
        return {**body, "sig": b64u(ed25519.sign(seed, canonical_bytes(body)))}
    return pub, sign


class Witness(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        self.rec = Recorder(home=self.home, upload="off")
        self.receipt = self.rec.record("refund", system="stripe", kind="payment", args={"amount": 5})
        self.pub, self.sign = make_witness()
        self.statement = self.sign({"type": "receipt", "issuer": "https://verfy.dev", "issued_at": "2026-11-16T10:00:00.000Z", "subject": {
            "receipt": {"hash": receipt_hash(self.receipt), "id": self.receipt["id"], "seq": 0, "received_at": "2026-11-16T09:00:00.000Z"},
            "chain": {"id": self.rec.kid, "public_key": self.rec.public_key, "head_seq": 0}}})
        self.keys = {witness.witness_kid(self.pub): self.pub}

    def test_the_shared_vector_matches(self):
        v = json.loads((ROOT / "tests" / "fixtures" / "witness.json").read_text("utf-8"))
        seed = recorder_b64(v["seed"])
        self.assertEqual(b64u(ed25519.public_key(seed)), v["public"])
        body = {k: x for k, x in v["statement"].items() if k != "sig"}
        self.assertEqual(canonical_bytes(body).decode(), v["canonical"])
        self.assertEqual(b64u(ed25519.sign(seed, canonical_bytes(body))), v["statement"]["sig"])
        self.assertTrue(witness.verify_statement(v["statement"], ed25519.public_key(seed)))

    def test_statement_signatures(self):
        self.assertTrue(witness.verify_statement(self.statement, self.pub))
        changed = json.loads(json.dumps(self.statement))
        changed["subject"]["receipt"]["received_at"] = "2026-11-17T09:00:00.000Z"
        self.assertFalse(witness.verify_statement(changed, self.pub))
        other_pub, _ = make_witness(b"\x09" * 32)
        self.assertFalse(witness.verify_statement(self.statement, other_pub))
        for bad in (None, [], {}, {**self.statement, "v": "verfy.witness/2"}, {**self.statement, "sig": "!!"}, {**self.statement, "sig": "AAAA"}):
            self.assertFalse(witness.verify_statement(bad, self.pub))

    def test_a_whole_proof(self):
        proof = {"kind": "receipt", "receipt": self.receipt, "witness": self.statement}
        res = witness.check_proof(proof, self.keys)
        self.assertTrue(res["ok"], res["errors"])
        self.assertEqual((res["witness"], res["receipt"]), (True, True))
        other = self.rec.record("other")
        res = witness.check_proof({**proof, "receipt": other}, self.keys)
        self.assertFalse(res["ok"])
        forged = {**self.receipt, "outcome": {"status": "error", "result_sha256": None}}
        st = self.sign({"type": "receipt", "subject": {"receipt": {"hash": receipt_hash(forged)}, "chain": {"public_key": self.rec.public_key}}})
        res = witness.check_proof({"receipt": forged, "witness": st}, self.keys)
        self.assertFalse(res["ok"])
        self.assertIn("own signature", " ".join(res["errors"]))
        self.assertFalse(witness.check_proof({"witness": None}, self.keys)["ok"])
        self.assertFalse(witness.check_proof(proof, {})["ok"])
        self.assertTrue(witness.check_proof(self.statement, self.keys)["ok"])  # a bare statement

    def test_published_keys(self):
        good = {"kid": witness.witness_kid(self.pub), "alg": "Ed25519", "public": b64u(self.pub)}
        keys = witness.keys_from({"keys": [good, {**good, "kid": "vw_0000000000000000"}, {"public": "x"}, "junk"]})
        self.assertEqual(keys, {good["kid"]: self.pub})
        self.assertEqual(witness.keys_from(None), {})
        with self.assertRaises(ValueError):
            witness.fetch_keys("http://verfy.dev/.well-known/verfy-witness.json")


def recorder_b64(s: str) -> bytes:
    from verfy.receipts import unb64u
    return unb64u(s)


class Commands(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        patcher = mock.patch.dict(os.environ, {"VERFY_HOME": str(self.home), "VERFY_AGENT": "", "VERFY_SESSION": ""})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)), mock.patch("verfy.team.sync_soon"):
            try:
                code = cli_main(list(argv))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
                err.write(str(e.code))
        return code, out.getvalue(), err.getvalue()

    def test_record_from_the_command_line(self):
        code, out, _ = self.run_cli("record", "refund", "--system", "stripe", "--kind", "payment", "--args", '{"amount": 5}', "--agent", "shop", "--json")
        self.assertEqual(code, 0)
        r = json.loads(out)["receipt"]
        self.assertEqual((r["agent"], r["session"], r["action"]["tool"]), ("shop", "cli", "refund"))
        code, out, _ = self.run_cli("record", "send", "--result", "-", stdin='{"id": 1}')
        self.assertEqual(code, 0)
        self.assertIn("Recorded rcpt_", out)
        self.assertEqual(len(read_ledger(self.home / "ledger.jsonl")), 2)
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED", out)

    def test_record_refusals(self):
        self.assertNotEqual(self.run_cli("record", "x", "--args", "{bad")[0], 0)
        self.assertNotEqual(self.run_cli("record", "x", "--args", "-", "--result", "-", stdin="{}")[0], 0)
        code, _, err = self.run_cli("record", "x", "--kind", "Bad Kind")
        self.assertEqual(code, 3)
        self.assertIn("kind must be", err)

    def test_share_needs_a_key_and_receipts(self):
        code, _, err = self.run_cli("share")
        self.assertNotEqual(code, 0)
        self.assertIn("no signing key", err)

    def test_share_from_the_command_line(self):
        cloud = FakeCloud()
        rec = Recorder(home=self.home, upload="off")
        team.enroll(self.home, "https://verfy.example.com", "CODE", rec.key, transport=cloud)
        first = rec.record("a")
        rec.record("b")
        with mock.patch("verfy.team.http_transport", cloud):
            code, out, _ = self.run_cli("share", "0")
            self.assertEqual(code, 0)
            self.assertIn(SHARE, out)
            self.assertEqual(cloud.calls[-1][2]["receipt_hash"], receipt_hash(first))
            code, out, _ = self.run_cli("share", "--agent", "--json")
            self.assertEqual(json.loads(out)["url"], SHARE.replace("/r/", "/a/"))
            code, out, _ = self.run_cli("record", "c", "--share")
            self.assertIn("Share link: " + SHARE, out)
            self.assertNotEqual(self.run_cli("share", "rcpt_nope")[0], 0)
            self.assertNotEqual(self.run_cli("share", "seven")[0], 0)

    def test_witness_verify_command(self):
        rec = Recorder(home=self.home, upload="off")
        receipt = rec.record("refund")
        pub, sign = make_witness()
        st = sign({"type": "receipt", "issuer": "https://verfy.dev", "issued_at": "2026-11-16T10:00:00.000Z", "subject": {
            "receipt": {"hash": receipt_hash(receipt), "seq": 0, "received_at": "2026-11-16T09:00:00.000Z"},
            "chain": {"id": rec.kid, "public_key": rec.public_key, "head_seq": 0}}})
        f = self.home / "proof.json"
        f.write_text(json.dumps({"receipt": receipt, "witness": st}), "utf-8")
        code, out, _ = self.run_cli("witness", "verify", str(f), "--key", b64u(pub))
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFIED", out)
        st["subject"]["receipt"]["seq"] = 3
        f.write_text(json.dumps({"receipt": receipt, "witness": st}), "utf-8")
        code, out, _ = self.run_cli("witness", "verify", str(f), "--key", b64u(pub))
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out)
        with mock.patch("verfy.witness.fetch_keys", return_value={witness.witness_kid(pub): pub}):
            code, out, _ = self.run_cli("witness", "verify", "-", "--json", stdin=json.dumps({"witness": sign({"type": "agent", "subject": {}})}))
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["ok"])


if __name__ == "__main__":
    unittest.main()
