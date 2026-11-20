"""Tests for rules that stop an agent's action before it runs (verfy.limits, Recorder.guard, guarded track/action).
Run from verfy-cli/: ``python -m unittest tests.test_guard``."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import limits, recorder, team  # noqa: E402
from verfy.receipts import read_ledger, verify_ledger  # noqa: E402
from verfy.recorder import ActionDenied, Recorder, RecordError  # noqa: E402

BIG = {"id": "big-refund", "kind": "payment", "amount": "amount", "over": 500, "then": "ask"}
DAY = {"id": "refund-day", "kind": "payment", "amount": "amount", "daily": 2000, "then": "deny"}
DROP = {"id": "no-drop", "action": "drop_*", "then": "deny"}


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


class ApprovalCloud:
    """Verfy Cloud's approval queue as far as a guard uses it."""

    def __init__(self, answers: list[str]):
        self.answers = list(answers)
        self.requests: list[dict] = []

    def __call__(self, method, url, body, headers):
        if url.endswith("/api/v1/devices/enroll"):
            return 201, {"device_id": "dev_1", "token": "atd_secret_token", "org_name": "Acme"}
        if url.endswith("/api/v1/approvals") and method == "POST":
            self.requests.append(body)
            return 201, {"id": "apr_1", "status": "pending"}
        if "/api/v1/approvals/" in url:
            status = self.answers.pop(0) if self.answers else "pending"
            return 200, {"id": "apr_1", "status": status, "decided_by": "Alice" if status == "approved" else None, "note": "too big" if status == "rejected" else None}
        return 404, {"title": "not found"}


class Rules(unittest.TestCase):
    def test_rules_are_checked(self):
        for bad in ([{"then": "maybe"}], [{"then": "ask", "over": 5}], [{"then": "ask", "amount": "a"}], [{"then": "ask", "kind": 3}],
                    [{"then": "ask", "kind": []}], [{"then": "deny", "colour": "red"}], [{"then": "deny", "over": -1, "amount": "a"}],
                    [{"then": "deny", "over": True, "amount": "a"}], [{"id": "bad id!", "then": "deny"}], [DROP, DROP], ["text"]):
            with self.assertRaises(limits.RuleError, msg=bad):
                limits.load_rules(bad)
        a, b = limits.load_rules([{"kind": "x", "then": "deny"}]), limits.load_rules([{"then": "deny", "kind": "x"}])
        self.assertEqual(a[0]["id"], b[0]["id"])
        self.assertTrue(a[0]["id"].startswith("rule-"))

    def test_what_rules_say(self):
        rules = limits.load_rules([BIG, DAY, DROP, {"system": ["prod-*", "billing"], "kind": "delete", "then": "ask"}])

        def ev(action, system="", kind="other", args=None, spent=None):
            return limits.evaluate(rules, action=action, system=system, kind=kind, args=args or {}, spent=spent or {}, agent="bot")["verdict"]

        self.assertEqual(ev("refund", kind="payment", args={"amount": 100}), "allow")
        self.assertEqual(ev("refund", kind="payment", args={"amount": 501}), "ask")
        self.assertEqual(ev("refund", kind="payment", args={"amount": "750.5"}), "ask")
        self.assertEqual(ev("refund", kind="payment", args={}), "deny")  # no amount: both limits fail closed
        self.assertEqual(ev("refund", kind="payment", args={"amount": 400}, spent={"bot|refund-day": 1700}), "deny")
        self.assertEqual(ev("refund", kind="payment", args={"amount": 400}, spent={"other|refund-day": 1900}), "allow")
        self.assertEqual(ev("drop_table"), "deny")
        self.assertEqual(ev("rows", system="prod-eu", kind="delete"), "ask")
        self.assertEqual(ev("rows", system="staging", kind="delete"), "allow")
        self.assertEqual(ev("rows", system="billing", kind="delete"), "ask")
        nested = limits.load_rules([{"kind": "payment", "amount": "payment.total", "over": 10, "then": "deny"}])
        self.assertEqual(limits.evaluate(nested, action="pay", system="", kind="payment", args={"payment": {"total": 11}}, spent={}, agent="a")["verdict"], "deny")
        for weird in (True, float("nan"), "abc", None, [5]):
            self.assertIsNone(limits.amount_at({"a": weird}, "a"))


class Guard(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)

    def rec(self, **kw) -> Recorder:
        return Recorder(agent="bot", home=self.home, upload="off", **kw)

    def receipts(self) -> list[dict]:
        return read_ledger(self.home / "ledger.jsonl")

    def test_a_denied_action_is_recorded_and_raised(self):
        r = self.rec(rules=[DROP])
        with self.assertRaises(ActionDenied) as cm:
            r.guard("drop_table", system="postgres", kind="delete", args={"table": "users"})
        e = cm.exception
        self.assertEqual(e.verdict, "deny")
        self.assertEqual(e.receipt["outcome"]["status"], "blocked")
        self.assertEqual(e.receipt["decision"]["verdict"], "deny")
        self.assertEqual(e.receipt["decision"]["rules"], ["no-drop"])
        self.assertEqual(e.receipt["decision"]["policy_sha256"], r.rules_sha)
        self.assertTrue(r.verify()["ok"])

    def test_asking_with_nobody_there_declines(self):
        r = self.rec(rules=[BIG])
        with self.assertRaises(ActionDenied) as cm:
            r.guard("refund", kind="payment", args={"amount": 900})
        self.assertEqual(cm.exception.verdict, "ask")
        self.assertEqual(cm.exception.receipt["outcome"]["status"], "declined")
        self.assertEqual(r.guard("refund", kind="payment", args={"amount": 90})["verdict"], "allow")

    def test_a_person_approves_through_a_function(self):
        asked = []
        r = self.rec(rules=[BIG], on_ask=lambda req: asked.append(req) or "alice@example.com")
        d = r.guard("refund", kind="payment", args={"amount": 900, "order": "A-1"})
        self.assertEqual(d["approved_by"], "alice@example.com")
        self.assertEqual(asked[0]["findings"][0]["rule"], "big-refund")
        rec = r.record("refund", kind="payment", args={"amount": 900, "order": "A-1"}, decision=d)
        self.assertEqual(rec["decision"]["verdict"], "ask")
        self.assertEqual(rec["decision"]["approved_by"], "alice@example.com")
        self.assertEqual(rec["decision"]["rules"], ["big-refund"])
        for answer in (False, None, "", 0):
            no = self.rec(rules=[BIG], on_ask=lambda req, a=answer: a)
            with self.assertRaises(ActionDenied):
                no.guard("refund", kind="payment", args={"amount": 900})

        def broken(req):
            raise RuntimeError("approver crashed")

        with self.assertRaises(ActionDenied) as cm:
            self.rec(rules=[BIG], on_ask=broken).guard("refund", kind="payment", args={"amount": 900})
        self.assertIn("approval function failed", str(cm.exception))

    def test_daily_limits_count_what_went_through(self):
        r = self.rec(rules=[DAY])
        r.guard("refund", kind="payment", args={"amount": 1500})
        with self.assertRaises(ActionDenied):
            r.guard("refund", kind="payment", args={"amount": 600})
        r.guard("refund", kind="payment", args={"amount": 500})  # exactly 2000 is not over
        with self.assertRaises(ActionDenied):
            r.guard("refund", kind="payment", args={"amount": 1})
        self.assertEqual(r.check("refund", kind="payment", args={"amount": 1})["verdict"], "deny")
        with mock.patch.object(limits, "today", return_value="2999-01-01"):
            r.guard("refund", kind="payment", args={"amount": 1999})  # a new day starts from 0
            self.assertEqual(r.check("refund", kind="payment", args={"amount": 2})["verdict"], "deny")
            self.assertEqual(r.check("refund", kind="payment", args={"amount": 1})["verdict"], "allow")

    def test_daily_limits_hold_across_threads(self):
        r = self.rec(rules=[DAY])
        allowed, denied = [], []

        def try_once():
            try:
                r.guard("refund", kind="payment", args={"amount": 300})
                allowed.append(1)
            except ActionDenied:
                denied.append(1)

        threads = [threading.Thread(target=try_once) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual((len(allowed), len(denied)), (6, 4))
        self.assertTrue(r.verify()["ok"])

    def test_a_denial_while_waiting_wins_over_the_approval(self):
        rules = [BIG, {"id": "day", "kind": "payment", "amount": "amount", "daily": 1000, "then": "deny"}]
        other = self.rec(rules=rules)

        def approve_after_spending(req):
            other.guard("refund", kind="payment", args={"amount": 400})  # spends most of the day while the person decides
            return "alice"

        r = self.rec(rules=rules, on_ask=approve_after_spending)
        with self.assertRaises(ActionDenied) as cm:
            r.guard("refund", kind="payment", args={"amount": 700})
        self.assertEqual(cm.exception.verdict, "deny")

    def test_guarded_track_and_action(self):
        r = self.rec(rules=[DROP, BIG])
        ran = []

        @r.track("drop_table", kind="delete")
        def drop(name):
            ran.append(name)

        with self.assertRaises(ActionDenied):
            drop("users")
        self.assertEqual(ran, [])

        @r.track("refund", kind="payment")
        def refund(order, amount):
            ran.append(order)
            return {"ok": True}

        self.assertEqual(refund("A-1", 20), {"ok": True})
        self.assertEqual(self.receipts()[-1]["decision"]["policy_sha256"], r.rules_sha)
        with self.assertRaises(ActionDenied):
            with r.action("drop_view", kind="delete"):
                ran.append("body")
        self.assertNotIn("body", ran)

        @r.track("drop_table", kind="delete", guard=False)
        def drop_anyway(name):
            ran.append(name)

        drop_anyway("tmp")
        self.assertIn("tmp", ran)
        self.assertTrue(r.verify()["ok"])

    def test_async_guard_does_not_run_a_denied_call(self):
        r = self.rec(rules=[DROP])
        ran = []

        @r.track("drop_table", kind="delete")
        async def drop():
            ran.append(1)

        with self.assertRaises(ActionDenied):
            asyncio.run(drop())
        self.assertEqual(ran, [])

    def test_without_rules_nothing_is_guarded(self):
        r = self.rec()
        self.assertEqual(r.rules, [])
        self.assertEqual(r.guard("drop_table", kind="delete")["verdict"], "allow")
        self.assertEqual(r.record("x")["decision"]["policy_sha256"], "none")

    def test_rules_from_the_policy_files(self):
        (self.home / "team").mkdir(parents=True)
        (self.home / "team" / "policy.json").write_text(json.dumps({"on_ask": "deny", "actions": [DROP]}), "utf-8")
        (self.home / "policy.json").write_text(json.dumps({"actions": [BIG]}), "utf-8")
        r = self.rec()
        self.assertEqual({x["id"] for x in r.rules}, {"team:no-drop", "big-refund"})
        with self.assertRaises(ActionDenied) as cm:
            r.guard("drop_table", kind="delete")
        self.assertEqual(cm.exception.findings[0]["rule"], "team:no-drop")
        self.assertEqual(self.rec(policy_rules=False).rules, [])
        (self.home / "policy.json").write_text(json.dumps({"actions": "deny everything"}), "utf-8")
        with self.assertRaises(RecordError):
            self.rec()

    def test_bad_settings(self):
        for kw in ({"on_ask": "maybe"}, {"approval_timeout": 5}, {"approval_timeout": 901}, {"rules": [{"then": "x"}]}):
            with self.assertRaises(RecordError, msg=kw):
                self.rec(**kw)
        with self.assertRaises(RecordError):
            self.rec().record("x", decision={"verdict": "deny"})


class TeamApproval(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        p = mock.patch.object(recorder, "POLL_SECONDS", 0.0)
        p.start()
        self.addCleanup(p.stop)

    def make(self, answers: list[str]) -> tuple[Recorder, ApprovalCloud]:
        cloud = ApprovalCloud(answers)
        r = Recorder(agent="bot", home=self.home, upload="off", rules=[BIG], on_ask="team", approval_timeout=10)
        team.enroll(self.home, "https://verfy.example.com", "CODE", r.key, transport=cloud)
        r._team_transport = cloud
        return r, cloud

    def test_approved_by_the_team(self):
        r, cloud = self.make(["pending", "approved"])
        d = r.guard("refund", system="stripe", kind="payment", args={"amount": 900, "order": "A-1042"})
        self.assertEqual(d["approved_by"], "team:Alice")
        sent = cloud.requests[0]
        self.assertEqual((sent["server_id"], sent["tool_name"], sent["kind"]), ("stripe", "refund", "payment"))
        self.assertEqual(sent["args_sha256"], r._ledger.hash({"amount": 900, "order": "A-1042"}))
        # the person deciding sees why it was asked (the amount against the limit), never the arguments themselves
        self.assertEqual(sent["findings"], [{"rule": "big-refund", "verdict": "ask", "message": "900 is over 500"}])
        self.assertNotIn("A-1042", json.dumps(sent))

    def test_rejected_expired_or_unreachable(self):
        for answers, words in ((["rejected"], "rejected"), (["expired"], "in time")):
            r, _ = self.make(answers)
            with self.assertRaises(ActionDenied) as cm:
                r.guard("refund", kind="payment", args={"amount": 900})
            self.assertIn(words, str(cm.exception))
        r = Recorder(agent="bot", home=tmpdir(self), upload="off", rules=[BIG], on_ask="team", approval_timeout=10)
        with self.assertRaises(ActionDenied) as cm:  # not enrolled
            r.guard("refund", kind="payment", args={"amount": 900})
        self.assertIn("could not reach your team", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
