"""0.29.0: stop and emergency access, observe mode, personal data, browser actions, payment limits, plain-language
rules and packs, the simulator, the daily summary, time stamps, disclosure, evidence packs, exports, disputes, agent
keys and hand-overs, mandates."""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verfy import control, daily, disclose, dispute, evidence, export, identity, mandate, plainrules, simulate, spend, tsa  # noqa: E402
from verfy import ed25519  # noqa: E402
from verfy.hook import run_pre_tool_use  # noqa: E402
from verfy.policy import load_policy, tighten  # noqa: E402
from verfy.precheck import check  # noqa: E402
from verfy.receipts import Key, Ledger, build_receipt, read_ledger, verify_ledger  # noqa: E402
from verfy.recorder import ActionDenied, Recorder  # noqa: E402

POL = {"home": "/home/you", "workspace": "/home/you/project"}


def _pol(extra=None):
    return load_policy({**POL, **(extra or {})})


class Home(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"VERFY_HOME": str(self.home)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class FixtureTests(unittest.TestCase):
    def test_control_fixtures(self):
        data = json.loads((ROOT / "tests" / "fixtures" / "control.json").read_text("utf-8"))
        for c in data["cases"]:
            with self.subTest(c["name"]):
                r = check(c["action"], {**data["policy"], **c["policy"]}, c["context"])
                got = {"verdict": r["verdict"], "kind": r["kind"], "findings": [{k: f[k] for k in ("rule", "verdict", "message", "waived") if k in f} for f in r["findings"]]}
                for k in ("would", "breakglass"):
                    if k in r:
                        got[k] = r[k]
                self.assertEqual(got, c["expect"])


class ControlTests(Home):
    def test_stop_injects_and_blocks_everything(self):
        control.stop(self.home, None, "incident 7")
        pol = control.inject(_pol(), self.home)
        r = check({"tool": "Bash", "arguments": {"command": "ls"}}, pol)
        self.assertEqual(r["verdict"], "deny")
        self.assertIn("incident 7", r["findings"][0]["message"])
        control.resume(self.home)
        self.assertNotIn("stop", control.inject(_pol(), self.home))

    def test_stop_one_agent_through_the_hook(self):
        control.stop(self.home, "cursor")
        get = lambda cwd: control.inject(_pol(), self.home)  # noqa: E731
        payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "session_id": "s"}
        self.assertEqual(run_pre_tool_use(payload, get_policy=get, record=None, agent="cursor")["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIsNone(run_pre_tool_use(payload, get_policy=get, record=None, agent="claude-code"))

    def test_team_stop_and_local_stop_merge(self):
        control.stop(self.home, "codex")
        pol = control.inject({**_pol(), "stop": {"all": {"by": "team"}}}, self.home)
        self.assertEqual(set(pol["stop"]), {"all", "agents"})

    def test_breakglass_window_and_receipt_marks(self):
        bg = control.open_breakglass(self.home, 5, "prod is down, need the fix")
        pol = control.inject(_pol(), self.home)
        r = check({"tool": "Write", "arguments": {"file_path": "/home/you/other/x", "content": "x"}}, pol)
        self.assertEqual((r["verdict"], r["breakglass"]), ("allow", bg["id"]))
        body = build_receipt(seq=0, prev=None, agent="a", session="s", action={"tool": "Write", "arguments": {}}, decision=r,
                             outcome={"status": "ok", "result_sha256": None}, policy_sha256="sha256:" + "0" * 64)
        self.assertEqual(body["decision"]["breakglass"], bg["id"])
        with self.assertRaises(ValueError):
            control.open_breakglass(self.home, 500, "too long a window")
        with self.assertRaises(ValueError):
            control.open_breakglass(self.home, 5, "")
        control.close_breakglass(self.home)
        self.assertNotIn("breakglass", control.inject(_pol(), self.home))

    def test_policy_cannot_bring_its_own_breakglass(self):
        pol = control.inject({**_pol(), "breakglass": {"id": "bg_x", "until": "2099-01-01T00:00:00Z"}}, self.home)
        self.assertNotIn("breakglass", pol)

    def test_control_actions_are_receipts(self):
        Key.generate().save(self.home / "key.json")
        control.stop(self.home)
        control.resume(self.home)
        control.open_breakglass(self.home, 3, "emergency test")
        tools = [r["action"]["tool"] for r in read_ledger(self.home / "ledger.jsonl")]
        self.assertEqual(tools, ["stop", "resume", "breakglass_open"])

    def test_agents_cannot_loosen(self):
        for cmd in ("verfy resume", "verfy breakglass --minutes 5 --reason x", "python -m verfy policy observe", "verfy rule add allow calls to x.com",
                    "verfy policy pack remove github", "verfy agent create bot"):
            r = check({"tool": "Bash", "arguments": {"command": cmd}}, _pol())
            self.assertEqual(r["verdict"], "deny", cmd)
        self.assertEqual(check({"tool": "Bash", "arguments": {"command": "verfy stop"}}, _pol())["verdict"], "allow")

    def test_recorder_respects_stop(self):
        rec = Recorder("bot", home=self.home)
        control.stop(self.home, "bot")
        with self.assertRaises(ActionDenied):
            rec.guard("send", kind="message")
        control.resume(self.home, "bot")
        self.assertEqual(rec.guard("send", kind="message")["verdict"], "allow")


class ObserveTests(unittest.TestCase):
    def test_observe_records_would(self):
        r = check({"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, _pol({"mode": "observe"}))
        self.assertEqual((r["verdict"], r["would"]), ("allow", "deny"))
        body = build_receipt(seq=0, prev=None, agent="a", session="s", action={"tool": "Bash", "arguments": {}}, decision=r,
                             outcome={"status": "ok", "result_sha256": None}, policy_sha256="sha256:" + "0" * 64)
        self.assertEqual(body["decision"]["would"], "deny")

    def test_observe_keeps_verfy_files_shut(self):
        r = check({"tool": "Bash", "arguments": {"command": "echo {} > ~/.verfy/policy.json"}}, _pol({"mode": "observe"}))
        self.assertEqual(r["verdict"], "deny")

    def test_cloned_policy_cannot_start_observe_but_can_end_it(self):
        base = _pol({"mode": "observe"})
        self.assertEqual(tighten(base, {"mode": "enforce"})["mode"], "enforce")
        self.assertNotEqual(tighten(_pol(), {"mode": "observe"}).get("mode"), "observe")

    def test_bad_mode_refused(self):
        with self.assertRaises(ValueError):
            load_policy({"mode": "loose"})

    def test_adaptive_and_scripts_keep_observe(self):
        from verfy import scripts
        pol = _pol({"mode": "observe"})
        action = {"tool": "Bash", "arguments": {"command": "rm -rf ~"}}
        checked = scripts.apply(None, "s", [(action, check(action, pol))], pol, "/home/you/project")
        self.assertEqual(checked[0][1]["verdict"], "allow")


class SpendTests(Home):
    def test_totals(self):
        now = datetime(2026, 11, 27, 12, tzinfo=timezone.utc)
        spend.add(self.home, {"amount": 30, "merchant": "acme", "category": "travel"}, 30, now)
        spend.add(self.home, {"amount": 20, "merchant": "acme", "category": "travel"}, 20, now - timedelta(days=2))
        spend.add(self.home, {"amount": 5, "merchant": "other"}, 5, now - timedelta(days=40))
        c = spend.context(self.home, {"merchant": "acme", "category": "travel"}, now)
        self.assertEqual((c["spent_today"], c["spent_month"], c["spent_payee_today"], c["spent_category_month"]), (30, 50, 30, 50))
        r = check({"tool": "pay", "arguments": {"amount": 60, "currency": "USD", "merchant": "acme", "category": "travel"}},
                  _pol({"payments": {"max_per_call": 1000, "daily_budget": 1000, "monthly_budget": 100}}), c)
        self.assertEqual([f["rule"] for f in r["findings"]][:1], ["VFY-PAY-007"])

    def test_bad_limits_refused(self):
        for bad in ({"payments": {"monthly_budget": -1}}, {"payments": {"merchants": {"a": 3}}}, {"payments": {"categories": {"x": {"then": "maybe"}}}},
                    {"dlp": {"personal": "sometimes"}}, {"dlp": {"patterns": [{"pattern": 3}]}}, {"payments": {"unknown_recipient": "allow"}}):
            with self.assertRaises(ValueError, msg=bad):
                load_policy(bad)


class PlainRuleTests(unittest.TestCase):
    def test_forms(self):
        cases = {
            "ask before payments over 50": {"payments": {"ask_above": 50}},
            "Block spending more than 300 per month.": {"payments": {"monthly_budget": 300}},
            "block calls to example.com": {"network": {"deny": ["example.com"]}},
            "trust the tool read_file": {"tools": {"trust": ["read_file"]}},
            "ask before sending messages": {"messages": {"send": "ask"}},
            "block sending personal data": {"dlp": {"personal": "deny"}},
        }
        for text, patch in cases.items():
            self.assertEqual(plainrules.compile_rule(text)["patch"], patch, text)

    def test_unknown_sentence_is_refused_with_forms(self):
        with self.assertRaises(plainrules.PlainRuleError) as e:
            plainrules.compile_rule("make everything safe please")
        self.assertIn("ask before payments over 50", str(e.exception))

    def test_compiled_rules_work_in_the_engine(self):
        pol = {}
        for text in ("block reading .env files", "block commands starting with terraform", "block pushing to main", "block deleting files"):
            pol = plainrules.apply_patch(pol, plainrules.compile_rule(text)["patch"])
        for tool, args in (("Read", {"file_path": "/home/you/project/.env"}), ("Bash", {"command": "terraform apply"}),
                           ("Bash", {"command": "git push origin main"}), ("Bash", {"command": "rm notes.txt"})):
            self.assertEqual(check({"tool": tool, "arguments": args}, _pol(pol))["verdict"], "deny", (tool, args))
        self.assertEqual(check({"tool": "Bash", "arguments": {"command": "git push origin feature"}}, _pol(pol))["verdict"], "allow")

    def test_packs_add_and_remove(self):
        pol = plainrules.add_pack({}, "github")
        pol = plainrules.add_pack(pol, "slack")
        self.assertEqual(check({"tool": "delete_repository", "arguments": {"repo": "x"}}, _pol(pol))["verdict"], "deny")
        pol = plainrules.remove_pack(pol, "github")
        self.assertEqual(check({"tool": "delete_repository", "arguments": {"repo": "x"}}, _pol(pol))["verdict"], "allow")
        self.assertEqual(pol["packs"], ["slack"])
        for name in plainrules.PACKS:
            load_policy(plainrules.add_pack({}, name))


class SimulateAndDailyTests(Home):
    def test_simulate_from_file(self):
        f = self.home / "actions.jsonl"
        f.write_text("\n".join(json.dumps(a) for a in [{"tool": "Bash", "arguments": {"command": "terraform apply"}},
                                                       {"tool": "Bash", "arguments": {"command": "ls"}}]), "utf-8")
        new = _pol(plainrules.compile_rule("block commands starting with terraform")["patch"])
        res = simulate.simulate(simulate.file_actions(f), _pol(), new)
        self.assertEqual((res["total"], len(res["changed"]), res["changed"][0]["after"]), (2, 1, "deny"))

    def test_simulate_reads_claude_transcripts(self):
        root = self.home / "projects" / "p"
        root.mkdir(parents=True)
        line = {"type": "assistant", "cwd": "/home/you/project", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "rm -rf ~"}}]}}
        (root / "s.jsonl").write_text(json.dumps(line) + "\n", "utf-8")
        acts = list(simulate.claude_actions(self.home / "projects", days=1))
        self.assertEqual(acts[0]["arguments"]["command"], "rm -rf ~")

    def test_daily_summary(self):
        key = Key.generate()
        led = Ledger(self.home / "ledger.jsonl", key)
        for verdict, rules in (("allow", []), ("deny", ["VFY-SH-001"]), ("ask", ["VFY-FS-002"])):
            led.append(agent="claude-code", session="s", action={"tool": "Bash", "arguments": {}}, decision={"verdict": verdict, "findings": [{"rule": r} for r in rules]},
                       outcome={"status": "ok", "result_sha256": None}, policy_sha256="sha256:" + "0" * 64)
        s = daily.summarize(read_ledger(self.home / "ledger.jsonl"))
        self.assertEqual((s["total"], len(s["blocked"]), len(s["asked"])), (3, 1, 1))
        self.assertIn("1 were blocked", daily.text(s, True))


def _fake_tsa(gen="20261127120000Z"):
    def der(tag, body):
        return tsa._tlv(tag, body)

    def post(url, req):
        tag, s, e = tsa._read(req, 0)
        kids = tsa._children(req, s, e)
        imprint = req[kids[1][1] - 2 - (1 if kids[1][2] - kids[1][1] > 127 else 0):kids[1][2]]
        imprint = der(0x30, req[kids[1][1]:kids[1][2]])
        nonce = der(0x02, req[kids[2][1]:kids[2][2]])
        tst = der(0x30, tsa._int(1) + bytes.fromhex("06032a0304") + imprint + tsa._int(42) + der(0x18, gen.encode()) + nonce)
        encap = der(0x30, tsa.TSTINFO_OID + der(0xA0, der(0x04, tst)))
        sd = der(0x30, tsa._int(3) + der(0x31, b"") + encap + der(0x31, b""))
        ci = der(0x30, bytes.fromhex("06092a864886f70d010702") + der(0xA0, sd))
        return der(0x30, der(0x30, tsa._int(0)) + ci)
    return post


class TimestampTests(Home):
    def test_stamp_and_check(self):
        head = "sha256:" + "ab" * 32
        info = tsa.stamp(head, "http://tsa.example", post=_fake_tsa())
        self.assertEqual((info["gen_time"], info["serial"]), ("2026-11-27T12:00:00Z", 42))
        path = tsa.save(self.home, info, 7)
        out = tsa.check_file(path)
        self.assertEqual((out["head"], out["signature"]), (head, "not checked"))

    def test_wrong_hash_or_nonce_refused(self):
        def lying(url, req):
            good = _fake_tsa()(url, req)
            return good.replace(bytes.fromhex("ab" * 32), bytes.fromhex("cd" * 32))
        with self.assertRaises(tsa.TimestampError):
            tsa.stamp("sha256:" + "ab" * 32, "http://tsa.example", post=lying)


class ReceiptFormatTests(Home):
    def setUp(self):
        super().setUp()
        self.rec = Recorder("bot", home=self.home, field_hashes=True)
        self.r = self.rec.record("pay", kind="payment", args={"amount": 12, "to": "acme", "memo": "private"})

    def test_disclosure(self):
        doc = disclose.disclose(self.r, {"amount": 12, "to": "acme", "memo": "private"}, ["amount"], self.rec.key.hash_salt())
        res = disclose.verify_disclosure(doc, self.rec.key.public)
        self.assertEqual((res["ok"], res["shown"], res["hidden"]), (True, {"amount": 12}, ["memo", "to"]))
        doc["show"]["amount"]["value"] = 13
        self.assertFalse(disclose.verify_disclosure(doc, self.rec.key.public)["ok"])
        with self.assertRaises(disclose.DisclosureError):
            disclose.disclose(self.r, {"amount": 99}, ["amount"], self.rec.key.hash_salt())

    def test_exports(self):
        receipts = read_ledger(self.home / "ledger.jsonl")
        ev = export.ocsf(receipts, "0.29.0")[0]
        self.assertEqual((ev["class_uid"], ev["type_uid"], ev["metadata"]["product"]["name"]), (6003, 600301, "Verfy"))
        a = export.acta(receipts, self.rec.key)
        self.assertTrue(export.verify_acta(a, self.rec.key.public)["ok"])
        a[0]["payload"]["decision"] = "deny"
        self.assertFalse(export.verify_acta(a, self.rec.key.public)["ok"])
        lines = export.aar(receipts, self.rec.key)
        self.assertTrue(export.verify_aar(lines, self.rec.key.public.hex())["ok"])

    def test_aar_matches_the_draft_vector(self):
        line = ('{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params":{"rule_id":"npm-publish","tier":"approve","class":"publish"},'
                '"success":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","user":"alice"},'
                '"public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",'
                '"signature":"ab6afa750440d38f72dc5601f45b1df918de60049b2accbb438dd909222f42755a534ee67e2eb1397f9d3ca6bd0bf67f1ec078ecc60c08c92438acd2b7dc5802"}')
        rec = json.loads(line)
        self.assertEqual(ed25519.sign(bytes([1]) * 32, export.aar_signed_bytes(rec)).hex(), rec["signature"])
        self.assertTrue(export.verify_aar([line])["ok"])

    def test_evidence_zip(self):
        receipts = read_ledger(self.home / "ledger.jsonl")
        data = evidence.build(receipts, verify_ledger(receipts, self.rec.key.public), kid=self.rec.kid, public="PUB", policy={},
                              frameworks=evidence.names("all"), version="0.29.0", ledger_text="x")
        z = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(set(z.namelist()), {"summary.json", "controls.json", "report.html", "report.pdf", "ledger.jsonl", "public-key.txt", "policy.json", "VERIFY.txt"})
        self.assertTrue(z.read("report.pdf").startswith(b"%PDF-1.4"))
        ids = {c["id"] for c in json.loads(z.read("controls.json"))}
        self.assertTrue({"CC7.2", "A.6.2.8", "E015", "Art. 12"} <= ids)
        with self.assertRaises(ValueError):
            evidence.names("hipaa")

    def test_dispute(self):
        receipts = read_ledger(self.home / "ledger.jsonl")
        doc = dispute.open_dispute(receipts, self.r["seq"], "The agent paid acme without asking me.", self.rec.key)
        self.assertEqual(doc["finding"], "policy_allowed")
        self.assertTrue(dispute.verify_dispute(doc)["ok"])
        doc["finding"] = "blocked"
        self.assertFalse(dispute.verify_dispute(doc)["ok"])


class IdentityTests(Home):
    def test_agent_cert_revoke(self):
        owner = Key.generate()
        agent, cert = identity.create_agent(owner, "buyer-bot", 30)
        self.assertTrue(identity.verify_cert(cert, owner.public)["ok"])
        self.assertFalse(identity.verify_cert(cert, Key.generate().public)["ok"])
        rv = identity.revoke(owner, cert, "laptop lost")
        self.assertFalse(identity.verify_cert(cert, owner.public, [rv])["ok"])
        with self.assertRaises(ValueError):
            identity.create_agent(owner, "bad name!", 30)

    def test_delegation_chain(self):
        boss = Recorder("boss", home=self.home)
        mid_key, last_key = Key.generate(), Key.generate()
        (self.home / "mid").mkdir()
        mid_key.save(self.home / "mid" / "key.json")
        d1 = boss.delegate(to_public=mid_key.public, to_agent="mid", tools=["buy_*", "search"], minutes=30,
                           rules=[{"id": "cap", "kind": "payment", "amount": "amount", "over": 50, "then": "deny"}])
        mid = Recorder("mid", home=self.home, key=self.home / "mid" / "key.json", delegation=d1, policy_rules=False)
        self.assertEqual(mid.guard("buy_book", kind="payment", args={"amount": 10})["verdict"], "allow")
        with self.assertRaises(ActionDenied):
            mid.guard("buy_book", kind="payment", args={"amount": 80})
        with self.assertRaises(ActionDenied):
            mid.guard("wire_money", kind="payment", args={"amount": 1})
        d2 = mid.delegate(to_public=last_key.public, to_agent="last", tools=["buy_*", "sell_*"], minutes=600)
        self.assertEqual(d2["tools"], ["buy_*"])
        self.assertLessEqual(d2["expires_at"], d1["expires_at"])
        self.assertTrue(identity.verify_chain([d1, d2])["ok"])
        bad = {**d2, "tools": ["*"]}
        self.assertFalse(identity.verify_chain([d1, bad])["ok"])
        with self.assertRaises(Exception):
            Recorder("x", home=self.home, delegation=d1)  # a hand-over for another key


class MandateTests(unittest.TestCase):
    CART = {"contents": {"id": "c1", "merchant_name": "shop", "cart_expiry": "2099-01-01T00:00:00Z",
                         "payment_request": {"details": {"total": {"label": "Total", "amount": {"currency": "USD", "value": 42.5}}}}}}

    def test_ap2_cart(self):
        self.assertEqual(mandate.check(self.CART, amount=42.5, currency="USD", payee="shop")["verdict"], "allow")
        r = mandate.check(self.CART, amount=50, currency="EUR", payee="other")
        self.assertEqual(sorted(f["rule"] for f in r["findings"]), ["VFY-MDT-001", "VFY-MDT-002", "VFY-MDT-003"])

    def test_expired_intent_and_x402(self):
        intent = {"natural_language_description": "shoes", "intent_expiry": "2020-01-01T00:00:00Z", "merchants": ["shop"], "user_cart_confirmation_required": False}
        self.assertEqual(mandate.check(intent, amount=1, payee="shop")["findings"][0]["rule"], "VFY-MDT-004")
        x = {"scheme": "exact", "network": "base", "maxAmountRequired": "10000", "payTo": "0xabc", "asset": "0xusdc", "resource": "https://x"}
        self.assertEqual(mandate.check(x, amount=10000, payee="0xabc")["verdict"], "allow")
        self.assertEqual(mandate.check(x, amount=10001, payee="0xabc")["verdict"], "deny")
        self.assertEqual(mandate.check({"foo": 1}, amount=1)["verdict"], "deny")


class CliTests(Home):
    def run_cli(self, *argv, stdin=""):
        from verfy import cli
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stdin", io.StringIO(stdin)):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_commands(self):
        Key.generate().save(self.home / "key.json")
        self.assertEqual(self.run_cli("stop", "--reason", "test")[0], 0)
        self.assertTrue((self.home / "stop.json").exists())
        self.assertEqual(self.run_cli("resume")[0], 1)  # no terminal
        code, out = self.run_cli("rule", "add", "ask", "before", "payments", "over", "50", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads((self.home / "policy.json").read_text("utf-8"))["payments"]["ask_above"], 50)
        self.assertEqual(self.run_cli("policy", "pack", "add", "github")[0], 0)
        code, out = self.run_cli("rule", "list")
        self.assertIn("pack-github-write-main", out)
        self.assertEqual(self.run_cli("policy", "enforce")[0], 0)
        code, out = self.run_cli("today")
        self.assertIn("stop at", out)
        f = self.home / "m.json"
        f.write_text(json.dumps(MandateTests.CART), "utf-8")
        self.assertEqual(self.run_cli("mandate", "check", str(f), "--amount", "99")[0], 2)
        code, out = self.run_cli("export", "--format", "ocsf")
        self.assertEqual(len(out.strip().splitlines()), 1)
        ev = self.home / "e.zip"
        self.assertEqual(self.run_cli("evidence", "--out", str(ev))[0], 0)
        self.assertTrue(zipfile.is_zipfile(ev))


if __name__ == "__main__":
    unittest.main()
