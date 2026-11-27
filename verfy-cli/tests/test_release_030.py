"""0.30.0: `verfy dispute send` puts a dispute record into Verfy Cloud."""

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

from verfy import dispute, team  # noqa: E402
from verfy.receipts import read_ledger  # noqa: E402
from verfy.recorder import Recorder  # noqa: E402


class DisputeSendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"VERFY_HOME": str(self.home)})
        self.env.start()
        rec = Recorder("bot", home=self.home)
        r = rec.record("pay", kind="payment", args={"amount": 12, "to": "acme"})
        self.doc = dispute.open_dispute(read_ledger(self.home / "ledger.jsonl"), r["seq"], "The agent paid acme without asking me.", rec.key)
        self.file = self.home / "d.json"
        self.file.write_text(json.dumps(self.doc), "utf-8")

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_send_posts_the_whole_record(self):
        team.save_team(self.home, {"url": "https://verfy.example.test", "token": "atd_" + "x" * 43, "kid": "atl_" + "0" * 16, "device_id": "d1"})
        calls = []

        def transport(method, url, body, headers):
            calls.append((method, url, body, headers))
            return 201, {"id": "11111111-2222-4333-8444-555555555555", "signer_enrolled": True}

        out = team.send_dispute(self.home, self.doc, transport=transport)
        self.assertEqual(out["signer_enrolled"], True)
        method, url, body, headers = calls[0]
        self.assertEqual((method, url), ("POST", "https://verfy.example.test/api/v1/disputes"))
        self.assertEqual(body, {"record": self.doc})
        self.assertIn("atd_", headers.get("Authorization", headers.get("authorization", "")))

    def test_send_needs_enrollment_and_a_good_record(self):
        from verfy import cli029

        with self.assertRaises(team.TeamError):
            team.send_dispute(self.home, self.doc, transport=lambda *a: (201, {}))
        args = mock.Mock(action="send", file=str(self.file))
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(cli029.cmd_dispute(args), 1)
        self.assertIn("not enrolled", err.getvalue())
        bad = dict(self.doc, claim="Something else that did not happen.")
        self.file.write_text(json.dumps(bad), "utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli029.cmd_dispute(args), 1)
        self.assertIn("FAILED", out.getvalue())
        missing = mock.Mock(action="send", file=None)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli029.cmd_dispute(missing), 2)


if __name__ == "__main__":
    unittest.main()
