"""Tests for Verfy's signed rule feed (verfy.rulefeed, `verfy rules`). Run from verfy-cli/: ``python -m unittest tests.test_rulefeed``."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import ed25519, rulefeed, witness  # noqa: E402
from verfy.canonical import canonical_bytes  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.policy import load_policy  # noqa: E402
from verfy.precheck import check  # noqa: E402
from verfy.receipts import b64u  # noqa: E402

SEED, OTHER = b"\x11" * 32, b"\x22" * 32
RULE = ["VFY-FEED-001", "deny", r"\bnew-attack-tool\b", "", "A tool used in a new attack."]


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


def kid(seed: bytes) -> str:
    return witness.witness_kid(ed25519.public_key(seed))


def sign(subject: dict, seed: bytes = SEED) -> dict:
    body = {"issuer": "https://verfy.example", "issued_at": "2026-11-18T00:00:00Z", "type": "rules", "subject": subject,
            "v": witness.VERSION, "kid": kid(seed)}
    return {**body, "sig": b64u(ed25519.sign(seed, canonical_bytes(body)))}


class Cloud:
    def __init__(self, statement: dict | None, seeds: tuple[bytes, ...] = (SEED, OTHER)):
        self.statement = statement
        self.keys = {"keys": [{"kid": kid(s), "alg": "Ed25519", "public": b64u(ed25519.public_key(s))} for s in seeds]}
        self.calls: list[str] = []

    def __call__(self, method, url, body, headers):
        self.calls.append(url)
        if url.endswith("/.well-known/verfy-witness.json"):
            return 200, self.keys
        if url.endswith("/api/v1/rules/feed"):
            return 200, {"feed": self.statement}
        return 404, {"title": "not found"}


def feed(version: int = 1, shell: list | None = None, hosts: list | None = None, seed: bytes = SEED) -> dict:
    return sign({"version": version, "shell": [RULE] if shell is None else shell, "network_deny": hosts or ["exfil.example"]}, seed)


class Feed(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)

    def update(self, statement: dict, **kw) -> dict:
        return rulefeed.update(self.home, "https://verfy.example", transport=Cloud(statement), **kw)

    def test_rules_from_the_feed_apply(self):
        res = self.update(feed())
        self.assertEqual((res["version"], res["rules"], res["hosts"], res["changed"]), (1, 1, 1, True))
        pol = rulefeed.merge(load_policy({"home": "/home/you", "workspace": "/home/you/project"}), self.home)
        d = check({"tool": "Bash", "arguments": {"command": "new-attack-tool --run"}}, pol)
        self.assertEqual((d["verdict"], [f["rule"] for f in d["findings"]]), ("deny", ["VFY-FEED-001"]))
        d = check({"tool": "Write", "arguments": {"file_path": "/home/you/project/notes.md", "content": "new-attack-tool"}}, pol)
        self.assertEqual(d["verdict"], "allow")  # a file that mentions it is not running it
        d = check({"tool": "Bash", "arguments": {"command": "curl https://exfil.example/x"}}, pol)
        self.assertEqual(d["verdict"], "deny")
        self.assertEqual(self.update(feed())["changed"], False)

    def test_a_feed_can_only_add(self):
        bad = [
            [["VFY-SH-001", "deny", "x", "", "takes another rule's name"]],
            [["VFY-FEED-002", "allow", "x", "", "would allow"]],
            [["VFY-FEED-003", "ask", "(", "", "does not compile"]],
            [["VFY-FEED-004", "ask", "(a+)+$", "", "could take too long"]],
            [["VFY-FEED-005", "ask", "x" * 700, "", "too long"]],
            [["VFY-FEED-006", "ask", "x", "m", "unknown flag"]],
            [["VFY-FEED-007", "ask", "x"]],
        ]
        for shell in bad:
            with self.assertRaises(rulefeed.FeedError, msg=shell):
                self.update(feed(shell=shell))
        with self.assertRaises(rulefeed.FeedError):
            self.update(feed(hosts=["not a host!"]))
        self.assertIsNone(rulefeed.load(self.home))  # nothing was kept

    def test_the_first_key_is_kept_and_versions_never_go_back(self):
        self.update(feed(version=2))
        with self.assertRaisesRegex(rulefeed.FeedError, "older"):
            self.update(feed(version=1))
        with self.assertRaisesRegex(rulefeed.FeedError, "trust-key"):
            self.update(feed(version=3, seed=OTHER))
        self.assertEqual(self.update(feed(version=3, seed=OTHER), trust_key=kid(OTHER))["version"], 3)
        forged = {**feed(version=4), "subject": {"version": 4, "shell": [], "network_deny": []}}
        with self.assertRaisesRegex(rulefeed.FeedError, "signature"):
            self.update(forged)
        self.assertEqual(rulefeed.load(self.home)["feed"]["version"], 3)

    def test_no_feed_published(self):
        with self.assertRaisesRegex(rulefeed.FeedError, "no rule feed"):
            rulefeed.update(self.home, "https://verfy.example", transport=Cloud(None))
        with self.assertRaises(rulefeed.FeedError):
            rulefeed.update(self.home, "http://verfy.example")  # https only

    def test_refreshing_in_the_background(self):
        started = []
        start = lambda home, url: started.append(url) or True  # noqa: E731
        self.assertFalse(rulefeed.refresh_soon(self.home, now=1000, start=start))  # not enrolled, not turned on
        rulefeed.set_auto(self.home, True)
        self.assertTrue(rulefeed.refresh_soon(self.home, now=1000, start=start))
        self.assertFalse(rulefeed.refresh_soon(self.home, now=1500, start=start))  # once an hour at most
        self.update(feed())
        self.assertFalse(rulefeed.refresh_soon(self.home, start=start))  # fresh
        rulefeed.set_auto(self.home, False)
        (self.home / "team.json").write_text(json.dumps({"url": "https://cloud.example", "token": "atd_x", "kid": "atl_x", "device_id": "d", "auto_sync": True}), "utf-8")
        self.assertFalse(rulefeed.refresh_soon(self.home, now=10**10, start=start))  # turned off wins
        (self.home / "rule-feed-auto.json").unlink()
        self.assertTrue(rulefeed.refresh_soon(self.home, now=10**10, start=start))  # enrolled with automatic upload
        self.assertEqual(started, ["https://verfy.dev", "https://cloud.example"])


class Command(unittest.TestCase):
    def test_verfy_rules(self):
        home = tmpdir(self)
        cloud = Cloud(feed(version=5))
        out = io.StringIO()
        with mock.patch.dict("os.environ", {"VERFY_HOME": str(home), "NO_COLOR": "1"}), mock.patch("verfy.team.http_transport", cloud), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(cli_main(["rules", "update", "--url", "https://verfy.example"]), 0)
            self.assertEqual(cli_main(["rules", "status", "--json"]), 0)
            self.assertEqual(cli_main(["rules", "auto", "off"]), 0)
            cloud.statement = feed(version=4)
            self.assertEqual(cli_main(["rules", "update", "--url", "https://verfy.example", "--quiet"]), 1)
        text = out.getvalue()
        self.assertIn("version 5: 1 rule(s), 1 blocked host(s)", text)
        self.assertEqual(json.loads(text[text.index("{"):text.rindex("}") + 1])["feed"]["feed"]["version"], 5)
        self.assertIs(rulefeed.auto(home), False)


if __name__ == "__main__":
    unittest.main()
