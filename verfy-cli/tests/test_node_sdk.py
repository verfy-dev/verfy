"""The Node.js recorder (js/verfy-node.mjs) and the Python one sign the same bytes: receipts written by one check with
the other. Skipped where Node.js is not installed. Run from verfy-cli/: ``python -m unittest tests.test_node_sdk``."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy.receipts import Key, read_ledger, salted_digest, verify_ledger  # noqa: E402
from verfy.recorder import Recorder  # noqa: E402

NODE = shutil.which("node")
RUN = ROOT / "tests" / "node_sdk_run.mjs"
NOTE = "ünïcode ✓"


@unittest.skipUnless(NODE, "Node.js is not installed")
class NodeRecorder(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = Path(d.name)

    def node(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([NODE, str(RUN), *args], capture_output=True, text=True, encoding="utf-8", timeout=120)

    def test_node_receipts_check_in_python(self):
        home = self.dir / "node"
        p = self.node("write", str(home))
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual((out["ok"], out["count"]), (True, 8))
        self.assertEqual(out["refused"], [True] * 6)
        key = Key.load(home / "key.json")
        self.assertEqual(out["public"], key.to_json(include_secret=False)["public"])
        receipts = read_ledger(home / "ledger.jsonl")
        res = verify_ledger(receipts, key.public)
        self.assertTrue(res["ok"], res["errors"])
        first = receipts[0]
        self.assertEqual(first["action"]["args_sha256"], salted_digest({"order": "A-1", "amount": 49.99, "note": NOTE}, key.hash_salt()))
        self.assertEqual(first["outcome"]["result_sha256"], salted_digest({"id": "re_1"}, key.hash_salt()))
        self.assertEqual([r["outcome"]["status"] for r in receipts[:3]], ["ok", "ok", "error"])
        self.assertEqual([r["seq"] for r in receipts], list(range(8)))
        # the Python recorder picks up where Node left off, with the same key and chain
        rec = Recorder(agent="py-bot", home=home, upload="off")
        rec.record("after-node")
        self.assertTrue(verify_ledger(read_ledger(home / "ledger.jsonl"), key.public)["ok"])

    def test_vercel_ai_sdk_tools(self):
        home = self.dir / "ai"
        env = {k: v for k, v in os.environ.items() if k != "AI_SDK_DIR"}
        if os.environ.get("AI_SDK_DIR"):  # a folder with `ai` and `zod` installed: also a real generateText run
            env["AI_SDK_DIR"] = os.environ["AI_SDK_DIR"]
        p = subprocess.run([NODE, str(ROOT / "tests" / "ai_sdk_run.mjs"), str(home)], capture_output=True, text=True,
                           encoding="utf-8", timeout=120, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual((out["direct"], out["untouched"], out["rethrown"]), ({"refunded": 20}, True, "not found"))
        self.assertTrue(out["check"]["ok"])
        key = Key.load(home / "key.json")
        receipts = read_ledger(home / "ledger.jsonl")
        self.assertEqual([(r["action"]["tool"], r["action"]["kind"], r["outcome"]["status"]) for r in receipts[:2]],
                         [("refund", "payment", "ok"), ("lookup", "other", "error")])
        self.assertEqual(receipts[0]["action"]["args_sha256"], salted_digest({"order": "A-1", "amount": 20}, key.hash_salt()))
        self.assertEqual(receipts[0]["action"]["server"], "ai-sdk")
        if "real" in out:
            self.assertEqual((out["real"], receipts[2]["action"]["tool"]), ("done", "refund"))
            self.assertEqual(receipts[2]["action"]["args_sha256"], salted_digest({"order": "C-3", "amount": 5}, key.hash_salt()))

    def test_python_receipts_check_in_node(self):
        rec = Recorder(agent="py-bot", home=self.dir / "py", upload="off")
        for i in range(4):
            rec.record("step", kind="write", args={"i": i, "text": NOTE, "f": 0.1 + 0.2}, result={"ok": True})
        p = self.node("verify", str(rec.ledger_path), rec.public_key)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(json.loads(p.stdout)["count"], 4)
        lines = rec.ledger_path.read_text("utf-8").splitlines()
        tampered = self.dir / "tampered.jsonl"
        tampered.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n", "utf-8")
        self.assertEqual(self.node("verify", str(tampered), rec.public_key).returncode, 1)

    def test_the_npm_package(self):
        out = self.dir / "pkg"
        p = subprocess.run([NODE, str(ROOT.parent / "scripts" / "build-npm.mjs"), str(out)], capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        pkg = json.loads((out / "package.json").read_text("utf-8"))
        version = next(ln.split('"')[1] for ln in (ROOT / "pyproject.toml").read_text("utf-8").splitlines() if ln.startswith("version = "))
        self.assertEqual((pkg["name"], pkg["version"]), ("@verfy-dev/receipts", version))
        for target in [e["default"] for e in pkg["exports"].values()] + [e["types"] for e in pkg["exports"].values()]:
            self.assertTrue((out / target).exists(), target)
        home = self.dir / "pkg-home"
        script = ("import(process.argv[1]).then(async (m) => { const r = new m.Recorder({ agent: 'pkg', home: process.argv[2] });"
                  " await r.record('x', { args: { n: 1 } }); console.log(JSON.stringify(await r.verify())); });")
        run = subprocess.run([NODE, "-e", script, (out / "verfy-node.mjs").as_uri(), str(home)], capture_output=True, text=True,
                             encoding="utf-8", timeout=120, cwd=str(self.dir))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)["ok"])
        self.assertTrue(verify_ledger(read_ledger(home / "ledger.jsonl"), Key.load(home / "key.json").public)["ok"])


if __name__ == "__main__":
    unittest.main()
