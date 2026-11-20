"""`verfy demo`: what each of its calls must show. Run from verfy-cli/: ``python -m unittest tests.test_demo``."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class Demo(unittest.TestCase):
    def test_each_call_shows_its_own_rule(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "NO_COLOR": "1"}
        p = subprocess.run([sys.executable, "-m", "verfy", "demo"], capture_output=True, text=True, encoding="utf-8", timeout=120, env=env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        lines = [ln for ln in p.stdout.splitlines() if ln.startswith(("RAN", "BLOCKED"))]
        got = [(ln.split()[0], ln.split()[1]) for ln in lines]
        self.assertEqual(got, [
            ("RAN", "run_command"),      # pytest -q
            ("BLOCKED", "run_command"),  # rm -rf ~
            ("BLOCKED", "run_command"),  # git push --force
            ("BLOCKED", "read_file"),    # ~/.ssh/id_rsa
            ("RAN", "write_file"),       # notes.md in the project
            ("BLOCKED", "fetch_url"),    # the cloud metadata address
            ("RAN", "send_payment"),     # 12, under the limit
            ("BLOCKED", "send_payment"),  # 500, over the limit
            ("BLOCKED", "add_numbers"),  # the poisoned tool
        ])
        self.assertNotIn("VFY-AD-", p.stdout)  # escalation is off in the demo, and said so
        self.assertIn("escalation", p.stdout)
        self.assertIn("9 signed receipts, chain verified", p.stdout)


if __name__ == "__main__":
    unittest.main()
