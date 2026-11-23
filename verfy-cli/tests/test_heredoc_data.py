"""A here-document that only writes text into a documentation file is not read as commands; every other one still is.
Run from verfy-cli/: ``python -m unittest tests.test_heredoc_data``."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy.policy import load_policy  # noqa: E402
from verfy.precheck import check, strip_data_heredocs  # noqa: E402

WIPE = "rm -rf " + "~"  # kept out of this file's own command lines


class DataHeredocs(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        (root / "home").mkdir()
        (root / "project").mkdir()
        self.pol = load_policy({"home": str(root / "home"), "workspace": str(root / "project")})

    def rules(self, cmd: str) -> tuple[str, list[str]]:
        d = check({"server": "claude-code", "tool": "Bash", "arguments": {"command": cmd}}, self.pol)
        return d["verdict"], [f["rule"] for f in d["findings"]]

    def assertText(self, cmd: str):
        verdict, rules = self.rules(cmd)
        self.assertNotIn("VFY-SH-001", rules, cmd)
        self.assertEqual(verdict, "allow", (cmd, rules))

    def assertStillChecked(self, cmd: str):
        verdict, rules = self.rules(cmd)
        self.assertIn("VFY-SH-001", rules, cmd)
        self.assertEqual(verdict, "deny", cmd)

    def test_text_for_a_documentation_file_is_not_a_command(self):
        self.assertText(f"cat >> notes.md <<'EOF'\nNever run `{WIPE}` on a laptop.\n{WIPE}\nEOF\ngrep -c Never notes.md")
        self.assertText(f"mkdir -p docs && cat > docs/guide.md <<EOF\n{WIPE}\nEOF")
        self.assertText(f"tee docs/a.txt <<'EOF' >/dev/null\nrm -rf /\nEOF")
        self.assertText(f"cat > a.md <<'A'\n{WIPE}\nA\ncat > b.rst <<'B'\n{WIPE}\nB\n")
        self.assertText(f"cat > a.md <<-EOF\n\t{WIPE}\n\tEOF")
        self.assertText(f"cat > a.md <<'EOF'\r\n{WIPE}\r\nEOF\r\n")

    def test_text_that_runs_is_still_checked(self):
        for cmd in [
            f"cat > notes.md <<'EOF'\n{WIPE}\nEOF\nbash notes.md",              # the file is run afterwards
            f"cat > notes.md <<'EOF' && sh notes.md\n{WIPE}\nEOF",              # ... on the same line
            f"cat <<'EOF' | bash\n{WIPE}\nEOF",                                 # piped into a shell
            f"bash <<'EOF'\n{WIPE}\nEOF",                                       # fed to a shell
            f"cat > run.sh <<'EOF'\n{WIPE}\nEOF",                               # a script
            f"cat >> ~/.bashrc <<'EOF'\n{WIPE}\nEOF",                           # runs at the next login
            f"cat > notes.md <<EOF\n$({WIPE})\nEOF",                            # unquoted: $(...) runs now
            f"cat > notes.md <<EOF\n`{WIPE}`\nEOF",
            f"eval \"$(cat <<'EOF'\n{WIPE}\nEOF\n)\"",                          # its output is run
            f"sudo tee /etc/motd.txt <<'EOF'\n{WIPE}\nEOF",
            f"cat > notes.md <<'EOF'\n{WIPE}\n",                                # never closed
            f"cat > $F <<'EOF'\n{WIPE}\nEOF",                                   # unknown file
            f"cat > notes.md <<'EOF'\n{WIPE}\nEOF\nxargs -a notes.md sh -c",
        ]:
            with self.subTest(cmd=cmd):
                self.assertStillChecked(cmd)

    def test_the_command_around_the_text_is_still_checked(self):
        verdict, rules = self.rules(f"cat > notes.md <<'EOF'\nhello\nEOF\n{WIPE}")
        self.assertIn("VFY-SH-001", rules)
        self.assertEqual(verdict, "deny")

    def test_nothing_else_changes(self):
        for cmd in ["ls -la", "echo hi > a.md", "cat <<<'x' > a.md", "x=$((1<<2)); echo $x"]:
            self.assertEqual(strip_data_heredocs(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
