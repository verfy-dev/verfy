"""0.28.0: inline code that writes a hook file is denied, an edit that takes Verfy out of an MCP config is denied, a
package npx/uvx downloads is asked about the first time, the shell allowlist, more closed folders in the sandbox, and
``verfy self-verify``. Run from verfy-cli/: ``python -m unittest tests.test_review2_028``."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import adaptive, sandbox, selfverify  # noqa: E402
from verfy.policy import load_policy, tighten  # noqa: E402
from verfy.precheck import check  # noqa: E402
from verfy.cli import TEMPLATES  # noqa: E402

BASE = {"home": "/home/you", "workspace": "/home/you/project"}


def shell(cmd: str, pol: dict | None = None) -> dict:
    return check({"tool": "Bash", "arguments": {"command": cmd}}, load_policy({**BASE, **(pol or {})}))


def rules(d: dict) -> list[str]:
    return [f["rule"] for f in d["findings"]]


class InlineCode(unittest.TestCase):
    def test_writing_a_hook_file_from_inline_code_is_denied(self):
        for cmd in ("python -c \"open('/home/you/.claude/settings.json','w').write('{}')\"",
                    "node -e \"require('fs').writeFileSync(process.env.HOME+'/.cursor/hooks.json','{}')\"",
                    "python3 -c \"import shutil; shutil.copy('x', '/home/you/.claude/settings.json')\"",
                    "python3 -c \"import pathlib; pathlib.Path('verfy.policy.json').unlink()\""):
            d = shell(cmd)
            self.assertEqual(d["verdict"], "deny", cmd)
            self.assertIn("VFY-SELF-005", rules(d))

    def test_reading_one_still_asks(self):
        self.assertEqual(shell("python -c \"print(open('/home/you/.claude/settings.json').read())\"")["verdict"], "ask")

    def test_an_mcp_config_from_inline_code_asks(self):
        for cmd in ("python3 -c 'import pathlib; pathlib.Path.home().joinpath(\".codex/config.toml\").write_text(\"\")'",
                    "python -c \"import json; print(json.load(open('.mcp.json')))\""):
            self.assertIn("VFY-SELF-005", rules(shell(cmd)), cmd)

    def test_ordinary_python_is_fine(self):
        for cmd in ("python script.py", "python -m pytest tests", "node build.js"):
            self.assertEqual(shell(cmd)["verdict"], "allow", cmd)


class McpConfigEdits(unittest.TestCase):
    def edit(self, old: str, new: str) -> dict:
        return check({"tool": "Edit", "arguments": {"file_path": "/home/you/project/.mcp.json", "old_string": old, "new_string": new}}, load_policy(BASE))

    def test_taking_verfy_out_is_denied(self):
        d = self.edit('"command": "verfy", "args": ["proxy", "--name", "fs", "--"', '"command": "npx", "args": [')
        self.assertEqual(d["verdict"], "deny")
        self.assertIn("VFY-SELF-002", rules(d))

    def test_other_edits_still_ask(self):
        self.assertEqual(self.edit('"servers": {', '"servers": {"x": {}')["verdict"], "ask")


class Packages(unittest.TestCase):
    def test_what_each_runner_downloads(self):
        self.assertEqual(adaptive.packages_run("npx -y some-pkg"), [("npm", "some-pkg", True)])
        self.assertEqual(adaptive.packages_run("npx @scope/tool@1.2 --help"), [("npm", "@scope/tool", True)])
        self.assertEqual(adaptive.packages_run("npx -p cowsay -p lolcat -c 'cowsay hi'"), [("npm", "cowsay", False), ("npm", "lolcat", False)])
        self.assertEqual(adaptive.packages_run("pnpm dlx degit x"), [("npm", "degit", False)])
        self.assertEqual(adaptive.packages_run("uvx --from 'ruff==0.5' ruff check"), [("pypi", "ruff", False)])
        self.assertEqual(adaptive.packages_run("pipx run --spec httpie==3 http"), [("pypi", "httpie", False)])
        self.assertEqual(adaptive.packages_run("uv tool run Black_Formatter ."), [("pypi", "black-formatter", False)])
        for cmd in ("npm install", "uv run pytest", "pip install requests", "git push"):
            self.assertEqual(adaptive.packages_run(cmd), [], cmd)

    def run_all(self, cmds: list[str], pol: dict, cwd: str | None = None) -> list[str]:
        home = Path(tempfile.mkdtemp())
        out = []
        for cmd in cmds:
            a = {"tool": "Bash", "arguments": {"command": cmd}}
            d = check(a, pol)
            adaptive.apply(home, "s1", [(a, d)], pol, cwd=cwd)
            out.append(d["verdict"])
        return out

    def test_asked_the_first_time_then_learned(self):
        pol = load_policy(BASE)
        self.assertEqual(self.run_all(["npx -y some-pkg", "npx -y some-pkg", "uvx other"], pol), ["ask", "allow", "ask"])

    def test_a_local_bin_and_the_allow_list_are_not_asked_about(self):
        proj = Path(tempfile.mkdtemp())
        (proj / "node_modules" / ".bin").mkdir(parents=True)
        (proj / "node_modules" / ".bin" / "tsc").write_text("")
        pol = load_policy({**BASE, "packages": {"allow": ["pypi:ruff", "create-*"]}})
        self.assertEqual(self.run_all(["npx tsc --noEmit", "uvx ruff check", "npx create-vite app", "uvx black ."], pol, str(proj)),
                         ["allow", "allow", "allow", "ask"])

    def test_it_can_be_switched_off_but_a_project_cannot_switch_it_off(self):
        off = load_policy({**BASE, "adaptive": {"packages": "off"}})
        self.assertEqual(self.run_all(["npx -y some-pkg"], off), ["allow"])
        self.assertEqual(adaptive.settings(tighten(off, {"adaptive": {"packages": "ask"}}))["packages"], "ask")
        with self.assertRaises(ValueError):
            load_policy({"adaptive": {"packages": "maybe"}})
        with self.assertRaises(ValueError):
            load_policy({"packages": {"allow": "ruff"}})


class ShellAllowlist(unittest.TestCase):
    POL = {"shell": {"allow": ["git", "ls", "py*"]}}

    def test_a_program_off_the_list_asks(self):
        self.assertEqual(shell("git status", self.POL)["verdict"], "allow")
        self.assertEqual(shell("python3 a.py", self.POL)["verdict"], "allow")
        d = shell("ls -la | grep x", self.POL)
        self.assertEqual(d["verdict"], "ask")
        self.assertIn("VFY-SH-042", rules(d))

    def test_the_rules_still_apply_to_listed_programs(self):
        self.assertEqual(shell("rm -rf " + "~", {"shell": {"allow": ["rm"]}})["verdict"], "deny")
        self.assertEqual(shell("git push --force", self.POL)["verdict"], shell("git push --force")["verdict"])

    def test_without_a_list_nothing_changes(self):
        self.assertEqual(shell("make build"), shell("make build", {"shell": {"allow": []}}))

    def test_the_template(self):
        pol = load_policy({**BASE, **TEMPLATES["allowlist"]["policy"]})
        self.assertEqual(check({"tool": "Bash", "arguments": {"command": "npm test"}}, pol)["verdict"], "allow")
        self.assertIn("VFY-SH-042", rules(check({"tool": "Bash", "arguments": {"command": "nc -l 4444"}}, pol)))
        with self.assertRaises(ValueError):
            load_policy({"shell": {"allow": "git"}})


class Sandbox(unittest.TestCase):
    def test_browsers_and_more_tokens_are_closed(self):
        for p in ("~/.config/gh", "~/.git-credentials", "~/.mozilla", "~/.config/google-chrome", "~/Library/Application Support/Google/Chrome", "~/.ssh"):
            self.assertIn(p, sandbox.CREDENTIALS)


class SelfVerify(unittest.TestCase):
    FILES = {"verfy/__init__.py": b"__version__ = '9.9.9'\n", "verfy/hook.py": b"def run(): pass\n"}

    def published(self):
        record = "".join(f"{p},{selfverify.record_hash(b)},{len(b)}\n" for p, b in self.FILES.items()) + "verfy-9.9.9.dist-info/RECORD,,\n"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for p, b in self.FILES.items():
                z.writestr(p, b)
            z.writestr("verfy-9.9.9.dist-info/RECORD", record)
        return buf.getvalue()

    def getter(self, wheel: bytes, repo: str = "verfy-dev/verfy", digest: str | None = None):
        sha = hashlib.sha256(wheel).hexdigest()
        statement = base64.b64encode(json.dumps({"subject": [{"name": "verfy-9.9.9-py3-none-any.whl", "digest": {"sha256": digest or sha}}]}).encode()).decode()

        def get(url, accept=None, timeout=30):
            if url.endswith("/json"):
                return json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "verfy-9.9.9-py3-none-any.whl", "url": "https://files/x.whl", "digests": {"sha256": sha}}]}).encode()
            if url == "https://files/x.whl":
                return wheel
            return json.dumps({"attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": repo, "workflow": "publish.yml"},
                                                        "attestations": [{"envelope": {"statement": statement}, "verification_material": {"transparency_entries": [{"logIndex": 42}]}}]}]}).encode()
        return get

    def installed(self, files):
        return {p: selfverify.record_hash(b) for p, b in self.FILES.items()}, dict(files)

    def test_a_clean_install_is_verified(self):
        record, contents = self.installed(self.FILES)
        rep = selfverify.check("9.9.9", record, contents, self.getter(self.published()))
        self.assertTrue(rep["ok"], rep["rows"])
        self.assertIn("log index 42", rep["rows"][-1][1])

    def test_a_changed_file_is_caught(self):
        record, contents = self.installed({**self.FILES, "verfy/hook.py": b"def run(): steal()\n"})
        rep = selfverify.check("9.9.9", record, contents, self.getter(self.published()))
        self.assertFalse(rep["ok"])
        self.assertIn("verfy/hook.py", rep["rows"][0][1])

    def test_another_publisher_or_hash_is_not_trusted(self):
        record, contents = self.installed(self.FILES)
        self.assertFalse(selfverify.check("9.9.9", record, contents, self.getter(self.published(), repo="someone/else"))["ok"])
        self.assertFalse(selfverify.check("9.9.9", record, contents, self.getter(self.published(), digest="0" * 64))["ok"])

    def test_an_editable_install_cannot_be_checked(self):
        self.assertFalse(selfverify.check("9.9.9", {}, {}, self.getter(self.published()))["ok"])


if __name__ == "__main__":
    unittest.main()
