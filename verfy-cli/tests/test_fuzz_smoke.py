"""The fuzz targets of tests/fuzz_precheck.py on random inputs, without Atheris: no input may make the rule engine or the
script reader raise. Run from verfy-cli/: ``python -m unittest tests.test_fuzz_smoke``."""

from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import scripts  # noqa: E402
from verfy.policy import load_policy  # noqa: E402
from verfy.precheck import check, parse_shell  # noqa: E402

# pieces that reach the parsers' corners: quotes, brackets, here-documents, substitutions, calls the script reader follows
PIECES = ["'", '"', "`", "$(", ")", "(", "[", "]", "{", "}", "${", "\\", "\n", ";", "&&", "|", "<<EOF", "<<-'X'", "EOF",
          "#", "//", "/*", "*/", '"""', "'''", "f'", "r\"", "rm -rf ~", "bash -c", "python -c", "os.system(",
          "subprocess.run([", "execSync(`", "spawn('rm', [", "shutil.rmtree(", "Path.home()", "~/.verfy/key.json",
          "http://169.254.169.254/", "eval(atob(", "%x{", "qx(", "npm test", "make", "cd ..", " ", "\t", "é", "\x00"]


class FuzzSmoke(unittest.TestCase):
    def test_random_inputs_never_raise(self):
        pol = load_policy({"home": "/home/you", "workspace": "/home/you/project"})
        rnd = random.Random(int(os.environ.get("VERFY_FUZZ_SEED", "20261120")))
        for _ in range(int(os.environ.get("VERFY_FUZZ_RUNS", "1500"))):
            text = "".join(rnd.choice(PIECES) if rnd.random() < 0.7 else chr(rnd.randrange(32, 0x2FF)) for _ in range(rnd.randrange(1, 60)))
            try:
                parse_shell(text)
                check({"server": "fuzz", "tool": "run_command", "arguments": {"command": text}}, pol)
                scripts.shell_units(text)
                for lang in ("py", "js", "rb", "pl", "php"):
                    scripts.literals(text, lang)
                scripts.lang_of("x", text)
            except Exception as e:  # noqa: BLE001 - the point is that nothing raises
                self.fail(f"{type(e).__name__}: {e} on {text!r}")

    def test_random_scripts_through_the_reader(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        home, proj = Path(d.name) / "home", Path(d.name) / "project"
        (home / ".verfy").mkdir(parents=True)
        proj.mkdir()
        pol = load_policy({"home": str(home), "workspace": str(proj)})
        rnd = random.Random(7)
        for i in range(int(os.environ.get("VERFY_FUZZ_RUNS", "1500")) // 10):
            body = "".join(rnd.choice(PIECES) for _ in range(rnd.randrange(1, 80)))
            for ext, runner in ((".py", "python"), (".js", "node"), (".sh", "bash"), (".rb", "ruby"), (".php", "php")):
                (proj / f"f{ext}").write_text(body, "utf-8")
                action = {"server": "claude-code", "tool": "Bash", "arguments": {"command": f"{runner} f{ext}"}}
                try:
                    scripts.apply(home / ".verfy", f"s{i}", [(action, check(action, pol))], pol, str(proj))
                except Exception as e:  # noqa: BLE001
                    self.fail(f"{type(e).__name__}: {e} on {runner} with {body!r}")


if __name__ == "__main__":
    unittest.main()
