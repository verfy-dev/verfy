"""Reading a script before it runs.

Verfy's rules judge the command an agent runs. ``python build.py``, ``./deploy.sh`` or ``npm test`` name a program
and a file; what runs is in the file. Before such a command runs, Verfy reads the code it starts and checks it with
the same rules:

* a script named on the command line: run by an interpreter (python, node, deno, bun, tsx, ruby, perl, php, bash,
  sh, zsh, pwsh), run directly (``./x.sh``), sourced (``source x``, ``. x``), a module of the project
  (``python -m pkg``), code given inline (``python -c``, ``node -e``) or in a here-document (``python - <<EOF``);
* package scripts: ``npm test``, ``npm run build``, ``npm install`` (its install scripts), the same for yarn, pnpm
  and bun, and the recipes of a Makefile for ``make``;
* when a command runs project code without naming it (an interpreter, a test runner, a build tool, a package
  script), the code files the agent wrote or changed in this session.

In a shell script every line is checked as a command. In other languages Verfy checks the commands the code hands
to the shell (``os.system``, ``subprocess``, ``child_process``, ``system``, backticks), recursive deletes
(``shutil.rmtree``, ``fs.rmSync``), the paths and URLs written in it, and code that decodes or downloads more code
and runs it, which nobody can read before it runs (VFY-SCRIPT-003). A script that starts another is followed, three
levels deep.

Who wrote the code matters. Code the agent wrote or changed in this session (a file tool, a shell redirect, a
download, or a file changed since the session started) gets every finding. Code that was already there gets only
what is blocked outright, so a project's own scripts do not ask each time they run.

Limits: the text is read before it runs. Code that builds a command while it runs, reads it from somewhere else, or
loads modules the agent did not write is not followed past what its text shows, and compiled programs are not read;
a sandbox holds the rest (``verfy run --sandbox``). This layer only adds findings: a file it cannot read or parse
leaves the rules' answer as it was.

Policy: ``"scripts": {"read": "on" | "off"}`` (on by default). The state, ``~/.verfy/scripts.json``, holds the paths
of the files each session wrote, for a day.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import shlex
import time
from pathlib import Path
from typing import Any

from ._util import PATTERNS, VERDICT_RANK, rx
from .fileio import FileLock, atomic_write
from .policy import DEFAULT_POLICY, load_policy
from .precheck import SHELLS, _Ctx, _home_vars, _urls, _written, check, check_url, operands, parse_shell

VERSION = 1
KEEP = 24 * 3600.0
SESSIONS_MAX = 200
FILES_MAX = 500  # remembered per session
MAX_BYTES = 512 * 1024  # one file
BUDGET = 2 * 1024 * 1024  # every file read for one call
MAX_FILES = 24
MAX_DEPTH = 3
PER_FILE = 4  # findings kept per file
LINES_MAX = 400  # lines checked one by one to name the line of a finding
SECRET = PATTERNS["self_protect"]["secret"]

LANG_EXT = {
    ".sh": "sh", ".bash": "sh", ".zsh": "sh", ".ksh": "sh", ".command": "sh",
    ".py": "py", ".pyw": "py",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".mts": "js", ".cts": "js", ".jsx": "js", ".tsx": "js",
    ".rb": "rb", ".pl": "pl", ".pm": "pl", ".php": "php",
    ".ps1": "ps", ".psm1": "ps", ".bat": "bat", ".cmd": "bat",
}
INLINE = {"py": {"-c"}, "js": {"-e", "--eval", "-p", "--print"}, "rb": {"-e"}, "pl": {"-e", "-E"}, "php": {"-r"}}
VALUE_FLAGS = {
    "py": {"-W", "-X", "--check-hash-based-pycs"},
    "js": {"-r", "--require", "--import", "--loader", "--experimental-loader", "--input-type", "--env-file", "-C",
           "--conditions", "--watch-path", "--tsconfig", "--config"},
    "rb": {"-r", "-I", "-C", "-E", "-F"},
    "pl": {"-I", "-x"},
    "php": {"-c", "-d", "-z"},
    "sh": {"-o", "-O", "+O", "--rcfile", "--init-file"},
    "ps": {"-executionpolicy", "-ep", "-workingdirectory", "-wd", "-version", "-v", "-windowstyle", "-w", "-inputformat",
           "-outputformat", "-configurationname", "-configurationfile", "-settingsfile"},
}
INSTALL = ["preinstall", "install", "postinstall", "prepare"]
PM_BUILTINS = {
    "add", "audit", "bin", "cache", "config", "create", "dedupe", "dlx", "exec", "help", "import", "info", "init",
    "link", "list", "ls", "login", "logout", "outdated", "pack", "patch", "plugin", "prune", "publish", "rebuild",
    "remove", "rm", "root", "set", "store", "unlink", "up", "update", "upgrade", "upgrade-interactive", "version",
    "why", "workspace", "workspaces", "global", "env", "node", "setup", "self-update", "whoami",
}
# programs that run project code without naming the file: test runners, build tools, task runners
RUNNERS = {
    "pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha", "ava", "tap", "karma", "playwright", "cypress",
    "go", "cargo", "make", "gmake", "gradle", "gradlew", "mvn", "mvnw", "dotnet", "rake", "rspec", "bundle", "phpunit",
    "composer", "npx", "pnpx", "bunx", "uvx", "pipx", "uv", "poetry", "pdm", "hatch", "turbo", "nx", "lerna", "just",
    "npm", "pnpm", "yarn", "pip", "pip3",
}

SHELL_CALLS = {
    "py": re.compile(r"\b(?:os\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)|subprocess\.(?:run|call|check_call|"
                     r"check_output|Popen|getoutput|getstatusoutput)|commands\.getoutput|pty\.spawn|"
                     r"asyncio\.create_subprocess_(?:shell|exec))\s*\(|(?<![\w.])(?:Popen|check_output|check_call|getoutput|"
                     r"getstatusoutput)\s*\("),
    # exec(...) on its own, on child_process (or what it is often named), or on require('child_process'), never regex.exec(...)
    "js": re.compile(r"(?:\b(?:child_process|childProcess|cp|proc)\.|(?<=\)\.)|(?<![\w$.]))(?:exec|execSync|execFile|execFileSync|"
                     r"spawn|spawnSync|fork)\s*\(|\bBun\.spawn(?:Sync)?\s*\(|\bnew\s+Deno\.Command\s*\(|\bDeno\.run\s*\("),
    "rb": re.compile(r"(?<![\w.:])(?:system|exec|spawn|IO\.popen|Open3\.(?:capture[23e]?|popen[23e]?|pipeline\w*))\b\s*\(?"),
    "pl": re.compile(r"(?<![\w$>:])(?:system|exec)\b\s*\(?"),
    "php": re.compile(r"(?<![\w$>:])(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\("),
}
# calls that take a program and its arguments as separate values
ARGV_CALLS = re.compile(r"(?:execFile|execFileSync|spawn|spawnSync|fork|Deno\.Command|os\.exec|os\.spawn|posix_spawn|"
                        r"create_subprocess_exec)\w*\s*\($")
DELETE_CALLS = {
    "py": [(re.compile(r"\bshutil\.rmtree\s*\("), True), (re.compile(r"\bos\.(?:remove|unlink|rmdir|removedirs)\s*\("), False)],
    "js": [(re.compile(r"\bfs(?:Promises|\.promises)?\.(?:rm|rmSync|rmdir|rmdirSync)\s*\("), None),
           (re.compile(r"\b(?:rimraf|fse?\.remove|fse?\.removeSync|del|deleteAsync)\s*\("), True),
           (re.compile(r"\bfs(?:Promises|\.promises)?\.(?:unlink|unlinkSync)\s*\("), False)],
    "rb": [(re.compile(r"\bFileUtils\.(?:rm_rf|rm_r|remove_dir|remove_entry_secure|rmtree)\s*\(?"), True),
           (re.compile(r"\bFile\.(?:delete|unlink)\s*\(?"), False)],
    "pl": [(re.compile(r"\b(?:rmtree|remove_tree)\s*\(?"), True), (re.compile(r"(?<![\w$>])unlink\s*\(?"), False)],
    "php": [(re.compile(r"(?<![\w$>])(?:unlink|rmdir)\s*\("), False)],
}
HOME_MARK = re.compile(r"expanduser\(\s*['\"]~['\"]\s*\)|Path\.home\(\)|os\.homedir\(\)|\bhomedir\(\)|environ(?:\.get\(|\[)\s*['\"](?:HOME|USERPROFILE)"
                       r"|process\.env\.(?:HOME|USERPROFILE)|process\.env\[['\"](?:HOME|USERPROFILE)|Dir\.home|ENV\[['\"]HOME|\$ENV\{\s*HOME|"
                       r"getenv\(\s*['\"](?:HOME|USERPROFILE)|\$_SERVER\[['\"]HOME|File\.expand_path\(\s*['\"]~['\"]")
NETWORK = re.compile(r"requests\.|urllib|http\.client|httpx|aiohttp|socket\.|smtplib|ftplib|paramiko|\bfetch\s*\(|axios|https?\.(?:request|get)\s*\("
                     r"|net\.(?:connect|createConnection)|WebSocket|XMLHttpRequest|\bgot\s*\(|node-fetch|Net::HTTP|open-uri|URI\.open|Faraday|"
                     r"HTTParty|LWP::|HTTP::Tiny|IO::Socket|curl_(?:init|exec)|fsockopen|stream_socket_client|\bcurl\b|\bwget\b")
WRITES = re.compile(r"open\([^)\n]*['\"][wax]b?\+?['\"]|write_text|write_bytes|writeFile|appendFile|createWriteStream|"
                    r"File\.(?:write|open\([^)\n]*['\"][wa])|IO\.write|fopen\([^)\n]*['\"][wax]|file_put_contents|json\.dump\(|"
                    r"\.write\s*\(|shutil\.(?:copy|move)|fs\.(?:copy|cp|rename)|FileUtils\.(?:cp|mv)")
EXEC = {
    "py": re.compile(r"(?<![\w.])(?:exec|eval|compile)\s*\(|marshal\.loads|pickle\.loads|__import__\s*\("),
    "js": re.compile(r"(?<![\w$.])eval\s*\(|new\s+Function\s*\(|(?<![\w$.])Function\s*\(|\bvm\.(?:run\w*|Script|compileFunction)|"
                     r"require\(\s*['\"](?:node:)?vm['\"]\s*\)"),
    "rb": re.compile(r"(?<![\w.])eval\s*\(?|\b(?:instance|class|module)_eval\b|Kernel\.eval"),
    "pl": re.compile(r"(?<![\w$>])eval\s*[({\"'$]"),
    "php": re.compile(r"(?<![\w$>])(?:eval|assert|create_function)\s*\(|preg_replace\s*\([^)]*/e['\"]"),
}
DECODE = re.compile(r"b64decode|base64|atob\s*\(|Buffer\.from\([^)]*['\"](?:base64|hex)['\"]|fromCharCode|decompress|zlib|gzinflate|"
                    r"gzuncompress|gzdecode|str_rot13|codecs\.decode|bytes\.fromhex|unhexlify|rot13|urlopen|requests\.get|httpx\.get|"
                    r"\bfetch\s*\(|https?\.get|axios|urllib|Net::HTTP|open-uri|URI\.open|LWP|file_get_contents|curl_exec|unpack\s*\(|"
                    r"decodeURIComponent|\.decode\(\s*['\"](?:hex|base64|rot13)")
HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
PATHISH = re.compile(r"^(?:~|/|\.{1,2}[\\/]|[A-Za-z]:[\\/]|\$HOME\b|\$\{HOME\}|%USERPROFILE%)")
PART = re.compile(r"^[\w.@-][\w.@/\\-]*$")


def _f(rule: str, verdict: str, message: str) -> dict:
    return {"rule": rule, "verdict": verdict, "message": message}


def settings(policy: dict) -> dict:
    s = policy.get("scripts") if isinstance(policy.get("scripts"), dict) else {}
    read = s.get("read", "on")
    if read not in ("on", "off"):
        raise ValueError("scripts.read must be on or off")
    return {"read": read}


def _base(name: str) -> str:
    return re.sub(r"\.(?:exe|cmd|bat)$", "", name.replace("\\", "/").rsplit("/", 1)[-1].lower())


def interpreter(name: str) -> str | None:
    """The language a program runs, for interpreters Verfy can follow."""
    base = _base(name)
    if re.match(r"^(?:python|pypy)[0-9.]*w?$", base) or base == "py":
        return "py"
    if base in ("node", "nodejs", "deno", "bun", "tsx", "ts-node", "ts-node-esm", "esno", "esrun"):
        return "js"
    if base in ("ruby", "jruby"):
        return "rb"
    if base == "perl":
        return "pl"
    if base == "php":
        return "php"
    if base in SHELLS or base in ("source", "."):
        return "sh"
    if base in ("pwsh", "powershell"):
        return "ps"
    return None


def _target(lang: str, base: str, args: list[str]) -> tuple[str, str] | None:
    """What an interpreter is asked to run: ("file", path), ("inline", code), ("module", name), ("stdin", "") or None."""
    a = list(args)
    if base == "deno":
        if not a:
            return None
        sub, a = a[0], a[1:]
        if sub == "eval":
            return ("inline", " ".join(a)) if a else None
        if sub not in ("run", "test", "bench"):
            return None
    if base == "bun":
        if a and a[0] in ("test", "install", "i", "add", "remove", "update", "x", "create", "init", "pm", "link", "build", "upgrade"):
            return None
        if a and a[0] == "run":
            a = a[1:]
    if base in ("node", "nodejs") and "--test" in a:
        return None
    if lang == "sh" and "-c" in a:
        return None  # the rules follow `bash -c` themselves
    i = 0
    while i < len(a):
        x = a[i]
        low = x.lower()
        if x in INLINE.get(lang, ()):
            return ("inline", a[i + 1]) if i + 1 < len(a) else None
        if lang == "py" and x == "-m":
            return ("module", a[i + 1]) if i + 1 < len(a) else None
        if lang == "py" and x.startswith("-c") and len(x) > 2:
            return ("inline", x[2:])
        if lang == "ps" and low in ("-file", "-f"):
            return ("file", a[i + 1]) if i + 1 < len(a) else None
        if lang == "ps" and low in ("-command", "-c", "-encodedcommand", "-ec", "-enc"):
            return None  # the rules read -Command; an encoded command is a rule of its own
        if lang == "php" and x == "-f":
            return ("file", a[i + 1]) if i + 1 < len(a) else None
        if x == "--":
            return ("file", a[i + 1]) if i + 1 < len(a) else None
        if x == "-" or (lang == "sh" and x == "-s"):
            return ("stdin", "")
        if x.startswith("-"):
            i += 2 if (x in VALUE_FLAGS.get(lang, ()) or low in VALUE_FLAGS.get(lang, ())) else 1
            continue
        return ("file", x)
    return ("stdin", "") if lang in ("py", "js", "rb", "pl", "php", "sh") and base != "deno" else None


def package_scripts(name: str, args: list[str]) -> list[str] | None:
    """The package.json scripts a package manager command runs, before and after hooks included."""
    base = _base(name)
    ops = [x for x in args if not x.startswith("-")]
    names: list[str] | None = None
    if base == "npm":
        if not ops:
            return None
        c = ops[0]
        if c in ("test", "t", "tst"):
            names = ["test"]
        elif c in ("start", "stop"):
            names = [c]
        elif c == "restart":
            names = ["restart", "stop", "start"]
        elif c in ("run", "run-script", "rum", "urn"):
            names = [ops[1]] if len(ops) > 1 else None
        elif c in ("install", "i", "ci", "in", "ins", "inst", "isntall"):
            return list(INSTALL) if len(ops) == 1 else None  # installing a named package runs its own scripts, not ours
        elif c in ("install-test", "it", "install-ci-test", "cit"):
            return [*INSTALL, "pretest", "test", "posttest"]
    elif base in ("yarn", "pnpm"):
        if not ops:
            return list(INSTALL) if base == "yarn" else None
        c = ops[0]
        if c in ("run", "run-script"):
            names = [ops[1]] if len(ops) > 1 else None
        elif c in ("install", "i"):
            return list(INSTALL) if len(ops) == 1 else None
        elif c in ("test", "t"):
            names = ["test"]
        elif c not in PM_BUILTINS:
            names = [c]
    elif base == "bun":
        if len(ops) > 1 and ops[0] == "run":
            names = [ops[1]]
        elif ops and ops[0] in ("install", "i") and len(ops) == 1:
            return list(INSTALL)
    if not names:
        return None
    out: list[str] = []
    for n in names:
        out += ["pre" + n, n, "post" + n]
    return out


def lang_of(path: str, text: str) -> str | None:
    base = os.path.basename(path).lower()
    if base in ("makefile", "gnumakefile"):
        return "make"
    ext = os.path.splitext(base)[1]
    if ext in LANG_EXT:
        return LANG_EXT[ext]
    m = re.match(r"#!\s*(\S+)(?:[ \t]+(\S+))?", text)
    if m:
        prog = m.group(1).rsplit("/", 1)[-1]
        if prog == "env" and m.group(2):
            prog = m.group(2)
        return interpreter(prog)
    return None


def shell_units(text: str) -> tuple[list[tuple[int, str]], list[tuple[int, str, str]]]:
    """The command lines of a shell script, as (line number, command), and the here-documents fed to an interpreter, as
    (line number, language, body). Comments and here-documents that are only data are left out."""
    lines = text.splitlines()
    cmds: list[tuple[int, str]] = []
    embedded: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        start = i
        line = lines[i]
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line.rstrip()[:-1] + " " + lines[i]
        i += 1
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        cmds.append((start + 1, line))
        for m in HEREDOC.finditer(line):
            delim, dash = m.group(3), m.group(1)
            body: list[str] = []
            first = i + 1
            while i < len(lines):
                cur = lines[i]
                i += 1
                if (cur.lstrip("\t") if dash else cur).rstrip() == delim:
                    break
                body.append(cur)
            lang = _heredoc_lang(line)
            if lang:
                embedded.append((first, lang, "\n".join(body)))
    return cmds, embedded


def _heredoc_lang(line: str) -> str | None:
    """The language of a here-document's body when the line feeds it to an interpreter (``python - <<EOF``)."""
    for s in parse_shell(line):
        lang = interpreter(s["name"])
        if lang and lang not in ("ps",):
            t = _target(lang, _base(s["name"]), s["args"])
            if t and t[0] == "stdin":
                return lang
        if s["name"] == "ssh":
            return "sh"
    return None


def literals(text: str, lang: str) -> tuple[list[tuple[int, int, str, str, str]], str]:
    """The string literals of a source file, as (start, end, quote, prefix, body), and the text with comments and the
    bodies of strings blanked out (newlines kept), so a call inside a string or a comment is not taken for code."""
    out: list[tuple[int, int, str, str, str]] = []
    masked = list(text)
    n = len(text)
    hash_comment = lang in ("py", "rb", "pl", "php")
    slash_comment = lang in ("js", "php")
    quotes = ("'", '"', "`") if lang != "py" else ("'", '"')

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if masked[k] != "\n":
                masked[k] = " "

    i = 0
    while i < n:
        c = text[i]
        if hash_comment and c == "#" and not (lang == "php" and text.startswith("#[", i)):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if slash_comment and c == "/" and i + 1 < n and text[i + 1] in "/*":
            if text[i + 1] == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
            else:
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if c in quotes:
            q = c
            if lang == "py" and text.startswith(c * 3, i):
                q = c * 3
            k = i - 1
            while k >= 0 and text[k] in "rRbBuUfF" and i - k <= 2:
                k -= 1
            prefix = text[k + 1:i] if lang == "py" else ("$" if lang == "js" and i > 0 and text[i - 1] == "$" else "")
            j = i + len(q)
            multiline = len(q) == 3 or q == "`"
            while j < n:
                if text[j] == "\\" and not (lang == "py" and "r" in prefix.lower()):
                    j += 2
                    continue
                if text.startswith(q, j):
                    break
                if text[j] == "\n" and not multiline:
                    break
                j += 1
            j = min(j, n)  # a backslash at the very end steps past it
            end = min(j + len(q), n) if j < n and text.startswith(q, j) else j
            body = text[i + len(q):j]
            out.append((i, end, q, prefix, body))
            blank(i + len(q), j)
            i = max(end, i + 1)
            continue
        i += 1
    return out, "".join(masked)


def _plain(body: str, quote: str, prefix: str) -> str:
    """A literal's text with what is filled in at run time written as ``$X``, except the home folder, written ``~``."""
    def fill(m: re.Match) -> str:
        return "~" if HOME_MARK.search(m.group(0)) else "$X"
    if quote == "`" or prefix == "$":
        body = re.sub(r"\$\{[^}]*\}", fill, body)
    if "f" in prefix.lower():
        body = re.sub(r"\{\{|\}\}", "", body)
        body = re.sub(r"\{[^{}]*\}", fill, body)
    return body


def _balanced(text: str, start: int) -> int:
    """The index just after the bracket that closes the one at ``start`` (in masked text, so strings cannot confuse it)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[text[start]]]
    i = start + 1
    while i < len(text) and stack:
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif stack and c == stack[-1]:
            stack.pop()
        i += 1
    return i


class _State:
    """``~/.verfy/scripts.json``: the files each session wrote, read and written under a lock."""

    def __init__(self, home: Path):
        self.path = Path(home) / "scripts.json"

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            if isinstance(data, dict) and data.get("v") == VERSION and isinstance(data.get("sessions"), dict):
                return data
        except (OSError, ValueError):
            pass
        return {"v": VERSION, "sessions": {}}

    def update(self, fn):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(self.path, timeout=10.0):
            data = self._read()
            result = fn(data)
            atomic_write(self.path, json.dumps(data, separators=(",", ":")) + "\n", mode=0o600)
            return result


class _Scan:
    def __init__(self, pol: dict, here: str, written: set[str], pending: set[str], started: float | None):
        self.pol = pol
        self.ctx = _Ctx(pol)
        self.home = str(pol["home"])
        self.ws = self.abs(str(pol["workspace"]), os.getcwd()) or str(pol["workspace"])
        self.here = here
        self.written = written
        self.pending = pending
        self.started = started
        self.out: list[dict] = []
        self.seen: set[str] = set()
        self.budget = BUDGET
        self.files = 0
        self.line_cache: dict[str, list[dict]] = {}

    # ---------------------------------------------------------------- paths
    def abs(self, p: str, here: str | None) -> str | None:
        p = p.strip().strip("'\"")
        if not p or "$" in p or "`" in p or "*" in p or "?" in p or "\n" in p:
            return None
        if p == "~" or p.startswith(("~/", "~\\")):
            p = self.home + p[1:]
        if os.name == "nt":
            m = re.match(r"^/([a-zA-Z])(/.*)?$", p)
            if m:
                p = m.group(1) + ":" + (m.group(2) or "/")
        if not os.path.isabs(p):
            p = os.path.join(here or self.here, p)
        return os.path.normpath(p)

    @staticmethod
    def key(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    def authored(self, path: str) -> bool:
        k = self.key(path)
        if k in self.written or k in self.pending:
            return True
        if self.started is not None:
            try:
                return os.stat(path).st_mtime >= self.started - 1.0
            except OSError:
                return False
        return False

    def show(self, path: str) -> str:
        try:
            rel = os.path.relpath(path, self.ws)
            if not rel.startswith(".."):
                return rel.replace("\\", "/")
        except ValueError:
            pass
        return path.replace("\\", "/")

    # ---------------------------------------------------------------- findings
    def add(self, rule: str, verdict: str, message: str, authored: bool) -> None:
        if verdict == "allow" or (not authored and verdict != "deny"):
            return
        self.out.append(_f(rule, verdict, message))

    def inner(self, where: str, findings: list[dict], authored: bool) -> None:
        kept = [f for f in findings if not f["rule"].startswith(("VFY-TOOL-", "VFY-SESSION-", "VFY-SCRIPT-"))]
        kept.sort(key=lambda f: -VERDICT_RANK[f["verdict"]])
        for f in kept[:PER_FILE]:
            self.add("VFY-SCRIPT-001", f["verdict"], f"In {where}: [{f['rule']}] {f['message']}", authored)

    def check_cmd(self, cmd: str) -> list[dict]:
        if cmd not in self.line_cache:
            d = check({"server": "verfy-script", "tool": "run_command", "arguments": {"command": cmd}}, self.pol)
            self.line_cache[cmd] = d["findings"]
        return self.line_cache[cmd]

    # ---------------------------------------------------------------- commands
    def command(self, cmd: str, here: str, depth: int, authored: bool, where: str | None) -> None:
        """Follow what ``cmd`` starts. ``where`` is None for the agent's own command (the rules already checked it)."""
        if where is not None:
            self.inner(where, self.check_cmd(cmd), authored)
        if depth >= MAX_DEPTH:
            return
        runs_code = False
        for s in parse_shell(cmd):
            name, args = s["name"], s["args"]
            if s["depth"] == 0 and name == "cd":
                ops = operands(args)
                nxt = self.abs(ops[0], here) if ops else self.home
                if nxt:
                    here = nxt
                continue
            base = _base(name)
            lang = interpreter(name)
            if lang:
                runs_code = True
                if base in ("source", ".") and args:
                    self.file(args[0], here, "sh", depth + 1)
                    continue
                t = _target(lang, base, args)
                if t and t[0] == "file":
                    self.file(t[1], here, None if lang == "js" else lang, depth + 1)
                elif t and t[0] == "inline":
                    self.code(t[1], lang, f"the inline {lang} code" + (f" in {where}" if where else ""), authored, depth + 1, here)
                elif t and t[0] == "module":
                    self.module(t[1], here, depth + 1)
                if base == "bun" and args and args[0] == "run" and len(args) > 1 and not os.path.exists(os.path.join(here, args[1])):
                    self.package(here, [f"pre{args[1]}", args[1], f"post{args[1]}"], depth + 1)
                continue
            names = package_scripts(name, args)
            if names:
                runs_code = True
                self.package(here, names, depth + 1)
                continue
            if base in ("make", "gmake"):
                runs_code = True
                self.make(here, args, depth + 1)
                continue
            if base in RUNNERS:
                runs_code = True
                continue
            if name and ("/" in name or "\\" in name or os.path.splitext(name)[1].lower() in LANG_EXT):
                p = self.abs(name, here)
                if p and (os.path.isfile(p) or self.key(p) in self.pending):
                    runs_code = True
                    self.file(name, here, None, depth + 1)
        if runs_code and where is None:
            self.session_files(depth + 1)

    def file(self, p: str, here: str, lang: str | None, depth: int, loaded: bool = False) -> None:
        """Read one script. ``loaded``: not named by the command, only code the agent wrote that a runner may load, so
        only what is blocked outright counts (an approved script must not ask again on every later command)."""
        path = self.abs(p, here)
        if not path:
            return
        k = self.key(path)
        if k in self.seen:
            return
        if not os.path.isfile(path):
            if k in self.pending:
                self.seen.add(k)
                self.add("VFY-SCRIPT-002", "ask", f"`{self.show(path)}` is written by this same command and then run, so Verfy cannot "
                                                  "read it before it runs. Write it first, then run it.", True)
            return
        self.seen.add(k)
        authored = self.authored(path) and not loaded
        if self.files >= MAX_FILES:
            return
        try:
            with open(path, "rb") as fh:
                head = fh.read(8192)
            size = os.path.getsize(path)
        except OSError:
            return
        if b"\0" in head:
            return  # a compiled program: there is no text to read
        if size > MAX_BYTES or size > self.budget:
            self.add("VFY-SCRIPT-002", "ask", f"`{self.show(path)}` is too large for Verfy to read before it runs.", authored)
            return
        try:
            raw = Path(path).read_bytes()
        except OSError:
            return
        self.files += 1
        self.budget -= len(raw)
        text = raw.decode("utf-8", "replace")
        lang = lang or lang_of(path, text)
        if not lang:
            return
        self.code(text, lang, f"`{self.show(path)}`", authored, depth, os.path.dirname(path) if lang == "make" else here)

    def module(self, mod: str, here: str, depth: int) -> None:
        if not re.match(r"^[A-Za-z_][\w.]*$", mod):
            return
        rel = mod.replace(".", os.sep)
        for cand in (rel + ".py", os.path.join(rel, "__main__.py")):
            p = os.path.join(here, cand)
            if os.path.isfile(p):
                self.file(p, here, "py", depth)
                return

    def package(self, here: str, names: list[str], depth: int) -> None:
        d = here
        pkg = None
        for _ in range(8):
            cand = os.path.join(d, "package.json")
            if os.path.isfile(cand):
                pkg = cand
                break
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        if not pkg:
            return
        try:
            scripts = json.loads(Path(pkg).read_text("utf-8")).get("scripts")
        except (OSError, ValueError, AttributeError):
            return
        if not isinstance(scripts, dict):
            return
        authored = self.authored(pkg)
        for n in dict.fromkeys(names):
            if self.key(pkg) + "#" + n in self.seen:
                continue
            self.seen.add(self.key(pkg) + "#" + n)
            cmd = scripts.get(n)
            if isinstance(cmd, str) and cmd.strip():
                self.command(cmd, os.path.dirname(pkg), depth, authored, f"`{self.show(pkg)}` (script `{n}`)")

    def make(self, here: str, args: list[str], depth: int) -> None:
        mf = None
        if "-f" in args and args.index("-f") + 1 < len(args):
            mf = self.abs(args[args.index("-f") + 1], here)
        else:
            try:
                names = set(os.listdir(here))
            except OSError:
                names = set()
            for name in ("GNUmakefile", "makefile", "Makefile"):  # the order make itself looks in
                if name in names:
                    mf = os.path.join(here, name)
                    break
        if mf:
            self.file(mf, here, "make", depth)

    def session_files(self, depth: int) -> None:
        """Code the agent wrote or changed in this session, inside the project: what a test runner or an interpreter
        may load without naming it."""
        for k in sorted(self.written):
            if self.files >= MAX_FILES:
                break
            base = os.path.basename(k).lower()
            if os.path.splitext(base)[1] not in LANG_EXT and base not in ("makefile", "gnumakefile"):
                continue
            ws = self.key(self.ws)
            if not (k == ws or k.startswith(ws.rstrip("\\/") + os.sep)):
                continue
            if os.path.isfile(k):
                self.file(k, self.here, None, depth, loaded=True)

    # ---------------------------------------------------------------- reading code
    def code(self, text: str, lang: str, where: str, authored: bool, depth: int, here: str, path: str | None = None) -> None:
        before = len(self.out)
        try:
            self._code(text, lang, where, authored, depth, here)
        except Exception:  # one file Verfy cannot parse must not drop what the others showed, nor let code through unread
            self.add("VFY-SCRIPT-002", "ask", f"Verfy could not read {where} before it runs.", authored)
        named = any(f"In {where}" in f["message"] and "[VFY-SELF-006]" in f["message"] for f in self.out[before:])
        if not named and rx(SECRET["text"], "i").search(text):  # the folder and the file named apart, e.g. in a path join
            self.add("VFY-SCRIPT-001", "deny", f"In {where}: [VFY-SELF-006] Names Verfy's folder and its signing key or device token.", authored)

    def _code(self, text: str, lang: str, where: str, authored: bool, depth: int, here: str) -> None:
        if lang in ("sh", "ps", "bat"):
            self.shell(text, where, authored, depth, here)
        elif lang == "make":
            recipes = "\n".join(re.sub(r"^\t[@+\-]*", "", ln) if ln.startswith("\t") else "" for ln in text.splitlines())
            self.shell(recipes, where, authored, depth, here)
        elif lang in SHELL_CALLS:
            self.source(text, lang, where, authored, depth, here)

    def shell(self, text: str, where: str, authored: bool, depth: int, here: str) -> None:
        cmds, embedded = shell_units(text)
        clean = "\n".join(c for _, c in cmds)
        if clean.strip():
            found = self.check_cmd(clean)
            for f in sorted(found, key=lambda f: -VERDICT_RANK[f["verdict"]])[:PER_FILE]:
                line = next((n for n, c in cmds[:LINES_MAX] if any(g["rule"] == f["rule"] for g in self.check_cmd(c))), None)
                self.inner(f"{where}, line {line}" if line else where, [f], authored)
            if depth < MAX_DEPTH:
                for n, c in cmds:
                    self._follow(c, here, depth, authored, f"{where}, line {n}")
        for n, lang, body in embedded:
            self.code(body, lang, f"{where} (here-document at line {n})", authored, depth + 1, here)

    def _follow(self, cmd: str, here: str, depth: int, authored: bool, where: str) -> None:
        """What one line of a script starts (the line itself was already checked with the rest of the script)."""
        saved = self.line_cache.get(cmd)
        self.line_cache[cmd] = []  # do not report the line twice
        try:
            self.command(cmd, here, depth, authored, where)
        finally:
            if saved is None:
                self.line_cache.pop(cmd, None)
            else:
                self.line_cache[cmd] = saved

    def source(self, text: str, lang: str, where: str, authored: bool, depth: int, here: str) -> None:
        lits, masked = literals(text, lang)
        starts = [x[0] for x in lits]
        newlines = [m.start() for m in re.finditer("\n", text)]

        def line_at(pos: int) -> int:
            return bisect.bisect_right(newlines, pos - 1) + 1

        def lits_in(a: int, b: int) -> list[tuple[int, int, str, str, str]]:
            return lits[bisect.bisect_left(starts, a):bisect.bisect_left(starts, b)]

        def region(m_end: int) -> tuple[int, int]:
            j = m_end
            if j > 0 and masked[j - 1] == "(":
                return j, _balanced(masked, j - 1)
            while j < len(masked) and masked[j] in " \t":
                j += 1
            if j < len(masked) and masked[j] == "(":
                return j + 1, _balanced(masked, j)
            e = masked.find("\n", j)
            return j, (len(masked) if e < 0 else e)

        network = bool(NETWORK.search(masked)) or any(re.match(r"https?://", x[4]) for x in lits)
        writes = bool(WRITES.search(text))
        commands: list[tuple[int, str]] = []

        # commands handed to the shell
        for m in SHELL_CALLS[lang].finditer(masked):
            a, b = region(m.end())
            inside = lits_in(a, b)
            if not inside:
                continue
            lead = masked[a:b].lstrip()
            first = inside[0]
            if lead.startswith("["):
                close = _balanced(masked, masked.index("[", a))
                parts = [_plain(x[4], x[2], x[3]) for x in lits_in(a, close)]
            elif re.fullmatch(r"[\s(]*[rRbBuUfF$]{0,2}", masked[a:first[0]]):  # the literal comes first, prefix and all
                parts = [_plain(first[4], first[2], first[3])]
                if ARGV_CALLS.search(masked[m.start():m.end()]):
                    rest = masked[first[1]:b]
                    k = rest.find("[")
                    if k >= 0:
                        close = _balanced(masked, first[1] + k)
                        parts += [_plain(x[4], x[2], x[3]) for x in lits_in(first[1] + k, close)]
            else:
                continue  # built at run time
            if len(parts) == 1:
                commands.append((line_at(m.start()), parts[0]))
            else:
                commands.append((line_at(m.start()), " ".join(p if re.match(r"^[\w./=:@%+,-]+$", p) else shlex.quote(p) for p in parts)))
        # backticks and %x{} / qx{}: commands in Ruby, Perl and PHP; $`...` in zx and Bun shell
        for st, _, q, prefix, body in lits:
            if q == "`" and (lang in ("rb", "pl", "php") or prefix == "$"):
                commands.append((line_at(st), _plain(body, q, prefix)))
        if lang in ("rb", "pl"):
            for m in re.finditer(r"(?:%x|\bqx)\s*([{(\[/|])", masked):
                close = {"{": "}", "(": ")", "[": "]"}.get(m.group(1), m.group(1))
                e = text.find(close, m.end())
                if e > 0:
                    commands.append((line_at(m.start()), text[m.end():e]))
        # recursive deletes in the language itself
        for pat, recursive in DELETE_CALLS.get(lang, []):
            for m in pat.finditer(masked):
                a, b = region(m.end())
                seg = text[a:b]
                parts = [_plain(x[4], x[2], x[3]) for x in lits_in(a, b)]
                rec = recursive if recursive is not None else bool(re.search(r"recursive\s*:\s*true", seg))
                home = bool(HOME_MARK.search(seg))
                path = self._joined(parts, home)
                if path:
                    commands.append((line_at(m.start()), ("rm -rf " if rec else "rm ") + shlex.quote(path)))
        for ln, cmd in commands:
            loc = f"{where}, line {ln}"
            self.inner(loc, self.check_cmd(cmd), authored)
            if depth < MAX_DEPTH:
                self._follow(cmd, here, depth, authored, loc)

        # paths and URLs written in the code
        by_line: dict[int, list[str]] = {}
        for st, _, q, prefix, body in lits:
            if q == "`" and lang in ("rb", "pl", "php"):
                continue
            body = _plain(body, q, prefix)
            ln = line_at(st)
            by_line.setdefault(ln, []).append(body)
            for u in _urls(body):
                for f in check_url(u, self.ctx):
                    self.add("VFY-SCRIPT-001", f["verdict"], f"In {where}, line {ln}: [{f['rule']}] {f['message']}", authored)
            if PATHISH.match(body) and len(body) < 512:
                self._path(body, ln, where, authored, network, writes)
        lines = text.splitlines()
        for ln, parts in by_line.items():
            home = ln - 1 < len(lines) and HOME_MARK.search(lines[ln - 1])
            if home or (parts and parts[0] == "~"):
                p = self._joined(parts, bool(home))
                if p and p not in parts:
                    self._path(p, ln, where, authored, network, writes)

        # code that decodes or downloads more code and runs it
        for m in EXEC[lang].finditer(masked):
            ln = line_at(m.start())
            window = "\n".join(lines[max(0, ln - 6):ln])
            if DECODE.search(window):
                self.add("VFY-SCRIPT-003", "ask", f"In {where}, line {ln}: the code decodes or downloads more code and runs it, "
                                                  "which Verfy cannot read before it runs.", authored)
                break

    @staticmethod
    def _joined(parts: list[str], home: bool) -> str | None:
        parts = [p for p in parts if p and PART.match(p.replace("~", "x", 1) if p.startswith("~") else p)]
        if home:
            rest = [p for p in parts if p != "~"]
            return "~/" + "/".join(x.strip("/\\") for x in rest) if rest else "~"
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        if PATHISH.match(parts[0]):
            return parts[0].rstrip("/\\") + "/" + "/".join(x.strip("/\\") for x in parts[1:])
        return None

    def _path(self, p: str, ln: int, where: str, authored: bool, network: bool, writes: bool) -> None:
        loc = f"In {where}, line {ln}"
        h = _home_vars(p.replace("\\", "/"))
        if rx(SECRET["token"], "i").search(h) or self.ctx.verfy_secret(self.ctx.path(h)):
            self.add("VFY-SCRIPT-001", "deny", f"{loc}: [VFY-SELF-006] Names Verfy's signing key or device token ({p}).", authored)
            return
        ap = self.ctx.path(h)
        own = self.ctx.guards_verfy(ap)
        if own:
            v = "deny" if own[0] == "deny" and writes else "ask"
            self.add("VFY-SCRIPT-001", v, f"{loc}: names {p}, which keeps Verfy on (`{own[1]}`).", authored)
            return
        sensitive = self.ctx.sensitive(ap)
        if sensitive and network:
            self.add("VFY-SCRIPT-001", "deny", f"{loc}: [VFY-SH-008] Names the sensitive file {p} in code that also uses the network.", authored)
            return
        hit = self.ctx.protected(ap)
        if hit:
            self.add("VFY-SCRIPT-001", "deny" if writes else "ask", f"{loc}: names {p}, which is protected (`{hit}`).", authored)
            return
        if sensitive:
            self.add("VFY-SCRIPT-001", "ask", f"{loc}: [VFY-SH-007] Names the sensitive file {p}.", authored)


def _shell_text(args: dict) -> str:
    keys = {str(k).lower(): v for k, v in args.items()}
    for k in [*PATTERNS["command_keys"], "args"]:
        v = keys.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            return " ".join(x if re.match(r"^[\w./=:@%+,-]+$", x) else shlex.quote(x) for x in v)
    return ""


def written_by(cmd: str, here: str, scan: _Scan) -> set[str]:
    """Files a shell command writes: redirects, cp/mv/tee and the like, and downloads (``curl -o``, ``wget -O``)."""
    out: set[str] = set()
    for s in parse_shell(cmd):
        if s["depth"] == 0 and s["name"] == "cd":
            ops = operands(s["args"])
            nxt = scan.abs(ops[0], here) if ops else scan.home
            if nxt:
                here = nxt
            continue
        paths = list(_written(s))
        a = s["args"]
        if s["name"] == "curl":
            for i, x in enumerate(a):
                if x in ("-o", "--output") and i + 1 < len(a):
                    paths.append(a[i + 1])
                elif x.startswith("--output="):
                    paths.append(x.split("=", 1)[1])
        if s["name"] == "wget":
            for i, x in enumerate(a):
                if x in ("-O", "--output-document") and i + 1 < len(a):
                    paths.append(a[i + 1])
                elif x.startswith("--output-document="):
                    paths.append(x.split("=", 1)[1])
        for p in paths:
            ap = scan.abs(p, here)
            if ap:
                out.add(scan.key(ap))
    return out


def _file_paths(args: dict, scan: _Scan, here: str) -> set[str]:
    out: set[str] = set()
    for k in PATTERNS["path_keys"]:
        v = args.get(k)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and x:
                ap = scan.abs(x, here)
                if ap:
                    out.add(scan.key(ap))
    return out


def _prune(data: dict, now: float) -> None:
    sessions = data["sessions"]
    for sid in list(sessions):
        s = sessions[sid]
        if not isinstance(s, dict) or now - float(s.get("last", 0)) > KEEP:
            del sessions[sid]
    if len(sessions) > SESSIONS_MAX:
        for sid in sorted(sessions, key=lambda x: sessions[x].get("last", 0))[: len(sessions) - SESSIONS_MAX]:
            del sessions[sid]


def apply(home: Path | None, session: str, checked: list[tuple[dict, dict]], policy: dict, cwd: str | None = None,
          now: float | None = None) -> list[tuple[dict, dict]]:
    """Add what the scripts a call starts would do to the rules' decisions for that call, and remember the files it
    writes. Returns the decisions, changed in place."""
    if not checked:
        return checked
    complete = policy and all(k in policy for k in DEFAULT_POLICY) and policy.get("home") and policy.get("workspace")
    pol = policy if complete else load_policy(policy)
    if settings(pol)["read"] == "off":
        return checked
    now = time.time() if now is None else now
    here = cwd if cwd and os.path.isdir(cwd) else str(pol["workspace"])
    state = _State(home) if home is not None else None
    sess: dict[str, Any] = {}
    if state is not None:
        try:
            data = state._read()
            sess = data["sessions"].get(session) if isinstance(data["sessions"].get(session), dict) else {}
        except Exception:
            sess = {}
    started = float(sess["start"]) if sess.get("start") else (now if state is not None else None)
    written = set((sess.get("files") or {}).keys())
    probe = _Scan(pol, here, written, set(), started)
    pending: set[str] = set()
    for action, decision in checked:
        args = action.get("arguments", action.get("args", {}))
        args = args if isinstance(args, dict) else {}
        kind = decision.get("kind")
        try:
            if kind == "shell":
                pending |= written_by(_shell_text(args), here, probe)
            elif kind in ("file_write", "file_delete"):
                pending |= _file_paths(args, probe, here)
        except Exception:
            pass
    disabled = set(pol.get("disabled_rules", []))
    for action, decision in checked:
        if decision.get("kind") != "shell" or decision.get("verdict") == "deny":
            continue
        args = action.get("arguments", action.get("args", {}))
        cmd = _shell_text(args if isinstance(args, dict) else {})
        if not cmd.strip():
            continue
        scan = _Scan(pol, here, written, pending, started)
        try:
            for _, lang, body in shell_units(cmd)[1]:
                scan.code(body, lang, "the here-document in this command", True, 1, here)
            scan.command(cmd, here, 0, True, None)
        except Exception:
            continue  # this layer only adds findings: what it cannot read leaves the rules' answer
        seen: set[tuple[str, str]] = {(f["rule"], f["message"]) for f in decision.get("findings", [])}
        added = []
        for f in scan.out:
            key = (f["rule"], f["message"])
            if f["rule"] in disabled or key in seen:
                continue
            seen.add(key)
            added.append(f)
        if added:
            added.sort(key=lambda f: -VERDICT_RANK[f["verdict"]])
            decision["findings"] = sorted([*decision.get("findings", []), *added[:8]], key=lambda f: -VERDICT_RANK[f["verdict"]])
            decision["verdict"] = decision["findings"][0]["verdict"]
    if state is not None:
        def step(data: dict) -> None:
            _prune(data, now)
            s = data["sessions"].setdefault(session, {"start": round(started or now, 3), "files": {}})
            s.setdefault("start", round(started or now, 3))
            s["last"] = round(now, 3)
            files = s.setdefault("files", {})
            for k in pending:
                files[k] = round(now, 3)
            if len(files) > FILES_MAX:
                for k in sorted(files, key=lambda x: files[x])[: len(files) - FILES_MAX]:
                    del files[k]
        try:
            state.update(step)
        except Exception:
            pass
    return checked
