"""What the hook needs, without the rest of the CLI: where Verfy keeps its files, which policy is in force, and how a
receipt is written. ``verfy hook <event>`` runs from here (entry.py), so an agent waits for these modules only, not for
the forty commands of cli.py. cli.py imports every name back.
"""

from __future__ import annotations

import functools
import hashlib
import json
import sys
from pathlib import Path

from ._util import real_file, verfy_home
from .fileio import atomic_write
from .policy import load_policy, policy_digest, tighten
from .receipts import Key, Ledger


def _sandboxes():
    from . import sandbox
    return sandbox


def home_file(name: str) -> Path:
    return verfy_home() / name


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def trusted_policies() -> dict:
    try:
        data = json.loads(home_file("trusted-policies.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_trusted(path: Path) -> bool:
    return trusted_policies().get(str(path.resolve())) == _file_digest(path)


def trust_policy(path: Path) -> None:
    """Remember this exact file as one a person chose. If it changes, it has to be trusted again."""
    home_file("trusted-policies.json").parent.mkdir(parents=True, exist_ok=True)
    atomic_write(home_file("trusted-policies.json"), json.dumps({**trusted_policies(), str(path.resolve()): _file_digest(path)}, indent=2) + "\n")


def _guard_home(pol: dict) -> dict:
    """A VERFY_HOME somewhere else holds the same signing key, so it gets the protection `~/.verfy` has."""
    home = verfy_home()
    if home != Path.home() / ".verfy":
        pat = home.as_posix() + "/**"
        files = pol["files"]  # may be the defaults themselves, so it gets a new object
        pol["files"] = {**files, "sensitive": [*files["sensitive"], pat], "deny_write": [*files["deny_write"], pat]}
    # and the rules Verfy published since this release (`verfy rules update`), which only make it stricter
    from . import rulefeed
    return rulefeed.merge(pol, home)


def resolve_policy(cwd: Path | None = None, workspace: str | None = None, notice: bool = False) -> dict:
    """The policy in force here. A `verfy.policy.json` in this folder may have come with a clone, so it only tightens your
    own or your team's policy, until you trust it. A team policy is never loosened by a file in a folder."""
    project = (cwd or Path(".")) / "verfy.policy.json"
    team, user = home_file("team") / "policy.json", home_file("policy.json")
    base = team if real_file(team) else user if real_file(user) else None
    if not real_file(project):
        return _guard_home(load_policy(base, workspace=workspace))
    if is_trusted(project) and base != team:
        return _guard_home(load_policy(project, workspace=workspace))
    if notice and not is_trusted(project):
        print(f"[verfy] {project} is not trusted, so only what makes Verfy stricter applies. Read it, then run `verfy policy trust`.", file=sys.stderr)
    return _guard_home(tighten(load_policy(base, workspace=workspace), json.loads(project.read_text("utf-8"))))


def _hook_policy(cwd: str | None) -> dict:
    return resolve_policy(Path(cwd) if cwd else None, workspace=cwd)


def _hook_record(*, action: dict, decision: dict, session: str, policy: dict, outcome: dict, agent: str | None = None) -> dict | None:
    kp = home_file("key.json")
    if not kp.exists():
        return None  # `verfy init` not run yet: still guard, just no receipt
    led = Ledger(home_file("ledger.jsonl"), Key.load(kp))
    receipt = led.append(agent=agent or policy.get("agent", "claude-code"), session=session, action=action, decision=decision,
                         outcome=outcome, policy_sha256=policy_digest(policy),
                         include_args=bool((policy.get("receipts") or {}).get("include_args", False)),
                         sandbox=_sandboxes().running_in() or ("claude-code" if not agent and _sandboxes().effective(Path.cwd(), Path.home())["enabled"] is True else None))
    home = verfy_home()
    if (home / "team.json").exists():  # the team module (and its HTTP client) only for an enrolled device
        from . import team as teamlib
        teamlib.sync_soon(home)
    from . import rulefeed
    rulefeed.refresh_soon(home)
    return receipt


def _hook_fail_mode() -> str:
    try:
        return resolve_policy().get("fail_mode", "ask")
    except Exception:  # noqa: BLE001
        return "ask"



def run(event: str) -> int | None:
    """``verfy hook EVENT`` for an agent; None when EVENT is not an agent's hook, so the full CLI answers."""
    from . import hook as hooks
    if event not in hooks.AGENTS:
        return None
    agent = {"pre-tool-use": None, "cursor": "cursor", "prompt": None}.get(event, event)  # the prompt guard names its agent itself
    record = functools.partial(_hook_record, agent=agent) if agent else _hook_record
    return hooks.run_hook(event, record=record, get_policy=_hook_policy, fail_mode=_hook_fail_mode, home=verfy_home())
