"""What is on and what is off in the policy in force, in words, so nobody has to read JSON to know where they stand.

`verfy setup`, `verfy init` and `verfy policy status` print it. Every line names the setting that changes it.
"""

from __future__ import annotations

from typing import Any


def summary(pol: dict[str, Any]) -> list[tuple[bool, str]]:
    from .adaptive import settings as adaptive_settings
    from .scripts import settings as script_settings

    ad = adaptive_settings(pol)
    session = pol.get("session") or {}
    after = session.get("after_outside_text", "off")
    where = {"hooks": ", in agents with hooks (session.after_outside_text; \"ask\" covers the MCP gateway too)",
             "ask": " (session.after_outside_text)", "deny": " and are denied (session.after_outside_text)", "off": " (session.after_outside_text)"}
    sends = (pol.get("messages") or {}).get("send", "ask")
    allow = (pol.get("network") or {}).get("allow") or []
    return [
        (True, "fixed rules check each command, file, URL, SQL query and payment before it runs"),
        (script_settings(pol)["read"] == "on", "a script the agent runs is read first, line by line (scripts.read)"),
        (ad["escalate"] == "on", "a session that tried something blocked needs a person for anything risky (adaptive.escalate)"),
        (ad["novelty"] == "ask", "a program or host never used on this machine is asked about once (adaptive.novelty)"),
        (sends != "allow", "a message (email, chat, post) needs a person" + (" and is denied" if sends == "deny" else "") + " (messages.send)"),
        (after != "off", "after outside text, deletes, messages, payments, uploads and git push need a person" + where.get(after, "")),
        (session.get("include_network") is True, "after outside text, any request to a site not on network.allow needs a person too (session.include_network)"),
        (bool(allow), "only sites on network.allow are reached without a person" + (f" ({len(allow)} listed)" if allow else "") + " (network.allow)"),
        ((pol.get("lock") or {}).get("on_new", "ask") != "allow", "a new MCP tool waits until it is approved into verfy.lock (lock.on_new)"),
        (False, "sandbox: only what you start with `verfy run --sandbox` runs in it (needs the srt runtime; WSL2 on Windows)"),
    ]


def lines(pol: dict[str, Any], where: str) -> list[str]:
    out = [f"What is on here (from {where}; change a setting there, or start from `verfy policy templates`):"]
    out += [f"  {'on ' if on else 'off'}  {text}" for on, text in summary(pol)]
    return out
