"""Who answers for an agent's action: Verfy's open responsibility rules (``verfy.liability/1``).

Fixed rules, read off the signed evidence, no model and no judgement of intent. They name the party whose
side of the chain the action came from, so an insurer, an arbitrator or two companies can start from the same
answer and argue only about what the rules leave open. The rules are public (docs/RESPONSIBILITY_RULES.md) and
versioned; a decision always names the version it used.

Parties:
  nobody          the action did not run
  agent_operator  whoever deployed and ran the agent: its device, its key, its policy
  approver        the person who approved this one action with a passkey
  tool_author     whoever publishes the tool, when its definition changed from the one that was locked

This is a starting point for people, not a ruling: an arbitrator may decide otherwise, and Verfy pays nothing.
"""

from __future__ import annotations

VERSION = "verfy.liability/1"

RULES = {
    "R1": ("nobody", "Verfy blocked the action, so it did not run and caused no loss through Verfy."),
    "R2": ("agent_operator", "The receipt chain does not check out, so the operator cannot show what happened; the burden stays with them."),
    "R3": ("agent_operator", "The action ran under emergency access that a person on the operator's side opened."),
    "R4": ("agent_operator", "Verfy was in observe mode: the rules would have stopped the action and the operator chose not to enforce them."),
    "R5": ("approver", "A person approved this exact action with a passkey; the signature covers its arguments."),
    "R6": ("agent_operator", "An approval is named, but no passkey signature proves who approved this action."),
    "R7": ("agent_operator", "A rule asked for a person and the agent went ahead without a recorded approval."),
    "R8": ("tool_author", "The tool's definition was not the one the operator locked: the tool changed under the agent."),
    "R9": ("agent_operator", "The operator's own policy allowed the action and no rule asked for a person."),
}


def decide(finding: str, *, passkey_ok: bool | None = None, tool_changed: bool | None = None) -> dict:
    """The rule that applies to a dispute's fixed-rule finding (dispute.FINDINGS), with what is known about the
    passkey proof (True: checked and good) and the tool (True: differs from the lock; None: no lock given)."""
    if finding == "blocked":
        rule = "R1"
    elif finding == "chain_broken":
        rule = "R2"
    elif finding == "emergency_access":
        rule = "R3"
    elif finding == "observe_mode":
        rule = "R4"
    elif finding == "person_approved":
        rule = "R5" if passkey_ok else "R6"
    elif finding == "asked_not_approved":
        rule = "R7"
    elif tool_changed:
        rule = "R8"
    else:
        rule = "R9"
    party, why = RULES[rule]
    out = {"v": VERSION, "rule": rule, "party": party, "why": why}
    if finding == "policy_allowed" and tool_changed is None:
        out["open"] = "No lock was given, so whether the tool changed under the agent (R8) was not checked."
    return out
