# Verfy responsibility rules (`verfy.liability/1`)

When an AI agent does something someone disputes, these rules give a first answer to one question: **on whose side of the chain did the action come from?** They read only the signed evidence (the receipt chain, the passkey signatures, the locked tool definitions). There is no model and no judgement of intent.

They are a common starting point, not a ruling. An insurer, an arbitrator or two companies may agree to use them, and then argue only about what they leave open. Verfy pays nothing and decides nothing. These rules are not legal advice and have not been reviewed by a lawyer.

## Parties

| Party | Who |
|---|---|
| `nobody` | The action did not run |
| `agent_operator` | Whoever deployed and ran the agent: its device, its key, its policy |
| `approver` | The person who approved this one action with a passkey |
| `tool_author` | Whoever publishes the tool, when its definition changed from the one that was locked |

## Rules

The first rule that applies is used. The input is the dispute record's fixed-rule finding (`verfy dispute open`), whether the passkey signature checks out, and, when a `verfy.lock` is given, whether the tool's definition matched it.

| Rule | When | Party |
|---|---|---|
| R1 | Verfy blocked the action, so it did not run | `nobody` |
| R2 | The receipt chain does not check out, so the operator cannot show what happened | `agent_operator` |
| R3 | The action ran under emergency access (`verfy breakglass`) that a person on the operator's side opened | `agent_operator` |
| R4 | Verfy was in observe mode: the rules would have stopped the action and the operator chose not to enforce them | `agent_operator` |
| R5 | A person approved this exact action with a passkey, and the signature covers its arguments | `approver` |
| R6 | An approval is named, but no passkey signature proves who approved this action | `agent_operator` |
| R7 | A rule asked for a person and the agent went ahead without a recorded approval | `agent_operator` |
| R8 | The tool's definition was not the one the operator locked: the tool changed under the agent | `tool_author` |
| R9 | The operator's own policy allowed the action and no rule asked for a person | `agent_operator` |

When no lock is given, R8 cannot be checked, and the decision says so (`open`).

## What they leave open

- Whether the loss is real, and how large it is.
- Whether the person who approved (R5) was misled, for example by an agent that described the action falsely.
- Agreements between the parties that move responsibility (a contract, terms of service, an insurance policy).
- Actions that did not go through Verfy.

## Using them

```
verfy claim rules                 # print the rules
verfy claim build dispute.json    # dispute record + passkeys + rule (+ --verdict, --lock) in one signed file
verfy claim verify clm_....json   # anyone checks it again, offline, including that the rule matches the evidence
```

A claim names the rules' version. A later version never changes the answer for a claim built under an earlier one.

Suggestions and objections: open an issue on github.com/verfy-dev/verfy.
