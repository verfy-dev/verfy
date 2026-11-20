# Action rules

Rules are checked before an action runs. An action no rule covers goes ahead. One a rule covers is either sent to a
person (`ask`) or stopped (`deny`); the strictest rule that covers it decides.

```json
{"id": "big-refund", "kind": "payment", "amount": "amount", "over": 500, "then": "ask"}
{"id": "refund-day", "kind": "payment", "amount": "amount", "daily": 2000, "then": "deny"}
{"id": "no-drop", "action": "drop_*", "then": "deny"}
{"system": ["prod-*", "billing"], "kind": "delete", "then": "ask", "message": "Deleting in production needs a second person"}
```

| Field | Meaning |
| --- | --- |
| `id` | 1 to 64 letters, digits or `. _ : -`. Without one, the id is `rule-` and 8 hex characters of the rule's hash |
| `kind`, `system`, `action` | which actions the rule covers: a name, a `*`/`?` pattern, or a list of them. A rule with none covers every action |
| `amount` | the dotted path of a number in the action's arguments (`amount`, `payment.total`); a number in a string counts |
| `over` | covers an action whose amount is above this |
| `daily` | covers an action that would take today's total (UTC day, per agent and rule) above this |
| `then` | `ask` or `deny` |
| `message` | shown to the person asked, and recorded with the finding |

Any other field is an error, so a misspelt rule never silently covers nothing.

## Failing closed

A rule with a limit covers an action whose amount is missing, not a number, or not finite: it is treated as over the
limit. A guard that cannot reach the person it must ask declines. An approval function that raises declines.

## Daily totals

Each machine keeps today's totals in `limits.json` (amounts only, owner-readable). An action the guard lets through
adds its amount to every daily rule that covered it, also when the action fails afterwards. Checking and adding happen
under one lock, so two processes cannot both spend the last of a limit. After an `ask`, the rules are checked again
when the answer comes, so a limit spent while the person was deciding still stops the action.

## Where rules come from

`Recorder(rules=[...])`, `~/.verfy/policy.json` and the team policy `verfy team pull` saves (`team/policy.json`),
each under `"actions": [...]`. Team rule ids are prefixed `team:`. Together they can only make an action stricter.

## What is recorded

An action the rules let through is recorded when it ends, with `decision.verdict` `allow` or `ask`, the covering rule
ids in `decision.rules`, `approved_by` for an approval, and `decision.policy_sha256` set to
`sha256` of canonical `{"actions": [the rules in force]}`. An action they stop is recorded at once with
`outcome.status` `blocked` (deny) or `declined` (nobody approved it), and never runs.

When the team approves (`on_ask="team"`), Verfy Cloud receives the action's name, system, kind, the salted hash of its
arguments and the findings (rule, verdict and message, which for a limit names the amount), never the arguments.
