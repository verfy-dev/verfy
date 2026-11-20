# The rule feed

Verfy's rules ship with each CLI release. The rule feed carries rules published between releases, so a rule for a new
attack reaches every machine within a day.

## Format

`GET /api/v1/rules/feed` answers `{"feed": <statement>}` (or `{"feed": null}` where Verfy Cloud has no witness key).
The statement is a [`verfy.witness/1`](witness.md) statement of type `rules`:

```json
{"type": "rules",
 "subject": {"version": 3,
             "shell": [["VFY-FEED-001", "deny", "\\bnew-attack-tool\\b", "", "A tool used in a new attack."]],
             "network_deny": ["*.oast.pro", "exfil.example"]}}
```

| Field | Meaning |
| --- | --- |
| `version` | a whole number from 1; a newer feed has a larger one |
| `shell` | rules `[id, verdict, pattern, flags, message]` checked against shell commands, as `patterns.json` rules are |
| `network_deny` | hosts added to the network deny list; `*.` covers every name under one |

## What a client must refuse

A client takes a feed only when all of these hold, and otherwise keeps the one it has:

- the signature checks with a witness key Verfy publishes at `/.well-known/verfy-witness.json`;
- it is signed by the key the client accepted the first time, unless the user accepts a new one (`--trust-key KID`);
- its version is not lower than the version the client keeps;
- every rule id is `VFY-FEED-` and three digits, every verdict is `ask` or `deny`, flags are empty or `i`, every
  pattern compiles, is at most 600 characters and has no nested quantifier such as `(a+)+`, and messages are 1 to 200
  characters; at most 500 rules and 1000 hosts;
- every host is a lower-case host name or an IP address.

A feed rule applies only to shell commands (a custom rule with `"kind": "shell"`), never to file contents. Nothing in a
feed can remove, loosen or rename another rule, so the worst a feed can do is ask or stop too much.

## On the machine

`verfy rules update` keeps the feed in `~/.verfy/rule-feed.json`, with the accepted key and the time it was fetched.
The policy in force then has the feed's rules and hosts in it, so receipts name a policy with them. A machine enrolled
in Verfy Cloud with automatic upload refreshes it in the background at most once a day (`verfy rules auto off` stops
that); elsewhere `verfy rules auto on` turns it on.
