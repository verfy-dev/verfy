# `verfy.receipt/1`

A receipt records one action an agent took (or was stopped from taking), signed by the machine it ran on and chained
to the receipt before it, so a ledger cannot be edited, cut or reordered without the signatures or links failing.

## Fields

```json
{
  "v": "verfy.receipt/1",
  "id": "rcpt_3f9c2a71d04e5b68",
  "seq": 41,
  "prev": "sha256:9b1d…",
  "issued_at": "2026-11-16T09:12:44.513Z",
  "agent": "refund-bot",
  "session": "ses_7c1e…",
  "action": {
    "server": "stripe",
    "tool": "refund",
    "kind": "payment",
    "args_sha256": "sha256:6f6b…"
  },
  "decision": {
    "verdict": "allow",
    "rules": [],
    "policy_sha256": "none"
  },
  "outcome": { "status": "ok", "result_sha256": "sha256:1a2b…" },
  "tool_sha256": null,
  "kid": "atl_56475aa75463474c",
  "sig": "…86 base64url characters…"
}
```

| Field | Meaning |
| --- | --- |
| `id` | `rcpt_` and 1 to 64 letters or digits; unique within a ledger |
| `seq` | 0 for the first receipt of a ledger, then one more each time |
| `prev` | `null` when `seq` is 0, else the `sha256:` hash of the whole previous receipt (including its `sig`) |
| `issued_at` | the signing machine's clock |
| `agent`, `session` | who acted, and in which run; at most 200 UTF-16 code units each |
| `action.server`, `action.tool` | the system acted on and the action's name (at most 200 each) |
| `action.kind` | one lowercase word: `payment`, `message`, `write`, `delete`, `read`, `exec`, `network`, `deploy`, `access`, `data`, `other`, or another |
| `action.args_sha256` | the salted hash of the arguments (below) |
| `action.args` | optional: the arguments themselves, only when the recorder was told to keep them |
| `decision.verdict` | `allow`, `ask` (a person approved it) or `deny` |
| `decision.rules` | the ids of the rules that covered the action |
| `decision.policy_sha256` | the hash of the rules in force, or `none` when no rules were checked |
| `decision.approved_by` | who approved an `ask` (at most 100 characters) |
| `outcome.status` | `ok`, `error`, `blocked` (a rule denied it; it never ran), `declined` (nobody approved it; it never ran), `pending` or `asked` |
| `outcome.result_sha256` | the salted hash of the result, or `null` |
| `tool_sha256` | for MCP tools: the hash of the tool's definition when it ran, else `null` |
| `kid` | `atl_` and the first 16 hex characters of SHA-256 of the 32-byte public key |
| `sig` | Ed25519 over the canonical JSON of every other field, base64url |

## Signing and checking

To sign: build every field except `sig`, set `v` and `kid`, take the canonical JSON, sign it with Ed25519, and add
`sig`. To check: remove `sig`, confirm `kid` matches the public key, and verify the signature over the canonical JSON
of the rest.

A ledger checks when every receipt's signature checks, `seq` counts up by one from the first, and each `prev` is the
hash of the receipt before. A slice of a ledger checks the same way, starting from its first receipt's `seq` and `prev`.

## Salted hashes

A plain hash of a short value (`{"command": "ls"}`) can be found by hashing likely values. So each key has a secret
32-byte salt, kept with the key and never uploaded, and the hashes in a receipt are

```
args_sha256   = sha256 of canonical {"salt": base64url(salt), "value": arguments}
result_sha256 = sha256 of canonical {"salt": base64url(salt), "value": result}
```

Whoever holds the key file (and so the salt) can show a given value produced a given hash; nobody else can test
guesses against it. Keys made before 0.9.0 have no salt; their hashes are plain `sha256` of the value.

## Ledger and key files

A ledger is a file of receipts, one canonical-or-plain JSON object per line (`\n`), appended under a lock so two
writers never take the same `seq`. The key file is JSON:
`{"kty": "Ed25519", "kid": "atl_…", "public": "<base64url>", "secret": "<base64url seed>", "hash_salt": "<base64url>"}`,
readable only by its owner.

The Python recorder keeps both in `~/.verfy` (`VERFY_HOME`), the Node.js recorder in `~/.verfy/node`
(`VERFY_NODE_HOME`). The two use different locks, so they must not write the same ledger at the same time.
