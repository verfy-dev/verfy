# Verfy formats

These pages describe every format Verfy writes or checks, precisely enough to build a second implementation that
interoperates with this one. They are part of the MIT-licensed project: anyone may implement them.

| Format | What it is | Page |
| --- | --- | --- |
| `verfy.receipt/1` | One signed, chained record of one action an agent took | [receipt.md](receipt.md) |
| Action rules | Limits checked before an action runs (`ask` or `deny`) | [rules.md](rules.md) |
| `verfy.witness/1` | A statement Verfy Cloud signs about receipts it holds | [witness.md](witness.md) |
| Transparency log | The append-only Merkle tree of every receipt Verfy Cloud accepted | [log.md](log.md) |
| `verfy.deal/1` | One action two agents both sign; payments tied to a mandate | [deal.md](deal.md) |
| `verfy.incident/1` | The evidence for a stretch of an agent's work, in one file | [incident.md](incident.md) |

Two implementations exist today and are tested against each other on shared vectors:

- Python: the `verfy` package (`verfy-cli/src/verfy`).
- JavaScript: `verfy-cli/js/verfy-engine.mjs` (browsers and Node.js) and `verfy-cli/js/verfy-node.mjs` (a Node.js
  recorder). Verfy Cloud's server uses the same engine.

The vectors are in `verfy-cli/tests/fixtures`: `canonical.json`, `receipts.json`, `witness.json` and `merkle.json`.

## Conventions

- **Canonical JSON** is the byte form everything is hashed and signed in: UTF-8, no whitespace, object keys sorted by
  their UTF-16 code units, strings escaped as `JSON.stringify` escapes them, numbers written as ECMAScript's
  `Number.prototype.toString` writes them. NaN, Infinity and integers outside ±(2^53 − 1) cannot be signed.
- **`sha256:<hex>`** is SHA-256 of the canonical JSON of a value, as 64 lowercase hex characters after the prefix.
- **base64url** is RFC 4648 section 5 without padding.
- **Ed25519** is RFC 8032 (pure Ed25519, no prehash). Keys are 32 bytes.
- Times are RFC 3339 in UTC with a `Z`.

A format's version string (`v`) changes only when a reader of the old version would misread the new one. Fields may
be added to a version; readers ignore fields they do not know, except that a signature always covers every field.
