# Verfy receipt verifiers

Check a Verfy ledger (`verfy.receipt/1`) without Verfy installed: every Ed25519 signature, every `prev` link and
the numbering. The same test vectors (`verfy-cli/tests/fixtures/receipts.json` and `canonical.json`) run against
each one in CI, next to the Python and JavaScript code they mirror.

| Language | Where | Use |
|---|---|---|
| Python | `pip install verfy` | `verfy verify --ledger ledger.jsonl --pub KEY` |
| JavaScript | `verfy-cli/js/verfy-node.mjs` | `verifyLedger(receipts, publicKey)` (Node 18+, browsers) |
| Go | `verifiers/go` (standard library only) | `go run ./cmd/verfy-verify ledger.jsonl KEY`, or `verfy.VerifyLedger` |
| Rust | `verifiers/rust` (crate `verfy-verify`) | `verfy_verify::verify_ledger(&receipts, &key)` |

The public key is the base64url text `verfy key` prints. A receipt holds hashes of the agent's arguments, never
the arguments, so a ledger can be handed to anyone who needs to check it.
