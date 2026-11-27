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

Since 0.32.0 each one also checks the passkey approvals receipts carry (`decision.approval`, written since 0.31.0
when a teammate approves a call in Verfy Cloud with Face ID, a fingerprint or a security key): that the passkey
signed that request, that call's `args_sha256` and the decision, on Verfy Cloud's site, with the person verified.
ES256, EdDSA and RS256 passkeys; the vectors are `verfy-cli/tests/fixtures/passkey_proofs.json`, made with
node:crypto. Python: `verfy verify`; JavaScript: `checkApprovals(receipts)`; Go: `verfy.CheckApprovals` (and
`verfy-verify` reports them); Rust: `verfy_verify::check_approvals`. Go stays on the standard library; the Rust crate
uses RustCrypto's `p256` and `rsa` for those two key types.

The public key is the base64url text `verfy key` prints. A receipt holds hashes of the agent's arguments, never
the arguments, so a ledger can be handed to anyone who needs to check it.
