# `verfy.incident/1`

When something an agent did needs looking into, an incident pack is the evidence in one file that anyone can check
without trusting whoever hands it over.

```
verfy incident export --since 2026-11-16T09:00:00Z --until 2026-11-16T12:00:00Z --prove -o refund-incident.json
verfy incident verify refund-incident.json
```

## Fields

| Field | Meaning |
| --- | --- |
| `v` | `verfy.incident/1` |
| `created_at` | when the pack was made |
| `window` | `{"since", "until", "agent"}` as asked |
| `public_key`, `kid` | the key that signed the receipts |
| `receipts` | every receipt from the first to the last one in the window, as one unbroken run of the chain |
| `next` | the hash of the receipt after the run, or `null` when the run reaches the end of the ledger |
| `ledger_length` | how many receipts the ledger held when the pack was made |
| `note` | optional, what the pack is about (at most 2000 characters) |
| `log` | optional (`--prove`): `{"url", "proofs": [...], "not_in_log": [...]}`, see below |
| `attestation` | optional (`--attest`): Verfy Cloud's signed statement about these receipts, see below |

With `--agent`, the run spans that agent's first to last receipt in the window. Receipts of other agents in between
stay in, so nothing is cut out of the chain.

The arguments of each action are in a pack only if they were stored in the receipts; otherwise only their salted
hashes are. A pack holds no key secret and no salt.

## Log proofs

With `--prove`, each receipt's [transparency-log](log.md) inclusion proof is added (the same document
`/api/v1/log/proof` returns). A receipt Verfy does not hold yet, for example one not uploaded, is listed under
`not_in_log` with the reason. A checked proof shows the receipt was in Verfy's public log no later than the time of
the head it is proved against, so it was not written after the fact.

## Verfy's attestation

With `--attest` (on a machine enrolled in Verfy Cloud), the CLI sends the receipts' hashes, in order and never the
receipts, to `POST /api/v1/incidents/attest`, and Verfy answers a [`verfy.witness/1`](witness.md) statement of type
`incident`:

```json
{"type": "incident",
 "subject": {
   "receipts": {"count": 6, "merkle_root": "<64 hex>", "known": 6, "in_log": 6,
                "first_received_at": "…", "last_received_at": "…"},
   "chains": ["atl_…"],
   "unknown": []}}
```

`merkle_root` is the RFC 6962 root (see [log.md](log.md)) over the receipts' hashes in pack order, so the statement
covers exactly that list. Verfy answers only for the device's own organization: a receipt another organization holds
is listed as unknown. Up to 10,000 receipts per statement.

## Checking

A pack checks when every receipt's signature checks with `public_key`, the receipts are one run of the chain (each
`seq` one more than the one before and each `prev` the hash of the one before), every log proof checks against a
head signed by a published witness key and is for a receipt in the pack, and an attestation is signed by a witness
key with `count` and `merkle_root` matching the pack's receipts. A receipt removed from the middle, an edited
receipt or a proof for something else makes the pack fail.

A pack shows what the agent's machine recorded, in order and complete for that stretch; with log proofs, also that
Verfy held those receipts by a given time. It does not show that the actions themselves were right.
