# `verfy.witness/1`

A receipt carries the clock of the machine that signed it, and that machine could have signed it at any time. A
witness statement is Verfy Cloud's own signed word about receipts it holds: when they first reached it, and how the
chain they belong to stood at the time of the statement.

## Keys

Verfy Cloud publishes its witness keys at `/.well-known/verfy-witness.json`:

```json
{"issuer": "https://verfy.dev", "format": "verfy.witness/1",
 "keys": [{"kid": "vw_56475aa75463474c", "alg": "Ed25519", "public": "<base64url>", "status": "current"}]}
```

A key id is `vw_` and the first 16 hex characters of SHA-256 of the 32-byte public key. A reader must check that the
id matches the key's bytes and skip a key whose id does not.

## Statements

Every statement has `v` (`verfy.witness/1`), `kid`, `issuer`, `issued_at`, `type` and `sig`. `sig` is Ed25519 over the
canonical JSON of every other field, as for receipts. The types:

**`receipt`**: one receipt, as a share link or the verification API shows it.

```json
{"type": "receipt",
 "subject": {
   "receipt": {"hash": "sha256:…", "id": "rcpt_…", "seq": 41, "issued_at": "…", "received_at": "…", "signature": "valid"},
   "chain": {"id": "atl_…", "public_key": "<base64url>", "head_seq": 57, "head_hash": "sha256:…", "device_status": "active", "seq": 41}}}
```

`received_at` is when the receipt first reached Verfy. `head_seq` and `head_hash` are the chain's last receipt when
the statement was made, so a later receipt cannot quietly replace this one. Where the chain's length is not shown
(the verification API), `head_seq` and `head_hash` are `null` and `continues` says whether the chain went on after it.

**`agent`**: a whole chain as numbers: first and last issue and arrival times, and counts of receipts by verdict,
outcome and kind. No action names or arguments.

**`tree_head`**: the transparency log's size and root, see [log.md](log.md).

**`incident`**: which receipts of an incident pack Verfy holds for the asking organization, see
[incident.md](incident.md).

**`deal`**: a deal both agents signed, and when each side reached Verfy, see [deal.md](deal.md).

## Checking

Fetch the keys (over HTTPS), find the key with the statement's `kid`, and verify `sig`. For a `receipt` statement
that comes with the receipt itself, also check that `sha256` of the receipt is `subject.receipt.hash` and that the
receipt's own signature checks with `subject.chain.public_key`. `verfy witness verify FILE` does all of this.

A statement is evidence of what Verfy Cloud held when it signed it, and nothing about the action beyond the receipt.
It does not show that a receipt's content is true.
