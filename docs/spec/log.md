# The transparency log

Verfy Cloud adds every receipt it accepts, from every organization, as the next leaf of one public, append-only
Merkle tree, and signs the tree's size and root. With that, anyone holding a receipt can check that Verfy holds it,
and anyone keeping signed heads can check that Verfy never changed, dropped or reordered a receipt it already
accepted. The leaves are receipt hashes only; they say nothing about whose receipt it is or what it records.

## The tree

RFC 6962 (Certificate Transparency) hashing, with each leaf the 32 bytes of a receipt's `sha256:` hash:

```
leaf hash = SHA-256(0x00 || receipt hash bytes)
node hash = SHA-256(0x01 || left || right)
```

A tree of n > 1 leaves splits at k, the largest power of two smaller than n: the first k leaves on the left. The root
of the empty tree is SHA-256 of nothing. Leaf i is the i-th receipt Verfy accepted (from 0). A receipt stored twice
(by two organizations) is one leaf.

## Signed heads

A head is a [`verfy.witness/1`](witness.md) statement:

```json
{"v": "verfy.witness/1", "kid": "vw_…", "issuer": "https://verfy.dev", "issued_at": "2026-11-17T00:30:02.114Z",
 "type": "tree_head", "tree_size": 18342, "root_hash": "<64 hex>", "sig": "…"}
```

Verfy signs a head at least once a day when the log has grown, and when a proof is asked for a receipt newer than
the last head. There is at most one head per size.

## Endpoints

All public, read-only, rate-limited per address, and readable from any origin.

| Request | Answer |
| --- | --- |
| `GET /api/v1/log` | `{"head": <newest head or null>}` |
| `GET /api/v1/log/proof?hash=sha256:…[&size=N]` | `{"hash", "index", "tree_size", "path": [hex…], "head"}`: the inclusion proof against the newest head, or the head of size N |
| `GET /api/v1/log/consistency?from=M[&to=N]` | `{"from", "to", "path": [hex…], "head"}`: the consistency proof from size M to the head of size N (default the newest) |
| `GET /api/v1/log/heads?after=N` | `{"heads": [...]}`: up to 100 heads larger than N, oldest first |

A hash the log does not hold answers 404. A `size` with no signed head answers 404, and one signed before the receipt
reached the log answers 409.

## Checking

**Inclusion** (RFC 9162 section 2.1.3.2): check the head's signature with the witness keys, then that `path` leads
from the receipt hash at `index` to the head's `root_hash` for a tree of `tree_size` leaves.

**Consistency** (RFC 9162 section 2.1.4.2): given two heads you hold, sizes M ≤ N, check that `path` proves the tree
of the first M leaves is a prefix of the tree of N. Two heads of the same size with different roots prove the log was
forked.

`verfy log prove <hash or receipt file>` checks an inclusion proof; `verfy log watch` fetches the newest head and
checks it against the heads this machine saw before, kept in `~/.verfy/log-heads.json`. Both fail on anything that
does not check. A monitor that runs `verfy log watch` regularly, and compares heads with other monitors, catches a
log that shows different histories to different people.

## Limits

The log proves that Verfy held a receipt by the time of a head, and that the log only grew. It cannot show that a
receipt was uploaded as soon as it was made, and a receipt never uploaded is not in it.
