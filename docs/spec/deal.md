# `verfy.deal/1` and payments

## Deals: one action two agents both sign

When two agents agree on something (a purchase, a booking, a hand-over), each side records it in its own ledger with
its own key, and the second receipt names the first, so neither side can later claim the other agreed to something
else.

```python
offer = seller.offer("sell", system="shop", kind="payment", counterparty="buyer-bot",
                     terms={"item": "sku-1", "price": 4999, "currency": "USD"})
deal = buyer.accept(offer)        # checks the offer, then signs its own receipt naming it
verfy.deals.verify_deal(deal)     # anyone holding the deal document
```

The deal document:

| Field | Meaning |
| --- | --- |
| `v` | `verfy.deal/1` |
| `deal` | `deal_` and 24 random hex characters |
| `terms` | what was agreed, any JSON |
| `offer`, `offer_key` | the offering side's receipt and its public key (base64url) |
| `accept`, `accept_key` | the accepting side's receipt and its public key, once accepted |

The terms are never in a receipt. Both receipts store, as their arguments, only references:

- offer: `{"deal", "terms_sha256", "role": "offer", "counterparty"}`
- accept: `{"deal", "terms_sha256", "role": "accept", "offer_receipt", "offer_kid"}`

where `terms_sha256` is `sha256` of canonical `{"deal": <deal id>, "terms": <terms>}` (the random deal id keeps the
hash from revealing guessable terms) and `offer_receipt` is the `sha256` hash of the whole offer receipt. Receipts
whose stored arguments hold only these reference fields upload to Verfy Cloud without `--allow-args`.

A deal checks when both receipt signatures check with their keys, both name the deal id and the same `terms_sha256`,
that hash matches the document's terms, the accepting receipt names the offer receipt's hash and key id, and the two
keys differ. `verfy deal verify FILE` checks it. Each side's receipt is also in its own chain, so it cannot be
removed from that side's ledger later without the chain breaking.

Rules (see [rules.md](rules.md)) are checked against the terms on both sides before signing: an accept that a rule
denies raises `ActionDenied` and signs nothing.

## Payments tied to a mandate

```python
d = rec.guard("payment", kind="payment", args={"amount": 49.99})          # limits first
rec.record_payment(49.99, "USD", payee="shop-1", mandate=cart_mandate, mandate_type="cart-mandate", decision=d)
```

The receipt's stored arguments are references only:

| Field | Meaning |
| --- | --- |
| `details_sha256` | the salted hash of `{"amount", "currency", "payee"}` |
| `mandate_sha256` | `sha256` of the canonical JSON of the payment mandate the payment carried out |
| `mandate_type` | a label for the mandate's format, as the caller names it |

A mandate is whatever signed instruction authorized the payment: an agent payments protocol's cart or intent mandate,
a card network's signed intent, or an organization's own approval. Verfy does not check the mandate itself; whoever
holds it can show this receipt carried out exactly that mandate (`verfy deal hash MANDATE.json` prints its
`mandate_sha256`). Verfy is not a payment service and moves no money.
