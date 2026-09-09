# Bound mint settlement receipts

Status: additive implementation proposal layered on current LUD-25 comment-bound minting.

This document records the wire contract implemented by the ForgeSworn /
lnurlcash repositories. It does not modify the upstream LUD-25 draft or
dni's reference repositories.

## Why the receipt exists

Current LUD-25 already lets a wallet choose `k1`: it sends
`comment = sha256(k1)` on the LUD-06 pay callback, and the payment preimage
never becomes the bearer secret. The `mintToHash` extension repeats that same
commitment as `h` so older Moneyer/ForgeSworn clients and the receipt fields
share one explicit output identifier. It never replaces the comment.

A sealed signer should not export `k1` merely so a browser can perform that
probe. It needs authenticated evidence that the invoice settled and the mint
created the exact output quoted before payment. The existing LUD-21 response
is the natural place for that evidence.

## Candidate extension text

The following is intended to be transplantable into the draft's “Minting a
bearer note from a `payRequest`” section.

A `SERVICE` that supports the receipt extension MAY add `"mintToHash": true`
to its `payRequest`. A `WALLET` MAY then repeat its mandatory LUD-25 comment
as `h=<hex sha256>` on the pay callback. `WALLET` MUST send the same 64
lowercase hexadecimal characters in both fields. `SERVICE` MUST reject a
missing or malformed comment, a malformed or mismatched `h`, or an output
already used by an outstanding note, invoice or unsettled quote, before
returning an invoice. Without `h`, comment-bound LUD-25 minting is unchanged.

When it accepts `h`, `SERVICE` credits the new note at the identical comment
commitment when the invoice settles and returns
`"mintToHash": true` on that pay callback response. The payment preimage
remains a LUD-21 proof of payment and is not a valid `k1` for the bound note.
A `WALLET` MUST NOT assume the binding from the request alone.

A `SERVICE` MAY additionally offer a bound settlement receipt by returning a
LUD-21 `verify` URL and `"mint": {"h": string, "amount": number}` on the
pay callback response. `amount` is the exact net note value in
millisatoshis after mint fees. The quote MUST NOT contain `mint.sig`.
`SERVICE` MUST make the verification key available before payment, either as
the node identity recoverable from the BOLT-11 invoice or as `mintPubkey` on
the `payRequest`. Publishing a key is not proof of identity; `WALLET` applies
the same pinning or trust policy it uses for other LUD-25 note signatures.

Before displaying or paying a receipt-required quote, `WALLET` MUST require
`mintToHash` to be exactly boolean `true`, require `verify` and `mint`, and
match `mint.h` and `mint.amount` to the output and net value it intends to
buy. Absence of `mint` means the optional receipt is not offered, not that
the current LUD-25 flow is non-compliant.

Before settlement, the LUD-21 response MAY repeat `mint.h` and `mint.amount`
but MUST NOT include `mint.sig`. After settlement, it MUST repeat the quote's
`pr`, `h` and `amount` and add `sig`, the recoverable Offline verification
signature over the existing message `LNURLcash:<amount>:<h>`. `WALLET` MUST
require `settled` to be exactly `true`, match all three committed values, and
verify `sig` against its trusted mint key before treating the bound note as
confirmed.

## Proposed additive wire fields

A wallet persists or stages `k1` first, computes lowercase `h`, and requests:

```text
GET <pay-callback>?amount=<gross-msat>&comment=<h>&h=<h>
```

A receipt-capable service returns the existing fields plus `mint`:

```json
{
  "pr": "lnbc...",
  "verify": "https://mint.example/verify/<payment-hash>",
  "mintToHash": true,
  "mint": {"h": "<64-lowercase-hex>", "amount": 21000}
}
```

`mint.amount` is the exact net note value in millisatoshis after mint fees.
No signature is valid before settlement.

Before settlement, LUD-21 may repeat the commitment:

```json
{
  "status": "OK",
  "settled": false,
  "preimage": null,
  "pr": "lnbc...",
  "mint": {"h": "<64-lowercase-hex>", "amount": 21000}
}
```

Once settled it adds the ordinary LUD-25 note signature:

```json
{
  "status": "OK",
  "settled": true,
  "preimage": "<payment-preimage>",
  "pr": "lnbc...",
  "mint": {
    "h": "<64-lowercase-hex>",
    "amount": 21000,
    "sig": "<recoverable-LUD-25-signature>"
  }
}
```

The signature message is unchanged:

```text
LNURLcash:<amount>:<h>
```

The payment preimage remains LUD-21 payment proof. It does not open a bound
note and must never replace the wallet's staged `k1`.

## Wallet requirements

Before exposing an invoice for payment, a receipt-requiring wallet must:

1. Persist `k1` (or stage it durably on the sealed signer).
2. Require `mintToHash` to be exactly boolean `true`.
3. Require `verify` and `mint` on the quote.
4. Match `mint.h` to the requested `h` and `mint.amount` to the expected net
   note value.
5. Refuse a quote that already carries `mint.sig`.

Before confirming the note, it must require `settled: true`, match `pr`, `h`
and `amount` to the quote, and verify `sig` against the pinned mint key. A
sealed signer can then transition its staged output from `PENDING` to
`CONFIRMED` without exporting `k1`.

## Compatibility

| Wallet | Service | Behaviour |
| --- | --- | --- |
| New software wallet | Receipt-capable service | Comment-bound quote and optional receipt; wallet keeps its chosen `k1`. |
| New sealed signer | Receipt-capable service | `PENDING` to `CONFIRMED` from the signed receipt; no export or preimage import. |
| New software wallet | LUD-25 service without receipts | It claims directly with its chosen `k1`; receipt use is optional. |
| New sealed signer | LUD-25 service without receipts | It must use another authenticated confirmation path or decline before payment. |
| Old minting wallet | Current LUD-25 service | It sends no comment and is rejected before invoice creation; redemption of existing notes remains compatible. |
| Generic LNURL wallet redeeming a note | New service | Ordinary LUD-03 redemption is unchanged; unknown response fields are ignored. |

Absence of `mint` means only that the optional receipt is unavailable. It
does not make a service non-compliant with the current LUD-25 draft.

The executable form of this proposal, including invalid/mismatched receipt
cases, is `vectors/mint-to-hash.json`.
