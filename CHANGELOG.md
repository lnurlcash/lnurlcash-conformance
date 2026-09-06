# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps
may add or tighten checks that a previously-passing mint now fails; pin an
exact version if you gate CI on the grade.

## Unreleased

- Documentation only, no grade changes. `previousPubkeys` is no longer a
  LUD-25 field: the spec carried it briefly and dropped it on 2026-09-04,
  replacing it with "`SERVICE` SHOULD NOT rotate `mintPubkey`" plus a
  `WALLET`-side MUST to pin per origin and require explicit holder approval
  for any replacement. The runner already graded it for shape only and never
  for presence, which is the right posture for a convention; the comments and
  the flag table now say that is what it is, and that a wallet must not read
  it as permission to move a pin by itself.

## 0.7.0 - 2026-09-04

**`cash-derivation.json`: LUD-25's own seed-recoverable note secrets.** The
draft specifies a BIP-32 scheme under `m/139'` and the reference wallet
implements it; `derivation.json` remains, unchanged, as the pre-spec HMAC
scheme that notes are still outstanding under.

Every case carries `cashRoot`, the four `domainIndices`, a `hardened` flag per
index, the `domainNode` and the resulting `k1`. The flags are the point of the
file. `d1..d4` are raw uint32 and BIP-32 reads any index `>= 2^31` as hardened,
so which levels are hardened is decided by the mint's own host name - an
implementation that masks the top bit, or hardens all four, derives a
different tree and restores nothing, silently. Both hosts in the vector land
on a mix, so an implementation that gets it wrong cannot pass by luck.

`bip32Vector1` carries BIP-32's own published test vector 1, so a port can
prove its CKDpriv before blaming the LUD-25 path above it. The generator
implements BIP-32 from `@noble` primitives rather than importing a BIP-32
library, for the reason at the top of `tools/generate.mjs`: a vector produced
by the library under test proves nothing.

## 0.6.0 - 2026-09-03

**Offline verification and mutation replay now grade the current LUD-25
MUSTs.** A rotate, split or merge without a valid note signature fails rather
than warning, as does a byte-identical retry that is answered as already
spent. The conforming mock now replays mutations by default; `signatures=false`
and `retriedMutation=refuse` remain explicit adversarial fixtures.

The optional hash lookup is also checked end to end once a mint offers it.
The runner requires exactly one of `k1` and `h`, compares the unknown-h response
with an unknown-k1 response, then burns the original note and confirms its hash
still gets that same unknown-note answer. This catches the privacy leak where a
mint answers a burned `h` as already spent. The mock gains separate
`revealsSpent` and `acceptsBoth` fixtures proving those checks fail.

The signature vectors now describe `mintPubkey` as a stable SERVICE key. It may
be the funding node identity where compatible signing exists, or a dedicated,
persistent secp256k1 key where it does not.

**The client-facing vectors carry the same MUSTs.** They had been left behind
by the prose, still describing a signature as one accepted shape among
several, so a wallet library could pass every vector while ignoring the
requirement entirely.

`withdraw-info.json` now puts `mintPubkey` on every accepted withdrawRequest
and rejects a response that omits it or publishes something that is not a
33-byte compressed secp256k1 key. A wallet handed a note by a mint that
publishes no key has nothing to verify it against, which is the gap offline
verification exists to close.

`responses.json` gains an `unverifiable` outcome for a mutation the SERVICE
confirms but does not sign. It is deliberately not folded into the existing
`error` or `ambiguous` outcomes: the mutation definitely landed, so the
wallet-generated secret is the only key to a real note and must be kept, and
a consumer that treats this as an ordinary failure loses the money it is
trying to protect. Every case now also declares the `op` it is driven
through, because a melt mints nothing and so needs no signature, while a
rotate returning none is the new outcome.

**The mock mint starts when its path reaches it through a symlink.** The
standalone guard compared `import.meta.url` against `file://` plus
`process.argv[1]`, and node resolves a module's URL to its real path while
argv[1] stays exactly as it was typed. A checkout symlinked into a sibling
workspace - which is how the language ports pick this repo up locally - failed
that comparison, so the mint exited silently, printing nothing at all. Every
port's adversarial suite then hung to EOF and reported the mint as never having
announced itself, which says nothing about the cause. CI, checking the repo out
for real, was never affected, so this only ever broke the local run.

## 0.5.0 - 2026-08-31

**Breaking: the current LUD-25 draft's mandatory mint comment is now the
baseline.** Every minting payRequest must advertise `commentAllowed >= 64`,
and every quote must carry `comment=hex(sha256(secret))`; missing or malformed
comments are refused before invoice creation. The payment preimage is
settlement proof and never a bearer credential. `mintToHash`/`h` remains an
additive ForgeSworn compatibility and receipt extension: when used, `h` must
repeat the mandatory comment and cannot replace it. The mock, runner,
lifecycle and pay-request vectors all enforce the same rule, including a
mismatched `h`/`comment` refusal. `commentFallsBack` remains only as the
non-compliant historical fixture documented in
`docs/COMMENT-IS-MANDATORY.md`.

**A mint that is not a Lightning Address is no longer failed for having no
mint address document.** The document is probed by swapping
`/.well-known/lnurlp/` for `/.well-known/lnurlw/` in the payRequest URL. On a
mint served from a plain path that swap changes nothing, so the probe
re-fetched the payRequest, read `tag: "payRequest"`, and failed the mint for
an optional document it has nowhere to publish. Found by grading
`bitkarrot/lnurlmint`, which is served at `/lnurlmint/lnurlp/<id>`; it now
grades 6 passed, 0 failed on the checks that predate the mandate above.


**Two checks for the draft's 25 August additions, both optional-graded.**

`answers a note lookup by hash without the secret` covers "Checking a note
without exposing it". The capability is detected rather than announced: the
draft deliberately gives an unrecognized `h` the same answer an unknown
`k1` gets, so a live note's own hash is the only probe that separates a
mint which implements the lookup from one which never did. A mint that does
not offer it is not graded down; one that offers it must omit `k1` from the
reply - a wallet asking by hash already holds the secret, and filling the
field in puts the note back on the wire the lookup exists to keep it off -
must report the same value by hash as by `k1`, and must refuse a hash it
never registered.

`refuses an oversized merge cleanly` covers the merge cap. The cap itself
is a MAY, so a mint that does not name one is not graded down, only
reported, since a wallet must then batch by URL length rather than rely on
a refusal. The one answer that fails is `OK`: every input on that probe is
fabricated by the runner, so a mint accepting it has minted an output
against notes it never held, which is what a truncated `k1` list read as a
shorter merge looks like from outside.

## 0.4.0 - 2026-08-26

**The mint-output naming check now reads the spelling LUD-25 actually
specifies.** The draft names the output with a LUD-12 `comment = hex(h)`,
advertised as a `commentAllowed` of at least 64; `mintToHash` is the
parameter form one mint shipped before the comment form was written. The
suite knew only the latter, so a mint naming notes exactly as the draft
describes graded as "not offered - a minted note's k1 is the invoice
preimage". That is the worst kind of wrong answer a conformance suite can
give: it tells a wallet author the safe mint is the unsafe one.

Both spellings are now read from the payRequest and the mint address
document, probed with a fresh hash each (a mint that binds output ids
uniquely would rightly refuse the second spelling for naming an output the
first just took), and reported as `named by comment` / `named by h`.

The two are deliberately not probed identically, because the draft's rules
for them are opposites:

- `h` is a parameter invented for naming, so a malformed one MUST be
  refused before an invoice exists. Unchanged.
- `comment` is plain LUD-12 free text any wallet may send for unrelated
  reasons, so a comment that is not a bare hash MUST fall back to crediting
  `k1=P` rather than be refused, and the mint MUST NOT serve LUD-21 `verify`
  on that fallback - there the preimage is not proof of payment, it is the
  note. Both are now checked, the second as a failure.

Only `mintToHash` is expected in both documents. `commentAllowed` is a
payRequest field; the mint address document is a withdrawRequest, where a
LUD-12 comment has nowhere to go, so its absence there is no longer
reported as a disagreement.

**A rate-limited grade no longer accuses the mint.** Every mint quote
issues a real invoice on a real node, so a grader firing a dozen looks like
the abuse a limiter exists to stop - and probing two spellings nearly
doubled the count. HTTP 429 was indistinguishable from a spec refusal, so
the mint was reported as violating whatever check happened to be running
when the bucket ran dry. 429 is now waited out (honouring `Retry-After`)
and retried, and reported as an incomplete grade rather than a verdict if
it persists.

The mock mint gains `commentAllowed`, `commentRefusesMalformed` and
`verifyOnUnnamedMint` to cover all of this.

## 0.3.0 - 2026-08-24

- Add an optional bound-mint settlement receipt for sealed signers. A
  receipt-capable quote commits to `mint: {h, amount}` before payment; its
  settled LUD-21 response repeats the invoice, output and exact net value and
  adds the ordinary LUD-25 note signature. Absence remains compatible with
  the current preimage-and-rotate flow.
- `vectors/mint-to-hash.json` now carries the valid quote, unsettled and
  settled shapes plus wrong-output, wrong-amount, premature-signature and
  invalid-signature cases. `docs/BOUND-MINT-RECEIPTS.md` contains candidate
  normative LUD-25 text and the compatibility matrix.
- The mock mint gains `mintReceipt`; when enabled it publishes the
  verification key before payment, commits the quote and signs only after
  settlement. Self-check and self-grade verify the complete lifecycle.

## 0.2.3 - 2026-08-22

- **New check: `keeps signatures off the informational endpoint`.** LUD-25
  says signatures are only ever delivered in the `withdrawSuccessResponse`
  of a rotate, split or merge, and that the informational endpoint never
  returns one. Nothing graded it. A mint that hands one out there lets
  anyone holding a note's public URL mint an offline certificate for it,
  and invites a wallet to treat an online answer as offline proof. Both
  known mints pass; the check exists so a third cannot quietly not.

## 0.2.2 - 2026-08-22

- The mock mint publishes `payLink` on a note's informational GET, as the
  reference mint does. That is the way home for a holder who has nothing
  but a note: without it a wallet that only ever received notes cannot
  reach the document carrying the mint's retired signing keys, so a
  correctly announced key rotation is indistinguishable from a substituted
  key. `noteInfoPayLink: false` models a mint that does not publish it, and
  `payLinkOffOrigin: true` is the misbehaviour where a mint points its
  `payLink` at a different origin, nominating a third party to vouch for
  its own key history - a client must ignore that.

## 0.2.1 - 2026-08-22

- The grader ships its own TypeScript declarations. The mock mint had them
  and the runner did not, so a TypeScript consumer hand-wrote a
  `declare module` shim, and those drift: moneyer carried one, `gradeBoundMint`
  landed here, and the shim did not know about it. A consumer could not call
  the newest check without editing a copy of a declaration it does not own.
  Now `runner/index.d.ts` sits next to the code it describes and the exports
  map points at it. No runtime change of any kind.

## 0.2.0 - 2026-08-22

- Naming the note you are buying. In LUD-25 a minted note's `k1` is the
  payment preimage, so the preimage IS the money, and two sets of people
  learn it without being trusted with it: every routing node on the
  payment path, because that is how HTLC settlement works, and anyone who
  merely saw the invoice, because they can poll LUD-21 verify with its
  payment hash and take the preimage the moment it settles. A QR on a
  desktop screen is exactly that. "Rotate immediately" is the only defence
  and it is a race. A wallet may instead send `h` on the LUD-06 pay
  callback, the sha256 of a secret it chose, and be credited there.

  - New `vectors/mint-to-hash.json` fixes the parameter and both refusal
    reasons, so kits in other languages answer the same wallet the same
    way. `h` is 64 lowercase hex, exactly what it means on the withdraw
    callback. A malformed one is refused with `Invalid h.` before any
    invoice exists, so a wallet never pays for a quote the mint was always
    going to reject; one that already names a note, an invoice, or another
    quote's output is refused with `Invalid or already spent k1.`, the
    same reason the withdraw callback gives a colliding output hash, so no
    oracle appears. Ten cases, four of them refusals, plus a worked
    settlement both ways round: bound, the note is at the wallet's own
    secret and the preimage opens nothing; unbound, it is the preimage's,
    exactly as before.

  - Support is advertised in three places and they say different things.
    `mintToHash: true` on the payRequest means "I accept an `h` on my pay
    callback", and since every mint publishes a payRequest while the mint
    address document is experimental, that is the one a wallet decides
    from. The mint address document repeats it, as corroboration. The pay
    callback's own response echoes it when *that* quote was bound, which
    is the one that matters at the moment money moves, because the other
    two can be cached or stale. Anything that is not exactly the boolean
    `true` is no, everywhere, so a mint that omits the field is safely
    read as not bound. All fifteen spellings are in the vector.

  - Mock knob `mintToHash`, off by default, and with it off nothing about
    this reaches the wire: nothing is advertised anywhere and the pay
    callback does not read `h` at all. `mintToHashAdvertisedOn` narrows
    which of the three places claim it, changing only what is claimed and
    never what the mint does, so a mint that shipped the feature before
    the advertisement can be reproduced. Three misbehaviours, each needing
    `mintToHash` alongside: `mintToHashAcceptsMalformedH`,
    `mintToHashAcceptsUsedH` and `mintToHashIgnoresH`, the last of which
    claims the capability, echoes it on the quote, and mints at the
    payment hash anyway.

  - New grader check `accepts an output hash on the mint quote
    (mintToHash, optional)`. Soft where it should be: a mint that says
    nothing anywhere and ignores `h` is reported as not offering it and
    the run passes, which is every mint today and not a defect. A mint
    that claims it is asked to prove the refusals, and an invoice issued
    for a malformed `h` fails, because a wallet that pays for a quote the
    mint will reject has bought nothing while the mint keeps the sats.
    Disagreements between the three claims are named rather than failed:
    none of them loses anyone money on its own, since a wallet reading a
    missing field as false falls back to the preimage flow.

  - New grader check `a bound mint credits the hash the wallet named
    (optional)`, exported as `gradeBoundMint` and wired to a new
    `--preimage` flag. Like the minted-value check it needs a payment the
    runner cannot make itself: given the note URL carrying the wallet's
    own secret and the preimage of the invoice that funded it, it fails a
    mint that claimed the capability and did not bind. That is the one
    worth failing rather than warning, because a wallet that believed the
    claim stopped rotating on sight.

  - Also refused now, on the withdraw callback: an `h` or `h2` colliding
    with the output a bound quote is waiting to credit. Unreachable unless
    `mintToHash` is on, so nothing about a mint without it changes.

  - The case rule, stated as a rule rather than a verdict. Hex is
    case-insensitive, so `AAAA...` and `aaaa...` are the same 32 bytes and
    name one output, not two. A wallet MUST send `h` as 64 lowercase hex,
    which keeps the producer side strict and is what every client here
    does. A service SHOULD normalise case before comparing, and MUST NOT
    treat an otherwise well-formed upper-case `h` as a different output
    from its lowercase form: keying the string it was handed files the
    note under the upper-case spelling and never finds it again when the
    wallet asks the withdraw endpoint for its own lowercase secret, and
    nobody is told. The vector says so with a worked pair and with two
    upper-case cases, one binding where its lowercase twin binds and one
    colliding where its twin collides, which is also what pins case being
    normalised *before* the collision check. Every genuinely malformed
    case is unchanged: empty, not hex, and both off-by-one lengths. The
    mock normalises. The grader does not probe it in either direction: a
    mint that normalises loses nobody money, and one that refuses upper
    case outright is being strict rather than wrong, because the wallet
    learns before it pays.

- New `vectors/derivation.json`: deterministic note secrets from a BIP39
  seed, so that a wallet can be restored from words alone and two
  implementations of the same wallet derive the same notes.
  - `k1` is WALLET-generated in LUD-25 and the draft says nothing about how
    one is produced, so a wallet is free to derive it instead of drawing it
    at random. Nothing about this is observable on the wire: the mint still
    only ever sees `sha256(k1)`.
  - The scheme, in full, so this entry alone is enough to reimplement it.
    `root = HMAC-SHA256(key = utf8("lnurlcash-note-v1"), msg = seed bytes)`,
    then `k1 = HMAC-SHA256(key = root, msg = utf8(host + ":" + index))`.
    Output is 32 bytes, lowercase hex, the same size as a payment preimage.
    `host` is the mint host as the wallet stores it, lowercase, with the
    port when there is one; `index` is decimal ASCII counting from 0. The
    seed is the 64-byte BIP39 seed of a 12-word English mnemonic with no
    passphrase.
  - Cases cover the standard `abandon ... about` mnemonic at `mint.example`
    for indices 0, 1, 2, 19 and 20 (19 and 20 straddle a 20-index gap
    limit), a second mnemonic at the same host and index to show the seed
    separates them, and a host carrying a port.
  - Every case carries `seedHex` as well as the mnemonic, so an
    implementation with no BIP39 library can still test the derivation
    half on its own.
  - `@scure/bip39` is a devDependency, used only to generate the file. The
    published package gains no runtime dependency.

- Self-check covers the new file: every `k1` recomputes from its own
  `seedHex`, every mnemonic validates against the English wordlist and
  produces the stated seed, and no two cases collide.

- The retried mutation. Every mutation in LUD-25 is a GET, and HTTP stacks
  retry a GET when the connection they used is dropped: Go's `net/http`
  retries one that failed on a reused idle connection, the JDK's
  `HttpClient` retries idempotent methods with no switch to turn it off.
  The service therefore sees the byte-identical request twice, and by the
  time the second arrives its inputs are burned. Answering it as an
  already-spent input tells the holder the mutation never happened, and a
  holder that believes it discards the only copy of a secret the service
  really did mint a note against. Nobody is told; the money is gone.

  - New `vectors/retried-mutation.json` fixes what identical means, so two
    services do not give the same wallet two different answers to the same
    dropped connection: the same input `k1` set (a set, so a merge naming
    the same notes in a different order is the same merge), the same `h`,
    the same `h2` and the same `amount`, present or absent alike. Twelve
    cases, four of them replays and eight of them still double-spend
    attempts, each turning on one thing being different. Anything that is
    not a retry keeps today's refusal and today's reason string, so no
    oracle appears for whoever holds a burned secret. Provenance is
    recorded, never inferred: matching on "a note exists at `h`" alone
    would let anyone holding a burned `k1` and any outstanding note id
    pull a success out of a mint.

  - Mock knob `retriedMutation`, `'refuse'` by default, which is exactly
    what this mock has always done. `'replay'` answers a byte-identical
    repeat with the original success. The replay path is a read: it burns
    nothing, mints nothing and moves no balance, and the signature is
    recomputed from the output id and amount rather than stored.

  - New grader check `replays a retried mutation rather than refusing it
    (optional)`, covering a rotate and a split so `h2` and the change
    amount are covered too. Soft, because this is a SHOULD: a mint that
    refuses the retry is reported as not having implemented it, not
    failed. What is not soft is damage, so a retry that burns the output
    or changes its value fails outright whichever answer it gives.

  - The existing `refuses a replayed burn` check is untouched. It sends a
    burned input with a *fresh* output hash, which is a genuine
    double-spend attempt and a different request, and it still passes in
    both modes.

- Three optional extensions a mint may publish, none of them in LUD-25,
  all of them absent or off unless asked for. A mock started with no
  options answers byte for byte what it answered before, and a mint
  publishing none of them is not graded down.

  - **Mint info** on the experimental discovery endpoint. Mock knobs
    `name`, `description`, `contact` (`{nostr, email, url}`), `tosUrl`,
    `motd`, `version` and `previousPubkeys`, appended after the existing
    fields so nothing above them moves. `fees: {baseFeeMsat, feePpm}` is
    emitted whenever a fee is configured: the structured twin of the fee
    line in the payRequest metadata, which stays exactly as it was.
    `nodeCapacity` is emitted as before, under that name.

  - **Liabilities**. Mock knob `stats: true` (default `false`, and when
    off `/stats` falls through to the same 404 every unknown path gets)
    serving `GET /stats` as `{at, outstandingMsat, outstandingNotes,
    pendingMsat, pendingMelts, oldestPendingMeltAgeSecs, localBalanceMsat?,
    coverage?, reconciledAt}`. Notes here are not blinded, so a mint can
    state what it owes exactly. A note mid-melt counts under `pending`
    rather than `outstanding`: its value is committed, not free, and it
    comes back if the payment fails. `coverage` is
    `localBalanceMsat / outstandingMsat` to four decimal places, omitted
    when nothing is owed. Knob `localBalanceMsat` sets what the node
    claims to hold, so a mock can be told to look under-covered.

  - **Signing-key rotation**. Mock knobs `previousPrivateKey` (an old key
    the mock still holds; its public half joins `previousPubkeys` on its
    own) and `previousPubkeys`. `state.creditNote(k1, amount,
    {previousKey: true})` signs one note under the old key and leaves the
    rest under the new, and `/_test/credit?...&key=previous` does the
    same out of process. `signWithPreviousKey` issues every note under the
    old key while still advertising the new one: the mid-rotation state a
    mint passes through when the advertisement moves before the signer.

- Grader, all soft, all read-only:

  - `publishes a mint address (experimental, optional)` keeps its name and
    its existing assertions, and now checks the shape of the new fields
    when they are present: the string fields non-empty, `tosUrl` and
    `contact.url` fetchable, `contact.nostr` decoded as an npub rather
    than pattern-matched, `contact.email` address-shaped, `fees` numeric
    and not negative, `previousPubkeys` an array of 33-byte compressed
    pubkeys in hex that does not merely restate the current one. A
    malformed field is a warning, never a failure, and absence is neither.
    The pass line names which fields it saw. A mint publishing its node
    capacity as `nodeCapacityMsat` warns as well: the wire name carries no
    suffix, and anything mapping the documented name reads undefined.

  - New `publishes liabilities (optional)`. No `/stats`, or a `/stats`
    that answers with something other than a liabilities body, is a
    warning and nothing more. When it does answer, `outstandingMsat` must
    be a number at or above zero and `coverage` must be numeric when
    present. A node holding less than the mint owes warns rather than
    fails: whether a mint is fully backed is the operator's to disclose,
    and one that publishes an uncomfortable number is behaving better than
    one that publishes nothing.

  - `signs the notes it issues (optional)` accepts a signature recovering
    any key the mint publishes, the current `mintPubkey` first and then
    anything in `previousPubkeys`, and says which it was. Grading a note
    issued before a rotation as forged would punish a mint for rotating
    properly. `gradeNote` takes the list as `options.previousPubkeys`; the
    CLI carries it across from the discovery endpoint on its own, which
    `gradeMint` now hangs off the payRequest it returns as `mintAddress`.

- New `vectors/payment-request.json`: one holder asking another for value,
  as a string a payer's wallet can act on. Not to be confused with
  `pay-request.json`, which is the LUD-06 payRequest a mint publishes; no
  mint is involved in reading this one.
  - Encoding is the NUT-18 `creqA` idiom with our own prefix:
    `lnurlcashreq1` followed by the request canonicalised under RFC 8785
    (JCS) and carried as unpadded base64url. Canonical because two wallets
    building the same request must produce the same string, or the payee
    cannot match what came back to what they asked for. One encode case is
    the same request with its keys in a different order, encoding
    identically, and one carries a non-ASCII memo, which JCS leaves alone
    rather than escaping.
  - `amount` is whole sat as a decimal string, matching what the 402
    payment-method schemas carry; the payer sends `amount * 1000` msat
    exactly. Sub-sat requests are not a thing.
  - Decode cases cover the round trips, an expiry still in the future, an
    expired one, one expiring exactly now, a bad prefix, no prefix, a
    payload that is not base64url, a payload that is not a JSON object, an
    unknown version, a non-integer amount in four spellings, an empty
    mints array, no `methodDetails` at all, a `to` that is neither an npub
    nor address-shaped, a `to` that looks like an npub but does not
    decode, a currency that is not sat, and a malformed id. Every refusal
    names a reason from a declared list, and every declared reason has a
    case.
  - The file states `evaluatedAt`, a fixed unix time the decode cases are
    read at, so an expiry means the same thing on every run.

- New `vectors/settle-for-value.json`: the decision table a server works
  through when a bearer note arrives as payment, with the order it works
  through it in.
  - The order is the interesting part. Host, then what the mint says
    (which is where a spent or in-flight note surfaces), then the
    signature when one is required, then the value, then the rotate. A
    note wrong in two ways is refused for the first reason in order, or
    two servers explain the same note two different ways, and cases where
    two things are wrong at once pin that.
  - The rotate is deliberately last: it is both the ownership transfer and
    the double-spend check, and a server that rotates before comparing the
    amount has taken the money and refused the request.
  - Outcomes are `accept`, `wrong-host`, `insufficient`, `bad-signature`,
    `missing-signature`, `spent` and `pending`, all reachable. Also pinned:
    hosts compare lowercased with the port included, an empty accepted-mint
    list takes nothing rather than everything, a note worth exactly the
    price is paid, and a signature that does not verify is accepted when
    none was required, because the value came from asking the mint and the
    mint is authoritative.

- Self-check reimplements both decision tables rather than calling the
  generator's, because a check that calls the function it is checking
  proves only that the function is deterministic.

- `signature.json` gains a `rotation` block: a note signed under a
  previous key with both keys published (valid), the same signature byte
  for byte with only the current key published (invalid), a
  current-key signature alongside a published previous one (valid), and a
  signature under a key that was never published (invalid). The cases
  carry `mintPubkeys` as a list rather than the single `mintPubkey` the
  existing cases carry, and live in their own block for that reason: a
  verifier that knows nothing about rotation reads `cases` and is
  completely unaffected by this release.

## 0.1.2 - 2026-08-21

- The minted-value check took a band instead of a single number, because
  it was failing the reference implementation.
  - LUD-25 states the mint fee as `base_fee_msat` plus a ppm cut and says
    nothing about rounding. dni's lnurl-mint ceilings that fee to a whole
    sat on purpose, so the mint is "never short a sat"; moneyer is
    msat-exact. Every public mint on the awesome list except moneyer runs
    lnurl-mint, so the majority of live services round.
  - The check asserted equality against the msat-exact formula, and even
    named the rounding in its failure message as something "the formula
    does not allow". Measured on real sats: 40,000 msat at
    mint.forgesworn.dev with a 1000 + 1000 ppm fee credits 38,000, not
    38,960. A clean grade was unreachable for the reference.
  - Deciding which reading is right is not this repo's job - "either may
    be wrong, and the LUD-25 PR is where that gets settled". So the
    compliant answer is now the range between the two: the formula is the
    most a holder can be credited, the sat-ceilinged fee the least. The
    report names which one it saw.
  - Both edges are graded, and selfgrade proves it: a msat past the
    ceilinged fee fails, and so does crediting more than the formula. A
    band with no edges would grade nothing. The mock's `roundFeeToSat` is
    reclassified from a misbehaviour to the reference's behaviour, and
    gains `extraFeeMsat` for landing outside the band deliberately.

- Two refusals LUD-25 spells out were never graded. Both are reachable
  against a live mint, and both were being stepped around rather than
  tested.
  - `refuses a split with no h2`: a split names two outputs, so a mint
    given only `h` either refuses or invents the change note's secret
    itself. The second is the exact prior-holder exposure wallet-generated
    secrets exist to close, and it was ungraded.
  - `refuses a split whose change cannot cover the base fee`: the grader
    already knew the advertised base fee, and skipped (`note too small to
    split past the advertised base fee`) rather than deliberately leaving
    change one msat short of it. It now does that on purpose and expects
    `insufficient value`. Warns when no fee is advertised, since the rule
    cannot bite.
  - Both confirm the note survives the refusal, and both are self-verified:
    the mock gains `acceptsMissingH2` and `splitIgnoresBaseFee`, and
    selfgrade asserts each is caught by name rather than by failure count.
- The grader never melts, so `pending`, restore-on-failure and a melt's own
  LUD-21 `verify` cannot be graded against a live service - melting real
  sats is not something a grader may do on its own initiative. The mock
  covers all three for client-side suites. Said so in the README, which
  previously left the gap to be inferred.

- `withdrawLink` has two legal spellings in the wild. LUD-25 calls it "a
  raw, non bech32-encoded URL as described in LUD-17", and LUD-17 describes
  both the `lnurlw://` scheme and the plain `https://` URL it stands for.
  lnurl-mint (and the spec's own diagram) emit `https://mint.example/w`;
  moneyer emits `lnurlw://moneyer.dev/w`. The mock mint only ever served
  the second, so a client that broke on the reference mint's form would
  still have passed here.
  - The mock mint now serves the plain `https://` spelling by default,
    matching the reference mint, and takes `withdrawLinkForm: 'lnurlw'`
    for the other. A test asserting the old `lnurlw://` default needs
    updating (lnurlcash-kit's did).
  - `pay-request.json` gains accepted cases for the plain form and for an
    onion host; a parser must pass both through untouched.
  - The grader accepts either spelling, rejects a bech32 `lnurl1...` value,
    and names the form in its report. Its three ad-hoc `lnurlw://` rewrites
    are now one exported `fromLud17`.
  - Selfgrade runs the compliant mock in both forms.

## 0.1.1 - 2026-08-20

- The mock mint's mint-address response now carries the node stats
  lnurl-mint advertises: `nodeCapacity` (msat), `nodeNumChannels` and
  `nodeNumPeers`. `nodeCapacity` is the field an implementation is most
  likely to rename on its own side and then forget to map - lnurl-wallet
  and lnurlcash-kit both did, and neither test caught it, because nothing
  they tested against ever sent the wire name.

## 0.1.0 - 2026-08-20

First release. Three things, usable independently.

- **`vectors/`** - language-neutral JSON test vectors, generated and frozen.
  Load them from a suite in any language; the release gate regenerates them
  and refuses to publish if a single byte moved.
- **`mock-mint/`** - a real HTTP mint that misbehaves on demand, in every
  way the spec warns about: destroyed responses, never-settling melts,
  wrong-`k1` echoes, mutation on non-GET, secrets served before settlement.
  Typed for TypeScript consumers.
- **`runner/`** - `lnurlcash-conform <mint>` grades a live service and exits
  non-zero if it is non-compliant. Read-only by default; `--spend` opts into
  the mutating checks, `--note`/`--paid` adds the minted-value check without
  spending anything.

Checks in this release cover the six LUD-25 endpoints, the fee algebra on
mutations (base fee from split change, `(n-1)` refunds on merge, insufficient
value), the adversarial mutation shapes a mint must refuse, that a mint never
mutates on a non-GET request, and that LUD-21 verify serves no secret before
settlement.
