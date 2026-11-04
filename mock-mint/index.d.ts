// Types for the mock mint, so TypeScript consumers get the misbehaviour flags
// checked rather than reaching for `any`. Hand-written to match index.mjs;
// the flag list here is the same one DEFAULTS declares there.

export type SignatureLayout = 'trailing' | 'leading'

export type NoteState = 'outstanding' | 'pending' | 'burned'

export type WithdrawLinkForm = 'lnurlw' | 'plain'

export type RetriedMutation = 'refuse' | 'replay'

/** a time-claim rule a misbehaving mock can be told to skip */
export type TimeRule = 'blockHeight' | 'future' | 'blockCount' | 'relative'

export type HashLookup =
  | boolean
  | 'echoesK1'
  | 'answersUnknown'
  | 'hidesSpent'
  /** Legacy alias for true: spent hashes are now distinguishable. */
  | 'revealsSpent'
  | 'acceptsBoth'

/** where a mint claims it accepts an `h` on its pay callback */
export type MintToHashPlace = 'payRequest' | 'mintAddress' | 'quote'

export interface MockMintOptions {
  username?: string
  minSendableMsat?: number
  maxSendableMsat?: number
  /** withheld on minting, advertised in the payRequest metadata */
  baseFeeMsat?: number
  feePpm?: number
  /**
   * 'trailing' is the LUD-25 wire format (r || s || recovery id). 'leading'
   * reproduces the layout lnurl-mint once emitted, forwarding its node's
   * signmessage output unreordered.
   */
  signatureLayout?: SignatureLayout
  /**
   * Certify every note issued with a cs1 over hex(Q), a bearer note
   * included (default). LUD-25 makes certifying a SHOULD; false withholds
   * c/c2 everywhere, which the grader warns about and never fails.
   */
  signatures?: boolean
  /**
   * The names certificates travel under: 'c' (default) is LUD-25 as of luds
   * 50d740a, c and c2; 'sig' is the pre-50d740a sig/sig2 alone; 'both'
   * sends each under both names, as a mint mid-transition does.
   */
  certificateNames?: 'c' | 'sig' | 'both'
  /**
   * The hosts a spend's signature may be bound to, as a list or a
   * comma-separated string. Unset, the hostname the mock was reached at.
   */
  domains?: string[] | string
  /**
   * How the payRequest spells its withdrawLink. 'plain' (default) is the
   * fetchable https:// URL the reference mint emits and the spec's diagram
   * shows; 'lnurlw' is the LUD-17 scheme form. Both are legal; test against both.
   */
  withdrawLinkForm?: WithdrawLinkForm
  /** LUD-21 verify endpoint. Off means 404, not merely unadvertised. */
  verify?: boolean
  privateKey?: string

  /**
   * Publish `payLink` on a note's informational GET - the way home for a
   * holder who has nothing but the note. On by default, as the reference
   * mint does it.
   */
  noteInfoPayLink?: boolean

  // ---- misbehaviour ----
  /**
   * Point `payLink` at a different origin, nominating a third party to
   * vouch for this mint's key history. A client must ignore it.
   */
  payLinkOffOrigin?: boolean
  /** answer the informational GET with a k1 other than the one queried */
  echoWrongK1?: boolean
  /** report a maxWithdrawable that is not what the note is worth */
  lieAboutValue?: number
  /** hang up mid-mutation, leaving the outcome unknown while it still lands */
  dropAfterMutation?: boolean
  /** reply 200 with a body that confirms nothing */
  unconfirmedMutation?: boolean
  /** reply with a body that is not JSON at all */
  malformedJson?: boolean
  /** hold every melt in flight forever, so the note stays locked as pending */
  meltNeverSettles?: boolean
  /** fail every melt's payment, restoring the note */
  meltAlwaysFails?: boolean
  /** non-compliant: generate the replacement secret SERVICE-side and hand it back */
  serverGeneratedSecrets?: boolean
  /** ceiling the mint fee to a whole sat, as dni's lnurl-mint does; compliant */
  roundFeeToSat?: boolean
  /** withhold this many msat on top of the fee, landing outside the compliant band */
  extraFeeMsat?: number
  /** non-compliant: accept a split with no p2, generating the change note instead of refusing */
  acceptsMissingP2?: boolean
  /** the older name of acceptsMissingP2 */
  acceptsMissingH2?: boolean
  /** non-compliant: split without taking the base fee out of change, and so without its floor */
  splitIgnoresBaseFee?: boolean
  /** delay before responding, in milliseconds */
  slowMs?: number
  /** reject splits and mints, as a mint winding down does */
  sunset?: boolean
  /** non-compliant: serve the preimage from verify before settlement */
  verifyLeaksEarly?: boolean
  /** expose /_test/ endpoints. Never enable against anything real. */
  testHooks?: boolean

  // ---- misbehaviour: the unified taproot model (luds 6e865b1) ----

  /** non-compliant: accept a leaf version other than 0xc0, as consensus alone does */
  leafVersionUnchecked?: boolean
  /** non-compliant: accept a leaf carrying an OP_SUCCESSx opcode */
  opSuccessUnchecked?: boolean
  /**
   * non-compliant: ignore a script path's time claim. true skips every
   * rule; otherwise one or more of 'blockHeight', 'future', 'blockCount'
   * and 'relative', as a list or comma-separated.
   */
  ignoresTimeClaims?: boolean | TimeRule | TimeRule[] | string
  /** non-compliant, over-strict: refuse every non-zero locktime, a past one included */
  refusesLocktimes?: boolean
  /** non-compliant: accept any ck1 whose Q is outstanding without checking its signature */
  unverifiedCk1?: boolean
  /** non-compliant: answer the informational GET for a k1 by its Q, never verifying the spend */
  infoSkipsVerification?: boolean
  /** non-compliant: match a retried mutation on raw strings rather than the notes they name */
  replayMatchesStrings?: boolean
  /** the reason a p1/p2 naming a note already in use gets; LUD-25 fixes "already in use" */
  alreadyInUseReason?: string
  /** non-compliant: certify a bearer note over its h, the pre-taproot message, not hex(Q) */
  certificateOverH?: boolean
  /** non-compliant: refuse a cp1 wherever one may go, as a mint without key-path notes does */
  refusesCp1Outputs?: boolean
  /** non-compliant: accept a cp1 whose Q is not the x coordinate of a curve point */
  acceptsOffCurveCp1?: boolean

  // ---- optional, non-spec extensions ----
  //
  // None of these is in LUD-25 and none is on by default. Every one is
  // absent from the wire unless it is set.

  /** operator-facing name, on the experimental discovery endpoint */
  name?: string
  /** one line about the mint, on the discovery endpoint */
  description?: string
  /** how to reach the operator, on the discovery endpoint */
  contact?: MintContact | string
  /** link to the mint's terms, on the discovery endpoint */
  tosUrl?: string
  /** message of the day: how an operator talks to holders */
  motd?: string
  /** the mint software's version string */
  version?: string
  /**
   * Compressed hex pubkeys this SERVICE has signed under before, so notes
   * it already issued still verify after a signing-key rotation. Emitted
   * only when the list is not empty. A comma-separated string is accepted
   * so the CLI can pass one.
   */
  previousPubkeys?: string[] | string
  /**
   * An old signing key the mock still holds, so a case can issue one note
   * under it and the rest under the current key. Its public half joins
   * previousPubkeys automatically. A real mint that has rotated keeps only
   * the public half.
   */
  previousPrivateKey?: string
  /**
   * Sign every note this mock issues under previousPrivateKey while still
   * advertising the current key as mintPubkey: the mid-rotation state a
   * mint passes through when the advertisement moves before the signer.
   */
  signWithPreviousKey?: boolean
  /**
   * What a retried mutation gets. A rotate, split or merge is a GET and
   * HTTP stacks retry a GET on a dropped connection, so a SERVICE sees
   * the byte-identical request twice. 'replay' (default) returns the
   * original success as LUD-25 requires; 'refuse' is the non-compliant
   * fixture. The same request means the same set of notes burned, the
   * same p1, the same p2 and the same amount, all compared as the Qs they
   * decode to; anything else naming a burned input is refused as before.
   */
  retriedMutation?: RetriedMutation
  /**
   * The informational lookup by `?p=` (a cp1, or a bearer note's hex h;
   * `?h=` is read as its older name), which LUD-25 makes a MUST. `true` is
   * conforming; string values reproduce distinct non-compliant responses,
   * and false an older SERVICE the grader fails.
   */
  hashLookup?: HashLookup
  /** serve GET /stats, the liabilities endpoint. Off means 404, as before. */
  stats?: boolean
  /** what the node behind a stats-publishing mock claims to hold */
  localBalanceMsat?: number
  /**
   * Additive compatibility spelling for the mandatory mint comment. Off,
   * `h` is not advertised or read, while comment-bound minting remains the
   * baseline. On, WALLET may repeat the same 64-hex output commitment as
   * `h`, enabling the ForgeSworn/Moneyer quote and receipt vocabulary.
   *
   * The capability is advertised in three places: `mintToHash: true` on
   * the payRequest (every mint has one, so it is what a wallet decides
   * from), the same on the mint address document (corroboration, for
   * consistency with the other capability fields there), and the same
   * echoed on the pay callback's own response when THAT quote was bound.
   *
   * Case is normalised before `h` is compared or keyed: hex is
   * case-insensitive, so the two spellings are one output rather than
   * two. A wallet still sends lowercase.
   */
  mintToHash?: boolean
  /**
   * Emit the optional mint:{h,amount} quote commitment and add the normal
   * note signature on settled LUD-21 verification. Requires mintToHash,
   * verify and signatures. Off by default for baseline compatibility.
   */
  mintReceipt?: boolean
  /**
   * non-compliant, and only reachable with mintToHash on: issue an
   * invoice for an `h` that is not 64 lowercase hex, so a wallet pays for
   * a quote this mint was always going to refuse.
   */
  mintToHashAcceptsMalformedH?: boolean
  /**
   * non-compliant, mintToHash on: issue an invoice for an `h` that
   * already names a note, an invoice or another quote's output, so two
   * payers' money points at one id.
   */
  mintToHashAcceptsUsedH?: boolean
  /**
   * non-compliant, mintToHash on: accept `h` and mandatory `comment` even
   * when they name different outputs. The normative comment still binds
   * the note, but the extension claim and any h-watching signer disagree.
   */
  mintToHashIgnoresH?: boolean
  /**
   * Which of the three places this mock claims the capability in.
   * Undefined means all three, which is what an honest mint publishes.
   * Narrowing it changes only what is CLAIMED, never what the mint does:
   * `['quote']` is the mint that shipped the feature before the
   * advertisement, and `['payRequest', 'mintAddress']` is the one that
   * binds without confirming at the moment money moves. Read only when
   * mintToHash is on. A comma-separated string is accepted so the CLI can
   * pass one.
   */
  mintToHashAdvertisedOn?: MintToHashPlace[] | string

  // ---- LUD-26 Lightning Address ----
  //
  // Registration (POST, PUT and DELETE on /.well-known/lnurlp/<username>)
  // is always served.

  /**
   * Pre-register `registeredUsername` against 26-vectors.json's first share
   * (derivation[1], account 0, share 0), already paid, so its notes are
   * luds' own.
   */
  registeredAddress?: boolean
  /** default 'alice' */
  registeredUsername?: string
  /** the address fee per registration, advertised as Mint fees' third value; 0 is free */
  addressFeeMsat?: number
  /** what the registration invoice charges, when not what is advertised */
  addressFeeChargedMsat?: number
  /** non-compliant: serve an address before its fee settles */
  publishesUnpaidAddress?: boolean
  /** non-compliant: accept any registration, update or unregister proof */
  registrationUnverified?: boolean
  /** non-compliant: verify the 0.15 register message, which binds no cx1 */
  registrationWithoutCx1?: boolean
  /** non-compliant: let a POST replace a registration */
  overwritesRegistration?: boolean
  /**
   * non-compliant: true accepts any cx1 again; 'afterUnregister' forgets a
   * cx1 once off file; 'byCx1' compares the string rather than x(P)
   */
  reusesCx1?: boolean | 'afterUnregister' | 'byCx1'
  /** non-compliant: register `mint` or a username containing `+` */
  acceptsReservedUsernames?: boolean
  /** non-compliant: verify only one of an update's two proofs */
  updateChecksOnly?: 'sig' | 'newsig'
  /** non-compliant: unregister on any proof */
  unregisterUnverified?: boolean
  /** 'lud26' (default) refuses with LUD-26's exact reasons; 'other' does not */
  registrationReasons?: 'lud26' | 'other'
  /** non-compliant: no Access-Control-Allow-Origin on POST, PUT and DELETE */
  noMutationCors?: boolean
  /** non-compliant: refuse the OPTIONS preflight */
  noPreflight?: boolean
  /** non-compliant: an address payRequest that sets commentAllowed */
  addressCommentAllowed?: boolean
  /** non-compliant: answer <name>+<tag> as an unknown user */
  plusTagUnknown?: boolean
  /** non-compliant: an address advertising other Mint fees than mint@ */
  addressFeesDiffer?: boolean
  /** non-compliant: publish the share's cx1 as the retired text/cpub hint */
  addressHint?: boolean
}

export interface MockRegistration {
  cx1: string
  chainCode: Uint8Array
  /** the share's compressed P */
  pubkey: Uint8Array
  /** hex x(P) */
  xOnly: string
  /** false while held on an unpaid address fee */
  paid: boolean
  paymentHash?: string
}

export interface MintContact {
  /** an npub */
  nostr?: string
  email?: string
  url?: string
}

export interface MintLiabilities {
  at: string
  outstandingMsat: number
  outstandingNotes: number
  pendingMsat: number
  pendingMelts: number
  oldestPendingMeltAgeSecs: number | null
  localBalanceMsat?: number
  /** localBalanceMsat / outstandingMsat, 4 dp; omitted when nothing is owed */
  coverage?: number
  reconciledAt: string
}

export interface MockMintState {
  /**
   * Keyed by hex(Q), the note's taproot output key. `lockedAt` is when the
   * mock credited it (Unix seconds), where a relative lock starts; `h` is
   * a bearer note's hash, kept only when it was named by one.
   */
  notes: Map<
    string,
    {amountMsat: number; state: NoteState; lockedAt: number; h?: string; pendingSince?: number}
  >
  invoices: Map<
    string,
    {
      amountMsat: number
      preimage: string
      settled: boolean
      /** hex(Q) of the note this quote was bound to, when the wallet named one */
      boundTo?: string
      /** the hex h that named it, when it was named by one */
      boundH?: string | null
      /** the exact invoice returned on the quote, for LUD-21 binding */
      pr?: string
      /** the username an address payment credits */
      share?: string
      /** the username an address fee holds */
      registrationFor?: string
      /** hex(Q) an address payment was credited at, once settled */
      creditedTo?: string
    }
  >
  pubkey: string
  /** the keys this mint has signed under before, as the discovery endpoint publishes them */
  previousPubkeys: string[]
  opts: Required<MockMintOptions>
  /**
   * Fund a note directly, bypassing the minting flow. `k1` is any spend of
   * it: a 64-hex preimage (the bearer note it names), a ck1 or a cw1.
   * Returns the note's cs1 certificate, or undefined for the
   * `signatures: false` fixture.
   *
   * Pass `{previousKey: true}` to certify it under `previousPrivateKey`
   * instead, which is how a case puts one note under the old signing key
   * and the rest under the new one.
   */
  creditNote(
    k1: string,
    amountMsat: number,
    options?: {previousKey?: boolean}
  ): string | undefined
  /** Fund a note by what names it rather than a spend: a cp1 or a bearer note's hex h. */
  creditOutput(
    ref: string,
    amountMsat: number,
    options?: {previousKey?: boolean}
  ): string | undefined
  noteState(k1: string): NoteState | null
  settleMelt(k1: string): void
  failMelt(k1: string): void
  /**
   * Settle an invoice this mock issued, as its node would: a mint quote's
   * note, an address payment's share note (at `creditedTo`) or an address
   * fee's registration. Null for an unknown payment hash.
   */
  settle(paymentHash: string): MockMintState['invoices'] extends Map<string, infer I> ? I | null : never
  /** LUD-26 registrations, by lowercase username */
  registrations: Map<string, MockRegistration>
}

export interface MockMint {
  url: string
  port: number
  state: MockMintState
  close(): Promise<void>
}

export function createMockMint(options?: MockMintOptions): Promise<MockMint>
