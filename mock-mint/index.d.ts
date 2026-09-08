// Types for the mock mint, so TypeScript consumers get the misbehaviour flags
// checked rather than reaching for `any`. Hand-written to match index.mjs;
// the flag list here is the same one DEFAULTS declares there.

export type SignatureLayout = 'trailing' | 'leading'

export type NoteState = 'outstanding' | 'pending' | 'burned'

export type WithdrawLinkForm = 'lnurlw' | 'plain'

export type RetriedMutation = 'refuse' | 'replay'

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
  /** non-compliant: withhold the mandatory sig/sig2 */
  signatures?: boolean
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
  /** non-compliant: accept a split with no h2, generating the change secret instead of refusing */
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
   * fixture. Identical means the same input k1 set, the
   * same h, the same h2 and the same amount; anything else naming a
   * burned input is refused exactly as before.
   */
  retriedMutation?: RetriedMutation
  /**
   * Optional informational lookup by sha256(k1). `true` is conforming;
   * string values reproduce distinct non-compliant responses.
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
  notes: Map<string, {amountMsat: number; state: NoteState; pendingSince?: number}>
  invoices: Map<
    string,
    {
      amountMsat: number
      preimage: string
      settled: boolean
      /** the output id this quote was bound to, when the wallet named one */
      boundTo?: string
      /** the exact invoice returned on the quote, for LUD-21 binding */
      pr?: string
    }
  >
  pubkey: string
  /** the keys this mint has signed under before, as the discovery endpoint publishes them */
  previousPubkeys: string[]
  opts: Required<MockMintOptions>
  /**
   * Fund a note directly, bypassing the minting flow. Returns the note's
   * signature, or undefined only for the deliberately non-compliant
   * `signatures: false` fixture.
   *
   * Pass `{previousKey: true}` to sign it under `previousPrivateKey`
   * instead, which is how a case puts one note under the old signing key
   * and the rest under the new one.
   */
  creditNote(
    k1: string,
    amountMsat: number,
    options?: {previousKey?: boolean}
  ): string | undefined
  noteState(k1: string): NoteState | null
  settleMelt(k1: string): void
  failMelt(k1: string): void
}

export interface MockMint {
  url: string
  port: number
  state: MockMintState
  close(): Promise<void>
}

export function createMockMint(options?: MockMintOptions): Promise<MockMint>
