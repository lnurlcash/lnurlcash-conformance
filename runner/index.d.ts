// Types for the grader, so a TypeScript consumer gets its shape checked
// rather than hand-writing a `declare module` shim of its own. Hand-written
// to match index.mjs.
//
// This file exists because those shims drift. moneyer carried one, the
// grader grew gradeBoundMint, and the shim did not: the consumer could not
// call the newest check without editing a copy of a declaration it does not
// own. Shipping the declarations puts that in one place, next to the code
// they describe.

/** what the mint fee is, in LUD-25's own two terms, and LUD-26's address fee */
export interface MintFee {
  baseFeeMsat: number
  feePpm: number
  /** per Lightning Address registration; null (or absent) where registering is free */
  addressFeeMsat?: number | null
}

export type ReportStatus = 'pass' | 'fail' | 'warn' | 'skip'

export interface ReportResult {
  status: ReportStatus
  name: string
  /** what the check saw, in a sentence. Present on nearly every result */
  detail?: string
}

export interface Report {
  results: ReportResult[]
  pass(name: string, detail?: string): void
  fail(name: string, detail?: string): void
  warn(name: string, detail?: string): void
  skip(name: string, detail?: string): void
  /**
   * Runs `fn` and records the outcome. A thrown error is a failure; an
   * error carrying a truthy `warning` is a warning, which is how an
   * optional extension in the wrong shape is reported without failing a
   * mint that need not have published it at all.
   */
  check(name: string, fn: () => Promise<unknown> | unknown): Promise<void>
  /** how many results are failures */
  readonly failed: number
}

export declare const createReport: () => Report

/**
 * The ck1 that spends the key-path note x(sk·G) at `domain` (the mint's
 * lowercase hostname, no port): Q || a BIP-340 signature, with an all-zero
 * aux_rand, over the key-path sighash of LUD-25's canonical spend
 * transaction for that domain.
 */
export declare const keyPathSpend: (secretKey: Uint8Array, domain: string) => string

/** an `lnurlw://` or `lnurlp://` URL as its https equivalent, per LUD-17 */
export declare const fromLud17: (value: string) => string

/** a lightning address or LNURL as the payRequest URL to fetch */
export declare const resolveMint: (input: string) => string

/** the msat a bolt11 invoice states, or null where it states none */
export declare const invoiceAmountMsat: (pr: string) => number | null

/** what a gross mint of `gross` msat leaves once `fee` is withheld */
export declare const applyMintFee: (gross: number, fee: MintFee | null) => number

/** the `Mint fees: base,ppm[,address fee]` token out of a payRequest's metadata array */
export declare const parseAdvertisedMintFee: (metadata: string) => MintFee | null

/**
 * The same, read as fees.json does: `unknown` when a token is present and
 * does not parse, `entry` the text it was found in.
 */
export declare const readFeeAdvertisement: (
  metadata: string
) => {fee: MintFee | null; unknown: boolean; entry: string | null}

/** a LUD-26 share's cx1: bech32m("cx", chainCode || compressed P) */
export declare const encodeCx1: (chainCode: Uint8Array, compressedPubkey: Uint8Array) => string
export declare const decodeCx1: (cx1: string) => {chainCode: Uint8Array; pubkey: Uint8Array} | null

/** the message a LUD-26 register, update or unregister proof signs */
export declare const registrationMessage: (
  action: 'register' | 'update' | 'unregister',
  domain: string,
  username: string,
  cx1?: string | null
) => string
/** hex BIP-340 signature over sha256(message) */
export declare const signRegistration: (message: string, secretKey: Uint8Array, auxRand?: Uint8Array) => string
export declare const verifyRegistration: (message: string, sigHex: string, xOnlyPubkey: Uint8Array) => boolean

/** the read-only mint checks: payRequest, withdrawLink, fees, verify, extensions */
export declare const gradeMint: (
  payUrl: string,
  report: Report,
  options?: {
    /** Grade as a LUD-26 cx1-registered Lightning Address rather than a
     * mint payLink: no commentAllowed, a plain LUD-16 payment, mint@'s
     * withdrawLink and fees, and a +tag paying the same share. Declared,
     * not detected - an unsafe preimage-keyed fallback looks identical
     * before settlement. */
    registeredAddress?: boolean
  }
) => Promise<unknown>

/**
 * MUTATING. Registers a throwaway username on the mint with a share only
 * the grader holds, probes every refusal LUD-26 requires, updates it to a
 * second share and unregisters it. Against a mint charging an address fee
 * the registration is held on an unpaid invoice, which is held to the
 * advertised fee, and the update and unregister checks are skipped.
 */
export declare const gradeRegistration: (
  mint: string,
  report: Report,
  options?: {username?: string}
) => Promise<{username: string; domain: string; addressFeeMsat: number | null} | undefined>

/**
 * Read-only. Needs a freshly minted, never-rotated note and what its mint
 * invoice was paid at, and grades the note's value against the advertised
 * fee.
 */
export declare const gradeMintedValue: (
  noteUrl: string,
  report: Report,
  options: {paidMsat: number; mintFee?: MintFee | null}
) => Promise<void>

/**
 * Read-only. Needs a note minted against a hash the WALLET chose, plus the
 * payment preimage of the invoice that funded it. Checks that the note is
 * at the wallet's own secret and that the preimage opens nothing.
 *
 * `payCallback` is optional: with it, the runner also checks that the id
 * the note occupies cannot be sold again as a mint quote.
 */
export declare const gradeBoundMint: (
  noteUrl: string,
  report: Report,
  options: {preimage: string; payCallback?: string | null}
) => Promise<void>

/**
 * SPENDS. Burns the note it is given and leaves the value in a fresh one.
 * The note URL's k1 may be any spend of it: a bearer note's 64-hex
 * preimage, a ck1 or a cw1.
 *
 * `mintFee` absent means unknown, and the conservation checks are bounded
 * rather than exact; null means known fee-free. `previousPubkeys` are keys
 * the mint has signed under before, so a note issued before a rotation is
 * not graded as a bad signature.
 *
 * Resolves to where the value ended up: the spend the grader holds and a
 * note URL carrying it. Undefined only when the first informational GET
 * failed, in which case nothing was spent.
 */
export declare const gradeNote: (
  noteUrl: string,
  report: Report,
  options?: {mintFee?: MintFee | null; previousPubkeys?: string[]}
) => Promise<{finalSecret: string; noteUrl: string} | undefined>
