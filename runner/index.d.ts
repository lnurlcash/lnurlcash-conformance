// Types for the grader, so a TypeScript consumer gets its shape checked
// rather than hand-writing a `declare module` shim of its own. Hand-written
// to match index.mjs.
//
// This file exists because those shims drift. moneyer carried one, the
// grader grew gradeBoundMint, and the shim did not: the consumer could not
// call the newest check without editing a copy of a declaration it does not
// own. Shipping the declarations puts that in one place, next to the code
// they describe.

/** what the mint fee is, in LUD-25's own two terms */
export interface MintFee {
  baseFeeMsat: number
  feePpm: number
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

/** an `lnurlw://` or `lnurlp://` URL as its https equivalent, per LUD-17 */
export declare const fromLud17: (value: string) => string

/** a lightning address or LNURL as the payRequest URL to fetch */
export declare const resolveMint: (input: string) => string

/** the msat a bolt11 invoice states, or null where it states none */
export declare const invoiceAmountMsat: (pr: string) => number | null

/** what a gross mint of `gross` msat leaves once `fee` is withheld */
export declare const applyMintFee: (gross: number, fee: MintFee | null) => number

/** the `Mint fees: base,ppm` line out of a payRequest's metadata array */
export declare const parseAdvertisedMintFee: (metadata: string) => MintFee | null

/** the read-only mint checks: payRequest, withdrawLink, fees, verify, extensions */
export declare const gradeMint: (
  payUrl: string,
  report: Report,
  options?: {
    /** Grade as a LUD-25 Part 2 registered Lightning Address rather than a
     * mint payLink: it mints on the next unused key of its own branch, so a
     * comment naming no output is free text and must not fail the payment.
     * Declared, not detected - an unsafe preimage-keyed fallback looks
     * identical before settlement. */
    registeredAddress?: boolean
  }
) => Promise<void>

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
 *
 * `mintFee` absent means unknown, and the conservation checks are bounded
 * rather than exact; null means known fee-free. `previousPubkeys` are keys
 * the mint has signed under before, so a note issued before a rotation is
 * not graded as a bad signature.
 */
export declare const gradeNote: (
  noteUrl: string,
  report: Report,
  options?: {mintFee?: MintFee | null; previousPubkeys?: string[]}
) => Promise<void>
