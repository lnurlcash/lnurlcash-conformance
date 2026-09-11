// The grader grades itself: a compliant mock mint must pass clean, and a
// deliberately broken one must be caught. This is the local twin of CI's
// 'grader' job, so the pre-push gate runs what CI would have run - in
// process, no ports or log scraping.

import assert from 'node:assert/strict'
import {bech32} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {bytesToHex, hexToBytes, randomBytes} from '@noble/hashes/utils.js'
import {createMockMint} from '../mock-mint/index.mjs'
import {
  createReport,
  gradeBoundMint,
  gradeMint,
  gradeMintedValue,
  gradeNote,
  parseAdvertisedMintFee
} from '../runner/index.mjs'

const grade = async (mockOptions, {previousPubkeys, payPath} = {}) => {
  const mint = await createMockMint(mockOptions)
  try {
    const k1 = bytesToHex(randomBytes(32))
    mint.state.creditNote(k1, 21_000)
    const report = createReport()
    const payUrl = payPath ? `${mint.url}${payPath}` : `${mint.url}/.well-known/lnurlp/mint`
    const pay = await gradeMint(payUrl, report)
    const options =
      pay && typeof pay.metadata === 'string'
        ? {mintFee: parseAdvertisedMintFee(pay.metadata)}
        : {}
    // What the CLI does: carry the keys the mint publishes into the note
    // checks, so a note issued before a signing-key rotation still
    // verifies. A caller can override to prove the acceptance is doing
    // work rather than waving everything through.
    const published = previousPubkeys ?? pay?.mintAddress?.previousPubkeys
    if (Array.isArray(published)) options.previousPubkeys = published
    await gradeNote(`${mint.url}/w?k1=${k1}&amount=21000`, report, options)
    return report
  } finally {
    await mint.close()
  }
}

const statusOf = (report, name) => report.results.find(r => r.name === name)?.status
const detailOf = (report, name) => report.results.find(r => r.name === name)?.detail ?? ''
const die = message => {
  console.error(message)
  process.exit(1)
}

const good = await grade({})
if (good.failed > 0) {
  console.error('a COMPLIANT mint failed grading:')
  for (const r of good.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log(`ok   compliant mock passes (${good.results.length} checks)`)

// A held melt must never look spent before settlement, and a failed melt
// restores the same value. Both lookup forms observe the retained state.
const lifecycleMint = await createMockMint({hashLookup: true, meltNeverSettles: true})
try {
  const k1 = bytesToHex(randomBytes(32))
  const h = bytesToHex(sha256(hexToBytes(k1)))
  lifecycleMint.state.creditNote(k1, 3000)
  const lookup = query => fetch(`${lifecycleMint.url}/w?${query}`).then(r => r.json())
  const live = await lookup(`h=${h}`)
  assert.equal(live.maxWithdrawable, 3000)
  assert.equal('k1' in live, false)
  const melt = () => fetch(`${lifecycleMint.url}/w/cb?k1=${k1}&pr=mock-invoice`).then(r => r.json())
  assert.equal((await melt()).status, 'OK')
  for (const query of [`h=${h}`, `k1=${k1}`]) {
    assert.deepEqual(await lookup(query), {status: 'ERROR', reason: 'pending'})
  }
  lifecycleMint.state.failMelt(k1)
  assert.equal((await lookup(`h=${h}`)).maxWithdrawable, 3000)
  assert.equal((await melt()).status, 'OK')
  lifecycleMint.state.settleMelt(k1)
  for (const query of [`h=${h}`, `k1=${k1}`]) {
    assert.deepEqual(await lookup(query), {status: 'ERROR', reason: 'Note already spent.'})
  }
  assert.deepEqual(await lookup(`h=${bytesToHex(randomBytes(32))}`), {status: 'ERROR', reason: 'Unknown note.'})
  assert.equal(lifecycleMint.state.noteState(k1), 'burned')
  console.log('ok   hash lookups follow live, pending, restored and retained spent states')
} finally {
  await lifecycleMint.close()
}

// The other legal spelling of withdrawLink: the lnurlw:// scheme form. The
// grader must take both, and say which it saw.
const plain = await grade({withdrawLinkForm: 'lnurlw'})
if (plain.failed > 0) {
  console.error('a mint with an lnurlw:// withdrawLink failed grading:')
  for (const r of plain.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
const forms = [good, plain].map(
  r => r.results.find(x => x.name.startsWith('advertises a withdrawLink'))?.detail ?? ''
)
if (!forms[0].includes('plain URL form') || !forms[1].includes('lnurlw:// form')) {
  console.error(`the grader did not report the withdrawLink form: ${JSON.stringify(forms)}`)
  process.exit(1)
}
console.log('ok   lnurlw:// withdrawLink passes, and both forms are named in the report')

const bad = await grade({echoWrongK1: true})
if (bad.failed === 0) {
  console.error('a mint echoing the wrong k1 PASSED - the grader is blind')
  process.exit(1)
}
console.log(`ok   broken mock caught (${bad.failed} failing check${bad.failed === 1 ? '' : 's'})`)

// The minted-value check: pay a mint invoice (via the test hooks - the mock
// invents its invoices), then compare the note against the fee formula.
const gradeMintFlow = async mockOptions => {
  const mint = await createMockMint({
    testHooks: true,
    baseFeeMsat: 1000,
    feePpm: 1000,
    ...mockOptions
  })
  try {
    const gross = 500_000
    const k1 = bytesToHex(randomBytes(32))
    const comment = bytesToHex(sha256(hexToBytes(k1)))
    const quote = await (
      await fetch(`${mint.url}/p/cb?amount=${gross}&comment=${comment}`)
    ).json()
    const paymentHash = quote.verify.split('/').pop()
    await fetch(`${mint.url}/_test/settle?payment_hash=${paymentHash}`)
    const report = createReport()
    await gradeMintedValue(`${mint.url}/w?k1=${k1}`, report, {
      mintFee: {baseFeeMsat: 1000, feePpm: 1000},
      paidMsat: gross
    })
    return report
  } finally {
    await mint.close()
  }
}

const exact = await gradeMintFlow({})
if (exact.failed > 0) {
  console.error('a formula-exact mint FAILED the minted-value check:')
  for (const r of exact.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log('ok   formula-exact mint passes the minted-value check')

// The reference mint ceilings its fee to a whole sat on purpose, and the
// draft does not say whether that is right. Grading it as a failure would
// be this repo picking a side, so the check takes a band - but the band
// has to have a far edge, or it grades nothing at all.
const rounded = await gradeMintFlow({roundFeeToSat: true})
if (rounded.failed > 0) {
  console.error('a mint ceilinging its fee to a whole sat FAILED - that is what the reference does:')
  for (const r of rounded.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
console.log('ok   sat-ceilinged fee accepted, as the reference mint charges it')

const greedy = await gradeMintFlow({roundFeeToSat: true, extraFeeMsat: 1})
if (greedy.failed === 0) {
  console.error('a mint taking a msat beyond the ceilinged fee PASSED - the band grades nothing')
  process.exit(1)
}
console.log('ok   a msat past the band still caught')

const generous = await gradeMintFlow({extraFeeMsat: -1})
if (generous.failed === 0) {
  console.error('a mint crediting more than it advertised PASSED - the band has no near edge')
  process.exit(1)
}
console.log('ok   crediting more than the formula still caught')

// The two split refusals LUD-25 spells out. Both need a fee-advertising
// mint to bite at all, so they are graded against one, and each must name
// its own check rather than merely pushing the failure count up.
const caughtBy = (report, name) =>
  report.results.some(r => r.status === 'fail' && r.name === name)

const looseH2 = await grade({acceptsMissingH2: true, baseFeeMsat: 1000, feePpm: 1000})
if (!caughtBy(looseH2, 'refuses a split with no h2')) {
  console.error('a mint generating the change secret itself PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   split with no h2 caught')

const looseFee = await grade({splitIgnoresBaseFee: true, baseFeeMsat: 1000, feePpm: 1000})
if (!caughtBy(looseFee, 'refuses a split whose change cannot cover the base fee')) {
  console.error('a mint splitting past its own base fee PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   split past the base fee caught')

const leaky = await grade({verifyLeaksEarly: true})
if (leaky.failed === 0) {
  console.error('a mint serving preimages before settlement PASSED - the grader is blind')
  process.exit(1)
}
console.log('ok   pre-settlement verify leak caught')

// ---- the optional extensions -------------------------------------------
//
// Mint info and liabilities are optional. Signing-key rotation is exercised
// here too, because old notes remain valid under published previous keys.

const MINT_INFO_CHECK = 'publishes a mint address (experimental, optional)'
const LIABILITIES_CHECK = 'publishes liabilities (optional)'
const SIGNATURE_CHECK = 'a plain note carries no signature, or one that verifies'
const PART2_CHECK = 'certifies a cp1 note it issues (Part 2)'

// a real npub, decoded rather than pattern-matched by the grader
const npub = bech32.encode('npub', bech32.toWords(new Uint8Array(32).fill(2)), 200)
const PREVIOUS_KEY = '3'.repeat(64)

const bare = await grade({})
if (statusOf(bare, LIABILITIES_CHECK) !== 'warn') {
  die(`a mint publishing no liabilities did not warn: ${statusOf(bare, LIABILITIES_CHECK)}`)
}
if (statusOf(bare, MINT_INFO_CHECK) !== 'pass') {
  die(`a mint publishing no info stopped passing the mint address check: ${detailOf(bare, MINT_INFO_CHECK)}`)
}
console.log('ok   a mint publishing none of the optional extensions is not graded down')

const dressed = await grade({
  name: 'Mock Mint',
  description: 'a mint that exists to be graded',
  contact: {nostr: npub, email: 'operator@example.com', url: 'https://mint.example/contact'},
  tosUrl: 'https://mint.example/terms',
  motd: 'fees change on the first',
  version: '0.2.0',
  previousPrivateKey: PREVIOUS_KEY,
  stats: true,
  baseFeeMsat: 1000,
  feePpm: 1000
})
if (dressed.failed > 0) {
  console.error('a mint publishing the optional extensions FAILED grading:')
  for (const r of dressed.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (statusOf(dressed, MINT_INFO_CHECK) !== 'pass') {
  die(`well-formed mint info did not pass: ${detailOf(dressed, MINT_INFO_CHECK)}`)
}
for (const field of ['name', 'contact', 'tosUrl', 'motd', 'fees', 'previousPubkeys']) {
  if (!detailOf(dressed, MINT_INFO_CHECK).includes(field)) {
    die(`the report does not name the published ${field}: ${detailOf(dressed, MINT_INFO_CHECK)}`)
  }
}
if (statusOf(dressed, LIABILITIES_CHECK) !== 'pass') {
  die(`a well-covered mint's liabilities did not pass: ${detailOf(dressed, LIABILITIES_CHECK)}`)
}
if (!/coverage/.test(detailOf(dressed, LIABILITIES_CHECK))) {
  die(`the liabilities report does not name the coverage: ${detailOf(dressed, LIABILITIES_CHECK)}`)
}
console.log('ok   mint info and liabilities pass and are named in the report')

// A published field of the wrong shape is a warning, never a failure: it
// is worth saying out loud, because a wallet will try to render it.
const malformed = await grade({contact: {nostr: 'npub1notarealkey'}})
if (statusOf(malformed, MINT_INFO_CHECK) !== 'warn') {
  die(`a contact.nostr that is not an npub did not warn: ${statusOf(malformed, MINT_INFO_CHECK)}`)
}
if (malformed.failed > 0) die('a malformed optional field FAILED the grade - it must only warn')
console.log('ok   a malformed optional field warns and never fails')

// Under-coverage is the operator's business to disclose. A mint that
// publishes an uncomfortable number is behaving better than one that
// publishes nothing, so it warns.
const thin = await grade({stats: true, localBalanceMsat: 1})
if (statusOf(thin, LIABILITIES_CHECK) !== 'warn') {
  die(`an under-covered mint did not warn: ${statusOf(thin, LIABILITIES_CHECK)}`)
}
if (thin.failed > 0) die('an under-covered mint FAILED the grade - it must only warn')
console.log('ok   an under-covered mint warns and never fails')

// A mint whose advertisement has rotated ahead of its signer: notes come
// out under the old key, which the mint still publishes.
const rotated = await grade({previousPrivateKey: PREVIOUS_KEY, signWithPreviousKey: true})
if (rotated.failed > 0) {
  console.error('a mint signing under a published previous key FAILED grading:')
  for (const r of rotated.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (!/previous signing key/.test(detailOf(rotated, SIGNATURE_CHECK))) {
  die(`the report does not say the note was signed under a previous key: ${detailOf(rotated, SIGNATURE_CHECK)}`)
}
console.log('ok   a signature under a published previous key is accepted, and named as one')

// ... and the acceptance has to be doing work. The same mint, graded
// without the keys it publishes, must be caught.
const unpublished = await grade(
  {previousPrivateKey: PREVIOUS_KEY, signWithPreviousKey: true},
  {previousPubkeys: []}
)
if (statusOf(unpublished, SIGNATURE_CHECK) !== 'fail') {
  die('a signature under a key the mint never published PASSED - the grader is blind')
}
console.log('ok   a signature under an unpublished key still caught')

// Since the Part 2 rewrite a plain note is unsigned by design: the mint's
// signature belongs on cp1 notes, and the mock does not issue those.
const unsigned = await grade({signatures: false})
if (statusOf(unsigned, SIGNATURE_CHECK) !== 'pass' || !/unsigned/.test(detailOf(unsigned, SIGNATURE_CHECK))) {
  die(`a mint issuing unsigned plain notes was graded down: ${detailOf(unsigned, SIGNATURE_CHECK)}`)
}
if (unsigned.failed > 0) die('a mint issuing unsigned plain notes FAILED the grade')
console.log('ok   an unsigned plain note is not graded down')
if (statusOf(good, PART2_CHECK) !== 'warn' || !/Part 2 not offered/.test(detailOf(good, PART2_CHECK))) {
  die(`a Part 1 mint refusing a cp1 output did not warn: ${statusOf(good, PART2_CHECK)} ${detailOf(good, PART2_CHECK)}`)
}
console.log('ok   a mint without Part 2 warns on the certificate check and never fails')

// ---- the retried mutation ----------------------------------------------
//
// A rotate, split or merge is a GET, and a dropped connection makes an
// HTTP stack send the byte-identical request again. The SERVICE must return
// its original success rather than classifying the retry as a double spend.

const RETRY_CHECK = 'replays a retried mutation rather than refusing it'
const REPLAYED_BURN = 'refuses a replayed burn'

const refusing = await grade({retriedMutation: 'refuse', baseFeeMsat: 1000, feePpm: 1000})
if (statusOf(refusing, RETRY_CHECK) !== 'fail') {
  die(`a mint refusing a retried mutation did not fail: ${statusOf(refusing, RETRY_CHECK)}`)
}
// The combined live check stops at the first mandatory failure, so rotate
// is the independently observable shape on this refusal fixture.
if (!detailOf(refusing, RETRY_CHECK).includes('rotate')) {
  die(`the retry report does not mention the retried rotate: ${detailOf(refusing, RETRY_CHECK)}`)
}
if (statusOf(refusing, REPLAYED_BURN) !== 'pass') {
  die(`the replayed-burn check stopped passing: ${detailOf(refusing, REPLAYED_BURN)}`)
}
console.log('ok   a mint refusing a mandatory mutation replay fails without opening a double spend')

const replaying = await grade({retriedMutation: 'replay', baseFeeMsat: 1000, feePpm: 1000})
if (replaying.failed > 0) {
  console.error('a mint replaying a retried mutation FAILED grading:')
  for (const r of replaying.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (statusOf(replaying, RETRY_CHECK) !== 'pass') {
  die(`a mint replaying a retried mutation did not pass: ${detailOf(replaying, RETRY_CHECK)}`)
}
// The replay must not have become a way to spend a burned note twice: the
// existing double-spend check sends a burned input with a FRESH output
// hash, which is a different request and must still be refused.
if (statusOf(replaying, REPLAYED_BURN) !== 'pass') {
  die(`replaying retries opened a double-spend: ${detailOf(replaying, REPLAYED_BURN)}`)
}
console.log('ok   a mint replaying a retried mutation passes, and a real double-spend is still refused')

// ---- naming the note you are buying ------------------------------------
//
// A wallet MUST name the output hash in the LUD-12 comment, so the payment
// preimage never becomes the money. `mintToHash` remains an optional,
// additive spelling, but it never replaces the mandatory comment.

const MINT_TO_HASH_CHECK = 'requires comment-bound minting and honours the mintToHash extension'
const BOUND_CHECK = 'a bound mint credits the hash the wallet named (optional)'

if (statusOf(bare, MINT_TO_HASH_CHECK) !== 'pass') {
  die(`the conforming default did not require comment-bound minting: ${statusOf(bare, MINT_TO_HASH_CHECK)}`)
}
if (bare.failed > 0) die('the conforming default failed comment-bound minting')
console.log('ok   the default mock requires comment-bound minting')

const noCommentCapability = await grade({commentAllowed: false})
if (statusOf(noCommentCapability, MINT_TO_HASH_CHECK) !== 'fail') {
  die(`a mint missing commentAllowed did not fail: ${statusOf(noCommentCapability, MINT_TO_HASH_CHECK)}`)
}
console.log('ok   a mint that cannot accept the mandatory comment fails')

const binding = await grade({mintToHash: true})
if (binding.failed > 0) {
  console.error('a mint offering mintToHash FAILED grading:')
  for (const r of binding.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (statusOf(binding, MINT_TO_HASH_CHECK) !== 'pass') {
  die(`a mint honouring mintToHash did not pass: ${detailOf(binding, MINT_TO_HASH_CHECK)}`)
}
for (const where of ['the payRequest', 'the mint address', 'the quote itself']) {
  if (!detailOf(binding, MINT_TO_HASH_CHECK).includes(where)) {
    die(`the report does not name ${where} as claiming it: ${detailOf(binding, MINT_TO_HASH_CHECK)}`)
  }
}
console.log('ok   a mint offering mintToHash passes, and the report names all three claims')

// A malformed h must be refused before an invoice exists, or a wallet pays
// for a quote the mint was always going to reject and the mint keeps the
// sats. That is damage, so it fails rather than warns.
const sloppy = await grade({mintToHash: true, mintToHashAcceptsMalformedH: true})
if (!caughtBy(sloppy, MINT_TO_HASH_CHECK)) {
  die('a mint invoicing a malformed h PASSED - the grader is blind')
}
console.log('ok   an invoice issued for a malformed h caught')

// The capability is claimed in three places - the payRequest, the mint
// address document and the quote's own response - and they must agree.
// None of the disagreements loses anyone money on its own, so each is
// named rather than failed, but the grader has to notice all three.

const disagreement = async (places, wanted) => {
  const report = await grade({mintToHash: true, mintToHashAdvertisedOn: places})
  if (statusOf(report, MINT_TO_HASH_CHECK) !== 'warn') {
    die(
      `a mint claiming mintToHash only on ${places} did not warn: ${statusOf(report, MINT_TO_HASH_CHECK)}`
    )
  }
  if (report.failed > 0) {
    die(`a mint claiming mintToHash only on ${places} FAILED - a disagreement is named, never failed`)
  }
  const detail = detailOf(report, MINT_TO_HASH_CHECK)
  if (!wanted.test(detail)) die(`the report does not name the disagreement: ${detail}`)
  return detail
}

await disagreement('payRequest,mintAddress', /no mintToHash in the response/)
console.log('ok   a mint that binds without confirming on the quote warns and names it')

// A mint that echoes on the quote and advertises nowhere is still
// claiming the capability, so the grader must engage rather than report
// it unimplemented.
await disagreement('quote', /does not advertise it on the payRequest/)
console.log('ok   a mint echoing on the quote alone is graded, not written off as unimplemented')

await disagreement('payRequest,quote', /mint address document does not/)
console.log('ok   a mint address that contradicts the payRequest warns and names it')

// Two quotes against one output id is soft: the draft says nothing, and
// the refusal is an inference from the collision rule the withdraw
// callback already enforces. Named, never failed.
const doubleSold = await grade({mintToHash: true, mintToHashAcceptsUsedH: true})
if (statusOf(doubleSold, MINT_TO_HASH_CHECK) !== 'warn') {
  die(`a mint selling one output id twice did not warn: ${statusOf(doubleSold, MINT_TO_HASH_CHECK)}`)
}
if (doubleSold.failed > 0) die('a mint selling one output id twice FAILED - that refusal is an inference, so it warns')
console.log('ok   a second quote against one output id warns and never fails')

// ---- the same capability, spelt the way LUD-25 actually spells it ------
//
// `comment = hex(sha256(secret))` (LUD-12), advertised as commentAllowed
// >= 64. A suite that knows only `mintToHash` reports a mint naming notes
// in this spelling as offering nothing, which tells a wallet author the
// safe mint is the unsafe one.

const byComment = await grade({commentAllowed: 64})
if (statusOf(byComment, MINT_TO_HASH_CHECK) !== 'pass') {
  die(`a mint naming outputs by LUD-12 comment did not pass: ${detailOf(byComment, MINT_TO_HASH_CHECK)}`)
}
if (!/named by comment/.test(detailOf(byComment, MINT_TO_HASH_CHECK))) {
  die(`the report does not say which spelling was used: ${detailOf(byComment, MINT_TO_HASH_CHECK)}`)
}
if (byComment.failed > 0) die('a mint naming outputs by comment FAILED the grade')
console.log('ok   a mint naming outputs by LUD-12 comment passes, and the report names the spelling')

// commentAllowed under 64 cannot carry a hex-encoded 32-byte hash and
// therefore cannot mint under the current draft.
const shortComment = await grade({commentAllowed: 32})
if (statusOf(shortComment, MINT_TO_HASH_CHECK) !== 'fail') {
  die(`commentAllowed of 32 did not fail minting: ${statusOf(shortComment, MINT_TO_HASH_CHECK)}`)
}
console.log('ok   a commentAllowed too short to hold a hash fails')

// Current LUD-25 requires a mint advertising comment protection to refuse a missing or malformed
// comment, not fall back to keying the note by the payment preimage: a
// preimage-keyed note is only as safe as every routing hop's honesty, and a
// funding source that settles without a preimage at all (Spark) cannot mint
// one. Refusing is now the compliant answer.
const refusesText = await grade({commentAllowed: 64})
if (statusOf(refusesText, MINT_TO_HASH_CHECK) !== 'pass') {
  die(`a mint refusing an unnamed mint did not pass: ${detailOf(refusesText, MINT_TO_HASH_CHECK)}`)
}
console.log('ok   a mint requiring comment protection passes')

// And the inverse is now the failure: a mint that quietly issues a
// preimage-keyed note for a quote nobody named.
const fallsBack = await grade({commentAllowed: 64, commentFallsBack: true})
if (statusOf(fallsBack, MINT_TO_HASH_CHECK) !== 'fail') {
  die(`a mint falling back to a preimage-keyed note did not fail: ${statusOf(fallsBack, MINT_TO_HASH_CHECK)}`)
}
console.log('ok   a mint falling back to a preimage-keyed note caught')

// Both spellings at once, which is what a mint that shipped mintToHash
// first and then adopted the draft looks like.
const bothSpellings = await grade({mintToHash: true, commentAllowed: 64})
if (statusOf(bothSpellings, MINT_TO_HASH_CHECK) !== 'pass') {
  die(`a mint offering both spellings did not pass: ${detailOf(bothSpellings, MINT_TO_HASH_CHECK)}`)
}
if (!/named by h and comment/.test(detailOf(bothSpellings, MINT_TO_HASH_CHECK))) {
  die(`the report does not name both spellings: ${detailOf(bothSpellings, MINT_TO_HASH_CHECK)}`)
}
console.log('ok   a mint offering both spellings is probed in both, each with its own hash')

// ---- the paid half -----------------------------------------------------
//
// Whether the note really landed at the hash the wallet named, and whether
// the preimage still opens it, can only be answered after a settlement.
// The mock invents its invoices, so the test hooks settle one.

const gradeBound = async (mockOptions = {}) => {
  const mint = await createMockMint({testHooks: true, mintToHash: true, ...mockOptions})
  try {
    const secret = bytesToHex(randomBytes(32))
    const h = bytesToHex(sha256(hexToBytes(secret)))
    const quote = await (
      await fetch(`${mint.url}/p/cb?amount=21000&comment=${h}&h=${h}`)
    ).json()
    if (quote.status === 'ERROR') die(`the mock refused a well-formed h: ${quote.reason}`)
    const paymentHash = quote.verify.split('/').pop()
    await fetch(`${mint.url}/_test/settle?payment_hash=${paymentHash}`)
    const preimage = mint.state.invoices.get(paymentHash).preimage
    const report = createReport()
    await gradeBoundMint(`${mint.url}/w?k1=${secret}`, report, {
      preimage,
      payCallback: `${mint.url}/p/cb`
    })
    return report
  } finally {
    await mint.close()
  }
}

const bound = await gradeBound()
if (bound.failed > 0) {
  console.error('a mint crediting the note at the hash the wallet named FAILED:')
  for (const r of bound.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  process.exit(1)
}
if (!/preimage opens nothing/.test(detailOf(bound, BOUND_CHECK))) {
  die(`the report does not say the preimage opens nothing: ${detailOf(bound, BOUND_CHECK)}`)
}
console.log('ok   a bound mint credits the wallet\'s own hash, and the preimage opens nothing')

// The optional sealed-signer receipt is additive: off on the baseline mock,
// and when enabled it commits before payment but signs only after settlement.
{
  const mint = await createMockMint({
    testHooks: true,
    mintToHash: true,
    mintReceipt: true
  })
  try {
    const payRequest = await (await fetch(`${mint.url}/.well-known/lnurlp/mint`)).json()
    if (payRequest.mintToHash !== true || payRequest.mintPubkey !== mint.state.pubkey) {
      die('the receipt mock did not publish its verification key before payment')
    }
    const secret = bytesToHex(randomBytes(32))
    const h = bytesToHex(sha256(hexToBytes(secret)))
    const quote = await (
      await fetch(`${mint.url}/p/cb?amount=21000&comment=${h}&h=${h}`)
    ).json()
    if (quote.mintToHash !== true || quote.mint?.h !== h || quote.mint?.amount !== 21000) {
      die('the receipt mock did not commit the bound quote before payment')
    }
    if (quote.mint.sig !== undefined) die('the receipt mock signed an unpaid quote')
    const pending = await (await fetch(quote.verify)).json()
    if (pending.settled !== false || pending.mint?.sig !== undefined) {
      die('the receipt mock signed before settlement')
    }
    const paymentHash = quote.verify.split('/').pop()
    await fetch(`${mint.url}/_test/settle?payment_hash=${paymentHash}`)
    const settled = await (await fetch(quote.verify)).json()
    if (
      settled.settled !== true ||
      settled.pr !== quote.pr ||
      settled.mint?.h !== quote.mint.h ||
      settled.mint?.amount !== quote.mint.amount ||
      typeof settled.mint?.sig !== 'string'
    ) {
      die('the receipt mock did not bind and sign the settled response')
    }
  } finally {
    await mint.close()
  }
}
console.log('ok   optional bound receipt commits before payment and signs only after settlement')

// A claimed extension must not ignore a disagreement between h and the
// mandatory comment. Accepting it leaves two different output commitments
// on one paid quote.
const lying = await grade({mintToHash: true, mintToHashIgnoresH: true})
if (!caughtBy(lying, MINT_TO_HASH_CHECK)) {
  die('a mint accepting mismatched h and comment PASSED - the grader is blind')
}
console.log('ok   a mint accepting mismatched h and comment caught')

// And the id a settled note occupies must not be sellable as a fresh
// quote: the payer would be buying a note somebody else can already spend.
const resold = await gradeBound({mintToHashAcceptsUsedH: true})
if (!caughtBy(resold, BOUND_CHECK)) {
  die('a mint selling a quote against a live note id PASSED - the grader is blind')
}
console.log('ok   a quote sold against a live note id caught')

// Not a grade, a description. Hex is case-insensitive, so the two
// spellings of one hash are one output: a WALLET MUST send lowercase, and
// a SERVICE SHOULD normalise before comparing rather than key the string
// it was handed, which would file the note where the wallet never looks.
// Nothing probes a live mint for this - a mint that refuses upper case
// outright is strict rather than wrong - but the mock is one of this
// repo's three descriptions of the feature and has to agree with the
// vector.
{
  const mint = await createMockMint({mintToHash: true, testHooks: true})
  try {
    const secret = bytesToHex(randomBytes(32))
    const h = bytesToHex(sha256(hexToBytes(secret)))
    const quote = await (
      await fetch(
        `${mint.url}/p/cb?amount=21000&comment=${h.toUpperCase()}&h=${h.toUpperCase()}`
      )
    ).json()
    if (quote.status === 'ERROR') die(`the mock refused an upper-case h: ${quote.reason}`)
    if (quote.mintToHash !== true) die('an upper-case h was taken without the quote saying it was bound')
    const paymentHash = quote.verify.split('/').pop()
    await fetch(`${mint.url}/_test/settle?payment_hash=${paymentHash}`)
    const note = await (await fetch(`${mint.url}/w?k1=${secret}`)).json()
    if (note.status === 'ERROR') {
      die(`an upper-case h filed the note somewhere the wallet cannot reach it: ${note.reason}`)
    }
    if (note.maxWithdrawable !== 21000) die(`the note is worth ${note.maxWithdrawable}`)
    // ...and the lowercase spelling is now the same taken id, not a free one
    const twin = await (
      await fetch(`${mint.url}/p/cb?amount=21000&comment=${h}&h=${h}`)
    ).json()
    if (twin.status !== 'ERROR') {
      die('the lowercase spelling of a bound hash was sold again - the two spellings are being read as two outputs')
    }
  } finally {
    await mint.close()
  }
}
console.log('ok   the two spellings of one output hash name one note')

// ---- Checking a note without exposing it ----
//
// LUD-25 lets a SERVICE answer the informational GET by `?h=sha256(k1)`, so
// a wallet can look a note up without putting the live secret in a query
// string every proxy between it and the mint will log. Optional, so a mint
// that does not offer it must not fail - but one that offers it wrongly
// must be caught, because a wallet asking by hash is trusting the answer.
const HASH_CHECK = 'answers a note lookup by hash without the secret (optional)'

const silentOnHash = await grade({})
if (statusOf(silentOnHash, HASH_CHECK) === 'fail') {
  die('a mint not offering the hash lookup FAILED - the check is not optional')
}

const byHash = await grade({hashLookup: true})
if (byHash.failed > 0) {
  for (const r of byHash.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  die('a mint answering by hash correctly FAILED grading')
}
if (statusOf(byHash, HASH_CHECK) !== 'pass') {
  die(`a compliant hash lookup was not graded as offered: ${statusOf(byHash, HASH_CHECK)}`)
}
// Both spellings of "did not fail" are a pass here, so the detail is what
// separates a mint that answers by hash from one that never offered it.
if (!detailOf(byHash, HASH_CHECK).includes('by hash')) {
  die(`a compliant hash lookup was graded but not named: ${detailOf(byHash, HASH_CHECK)}`)
}
if (!detailOf(silentOnHash, HASH_CHECK).includes('not offered')) {
  die(`a mint not offering the lookup was not reported as such: ${detailOf(silentOnHash, HASH_CHECK)}`)
}
console.log('ok   a mint answering a lookup by hash passes, and one not offering it is not graded down')

// The response carries no k1. A wallet querying by hash already holds the
// secret - the field buys nothing, and a mint that fills it in is putting
// the note back on the wire the lookup existed to keep off it.
const leaks = await grade({hashLookup: 'echoesK1'})
if (!caughtBy(leaks, HASH_CHECK)) {
  die('a mint echoing the secret back on a hash lookup PASSED - the grader is blind')
}
console.log('ok   a hash lookup that echoes the secret caught')

// An h it never registered must get the answer an unknown k1 gets. A mint
// answering anyway tells a wallet a note exists where none does.
const invents = await grade({hashLookup: 'answersUnknown'})
if (!caughtBy(invents, HASH_CHECK)) {
  die('a mint answering for a hash it never registered PASSED - the grader is blind')
}
console.log('ok   a hash lookup that answers for an unregistered hash caught')

const hidesSpent = await grade({hashLookup: 'hidesSpent'})
if (!caughtBy(hidesSpent, 'reports a spent hash distinguishably from an unknown hash')) {
  die('a hash lookup hiding a spent hash as unknown PASSED - the grader is blind')
}
console.log('ok   a hash lookup hiding a retained spent note caught')

// Keep the old fixture name accepted as a compatible alias, but stop
// describing the intended spent response as a privacy violation.
const revealsSpent = await grade({hashLookup: 'revealsSpent'})
if (revealsSpent.failed > 0) die('the legacy revealsSpent alias failed the revised contract')

const acceptsBoth = await grade({hashLookup: 'acceptsBoth'})
if (!caughtBy(acceptsBoth, HASH_CHECK)) {
  die('a hash lookup accepting k1 and h together PASSED - the grader is blind')
}
console.log('ok   a hash lookup accepting both k1 and h caught')

// ---- the merge cap ----
//
// LUD-25 bounds a merge by URL length, not by the protocol, and warns that
// past roughly 20-30 notes something upstream truncates the request -
// turning a large merge into a malformed one rather than a clean error. A
// SERVICE MAY refuse an oversized request outright with "too many k1". The
// grade is informational either way; what must never happen is an OK.
const CAP_CHECK = 'refuses an oversized merge cleanly (optional cap)'

const uncapped = await grade({})
if (statusOf(uncapped, CAP_CHECK) !== 'pass') {
  die(`a mint without an explicit cap was graded ${statusOf(uncapped, CAP_CHECK)} - the cap is a MAY`)
}
if (!detailOf(uncapped, CAP_CHECK).includes('no explicit cap')) {
  die(`an uncapped mint was not reported as such: ${detailOf(uncapped, CAP_CHECK)}`)
}

const capped = await grade({mergeCap: 20})
if (statusOf(capped, CAP_CHECK) !== 'pass') {
  die(`a mint capping its merges FAILED: ${detailOf(capped, CAP_CHECK)}`)
}
if (!detailOf(capped, CAP_CHECK).includes('too many k1')) {
  die(`a mint naming the draft's refusal was not credited: ${detailOf(capped, CAP_CHECK)}`)
}
console.log('ok   an explicit merge cap is named, and its absence is not graded down')

// The one outcome that is never acceptable. A truncated merge that still
// answers OK has minted an output against inputs it never saw.
const mints_from_nothing = await grade({acceptsOversizedMerge: true})
if (!caughtBy(mints_from_nothing, CAP_CHECK)) {
  die('a mint answering OK to an oversized merge of notes it never held PASSED - the grader is blind')
}
console.log('ok   an oversized merge answered OK caught')

// ---- a mint that is not at a Lightning Address ----
//
// The mint address document is probed by swapping /.well-known/lnurlp/ for
// /.well-known/lnurlw/ in the payRequest URL. On a mint served from a plain
// path - an LNbits extension, say - that swap changes nothing, so the probe
// re-fetches the payRequest, sees tag "payRequest", and failed the mint for
// an optional document it was never asked to publish. Caught against
// bitkarrot/lnurlmint, which is served at /lnurlmint/lnurlp/<id>.
const ADDRESS_CHECK = 'publishes a mint address (experimental, optional)'
const plainPath = await grade({}, {payPath: '/lnurlp/mint'})
if (statusOf(plainPath, ADDRESS_CHECK) === 'fail') {
  die(
    `a mint not served from a Lightning Address FAILED the mint-address check: ${detailOf(plainPath, ADDRESS_CHECK)}`
  )
}
if (plainPath.failed > 0) {
  for (const r of plainPath.results.filter(r => r.status === 'fail')) {
    console.error(`  FAIL ${r.name} - ${r.detail}`)
  }
  die('a mint served from a plain path failed grading')
}
console.log('ok   a mint not at a Lightning Address is not failed for having no mint address')

// The absent case, separately from the malformed one. A mint may refuse a
// comment it cannot parse and still quietly mint a preimage-keyed note when
// none was sent at all - which is the commonest way to arrive unnamed, since
// it is what every ordinary LUD-06 wallet sends.
const absentOnly = await grade({commentAllowed: 64, commentFallsBackWhenAbsent: true})
if (!caughtBy(absentOnly, MINT_TO_HASH_CHECK)) {
  die('a mint falling back only when no comment was sent PASSED - the grader is blind')
}
console.log('ok   a mint falling back when no comment was sent at all caught')
