// Checks the vectors against themselves.
//
// A vector file is only useful if it is right, and "right" here means
// internally consistent: every digest recomputes, every valid signature
// verifies, every fee expectation follows from the formula, every declared
// round trip round-trips. This catches a hand-edited expectation before an
// implementation inherits it as gospel.

import {readdirSync, readFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {bech32, bech32m, base64urlnopad} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {hmac} from '@noble/hashes/hmac.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {mnemonicToSeedSync, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors')
const load = name => JSON.parse(readFileSync(join(VECTORS, name), 'utf8'))

let failures = 0
const check = (name, fn) => {
  try {
    fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    failures++
    console.log(` FAIL  ${name}\n         ${err.message}`)
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg)
}

// ---- the manifest ----

const index = load('index.json')
check('every file in the manifest exists and parses', () => {
  for (const name of index.files) load(name)
})
check('every vector file is in the manifest', () => {
  const onDisk = readdirSync(VECTORS).filter(f => f.endsWith('.json') && f !== 'index.json')
  const missing = onDisk.filter(f => !index.files.includes(f))
  assert(missing.length === 0, `not listed in index.json: ${missing.join(', ')}`)
})
check('every vector file declares a version and a spec', () => {
  for (const name of index.files) {
    const v = load(name)
    assert(v.version === index.version, `${name}: version ${v.version}`)
    assert(typeof v.spec === 'string' && v.spec, `${name}: no spec`)
    assert(typeof v.description === 'string' && v.description, `${name}: no description`)
  }
})

// ---- signatures ----

const sig = load('signature.json')
const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))
const digestOf = (k1, amountMsat) =>
  sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes('Lightning Signed Message:'),
        ...utf8ToBytes(`LNURLcash:${amountMsat}:${noteId(k1)}`)
      ])
    )
  )

check('every signature case recomputes its own message and digest', () => {
  for (const c of sig.cases) {
    if (c.message === null) continue
    assert(
      c.message === `LNURLcash:${c.amountMsat}:${noteId(c.k1)}`,
      `${c.name}: message does not match`
    )
    assert(c.noteId === noteId(c.k1), `${c.name}: noteId does not match`)
    assert(
      c.digest === bytesToHex(digestOf(c.k1, c.amountMsat)),
      `${c.name}: digest does not match`
    )
  }
})

check('every signature case verifies exactly as declared', () => {
  const verify = (k1, amountMsat, sigHex, pubHex) => {
    let bytes
    try {
      bytes = hexToBytes(sigHex)
    } catch {
      return false
    }
    if (bytes.length !== 65) return false
    let digest
    try {
      digest = digestOf(k1, amountMsat)
    } catch {
      return false
    }
    const leading = new Uint8Array([bytes[64], ...bytes.subarray(0, 64)])
    for (const candidate of [leading, bytes]) {
      try {
        if (bytesToHex(secp256k1.recoverPublicKey(candidate, digest, {prehash: false})) === pubHex.toLowerCase()) {
          return true
        }
      } catch {
        // wrong ordering
      }
    }
    return false
  }
  for (const c of sig.cases) {
    assert(
      verify(c.k1, c.amountMsat, c.signature, c.mintPubkey) === c.valid,
      `${c.name}: expected valid=${c.valid}`
    )
  }
})

check('the signature set covers both recovery-id orderings and refusal cases', () => {
  assert(sig.cases.some(c => c.valid && /trailing/.test(c.name)), 'no trailing case')
  assert(sig.cases.some(c => c.valid && /leading/.test(c.name)), 'no leading case')
  assert(sig.cases.filter(c => !c.valid).length >= 6, 'too few refusal cases')
})

check('every rotation case verifies against exactly the keys it publishes', () => {
  const verify = (k1, amountMsat, sigHex, pubkeys) => {
    let bytes
    try {
      bytes = hexToBytes(sigHex)
    } catch {
      return false
    }
    if (bytes.length !== 65) return false
    const digest = digestOf(k1, amountMsat)
    const leading = new Uint8Array([bytes[64], ...bytes.subarray(0, 64)])
    for (const candidate of [leading, bytes]) {
      try {
        const recovered = bytesToHex(
          secp256k1.recoverPublicKey(candidate, digest, {prehash: false})
        )
        if (pubkeys.some(p => p.toLowerCase() === recovered)) return true
      } catch {
        // wrong ordering
      }
    }
    return false
  }
  const rotation = sig.rotation
  assert(rotation && Array.isArray(rotation.cases), 'no rotation block')
  for (const c of rotation.cases) {
    assert(Array.isArray(c.mintPubkeys) && c.mintPubkeys.length > 0, `${c.name}: no mintPubkeys`)
    assert(c.message === `LNURLcash:${c.amountMsat}:${noteId(c.k1)}`, `${c.name}: message does not match`)
    assert(c.noteId === noteId(c.k1), `${c.name}: noteId does not match`)
    assert(
      c.digest === bytesToHex(digestOf(c.k1, c.amountMsat)),
      `${c.name}: digest does not match`
    )
    assert(
      verify(c.k1, c.amountMsat, c.signature, c.mintPubkeys) === c.valid,
      `${c.name}: expected valid=${c.valid}`
    )
  }
})

check('the rotation pair turns on the published list and nothing else', () => {
  const cases = sig.rotation.cases
  const good = cases.find(c => c.valid && c.mintPubkeys.length > 1 && c.k1 === cases[0].k1)
  const bad = cases.find(c => !c.valid && c.signature === good.signature)
  assert(good && bad, 'no pair sharing a signature across two published lists')
  assert(
    bad.mintPubkeys.length < good.mintPubkeys.length,
    'the invalid case does not publish a shorter list'
  )
  assert(
    !bad.mintPubkeys.includes(sig.rotation.previousPubkey),
    'the invalid case still publishes the previous key'
  )
  assert(
    !sig.rotation.cases.some(c => c.mintPubkeys.includes(sig.rotation.currentPubkey) === false),
    'every rotation case must publish the current key'
  )
})

// ---- derivation ----

const derivation = load('derivation.json')

check('every derived secret recomputes from its own seed', () => {
  const root = seed => hmac(sha256, utf8ToBytes(derivation.scheme.rootKey), seed)
  for (const c of derivation.cases) {
    const k1 = bytesToHex(
      hmac(sha256, root(hexToBytes(c.seedHex)), utf8ToBytes(`${c.host}:${c.index}`))
    )
    assert(k1 === c.k1, `${c.name}: k1 does not recompute`)
    assert(c.noteId === noteId(c.k1), `${c.name}: noteId does not match k1`)
    assert(/^[0-9a-f]{64}$/.test(c.k1), `${c.name}: k1 is not 32 bytes of lowercase hex`)
  }
})

check('every derivation case states a real BIP39 mnemonic and its seed', () => {
  for (const c of derivation.cases) {
    assert(validateMnemonic(c.mnemonic, wordlist), `${c.name}: mnemonic fails BIP39 validation`)
    assert(
      bytesToHex(mnemonicToSeedSync(c.mnemonic)) === c.seedHex,
      `${c.name}: seedHex is not the passphrase-less BIP39 seed of the mnemonic`
    )
  }
})

check('derived secrets are distinct across index, host and seed', () => {
  const seen = new Map()
  for (const c of derivation.cases) {
    const prior = seen.get(c.k1)
    assert(!prior, `${c.name}: collides with ${prior}`)
    seen.set(c.k1, c.name)
  }
  const byHost = derivation.cases.filter(c => c.host === 'mint.example' && c.index === 0)
  assert(byHost.length >= 2, 'no two seeds derive at the same host and index')
  const ported = derivation.cases.find(c => /:\d+$/.test(c.host))
  assert(ported, 'no case exercises a host carrying a port')
  const indices = derivation.cases.map(c => c.index)
  assert(indices.includes(19) && indices.includes(20), 'the gap-limit boundary is not covered')
})

// ---- bech32 ----

const b32 = load('bech32.json')
check('every bech32 encoding round-trips', () => {
  for (const c of b32.encode) {
    const encoded = bech32
      .encode('lnurl', bech32.toWords(utf8ToBytes(c.url)), 2048)
      .toUpperCase()
    assert(encoded === c.lnurl, `${c.url}: encoding does not match`)
    const decoded = new TextDecoder().decode(
      bech32.fromWords(bech32.decode(c.lnurl.toLowerCase(), 2048).words)
    )
    assert(decoded === c.url, `${c.url}: decoding does not round-trip`)
  }
})

check('every invalid bech32 input really is invalid', () => {
  for (const c of b32.decodeInvalid) {
    let decoded = null
    try {
      const safe = c.input.trim().toUpperCase()
      if (safe.startsWith('LNURL1')) {
        decoded = new TextDecoder().decode(
          bech32.fromWords(bech32.decode(safe.toLowerCase(), 2048).words)
        )
      }
    } catch {
      decoded = null
    }
    assert(decoded === null, `${c.input}: decoded to ${decoded}`)
  }
})

// ---- the retried mutation ----

const retried = load('retried-mutation.json')

check('every retry case follows the declared identity', () => {
  // Reimplemented rather than shared with the generator: identity is the
  // whole content of this file, and a check that calls the function it is
  // checking proves only that the function is deterministic.
  const key = req =>
    JSON.stringify([
      [...req.k1].sort(),
      req.h ?? null,
      req.h2 ?? null,
      req.amount ?? null
    ])
  for (const c of retried.cases) {
    assert(
      Object.keys(retried.outcomes).includes(c.outcome),
      `${c.name}: unknown outcome ${c.outcome}`
    )
    for (const side of [c.recorded, c.retry]) {
      assert(Array.isArray(side.k1) && side.k1.length > 0, `${c.name}: a side names no inputs`)
      assert(/^[0-9a-f]{64}$/.test(side.h), `${c.name}: h is not a 32-byte hex id`)
      if (side.h2 !== undefined) {
        assert(/^[0-9a-f]{64}$/.test(side.h2), `${c.name}: h2 is not a 32-byte hex id`)
      }
    }
    const expected = key(c.recorded) === key(c.retry) ? 'replay' : 'double-spend'
    assert(expected === c.outcome, `${c.name}: identity gives ${expected}, not ${c.outcome}`)
  }
})

check('the retry set pins every way a request can differ', () => {
  const replays = retried.cases.filter(c => c.outcome === 'replay')
  const refusals = retried.cases.filter(c => c.outcome === 'double-spend')
  assert(replays.length >= 3, 'too few replay cases')
  assert(refusals.length >= 5, 'too few double-spend cases')
  assert(
    replays.some(c => c.recorded.k1.length > 1 && c.recorded.k1.join() !== c.retry.k1.join()),
    'nothing states that the inputs are a set rather than a sequence'
  )
  assert(
    replays.some(c => c.recorded.h2 !== undefined) &&
      replays.some(c => c.recorded.h2 === undefined),
    'the replay cases do not cover both a split and a rotate'
  )
  for (const [what, differs] of [
    ['h', c => c.recorded.h !== c.retry.h],
    ['h2', c => (c.recorded.h2 ?? null) !== (c.retry.h2 ?? null)],
    ['amount', c => (c.recorded.amount ?? null) !== (c.retry.amount ?? null)],
    ['the input set', c => [...c.recorded.k1].sort().join() !== [...c.retry.k1].sort().join()]
  ]) {
    assert(
      refusals.some(differs),
      `no double-spend case turns on ${what} alone being different`
    )
  }
  assert(
    refusals.some(c => c.recorded.h2 !== undefined && c.retry.h2 === undefined),
    'nothing states that an absent h2 is not the same as a present one'
  )
})

// ---- naming the note you are buying ----
//
// Reimplemented rather than shared with the generator, for the same reason
// the retry rules are: a self-check that calls the function it is checking
// proves only that the function is deterministic.

const mintToHash = load('mint-to-hash.json')

check('every mint-to-hash case follows the declared rule', () => {
  const inUse = Object.entries(mintToHash.idsAlreadyInUse)
    .filter(([key]) => key !== 'why')
    .map(([, id]) => id)
  for (const c of mintToHash.cases) {
    assert(
      Object.keys(mintToHash.outcomes).includes(c.outcome),
      `${c.name}: unknown outcome ${c.outcome}`
    )
    // hex is case-insensitive, so well-formedness is judged on the bytes
    // and the SERVICE compares the lowercase form
    const wellFormed = c.h !== null && /^[0-9a-f]{64}$/i.test(c.h)
    const compared = wellFormed ? c.h.toLowerCase() : null
    assert(
      c.comparedAs === compared,
      `${c.name}: comparedAs is ${JSON.stringify(c.comparedAs)}, not ${JSON.stringify(compared)}`
    )
    const expected =
      c.h === null
        ? 'comment-only'
        : !wellFormed
          ? 'malformed-h'
          : inUse.includes(compared)
            ? 'collision'
            : 'extension-bound'
    assert(expected === c.outcome, `${c.name}: the rule gives ${expected}, not ${c.outcome}`)
    const refused = c.outcome === 'malformed-h' || c.outcome === 'collision'
    assert(c.invoiced === !refused, `${c.name}: invoiced does not follow the outcome`)
    // the pay callback's own response says whether THIS quote was bound,
    // so it is true exactly when the note will land at h
    assert(c.echo === (c.outcome === 'extension-bound'), `${c.name}: the quote echo does not follow the outcome`)
    if (refused) {
      assert(c.noteId === null, `${c.name}: a refusal names a note id`)
      const reason =
        c.outcome === 'malformed-h' ? mintToHash.reasons.malformed : mintToHash.reasons.collision
      assert(c.reason === reason, `${c.name}: reason was ${JSON.stringify(c.reason)}`)
    } else {
      assert(c.reason === null, `${c.name}: an issued quote carries a refusal reason`)
      const landsAt = c.outcome === 'extension-bound' ? compared : mintToHash.settlement.comment
      assert(c.noteId === landsAt, `${c.name}: the note lands at ${c.noteId}`)
      assert(/^[0-9a-f]{64}$/.test(c.comment), `${c.name}: mandatory comment is not 64 lowercase hex`)
      if (c.outcome === 'extension-bound') {
        assert(c.comment === compared, `${c.name}: h and comment name different outputs`)
      }
    }
  }
})

check('the mint-to-hash refusals are the two the wire fixes, and no more', () => {
  const reasons = Object.values(mintToHash.reasons)
  assert(reasons.length === 2, `${reasons.length} refusal reasons`)
  assert(
    mintToHash.reasons.collision === 'Invalid or already spent k1.',
    'the collision reason is not the one the withdraw callback already uses, so a probe could tell the two apart'
  )
  const seen = new Set(mintToHash.cases.map(c => c.outcome))
  for (const outcome of Object.keys(mintToHash.outcomes)) {
    assert(seen.has(outcome), `no case covers the ${outcome} outcome`)
  }
  for (const [what, id] of Object.entries(mintToHash.idsAlreadyInUse)) {
    if (what === 'why') continue
    assert(
      mintToHash.cases.some(c => c.h === id && c.outcome === 'collision'),
      `no collision case for an id already in use as a ${what}`
    )
  }
  assert(
    mintToHash.cases.some(c => c.h === ''),
    'nothing states what an empty h means, so a SERVICE is free to read it as absent'
  )
  // Upper case is a spelling, not a defect. Labelling it malformed would
  // put this file at odds with a reference mint that normalises, which is
  // exactly the quiet divergence a vector exists to prevent.
  assert(
    !mintToHash.cases.some(c => c.outcome === 'malformed-h' && /^[0-9a-fA-F]{64}$/.test(c.h ?? '')),
    'a case calls 32 bytes of hex malformed on its casing alone'
  )
})

check('the two spellings of one hash name one output', () => {
  const rule = mintToHash.caseRule
  assert(/MUST send/.test(rule.wallet), 'the wallet rule is not a MUST')
  assert(/lowercase/.test(rule.wallet), 'the wallet rule does not say lowercase')
  assert(/SHOULD normalise/.test(rule.service), 'the service rule does not say SHOULD normalise')
  assert(/MUST NOT/.test(rule.service), 'the service rule does not forbid two outputs for one hash')

  const n = mintToHash.normalisation
  assert(n.sent !== n.comparedAs, 'the worked pair sends what it compares, so it shows nothing')
  assert(n.comparedAs === n.sent.toLowerCase(), 'comparedAs is not the sent value lowercased')
  assert(n.outputId === n.comparedAs, 'the output does not land at the compared id')
  assert(n.sameOutputAs === n.comparedAs, 'the pair does not name the lowercase output it matches')
  assert(n.comparedAs === noteId(n.walletSecret), 'the compared id is not the hash of the wallet secret')

  // and the cases say it too: one upper-case spelling that binds where its
  // lowercase twin binds, and one that collides where its twin collides
  const upper = mintToHash.cases.filter(c => typeof c.h === 'string' && /[A-F]/.test(c.h))
  assert(upper.length >= 2, 'fewer than two upper-case cases')
  for (const c of upper) {
    const twin = mintToHash.cases.find(
      t => t !== c && t.comparedAs === c.comparedAs && !/[A-F]/.test(t.h ?? '')
    )
    assert(twin, `${c.name}: no lowercase twin to compare against`)
    assert(
      twin.outcome === c.outcome && twin.noteId === c.noteId,
      `${c.name}: answered differently from its lowercase twin (${twin.outcome} vs ${c.outcome})`
    )
  }
  assert(
    upper.some(c => c.outcome === 'extension-bound'),
    'no upper-case case binds, so nothing states that the spellings are one output'
  )
  assert(
    upper.some(c => c.outcome === 'collision'),
    'no upper-case case collides, so nothing states that case is normalised before the collision check'
  )
})

check('the worked settlement recomputes from its own secrets', () => {
  const s = mintToHash.settlement
  assert(s.h === noteId(s.walletSecret), 'h is not the sha256 of the wallet secret')
  assert(s.comment === s.h, 'the extension h differs from the mandatory comment')
  assert(s.paymentHash === noteId(s.preimage), 'paymentHash is not the sha256 of the preimage')
  assert(s.walletSecret !== s.preimage, 'the two secrets are the same value')
  assert(s.extensionBound.noteId === s.h, 'an extension-bound note does not land at h')
  assert(s.extensionBound.k1 === s.walletSecret, 'an extension-bound note is not opened by the wallet secret')
  assert(s.extensionBound.preimageIsAValidK1 === false, 'the preimage still opens an extension-bound note')
  assert(s.commentOnly.noteId === s.comment, 'a comment-only note does not land at the commitment')
  assert(s.commentOnly.k1 === s.walletSecret, 'a comment-only note is not opened by the wallet secret')
  assert(s.commentOnly.preimageIsAValidK1 === false, 'the preimage opens a comment-only note')
})

check('the optional bound receipt is tied to the quote and authenticates the note', () => {
  const {receipt, settlement} = mintToHash
  const quote = receipt.quote
  const pending = receipt.unsettled
  const settled = receipt.settled
  assert(receipt.optional === true, 'the additive receipt is not marked optional')
  assert(receipt.keyEstablishment.payRequest.mintPubkey === sig.mintPubkey, 'the receipt key is unavailable before payment')
  assert(quote.mintToHash === true, 'the receipt quote is not explicitly bound')
  assert(quote.mint.h === settlement.h, 'the quote commits a different h')
  assert(Number.isSafeInteger(quote.mint.amount) && quote.mint.amount > 0, 'the quote amount is not positive integer msat')
  assert(quote.mint.sig === undefined, 'the quote is already signed before settlement')
  assert(pending.settled === false && pending.mint.sig === undefined, 'an unsettled response carries a signature')
  assert(settled.settled === true, 'the settled fixture is not settled')
  assert(settled.pr === quote.pr, 'verify names a different invoice')
  assert(settled.mint.h === quote.mint.h, 'verify changes h')
  assert(settled.mint.amount === quote.mint.amount, 'verify changes the net amount')

  const bytes = hexToBytes(settled.mint.sig)
  assert(bytes.length === 65, 'the receipt signature is not recoverable')
  const digest = digestOf(settlement.walletSecret, settled.mint.amount)
  const leading = new Uint8Array([bytes[64], ...bytes.subarray(0, 64)])
  let recovered = null
  for (const candidate of [leading, bytes]) {
    try {
      recovered = bytesToHex(secp256k1.recoverPublicKey(candidate, digest, {prehash: false}))
      if (recovered === sig.mintPubkey) break
    } catch {
      // try the other recoverable-signature ordering
    }
  }
  assert(recovered === sig.mintPubkey, 'the receipt signature does not authenticate the bound note')

  const invalid = new Map(receipt.invalid.map(c => [c.name, c]))
  assert(invalid.get('quote commits a different h').quote.mint.h !== quote.mint.h, 'no wrong-h case')
  assert(invalid.get('verify changes the net amount').verify.mint.amount !== quote.mint.amount, 'no wrong-amount case')
  assert(invalid.get('signature appears before settlement').verify.mint.sig, 'no premature-signature case')
  assert(invalid.get('settled response has the wrong signature').verify.mint.sig !== settled.mint.sig, 'no bad-signature case')
})

check('the capability is fixed in all three places, and only the boolean true means yes', () => {
  const field = mintToHash.advertisement.field
  const places = mintToHash.advertisement.places.map(p => p.where)
  assert(
    JSON.stringify(places) === JSON.stringify(['payRequest', 'mintAddress', 'quoteResponse']),
    `the advertisement places are ${places.join(', ')}`
  )
  for (const p of mintToHash.advertisement.places) {
    assert(typeof p.read === 'string' && p.read, `${p.where}: does not say where it is read from`)
    assert(typeof p.means === 'string' && p.means, `${p.where}: does not say what it means`)
    assert(
      mintToHash.advertisements.some(c => c.where === p.where && c.offered),
      `${p.where}: no case advertises the capability there`
    )
    assert(
      mintToHash.advertisements.some(
        c => c.where === p.where && c.body[field] === undefined && !c.offered
      ),
      `${p.where}: nothing states that an absent field means no`
    )
    assert(
      mintToHash.advertisements.some(
        c => c.where === p.where && typeof c.body[field] === 'string' && !c.offered
      ),
      `${p.where}: nothing states that a truthy non-boolean is not the capability`
    )
  }
  for (const c of mintToHash.advertisements) {
    assert(places.includes(c.where), `${c.name}: unknown place ${c.where}`)
    assert(
      c.offered === (c.body[field] === true),
      `${c.where}/${c.name}: offered does not follow the field`
    )
  }
  // the payRequest is the one every mint publishes, so it is the one a
  // wallet decides from
  const payRequest = mintToHash.advertisement.places.find(p => p.where === 'payRequest')
  assert(/decide/.test(payRequest.why), 'the payRequest is not named as the one to decide from')
  assert(
    mintToHash.walletRules.some(r => /payRequest/.test(r)),
    'no wallet rule sends a wallet to the payRequest'
  )
})

check('every contradiction between the three carries a verdict', () => {
  const verdicts = mintToHash.contradictions.map(c => c.verdict)
  for (const c of mintToHash.contradictions) {
    assert(typeof c.what === 'string' && c.what, `${c.name}: does not say what it is`)
    assert(typeof c.why === 'string' && c.why.length > 40, `${c.name}: does not say why it matters`)
  }
  assert(verdicts.includes('broken'), 'nothing says that claiming it and not binding is broken')
  assert(
    verdicts.includes('not implemented'),
    'nothing says that saying nothing anywhere is simply not implemented'
  )
})

// ---- payment requests ----
//
// The rules are reimplemented here rather than shared with the generator:
// a self-check that calls the same function it is checking proves only
// that the function is deterministic.

const paymentRequest = load('payment-request.json')

const canonical = value => {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value !== null && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .filter(key => value[key] !== undefined)
        .sort()
        .map(key => JSON.stringify(key) + ':' + canonical(value[key]))
        .join(',') +
      '}'
    )
  }
  return JSON.stringify(value)
}

const looksLikeNpub = value => {
  if (typeof value !== 'string' || !value.startsWith('npub1')) return false
  try {
    const {prefix, words} = bech32.decode(value, 200)
    return prefix === 'npub' && bech32.fromWords(words).length === 32
  } catch {
    return false
  }
}

const readRequest = (input, now) => {
  const prefix = paymentRequest.prefix
  if (typeof input !== 'string' || !input.startsWith(prefix)) return {reason: 'wrong-prefix'}
  let bytes
  try {
    bytes = base64urlnopad.decode(input.slice(prefix.length))
  } catch {
    return {reason: 'not-base64url'}
  }
  let request
  try {
    request = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return {reason: 'not-json'}
  }
  if (request === null || typeof request !== 'object' || Array.isArray(request)) {
    return {reason: 'not-json'}
  }
  if (request.v !== 1) return {reason: 'unknown-version'}
  if (typeof request.id !== 'string' || !/^[0-9a-f]{16}$/.test(request.id)) {
    return {reason: 'bad-id'}
  }
  if (typeof request.amount !== 'string' || !/^[1-9][0-9]*$/.test(request.amount)) {
    return {reason: 'amount-not-an-integer'}
  }
  if (request.currency !== 'sat') return {reason: 'wrong-currency'}
  const mints = request.methodDetails?.mints
  if (!Array.isArray(mints) || mints.length === 0) return {reason: 'no-mints'}
  if (
    request.to !== undefined &&
    !looksLikeNpub(request.to) &&
    !(typeof request.to === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(request.to))
  ) {
    return {reason: 'unroutable-to'}
  }
  if (request.expires !== undefined && now >= request.expires) return {reason: 'expired'}
  return {request}
}

check('every payment request encodes to the string it declares', () => {
  for (const c of paymentRequest.encode) {
    assert(canonical(c.request) === c.canonical, `${c.name}: canonical form does not match`)
    const encoded =
      paymentRequest.prefix +
      base64urlnopad.encode(utf8ToBytes(canonical(c.request)))
    assert(encoded === c.encoded, `${c.name}: encoding does not match`)
  }
})

check('canonicalisation makes key order irrelevant', () => {
  const same = paymentRequest.encode.filter(c => c.encoded === paymentRequest.encode[0].encoded)
  assert(same.length >= 2, 'no two differently-ordered requests encode identically')
  const orders = same.map(c => Object.keys(c.request).join(','))
  assert(new Set(orders).size > 1, 'the identical encodings came from identically-ordered objects')
})

check('every payment request decodes exactly as declared', () => {
  for (const c of paymentRequest.decode) {
    const result = readRequest(c.input, paymentRequest.evaluatedAt)
    assert(
      (result.reason === undefined) === c.valid,
      `${c.name}: expected valid=${c.valid}, got ${result.reason ?? 'valid'}`
    )
    if (c.valid) {
      assert(c.request !== undefined, `${c.name}: a valid case states no request`)
      assert(
        canonical(result.request) === canonical(c.request),
        `${c.name}: decoded to something other than the stated request`
      )
    } else {
      assert(result.reason === c.reason, `${c.name}: refused as ${result.reason}, not ${c.reason}`)
    }
  }
})

check('every declared refusal reason is exercised, and no other is used', () => {
  const declared = Object.keys(paymentRequest.reasons)
  const used = new Set(paymentRequest.decode.filter(c => !c.valid).map(c => c.reason))
  for (const reason of used) assert(declared.includes(reason), `undeclared reason ${reason}`)
  for (const reason of declared) assert(used.has(reason), `no case refuses with ${reason}`)
})

check('the payment request set covers what the brief asks of it', () => {
  const valid = paymentRequest.decode.filter(c => c.valid)
  assert(valid.length >= 2, 'too few decodable cases')
  assert(
    valid.some(c => c.request.memo && c.request.expires),
    'no case carries both a memo and an expiry'
  )
  assert(
    paymentRequest.encode.some(c => /[^\x00-\x7f]/.test(c.canonical)),
    'no case carries a non-ASCII character, so nothing pins the escaping'
  )
  assert(Number.isInteger(paymentRequest.evaluatedAt), 'no fixed clock for the expiry cases')
})

// ---- settling a note for value ----

const settle = load('settle-for-value.json')

check('every settlement case follows the declared order', () => {
  const decide = c => {
    const accepted = c.acceptedMints.map(h => h.toLowerCase())
    if (!accepted.includes(c.noteHost.toLowerCase())) return 'wrong-host'
    if (c.noteState === 'spent') return 'spent'
    if (c.noteState === 'pending') return 'pending'
    if (c.requireSignature && !c.hasSig) return 'missing-signature'
    if (c.requireSignature && !c.sigValid) return 'bad-signature'
    if (c.maxWithdrawableMsat < c.minMsat) return 'insufficient'
    return 'accept'
  }
  for (const c of settle.cases) {
    assert(
      Object.keys(settle.outcomes).includes(c.outcome),
      `${c.name}: unknown outcome ${c.outcome}`
    )
    assert(decide(c) === c.outcome, `${c.name}: the order gives ${decide(c)}, not ${c.outcome}`)
    for (const key of [
      'noteHost',
      'acceptedMints',
      'maxWithdrawableMsat',
      'minMsat',
      'hasSig',
      'sigValid',
      'requireSignature',
      'noteState'
    ]) {
      assert(c[key] !== undefined, `${c.name}: no ${key}`)
    }
  }
})

check('every settlement outcome is reachable', () => {
  for (const outcome of Object.keys(settle.outcomes)) {
    assert(
      settle.cases.some(c => c.outcome === outcome),
      `no case reaches the ${outcome} outcome`
    )
  }
})

check('the settlement table pins its own precedence', () => {
  const both = settle.cases.filter(
    c => c.noteState !== 'live' && !c.acceptedMints.includes(c.noteHost)
  )
  assert(
    both.some(c => c.outcome === 'wrong-host'),
    'nothing pins the host check as coming before the mint is asked'
  )
  assert(
    settle.cases.some(
      c => c.noteState === 'spent' && c.maxWithdrawableMsat < c.minMsat && c.outcome === 'spent'
    ),
    'nothing pins the mint answer as coming before the amount comparison'
  )
  assert(
    settle.cases.some(
      c =>
        c.requireSignature &&
        !c.hasSig &&
        c.maxWithdrawableMsat < c.minMsat &&
        c.outcome === 'missing-signature'
    ),
    'nothing pins the signature check as coming before the amount comparison'
  )
  assert(
    settle.cases.some(
      c => !c.requireSignature && c.hasSig && !c.sigValid && c.outcome === 'accept'
    ),
    'nothing states what an unrequired signature that does not verify does'
  )
  assert(
    settle.cases.some(c => c.acceptedMints.length === 0 && c.outcome === 'wrong-host'),
    'nothing states that an empty mint list accepts nothing'
  )
  assert(
    settle.cases.some(c => c.maxWithdrawableMsat === c.minMsat && c.outcome === 'accept'),
    'nothing pins the boundary where the note is worth exactly the price'
  )
})

// ---- fees ----

const fees = load('fees.json')
const proportional = (g, ppm) =>
  Math.floor(g / 1e6) * ppm + Math.floor(((g % 1e6) * ppm) / 1e6)
const applyFee = (g, f) => Math.max(0, g - f.baseFeeMsat - proportional(g, f.feePpm))
const grossUp = (net, f) => {
  if (net <= 0) return 0
  let hi = net + f.baseFeeMsat
  while (applyFee(hi, f) < net) hi *= 2
  let lo = 0
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2)
    if (applyFee(mid, f) >= net) hi = mid
    else lo = mid + 1
  }
  return lo
}

check('every apply expectation follows from the formula', () => {
  for (const c of fees.apply) {
    assert(
      applyFee(c.grossMsat, c.fee) === c.expect,
      `${c.grossMsat} with ${JSON.stringify(c.fee)}: expected ${c.expect}, formula gives ${applyFee(c.grossMsat, c.fee)}`
    )
  }
})

check('every gross-up expectation is the true minimum', () => {
  for (const c of fees.grossUp) {
    assert(grossUp(c.netMsat, c.fee) === c.expect, `${c.netMsat}: expected ${c.expect}`)
    if (c.netMsat > 0) {
      assert(applyFee(c.expect, c.fee) === c.netMsat, `${c.netMsat}: does not net back`)
      assert(applyFee(c.expect - 1, c.fee) < c.netMsat, `${c.netMsat}: not minimal`)
    }
  }
})

check('the gross-up round trip holds for every listed fee and amount', () => {
  for (const fee of fees.grossUpRoundTrip.fees) {
    for (const net of fees.grossUpRoundTrip.netAmountsMsat) {
      const gross = grossUp(net, fee)
      assert(applyFee(gross, fee) === net, `${net} with ${JSON.stringify(fee)}: nets ${applyFee(gross, fee)}`)
      assert(applyFee(gross - 1, fee) < net, `${net} with ${JSON.stringify(fee)}: not minimal`)
    }
  }
})

check('the overflow case really does exceed a naive 64-bit multiply', () => {
  const big = fees.apply.find(c => c.grossMsat >= 1e15)
  assert(big, 'no large-amount case present')
  assert(
    big.grossMsat * big.fee.feePpm > Number.MAX_SAFE_INTEGER,
    'the large case does not actually stress the multiply'
  )
})

// ---- callbacks ----

const callbacks = load('callbacks.json')
check('every callback case is consistent with its declared parameters', () => {
  for (const c of callbacks.cases) {
    const query = c.expectQuery
    const k1s = query.filter(([k]) => k === 'k1').map(([, v]) => v)
    assert(
      JSON.stringify(k1s) === JSON.stringify(c.params.k1),
      `${c.name}: k1 list does not match`
    )
    if (c.params.h) {
      assert(query.some(([k, v]) => k === 'h' && v === c.params.h), `${c.name}: h missing`)
    }
    if (c.params.h2) {
      assert(query.some(([k, v]) => k === 'h2' && v === c.params.h2), `${c.name}: h2 missing`)
    }
    if (c.params.amountMsat !== undefined) {
      assert(
        query.some(([k, v]) => k === 'amount' && v === String(c.params.amountMsat)),
        `${c.name}: amount missing`
      )
    }
    if (c.params.pr) {
      assert(query.some(([k, v]) => k === 'pr' && v === c.params.pr), `${c.name}: pr missing`)
      assert(k1s.length === 1, `${c.name}: a melt names more than one k1`)
      assert(
        !query.some(([k]) => k === 'amount'),
        `${c.name}: a melt carries an amount`
      )
    }
  }
})

check('every rejected callback case states why', () => {
  for (const c of callbacks.rejected) {
    assert(typeof c.why === 'string' && c.why.length > 10, `${c.name}: no reason given`)
  }
})

// ---- responses ----

const responses = load('responses.json')
check('every response case declares a known outcome', () => {
  const known = Object.keys(responses.outcomes)
  for (const c of responses.cases) {
    assert(known.includes(c.expect), `${c.name}: unknown outcome ${c.expect}`)
  }
  for (const outcome of known) {
    assert(
      responses.cases.some(c => c.expect === outcome),
      `no case covers the ${outcome} outcome`
    )
  }
})

// A consumer drives these cases through a real call, and which call it is
// changes the answer: a melt mints nothing and so returns no signature,
// while a rotate that returns none is the unverifiable outcome. An untagged
// case would be driven through whatever the consumer happened to pick.
check('every response case names the call it is driven through', () => {
  const ops = ['mutation', 'split', 'melt']
  for (const c of responses.cases) {
    assert(ops.includes(c.op), `${c.name}: op must be one of ${ops.join(', ')}`)
  }
  assert(
    responses.cases.some(c => c.op === 'melt'),
    'no case is driven through a melt, so nothing proves a melt needs no signature'
  )
})

// The signature is what makes a note checkable by whoever receives it, so
// the vectors have to state it as a requirement rather than leave it as one
// accepted shape among several.
check('every accepted withdrawRequest publishes a mintPubkey', () => {
  const withdrawInfo = load('withdraw-info.json')
  for (const c of withdrawInfo.accepted) {
    assert(
      typeof c.body.mintPubkey === 'string',
      `${c.name}: an accepted withdrawRequest must carry mintPubkey`
    )
  }
  for (const name of ['no mintPubkey', 'mintPubkey that is not a compressed secp256k1 key']) {
    assert(
      withdrawInfo.rejected.some(c => c.name === name),
      `no rejected case covers "${name}"`
    )
  }
})

check('the pending case uses the exact reason string the spec names', () => {
  const pending = responses.cases.find(c => c.expect === 'pending')
  assert(pending.body.reason === 'pending', `reason was ${JSON.stringify(pending.body.reason)}`)
})

// ---- withdraw info and pay request ----

for (const name of ['withdraw-info.json', 'pay-request.json']) {
  const v = load(name)
  check(`${name} has both accepted and rejected cases`, () => {
    const groups = [
      [v.accepted, v.rejected],
      [v.invoice?.accepted, v.invoice?.rejected],
      [v.mintCallback?.accepted, v.mintCallback?.rejected],
      [v.verify?.accepted, v.verify?.rejected]
    ].filter(([a]) => a)
    for (const [accepted, rejected] of groups) {
      assert(accepted.length > 0, 'no accepted cases')
      assert(rejected.length > 0, 'no rejected cases')
      for (const c of [...accepted, ...rejected]) {
        assert(typeof c.name === 'string' && c.name, 'a case has no name')
      }
    }
  })
}

check('pay-request.json covers both legal withdrawLink spellings', () => {
  const pay = load('pay-request.json')
  const links = pay.accepted.map(c => c.withdrawLink).filter(Boolean)
  assert(links.some(l => /^lnurlw:\/\//.test(l)), 'no lnurlw:// withdrawLink case')
  assert(links.some(l => /^https:\/\//.test(l)), 'no plain https:// withdrawLink case')
})

check('every minting payRequest requires a 64-character hash comment', () => {
  const pay = load('pay-request.json')
  const minting = pay.accepted.filter(c => c.withdrawLink)
  assert(minting.length > 0, 'no accepted minting payRequest')
  for (const c of minting) {
    assert(c.body.commentAllowed === 64, `${c.name}: body does not advertise commentAllowed 64`)
    assert(c.commentAllowed === 64, `${c.name}: parsed expectation is not commentAllowed 64`)
  }
  assert(
    pay.rejected.some(c => c.body.withdrawLink && c.body.commentAllowed === undefined),
    'no rejected minting payRequest omits commentAllowed'
  )
  const accepted = pay.mintCallback.accepted.find(c => c.result === 'invoice')
  assert(/^[0-9a-f]{64}$/.test(accepted.comment), 'accepted mint comment is not 64 lowercase hex')
  assert(accepted.noteId === accepted.comment, 'accepted mint does not land at the committed hash')
  assert(accepted.paymentPreimageIsBearerK1 === false, 'payment preimage still opens the minted note')
  for (const c of pay.mintCallback.rejected) {
    assert(c.result === 'error-before-invoice', `${c.name}: rejection happens after invoicing`)
  }
})

// ---- lifecycle ----

const lifecycle = load('lifecycle.json')
check('every lifecycle scenario states a requirement', () => {
  for (const s of lifecycle.scenarios) {
    assert(Array.isArray(s.steps) && s.steps.length > 0, `${s.name}: no steps`)
    assert(
      typeof s.requirement === 'string' && s.requirement.length > 40,
      `${s.name}: no requirement`
    )
  }
})

// ---- threat suite ----

const threatSuite = load('threat-suite.json')
const THREAT_KINDS = ['attack', 'control', 'property', 'gap']
const THREAT_STATUSES = [
  'pins-current',
  'inverts-when-option-B',
  'inverts-when-option-D',
  'spec-gap',
  'arithmetic',
  'privacy-axis'
]

check('the threat suite covers T1 through T11 in order', () => {
  assert(
    threatSuite.scenarios.map(s => s.id).join(',') === 'T1,T2,T3,T4,T5,T6,T7,T8,T9,T10,T11',
    'scenario ids are not T1..T11 in order'
  )
})

check('every threat-suite scenario is well formed', () => {
  const letters = Object.keys(threatSuite.options)
  for (const s of threatSuite.scenarios) {
    assert(THREAT_KINDS.includes(s.kind), `${s.id}: unknown kind ${s.kind}`)
    assert(THREAT_STATUSES.includes(s.status), `${s.id}: unknown status ${s.status}`)
    assert(typeof s.name === 'string' && s.name, `${s.id}: no name`)
    assert(typeof s.adversary === 'string' && s.adversary, `${s.id}: no adversary`)
    assert(Array.isArray(s.steps) && s.steps.length > 0, `${s.id}: no steps`)
    assert(
      typeof s.currentBehavior === 'string' && s.currentBehavior.length > 10,
      `${s.id}: no current behavior`
    )
    assert(typeof s.notes === 'string' && s.notes, `${s.id}: no notes`)
    for (const key of ['closedBy', 'notClosedBy', 'preservedBy', 'brokenBy', 'holdsUnder']) {
      for (const letter of s.options[key] || []) {
        assert(letters.includes(letter), `${s.id}: ${key} names unknown option ${letter}`)
      }
    }
  }
})

check('threat-suite options beyond the status quo are marked as proposals', () => {
  assert(threatSuite.options.A.status === 'current-draft', 'option A must be the current draft')
  for (const [letter, option] of Object.entries(threatSuite.options)) {
    if (letter === 'A') continue
    assert(option.status === 'proposal', `option ${letter} is not marked as a proposal`)
  }
})

check('every inverting scenario names the option its status names', () => {
  for (const s of threatSuite.scenarios) {
    const m = /^inverts-when-option-([A-Z])$/.exec(s.status)
    if (m) {
      assert(
        (s.options.closedBy || []).includes(m[1]),
        `${s.id}: status names option ${m[1]} but closedBy does not`
      )
    }
  }
})

check('the merge URL budget arithmetic recomputes', () => {
  const a = threatSuite.scenarios.find(s => s.id === 'T10').arithmetic
  const url = (param, chars, n) =>
    a.exampleCallback +
    '?' +
    Array.from({length: n}, () => `${param}=` + 'a'.repeat(chars)).join('&') +
    '&h=' +
    'a'.repeat(64)
  const cap = (param, chars) => {
    let n = 0
    while (url(param, chars, n + 1).length <= a.budgetChars) n++
    return n
  }
  assert(
    4 * Math.ceil(a.encryptedK1.bytes / 3) === a.encryptedK1.base64Chars,
    'encrypted k1 base64 length does not follow from its byte count'
  )
  assert(
    url('k1', a.plaintextK1Chars, 25).length === a.mergeOf25.plaintextChars,
    'plaintext merge length does not recompute'
  )
  assert(
    url('p', a.encryptedK1.base64Chars, 25).length === a.mergeOf25.encryptedChars,
    'encrypted merge length does not recompute'
  )
  assert(
    a.mergeOf25.plaintextFits && a.mergeOf25.plaintextChars <= a.budgetChars,
    'a plaintext merge of 25 must fit the budget'
  )
  assert(
    !a.mergeOf25.encryptedFits && a.mergeOf25.encryptedChars > a.budgetChars,
    'an encrypted merge of 25 must exceed the budget'
  )
  assert(
    cap('k1', a.plaintextK1Chars) === a.mergeCapacity.plaintext,
    'plaintext merge capacity does not recompute'
  )
  assert(
    cap('p', a.encryptedK1.base64Chars) === a.mergeCapacity.encrypted,
    'encrypted merge capacity does not recompute'
  )
  assert(
    a.mergeCapacity.plaintext < a.mergeCapacity.advertisedMaxK1s,
    'the scenario requires advertised max_k1s to exceed the plaintext capacity'
  )
})

check('the threat suite cross-references its executable companion', () => {
  assert(
    threatSuite.policy.redGreen.includes('test_bearer_threat_suite_poc.py'),
    'policy.redGreen does not name the lnurl-mint companion file'
  )
})

// ---- Part 2 ----

const part2 = load('part2.json')
const N2 = secp256k1.Point.Fn.ORDER
const toNum = bytes => BigInt(`0x${bytesToHex(bytes)}`)
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
// Strict, as BIP-350 and the reference mint read them: bech32m only, one
// case, the right prefix, the right length, zero padding.
const decode2 = (hrp, value, length) => {
  try {
    const d = bech32m.decode(value, false)
    if (d.prefix.toLowerCase() !== hrp) return null
    const bytes = bech32m.fromWords(d.words)
    return bytes.length === length ? bytes : null
  } catch {
    return null
  }
}
const LENGTHS = {cp1: ['cp', 32], ck1: ['ck', 65], cs1: ['cs', 65], cx1: ['cx', 64]}
const lsmDigest = message =>
  sha256(sha256(cat(utf8ToBytes('Lightning Signed Message:'), utf8ToBytes(message))))
const recoverX = (signature, digest) => {
  const recIdFirst = cat(signature.subarray(64), signature.subarray(0, 64))
  return secp256k1.recoverPublicKey(recIdFirst, digest, {prehash: false}).slice(1)
}

check('part2: the ownership digest recomputes', () => {
  assert(bytesToHex(lsmDigest('LNURLcash')) === part2.conventions.ownershipDigest, 'ownershipDigest')
})

check('part2: every cx1 is its branch key and chain code', () => {
  for (const b of part2.branches) {
    const bytes = decode2('cx', b.cx1, 64)
    assert(bytes && bytesToHex(bytes) === b.branchPubkey + b.chainCode, `${b.host}: cx1`)
    const node = hexToBytes(b.addressNode)
    const P = secp256k1.Point.BASE.multiply(toNum(node.subarray(0, 32)))
    assert(bytesToHex(P.toBytes(true).slice(1)) === b.branchPubkey, `${b.host}: branchPubkey`)
    assert((P.y % 2n === 0n ? 'even' : 'odd') === b.branchParity, `${b.host}: branchParity`)
    assert(bytesToHex(node.subarray(32)) === b.chainCode, `${b.host}: chainCode`)
  }
  assert(part2.branches.some(b => b.branchParity === 'odd'), 'no odd-parity branch, so the negation goes untested')
})

check('part2: a watcher holding only the cx1 derives every note key', () => {
  const tag = sha256(utf8ToBytes('LNURLcash/derive'))
  for (const b of part2.branches) {
    const P = secp256k1.Point.fromBytes(cat(Uint8Array.of(0x02), hexToBytes(b.branchPubkey)))
    for (const n of b.notes) {
      const i = new Uint8Array(4)
      new DataView(i.buffer).setUint32(0, n.index, false)
      const t = toNum(sha256(cat(tag, tag, hexToBytes(b.branchPubkey), hexToBytes(b.chainCode), i)))
      const pk = P.add(secp256k1.Point.BASE.multiply(t)).toBytes(true).slice(1)
      assert(bytesToHex(pk) === n.notePubkey, `${b.host} #${n.index}: watch-only pk`)
      const sk = toNum(hexToBytes(n.noteSecretKey))
      assert(sk > 0n && sk < N2, `${b.host} #${n.index}: sk out of range`)
      assert(
        bytesToHex(secp256k1.Point.BASE.multiply(sk).toBytes(true).slice(1)) === n.notePubkey,
        `${b.host} #${n.index}: sk does not match pk`
      )
      const cp1 = decode2('cp', n.cp1, 32)
      assert(cp1 && bytesToHex(cp1) === n.notePubkey, `${b.host} #${n.index}: cp1`)
    }
  }
})

check('part2: every ck1 is an ownership signature that recovers its note key', () => {
  const digest = hexToBytes(part2.conventions.ownershipDigest)
  for (const b of part2.branches) {
    for (const n of b.notes) {
      const sig = decode2('ck', n.ck1, 65)
      assert(sig && bytesToHex(sig) === n.ownershipSignature, `${b.host} #${n.index}: ck1`)
      assert(sig[64] <= 3, `${b.host} #${n.index}: recovery id`)
      assert(toNum(sig.subarray(32, 64)) <= N2 / 2n, `${b.host} #${n.index}: high-S`)
      assert(bytesToHex(recoverX(sig, digest)) === n.notePubkey, `${b.host} #${n.index}: recovery`)
    }
  }
})

check('part2: every certificate is the mint key over its message', () => {
  const mintX = bytesToHex(hexToBytes(part2.mint.mintPubkey).slice(1))
  assert(
    bytesToHex(secp256k1.getPublicKey(hexToBytes(part2.mint.privateKey), true)) === part2.mint.mintPubkey,
    'mint key pair'
  )
  for (const c of part2.certificates) {
    assert(c.message === `LNURLcash:${c.amountMsat}:${c.notePubkey}`, `${c.amountMsat}: message`)
    assert(bytesToHex(lsmDigest(c.message)) === c.digest, `${c.amountMsat}: digest`)
    const sig = decode2('cs', c.cs1, 65)
    assert(sig && bytesToHex(sig) === c.signature, `${c.amountMsat}: cs1`)
    assert(bytesToHex(recoverX(sig, hexToBytes(c.digest))) === mintX, `${c.amountMsat}: recovers to the mint key`)
  }
})

check('part2: the valid strings decode and the invalid ones do not, for the reason given', () => {
  for (const v of part2.valid) {
    const [hrp, length] = LENGTHS[v.type]
    const bytes = decode2(hrp, v.value, length)
    assert(bytes && bytesToHex(bytes) === v.bytes, `valid ${v.type}: ${v.why}`)
  }
  for (const v of part2.invalid) {
    const [hrp, length] = LENGTHS[v.type]
    assert(decode2(hrp, v.value, length) === null, `invalid ${v.type} decoded: ${v.why}`)
    assert(typeof v.why === 'string' && v.why.length > 0, `invalid ${v.type}: no reason given`)
  }
})

// ---- the Nostr-key branch extension ----

const nostrSeed = load('nostr-seed.json')

check('nostr-seed: marked as an extension, not LUD-25', () => {
  assert(nostrSeed.extension === true && nostrSeed.label === 'LNURLcash/nostr-seed', 'extension/label')
})

check('nostr-seed: every seed, branch and note recomputes', () => {
  const tag = sha256(utf8ToBytes('LNURLcash/derive'))
  const digest = hexToBytes(part2.conventions.ownershipDigest)
  for (const c of nostrSeed.cases) {
    const identity = hexToBytes(c.identity)
    assert(bytesToHex(hmac(sha256, identity, utf8ToBytes(nostrSeed.label))) === c.seed, `${c.host}: seed`)
    assert(
      bytesToHex(secp256k1.Point.BASE.multiply(toNum(identity)).toBytes(true).slice(1)) === c.identityPubkey,
      `${c.host}: identityPubkey`
    )
    const node = hexToBytes(c.addressNode)
    const P = secp256k1.Point.BASE.multiply(toNum(node.subarray(0, 32)))
    const x = P.toBytes(true).slice(1)
    const cx = decode2('cx', c.cx1, 64)
    assert(cx && bytesToHex(cx) === bytesToHex(x) + bytesToHex(node.subarray(32)), `${c.host}: cx1`)
    const lifted = secp256k1.Point.fromBytes(cat(Uint8Array.of(0x02), x))
    for (const n of c.notes) {
      const i = new Uint8Array(4)
      new DataView(i.buffer).setUint32(0, n.index, false)
      const t = toNum(sha256(cat(tag, tag, x, node.subarray(32), i)))
      const pk = bytesToHex(lifted.add(secp256k1.Point.BASE.multiply(t)).toBytes(true).slice(1))
      assert(pk === n.notePubkey, `${c.host} #${n.index}: watch-only pk`)
      const sig = decode2('ck', n.ck1, 65)
      assert(sig && bytesToHex(recoverX(sig, digest)) === n.notePubkey, `${c.host} #${n.index}: ck1 recovery`)
    }
  }
})

console.log(
  failures === 0
    ? '\nvectors are self-consistent'
    : `\n${failures} check(s) failed`
)
process.exit(failures === 0 ? 0 : 1)
