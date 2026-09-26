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
import {sha256, sha512} from '@noble/hashes/sha2.js'
import {schnorr, secp256k1} from '@noble/curves/secp256k1.js'
import {hmac} from '@noble/hashes/hmac.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {mnemonicToSeedSync, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'
// The grader's own taproot reading, independent of the generator's: every
// spend value below is recomputed with it, and it in turn is held to the
// numbers 25.md publishes.
import {
  bearerNote,
  bearerSpend,
  decodeCp1,
  decodeNoteRef,
  decodeSpend,
  encodeCk1,
  encodeCp1,
  encodeCw1,
  keyPathSighash,
  keyPathSpend,
  NUMS_H,
  outputKeyOf,
  scriptPathSighash,
  scriptTree,
  spendDomainOf,
  spendPrevout,
  spendSigMsg,
  tapBranchHash,
  tapLeafHash,
  taprootTweak,
  tweakSecretKey
} from '../runner/spend.mjs'

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
const LENGTHS = {cp1: ['cp', 32], ck1: ['ck', 96], cx1: ['cx', 64]}
const AMOUNT_MSAT_PER_UNIT = {'': 100_000_000_000, m: 100_000_000, u: 100_000, n: 100, p: 0.1}
const decodeAmountSuffix = suffix => {
  const match = suffix.match(/^(\d+)([munp])?$/)
  if (!match) return null
  const amount = Number(match[1]) * AMOUNT_MSAT_PER_UNIT[match[2] ?? '']
  return Number.isSafeInteger(amount) ? amount : null
}
const decodeCertificate = value => {
  if (typeof value !== 'string') return null
  const lower = value.toLowerCase()
  const sep = lower.lastIndexOf('1')
  if (sep < 3 || !lower.startsWith('cs')) return null
  const amountMsat = decodeAmountSuffix(lower.slice(2, sep))
  if (amountMsat === null) return null
  const signature = decode2(lower.slice(0, sep), value, 65)
  return signature ? {amountMsat, signature} : null
}
const lsmDigest = message =>
  sha256(sha256(cat(utf8ToBytes('Lightning Signed Message:'), utf8ToBytes(message))))
const recoverX = (signature, digest) => {
  const recIdFirst = cat(signature.subarray(64), signature.subarray(0, 64))
  return secp256k1.recoverPublicKey(recIdFirst, digest, {prehash: false}).slice(1)
}

// A ck1 signs the key-path sighash of the canonical spend transaction for
// one domain, and nothing else: the fixed "LNURLcash" message it signed
// before luds 6e865b1 must be gone from the conventions.
check('part2: every branch is bound to its host without the port', () => {
  assert(part2.conventions.ownershipMessage === undefined, 'ownershipMessage is still a convention')
  assert(/TapSighash/.test(part2.conventions.ck1Signs), 'ck1Signs does not name the sighash')
  for (const b of part2.branches) {
    assert(b.domain === spendDomainOf(`http://${b.host}`), `${b.host}: domain ${b.domain}`)
    assert(!b.domain.includes(':'), `${b.host}: the domain carries a port`)
  }
  assert(part2.branches.some(b => b.host !== b.domain), 'no branch host carries a port, so the stripping goes untested')
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

// Some other domain the branch is not at, to prove the signature is bound.
const elsewhere = domain => (domain === 'moneyer.dev' ? 'mint.example' : 'moneyer.dev')

check("part2: every ck1 signs its domain's key-path sighash and verifies nowhere else", () => {
  for (const b of part2.branches) {
    for (const n of b.notes) {
      const pk = hexToBytes(n.notePubkey)
      const sighash = keyPathSighash(pk, b.domain)
      assert(bytesToHex(sighash) === n.sighash, `${b.host} #${n.index}: sighash`)
      const ck1 = decode2('ck', n.ck1, 96)
      assert(ck1 && bytesToHex(ck1.subarray(0, 32)) === n.notePubkey, `${b.host} #${n.index}: ck1 key`)
      assert(bytesToHex(ck1.subarray(32)) === n.keyPathSignature, `${b.host} #${n.index}: ck1 signature`)
      assert(schnorr.verify(ck1.subarray(32), sighash, pk), `${b.host} #${n.index}: does not verify at ${b.domain}`)
      assert(
        !schnorr.verify(ck1.subarray(32), keyPathSighash(pk, elsewhere(b.domain)), pk),
        `${b.host} #${n.index}: verifies at ${elsewhere(b.domain)} too`
      )
      assert(keyPathSpend(hexToBytes(n.noteSecretKey), b.domain) === n.ck1, `${b.host} #${n.index}: not the zero-aux ck1`)
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
    const decoded = decodeCertificate(c.cs1)
    assert(decoded && decoded.amountMsat === c.amountMsat, `${c.amountMsat}: cs1 amount`)
    assert(bytesToHex(decoded.signature) === c.signature, `${c.amountMsat}: cs1 signature`)
    assert(bytesToHex(recoverX(decoded.signature, hexToBytes(c.digest))) === mintX, `${c.amountMsat}: recovers to the mint key`)
  }
})

check('part2: every address proof is action-, domain- and username-bound to index zero', () => {
  for (const proof of part2.addressProofs) {
    assert(['register', 'unregister'].includes(proof.action), `${proof.action}: action`)
    assert(
      proof.message === `LNURLcash:${proof.action}:${proof.domain}:${proof.username}`,
      `${proof.action}: message`
    )
    assert(bytesToHex(sha256(utf8ToBytes(proof.message))) === proof.digest, `${proof.action}: digest`)
    const signature = hexToBytes(proof.signature)
    assert(signature.length === 64, `${proof.action}: signature length`)
    assert(
      schnorr.verify(signature, sha256(utf8ToBytes(proof.message)), hexToBytes(proof.indexZeroPubkey)),
      `${proof.action}: verifies against index zero`
    )
    // The pre-265759f message, with no domain, must not verify.
    assert(
      !schnorr.verify(signature, sha256(utf8ToBytes(`LNURLcash:${proof.action}:${proof.username}`)), hexToBytes(proof.indexZeroPubkey)),
      `${proof.action}: verifies without the domain`
    )
  }
  const [register, unregister, bob, elsewhereProof] = part2.addressProofs
  assert(register.signature !== unregister.signature, 'action separation')
  assert(register.signature !== bob.signature, 'username separation')
  assert(
    register.username === elsewhereProof.username && register.domain !== elsewhereProof.domain &&
      register.signature !== elsewhereProof.signature,
    'domain separation'
  )
})

check('part2: the valid strings decode and the invalid ones do not, for the reason given', () => {
  for (const v of part2.valid) {
    const fixed = LENGTHS[v.type]
    const bytes = v.type === 'cs1'
      ? decodeCertificate(v.value)?.signature
      : decode2(fixed[0], v.value, fixed[1])
    assert(bytes && bytesToHex(bytes) === v.bytes, `valid ${v.type}: ${v.why}`)
  }
  for (const v of part2.invalid) {
    const fixed = LENGTHS[v.type]
    const bytes = v.type === 'cs1'
      ? decodeCertificate(v.value)?.signature ?? null
      : decode2(fixed[0], v.value, fixed[1])
    assert(bytes === null, `invalid ${v.type} decoded: ${v.why}`)
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
  for (const c of nostrSeed.cases) {
    const identity = hexToBytes(c.identity)
    assert(bytesToHex(hmac(sha256, identity, utf8ToBytes(nostrSeed.label))) === c.seed, `${c.host}: seed`)
    assert(
      bytesToHex(secp256k1.Point.BASE.multiply(toNum(identity)).toBytes(true).slice(1)) === c.identityPubkey,
      `${c.host}: identityPubkey`
    )
    assert(c.domain === spendDomainOf(`http://${c.host}`), `${c.host}: domain ${c.domain}`)
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
      const pk = lifted.add(secp256k1.Point.BASE.multiply(t)).toBytes(true).slice(1)
      assert(bytesToHex(pk) === n.notePubkey, `${c.host} #${n.index}: watch-only pk`)
      const sighash = keyPathSighash(pk, c.domain)
      assert(bytesToHex(sighash) === n.sighash, `${c.host} #${n.index}: sighash`)
      const ck1 = decode2('ck', n.ck1, 96)
      assert(ck1 && bytesToHex(ck1.subarray(0, 32)) === n.notePubkey, `${c.host} #${n.index}: ck1 key`)
      assert(bytesToHex(ck1.subarray(32)) === n.keyPathSignature, `${c.host} #${n.index}: ck1 signature`)
      assert(schnorr.verify(ck1.subarray(32), sighash, pk), `${c.host} #${n.index}: ck1 does not verify at ${c.domain}`)
      assert(
        !schnorr.verify(ck1.subarray(32), keyPathSighash(pk, elsewhere(c.domain)), pk),
        `${c.host} #${n.index}: ck1 verifies at ${elsewhere(c.domain)} too`
      )
    }
  }
})

// ---- LUD-25's own test vectors ----
//
// spec-vectors.json is produced by the generator from the primitives. Two
// independent checks hold it to the spec: every value is compared with the
// hex 25.md itself prints (transcribed below from lnurl/luds 6e865b1, the
// one place in this repo those numbers are typed rather than computed), and
// every value is recomputed with the grader's own primitives and code here.

const SPEC_TEXT = {
  vector1: {
    seedHex: '000102030405060708090a0b0c0d0e0f',
    domain: 'mint.example',
    cashHashingKey: '45a46de715668a4250ddb7420e71f8cb2a165047095edda920c0bfeb7c4ab7a6',
    domainIndices: [2728808236, 3900943163, 3604736224, 1452184550],
    branchPrivateKey: '7bbab40e4a022ea909cfee28eb1c7a9f56cf746feea94ff73f155a14f2c57d1e',
    branchPubkeyCompressed: '03b783d2930dc053a971f019054ca43e7c9de50e0769de872dd1ddde5d0bf4c9d1',
    branchPubkeyXOnly: 'b783d2930dc053a971f019054ca43e7c9de50e0769de872dd1ddde5d0bf4c9d1',
    chainCode: 'ab91cc11aea395ea6b62292a6147f51ef4150ebea04e745137b68719e238f904',
    branchParity: 'odd',
    cx1: 'cx1k7pa9ycdcpf6ju0sryz5efp70jw72rs8d80gwtw3mh096zl5e8g6hywvzxh28902dd3zj2npgl63aaq4p6l2qnn52ymmdpceugu0jpqes280t',
    notes: [
      {
        index: 0,
        t: '10054a4025dc5678a26e16087703ac1af6be92dab9cc20f10c5a5ae0ffbd057c',
        Q: '02aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
        pk: 'aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
        sk: '944a9631dbda27cf989e27df8be7317a5a9dfb517a6b71358d175f58dd2dc99f',
        cp1: 'cp14tf6pcmvpqltp5ke9mqgvzthm3rdzry49uccxrnygwcl4gvewc6qh2fkky'
      },
      {
        index: 1,
        t: '08c401f6e9646a046291700ec99fa5181f46b241cb4667cd1aa7b86ed30fde19',
        Q: '02f0c1ea9aede945b9cf84f3bf8df27ac65154a937e4d10cb8a5865df0583b1083',
        pk: 'f0c1ea9aede945b9cf84f3bf8df27ac65154a937e4d10cb8a5865df0583b1083',
        sk: '8d094de89f623b5b58c181e5de832a7783261ab88be5b8119b64bce6b080a23c',
        cp1: 'cp17rq74xhda9zmnnuy7wlcmun6ceg4f2fhungsew99sewlqkpmzzpsf28ex8'
      },
      {
        index: 2,
        t: 'b17b1b45fb64a2d70009c968f965790e11a6b9879041eb9730fda21ca199181f',
        Q: '03c1e51bc2b8ad1c6ecfe382fe201c322506e2783a2e4d3eae0da47fece2eab078',
        pk: 'c1e51bc2b8ad1c6ecfe382fe201c322506e2783a2e4d3eae0da47fece2eab078',
        sk: '35c06737b162742df639db400e48fe6ebad74517a1989b9ff1e84807aed39b01',
        cp1: 'cp1c8j3hs4c45wxanlrstlzq8pjy5rwy7p69exnatsd53l7ech2kpuqsypsv2'
      },
      {
        index: 5,
        t: '468c1cdcf8fe1194f33d2b4c543c9a6000423bddc9b8a83f17c3ace9b0796568',
        Q: '02c2b6a6d230d3ca51cc680bf84948c416eab70109542a0cf4fd1fbebbd647891a',
        pk: 'c2b6a6d230d3ca51cc680bf84948c416eab70109542a0cf4fd1fbebbd647891a',
        sk: 'cad168ceaefbe2ebe96d3d2369201fbf6421a4548a57f8839880b1618dea298b',
        cp1: 'cp1c2m2d53s6099rnrgp0uyjjxyzm4twqgf2s4qea8ar7lth4j83ydqcznzj6'
      }
    ]
  },
  vector2: {
    seedHex:
      'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
    domain: 'cash.example.com',
    cashHashingKey: '7d6d06012307b130432c5ab845fc746f72d4703a91981a6c012a420b83176dd8',
    domainIndices: [2886871684, 4226627351, 2748717696, 1002847463],
    branchPrivateKey: '6f1d381ccdda9a69f966b492b19de687930c19b19e7f8d581088402d6a3b7818',
    branchPubkeyCompressed: '0264885a9cab93ec051761b8a0b80e1854a61865878d58f72a365dfd640850f675',
    branchPubkeyXOnly: '64885a9cab93ec051761b8a0b80e1854a61865878d58f72a365dfd640850f675',
    chainCode: '6b95795f9807ada85c8ca50ec93c921483a183abfed4a3b4abe6b95c89880306',
    branchParity: 'even',
    cx1: 'cx1vjy9489tj0kq29mphzstsrsc2jnpsev834v0w23kth7kgzzs7e6kh9tet7vq0tdgtjx22rkf8jfpfqapsw4la49rkj47dw2u3xyqxpspgvxpa',
    notes: [
      {
        index: 0,
        t: '4d010c0ae5b4e0def5d0eb651d5e08de7fc36aef5703231480372b24688d2711',
        Q: '0223bf26d94335b65e84b8383eb0a8baec8c32e2ebc561a204a386bb720b4cd130',
        pk: '23bf26d94335b65e84b8383eb0a8baec8c32e2ebc561a204a386bb720b4cd130',
        sk: 'bc1e4427b38f7b48ef379ff7cefbef6612cf84a0f582b06c90bf6b51d2c89f29',
        cp1: 'cp1ywljdk2rxkm9ap9c8qltp296ajxr9chtc4s6yp9rs6ahyz6v6ycqvtd8z5'
      },
      {
        index: 1,
        t: '370d05e7dca3f107e7ec061de1ea81a51f2a7f5756330317d1a662fdfd35f618',
        Q: '03b1ab49e8ca397385ccb6d17d611bf8afc75390513bdcdfe3d760e0bb9860e0aa',
        pk: 'b1ab49e8ca397385ccb6d17d611bf8afc75390513bdcdfe3d760e0bb9860e0aa',
        sk: 'a62a3e04aa7e8b71e152bab09388682cb2369908f4b2906fe22ea32b67716e30',
        cp1: 'cp1kx45n6x289ectn9k697kzxlc4lr48yz380wdlc7hvrsthxrquz4qtpysaz'
      },
      {
        index: 2,
        t: '3d978b10770f8566e6630d978f46a79cb2d237ab0f6168123154dc83c3dc1392',
        Q: '039cf00b60589f863cedd2773b42341e6f5102d6bd23d04559a3103d50611b2ada',
        pk: '9cf00b60589f863cedd2773b42341e6f5102d6bd23d04559a3103d50611b2ada',
        sk: 'acb4c32d44ea1fd0dfc9c22a40e48e2445de515cade0f56a41dd1cb12e178baa',
        cp1: 'cp1nncqkczcn7rremwjwua5ydq7dags944ay0gy2kdrzq74qcgm9tdq37e4dd'
      }
    ],
    addressProofs: [
      {
        action: 'register',
        domain: 'cash.example.com',
        username: 'alice',
        message: 'LNURLcash:register:cash.example.com:alice',
        digest: 'be730f1fc4a81feea4bc0464d9f6adff04dfe652687e39cba30eac9caa73fcdd',
        signature:
          '9d96780fe55f602a9e238a4b2640a9f8ca939cacbbcde109cfd6ba94a6f9d46ff4aaf56ba1e4e72696f7c0e8833445bd194bd06155a133cf524eb587d52e8d22'
      },
      {
        action: 'unregister',
        domain: 'cash.example.com',
        username: 'alice',
        message: 'LNURLcash:unregister:cash.example.com:alice',
        digest: 'dc12e80f7d0486fab791c743688e54bcc759111722d80dfa5fa70586a7d9d9d9',
        signature:
          '7250ab2403333eb5ed73f7a212ac4f35b58f426fe5c2acb8b2194a112881332bfbeebeba0bc4615bcf361bc125d5a4149ddbe4b6ea3b755b711fefd8bba58728'
      }
    ]
  },
  vector3: {
    sk: '944a9631dbda27cf989e27df8be7317a5a9dfb517a6b71358d175f58dd2dc99f',
    Q: 'aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
    cp1: 'cp14tf6pcmvpqltp5ke9mqgvzthm3rdzry49uccxrnygwcl4gvewc6qh2fkky',
    domain: 'mint.example',
    prevoutTxid: 'd5ac2de3423432e37713bcb133cfea7938ff6b2f8ea4174dfcec84bea705d6b2',
    spentScriptPubKey: '5120aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
    sigMsgFields: {
      hash_type: '00',
      nVersion: '02000000',
      nLockTime: '00000000',
      sha_prevouts: '30b1cba17526057f8343b434d78c6e2daf43429c3a38e236d22cf5f5b78b9024',
      sha_amounts: 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc',
      sha_scriptpubkeys: 'ddd2d8771df7fb07a13626816ef020a553559bdcd01734d1259655430f6b91fa',
      sha_sequences: 'ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e',
      sha_outputs: '3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d',
      spend_type: '00',
      input_index: '00000000'
    },
    sigMsg:
      '00020000000000000030b1cba17526057f8343b434d78c6e2daf43429c3a38e236d22cf5f5b78b9024af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfcddd2d8771df7fb07a13626816ef020a553559bdcd01734d1259655430f6b91faad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d0000000000',
    sighash: 'b8933a42090297a1f80d7f1fc0023ec1aa2ab36a7df332520f0dacf07f617943',
    auxRand: '0000000000000000000000000000000000000000000000000000000000000000',
    signature:
      '83bbe1fe044d3d15cd1c18b484168c37f921864a9f85e9251f8457b576abd66b211b70b97fb3d63856ae271e4b3e3cf95da8e8b7769fefc309d8dc4989120e8e',
    spendTransaction:
      '02000000000101d5ac2de3423432e37713bcb133cfea7938ff6b2f8ea4174dfcec84bea705d6b20000000000ffffffff01000000000000000000014083bbe1fe044d3d15cd1c18b484168c37f921864a9f85e9251f8457b576abd66b211b70b97fb3d63856ae271e4b3e3cf95da8e8b7769fefc309d8dc4989120e8e00000000',
    ck1: 'ck14tf6pcmvpqltp5ke9mqgvzthm3rdzry49uccxrnygwcl4gvewc6g8wlplczy60g4e5wp3dyyz6xr07fpse9flp0fy50cg4a4w64av6eprdctjlan6cu9dt38re9nu08etk5w3dmknlhuxzwcm3ycjysw3c9dpmpy'
  },
  vector4: {
    mintPrivateKey: 'a8358061952ee158b42ffe1607c00adda3e63098247f837f08a4ef9492b4f798',
    mintPubkey: '035acdbd57663f858be6d61ec4bfcbc99492699010f1451e30a6550f26295e813d',
    notePubkey: 'aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
    certificates: [
      {
        amountMsat: 1000,
        message: 'LNURLcash:1000:aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
        digest: '30894ad113df18b1e00a27015ed62e8b94a87498c8da7997ddac48e4cd7bb20f',
        signature:
          '41a69c2e826555b1c5c099b3166e8d50cc3bbba3ccb9b87c377e96ae070d532c3b6230194ae97d322d663fb38266abd26f3553c62a7d5a528ce9c72d3838fffc01',
        cs1: 'cs10n1gxnfct5zv42mr3wqnxe3vm5d2rxrhwarejumslph06t2upcd2vkrkc3sr99wjlfj94nrlvuzv64ayme420rz5l2622xwn3ed8qu0llqpeg9n5x'
      },
      {
        amountMsat: 21000000,
        message: 'LNURLcash:21000000:aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634',
        digest: '6186fd2c1c258a6c0a3627e895efbc3d0988325c4f36f0050b52b4c4751ab13d',
        signature:
          'b5c6c3dd151708501bc8820ae00ef3d6439cdcca8bac00fb2675fee6b89a7767079e37f62c2502c6744a56295c459d52c0475e27a0eb34745790b44c54b9386200',
        cs1: 'cs210u1khrv8hg4zuy9qx7gsg9wqrhn6epeehx23wkqp7exwhlwdwy6wans083h7ckz2qkxw399v22ugkw49sz8tcn6p6e5w3tepdzv2junscsqwvvr03'
      }
    ]
  },
  vector5: {
    preimage: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    h: '630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd',
    leaf: 'a820630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd87',
    tapleafHash: 'edffc9fa683d8844ded0ba5ec4215d5940ae436b0675257c1344bcb082516b50',
    H: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    t: '5649b0259110c0c11426819ea5a40b53e5a9a2b8c6fb3d6c43217df73b326364',
    Q: 'd18b619687343df2fc7a47e1daf25260b909bb563fb4b4b11e59e2bd64880982',
    controlBlock: 'c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    cp1: 'cp16x9kr958xs7l9lr6glsa4ujjvzusnw6k876tfvg7t83t6eygpxpq6we0xc',
    cw1: 'cw1qqqqqq8lllll7qpr4qsxxrwd99nvgvmxjyf9gj9mkfd5laqj5jw8xtdjez4urwzcr0t3phv8qqsuq5yjnd6vrgzf2jmckjmqxh5h5hs83fdq728vjm2500lwnt8gqwkqqqsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8c6x6a4c',
    certificate: {
      amountMsat: 1000,
      message: 'LNURLcash:1000:d18b619687343df2fc7a47e1daf25260b909bb563fb4b4b11e59e2bd64880982',
      digest: 'e44e0e215367429a8a503ee0095e070cfb215b8e8b3af523b75e54138e75ee84',
      signature:
        'c74d78b8c9ebd0a11a5afacaf1fed061da8ced7d6625e6809b624ddf68f16ab47df5cd830886bf7d1f1eaa88b9badaca242be6e038adec7b38c51a392d234a7800',
      cs1: 'cs10n1caxh3wxfa0g2zxj6lt90rlksv8dgemtavcj7dqymvfxa7683d268mawdsvygd0maru024z9ehtdv5fptumsr3t0v0vuv2x3e953557qq5c70z5'
    },
    certifiedNoteUrl:
      'lnurlw://mint.example/w?k1=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&sig=cs10n1caxh3wxfa0g2zxj6lt90rlksv8dgemtavcj7dqymvfxa7683d268mawdsvygd0maru024z9ehtdv5fptumsr3t0v0vuv2x3e953557qq5c70z5'
  }
}

const specVectors = load('spec-vectors.json')

// Every field 25.md prints must be in the file with the same value; the
// file may carry more (intermediate values the spec leaves implicit).
const sameAsSpec = (label, fromFile, fromSpec) => {
  if (Array.isArray(fromSpec)) {
    assert(Array.isArray(fromFile) && fromFile.length === fromSpec.length, `${label}: length`)
    fromSpec.forEach((value, i) => sameAsSpec(`${label}[${i}]`, fromFile[i], value))
  } else if (fromSpec !== null && typeof fromSpec === 'object') {
    assert(fromFile !== null && typeof fromFile === 'object', `${label}: missing`)
    for (const key of Object.keys(fromSpec)) sameAsSpec(`${label}.${key}`, fromFile[key], fromSpec[key])
  } else {
    assert(fromFile === fromSpec, `${label}: ${JSON.stringify(fromFile)}, 25.md says ${JSON.stringify(fromSpec)}`)
  }
}

check('spec-vectors: vector 1 is 25.md\'s own', () => {
  sameAsSpec('vector1', specVectors.vector1, SPEC_TEXT.vector1)
})
check('spec-vectors: vector 2 is 25.md\'s own, domain-bound proofs included', () => {
  sameAsSpec('vector2', specVectors.vector2, SPEC_TEXT.vector2)
})
check('spec-vectors: vector 3 is 25.md\'s own', () => {
  const {sk, ...rest} = SPEC_TEXT.vector3
  sameAsSpec('vector3', specVectors.vector3, {secretKey: sk, ...rest})
})
check('spec-vectors: vector 4 is 25.md\'s own', () => {
  sameAsSpec('vector4', specVectors.vector4, SPEC_TEXT.vector4)
})
check('spec-vectors: vector 5 is 25.md\'s own', () => {
  sameAsSpec('vector5', specVectors.vector5, SPEC_TEXT.vector5)
})

// BIP-32 CKDpriv, written again here so vectors 1 and 2 are re-derived by
// code the generator never ran.
const ckd = (node, index) => {
  const data =
    index >= 0x80000000
      ? cat(Uint8Array.of(0), node.key)
      : secp256k1.Point.BASE.multiply(toNum(node.key)).toBytes(true)
  const i = new Uint8Array(4)
  new DataView(i.buffer).setUint32(0, index, false)
  const I = hmac(sha512, node.chainCode, cat(data, i))
  const key = (toNum(I.subarray(0, 32)) + toNum(node.key)) % N2
  return {key: hexToBytes(key.toString(16).padStart(64, '0')), chainCode: I.slice(32)}
}

check('spec-vectors: vectors 1 and 2 re-derive from their seeds', () => {
  for (const name of ['vector1', 'vector2']) {
    const v = SPEC_TEXT[name]
    const I = hmac(sha512, utf8ToBytes('Bitcoin seed'), hexToBytes(v.seedHex))
    const root = ckd({key: I.slice(0, 32), chainCode: I.slice(32)}, 0x80000000 + 139)
    const hashingKey = ckd(root, 0).key
    assert(bytesToHex(hashingKey) === v.cashHashingKey, `${name}: cashHashingKey`)
    const material = hmac(sha256, hashingKey, utf8ToBytes(v.domain))
    const view = new DataView(material.buffer, material.byteOffset, material.byteLength)
    const indices = [0, 4, 8, 12].map(offset => view.getUint32(offset, false))
    assert(indices.join() === v.domainIndices.join(), `${name}: domain indices`)
    const branch = indices.reduce(ckd, root)
    assert(bytesToHex(branch.key) === v.branchPrivateKey, `${name}: p`)
    assert(bytesToHex(branch.chainCode) === v.chainCode, `${name}: chaincode`)
    const P = secp256k1.Point.BASE.multiply(toNum(branch.key))
    assert(bytesToHex(P.toBytes(true)) === v.branchPubkeyCompressed, `${name}: P`)
    assert((P.y % 2n === 0n ? 'even' : 'odd') === v.branchParity, `${name}: parity`)
    const Px = P.toBytes(true).slice(1)
    assert(bytesToHex(Px) === v.branchPubkeyXOnly, `${name}: P x-only`)
    assert(bech32m.encode('cx', bech32m.toWords(cat(Px, branch.chainCode)), false) === v.cx1, `${name}: cx1`)
    const tag = sha256(utf8ToBytes('LNURLcash/derive'))
    for (const n of v.notes) {
      const i = new Uint8Array(4)
      new DataView(i.buffer).setUint32(0, n.index, false)
      const t = toNum(sha256(cat(tag, tag, Px, branch.chainCode, i))) % N2
      assert(t.toString(16).padStart(64, '0') === n.t, `${name} #${n.index}: t`)
      const Q = secp256k1.Point.fromBytes(cat(Uint8Array.of(0x02), Px)).add(secp256k1.Point.BASE.multiply(t))
      assert(bytesToHex(Q.toBytes(true)) === n.Q, `${name} #${n.index}: Q`)
      assert(bytesToHex(Q.toBytes(true).slice(1)) === n.pk, `${name} #${n.index}: pk`)
      const p = toNum(branch.key)
      const sk = ((P.y % 2n === 0n ? p : N2 - p) + t) % N2
      assert(sk.toString(16).padStart(64, '0') === n.sk, `${name} #${n.index}: sk`)
      assert(encodeCp1(hexToBytes(n.pk)) === n.cp1, `${name} #${n.index}: cp1`)
    }
  }
})

check("spec-vectors: vector 2's proofs verify under pk_0 and bind their domain", () => {
  const v = SPEC_TEXT.vector2
  const pk0 = hexToBytes(v.notes[0].pk)
  for (const proof of v.addressProofs) {
    assert(bytesToHex(sha256(utf8ToBytes(proof.message))) === proof.digest, `${proof.action}: digest`)
    assert(schnorr.verify(hexToBytes(proof.signature), hexToBytes(proof.digest), pk0), `${proof.action}: does not verify`)
    for (const other of ['LNURLcash:' + proof.action + ':alice', `LNURLcash:${proof.action}:mint.example:alice`]) {
      assert(!schnorr.verify(hexToBytes(proof.signature), sha256(utf8ToBytes(other)), pk0), `${proof.action}: verifies as ${other}`)
    }
  }
})

// The canonical spend transaction with its witness, serialised by hand
// here rather than by anything the generator or the grader uses.
const le32 = n => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, true)
  return out
}
const canonicalTx = (domain, locktime, sequence, stack) =>
  cat(
    le32(2),
    Uint8Array.of(0, 1, 1),
    spendPrevout(domain),
    le32(0),
    Uint8Array.of(0),
    le32(sequence),
    Uint8Array.of(1),
    new Uint8Array(8),
    Uint8Array.of(0, stack.length),
    ...stack.flatMap(item => [Uint8Array.of(item.length), item]),
    le32(locktime)
  )

check('spec-vectors: vector 3 recomputes, from the prevout to the serialised spend', () => {
  const v = SPEC_TEXT.vector3
  const Q = hexToBytes(v.Q)
  assert(bytesToHex(schnorr.getPublicKey(hexToBytes(v.sk))) === v.Q, 'Q is not sk·G')
  assert(bytesToHex(spendPrevout(v.domain)) === v.prevoutTxid, 'prevout')
  const sigMsg = spendSigMsg({outputKey: Q, domain: v.domain, locktime: 0, sequence: 0xffffffff})
  assert(sigMsg.length === 174, `SigMsg is ${sigMsg.length} bytes`)
  assert(bytesToHex(sigMsg) === v.sigMsg, 'SigMsg')
  assert(Object.values(v.sigMsgFields).join('') === v.sigMsg, 'the named fields do not concatenate to SigMsg')
  const sighash = keyPathSighash(Q, v.domain)
  assert(bytesToHex(sighash) === v.sighash, 'sighash')
  assert(bytesToHex(schnorr.sign(sighash, hexToBytes(v.sk), new Uint8Array(32))) === v.signature, 'zero-aux signature')
  assert(schnorr.verify(hexToBytes(v.signature), sighash, Q), 'signature')
  assert(bytesToHex(canonicalTx(v.domain, 0, 0xffffffff, [hexToBytes(v.signature)])) === v.spendTransaction, 'spend transaction')
  assert(encodeCk1(Q, hexToBytes(v.signature)) === v.ck1, 'ck1')
  assert(!schnorr.verify(hexToBytes(v.signature), keyPathSighash(Q, 'mint.example.com'), Q), 'verifies at another domain')
})

check("spec-vectors: vector 4's certificates recover to its mintPubkey", () => {
  const v = SPEC_TEXT.vector4
  assert(bytesToHex(secp256k1.getPublicKey(hexToBytes(v.mintPrivateKey), true)) === v.mintPubkey, 'mint key pair')
  assert(bytesToHex(sha256(utf8ToBytes(specVectors.vector4.mintSeedLabel))) === v.mintPrivateKey, 'mint seed label')
  for (const c of v.certificates) {
    assert(c.message === `LNURLcash:${c.amountMsat}:${v.notePubkey}`, `${c.amountMsat}: message`)
    assert(bytesToHex(lsmDigest(c.message)) === c.digest, `${c.amountMsat}: digest`)
    const decoded = decodeCertificate(c.cs1)
    assert(decoded && decoded.amountMsat === c.amountMsat, `${c.amountMsat}: cs1 amount`)
    assert(bytesToHex(decoded.signature) === c.signature, `${c.amountMsat}: cs1 signature`)
    assert(bytesToHex(recoverX(decoded.signature, hexToBytes(c.digest))) === v.mintPubkey.slice(2), `${c.amountMsat}: recovers`)
  }
})

check('spec-vectors: vector 5 recomputes, and its certificate is over hex(Q)', () => {
  const v = SPEC_TEXT.vector5
  const preimage = hexToBytes(v.preimage)
  assert(bytesToHex(sha256(preimage)) === v.h, 'h')
  const note = bearerNote(hexToBytes(v.h))
  assert(bytesToHex(note.leaf) === v.leaf, 'leaf')
  assert(bytesToHex(tapLeafHash(note.leaf)) === v.tapleafHash, 'tapleaf hash')
  assert(bytesToHex(NUMS_H) === v.H, 'H')
  const tweaked = taprootTweak(NUMS_H, tapLeafHash(note.leaf))
  assert(tweaked.tweak.toString(16).padStart(64, '0') === v.t, 't')
  assert(bytesToHex(note.outputKey) === v.Q, 'Q')
  assert(bytesToHex(note.controlBlock) === v.controlBlock, 'control block')
  assert(encodeCp1(note.outputKey) === v.cp1, 'cp1')
  assert(bearerSpend(preimage) === v.cw1, 'cw1')
  assert(bytesToHex(decodeSpend(v.cw1).outputKey) === v.Q, 'the cw1 opens another Q')
  assert(bytesToHex(decodeSpend(v.preimage).outputKey) === v.Q, 'the preimage opens another Q')
  assert(decodeNoteRef(v.h) === v.Q && decodeNoteRef(v.cp1) === v.Q, 'the short forms name another note')
  const c = v.certificate
  assert(c.message === `LNURLcash:${c.amountMsat}:${v.Q}`, 'certificate message')
  assert(bytesToHex(lsmDigest(c.message)) === c.digest, 'certificate digest')
  const decoded = decodeCertificate(c.cs1)
  assert(decoded && decoded.amountMsat === c.amountMsat && bytesToHex(decoded.signature) === c.signature, 'cs1')
  assert(
    bytesToHex(recoverX(decoded.signature, hexToBytes(c.digest))) === SPEC_TEXT.vector4.mintPubkey.slice(2),
    "does not recover to vector 4's mintPubkey"
  )
  const url = new URL(v.certifiedNoteUrl.replace(/^lnurlw:/, 'https:'))
  assert(url.searchParams.get('k1') === v.preimage && url.searchParams.get('sig') === c.cs1, 'certified note URL')
})

// ---- spends ----

const spends = load('spends.json')

// The two rules consensus leaves to the SERVICE, written here on their own
// from 25.md's text rather than copied from any implementation.
const OP_SUCCESS_RANGES = [[80, 80], [98, 98], [126, 129], [131, 134], [137, 138], [141, 142], [149, 153], [187, 254]]
const isOpSuccess = op => OP_SUCCESS_RANGES.some(([lo, hi]) => op >= lo && op <= hi)
const judgeLeaf = (version, script) => {
  if ((version & 0xfe) !== 0xc0) return {verdict: 'refused', reason: 'unknown tapleaf version'}
  let i = 0
  while (i < script.length) {
    const op = script[i++]
    let pushed = 0
    if (op >= 0x01 && op <= 0x4b) pushed = op
    else if (op === 0x4c) pushed = 1 + (script[i] ?? 0)
    else if (op === 0x4d) pushed = 2 + ((script[i] ?? 0) | ((script[i + 1] ?? 0) << 8))
    else if (op === 0x4e) pushed = 4 + new DataView(cat(script.slice(i, i + 4), new Uint8Array(4)).buffer).getUint32(0, true)
    else if (isOpSuccess(op)) return {verdict: 'refused', reason: 'OP_SUCCESS'}
    i += pushed
  }
  return {verdict: 'allowed', reason: null}
}
const judgeTime = ({locktime, sequence, now, lockedAt}) => {
  if (locktime !== 0 && (locktime < 500_000_000 || locktime > now)) return 'reject'
  if (sequence >= 2 ** 31) return 'accept'
  if (Math.floor(sequence / 2 ** 22) % 2 === 0) return 'reject'
  return now - lockedAt >= (sequence % 2 ** 16) * 512 ? 'accept' : 'reject'
}

check('spends: every bearer note recomputes from its preimage', () => {
  for (const b of spends.bearers) {
    const preimage = hexToBytes(b.preimage)
    assert(bytesToHex(sha256(preimage)) === b.h, `${b.name}: h`)
    const note = bearerNote(hexToBytes(b.h))
    assert(bytesToHex(note.leaf) === b.leaf, `${b.name}: leaf`)
    assert(bytesToHex(tapLeafHash(note.leaf)) === b.tapleafHash, `${b.name}: tapleaf hash`)
    const tweaked = taprootTweak(NUMS_H, tapLeafHash(note.leaf))
    assert(tweaked.tweak.toString(16).padStart(64, '0') === b.tweak, `${b.name}: tweak`)
    assert(bytesToHex(tweaked.outputKey) === b.Q && tweaked.parity === b.parity, `${b.name}: Q and parity`)
    assert(bytesToHex(note.controlBlock) === b.controlBlock, `${b.name}: control block`)
    assert((hexToBytes(b.controlBlock)[0] & 1) === b.parity, `${b.name}: parity bit`)
    assert(bytesToHex(outputKeyOf(note.leaf, note.controlBlock)) === b.Q, `${b.name}: control block commits to Q`)
    assert(encodeCp1(hexToBytes(b.Q)) === b.cp1, `${b.name}: cp1`)
    assert(bearerSpend(preimage) === b.cw1, `${b.name}: cw1`)
  }
  assert(spends.bearers.some(b => b.parity === 1) && spends.bearers.some(b => b.parity === 0), 'both parities')
})

check("spends: every domain is its URL's lowercase hostname", () => {
  for (const d of spends.domains) assert(spendDomainOf(d.url.replace(/^lnurlw:/, 'https:')) === d.domain, d.url)
})

check('spends: every key-path ck1 verifies at its own domain and no other', () => {
  const k = spends.keyPath
  const Q = hexToBytes(k.Q)
  assert(bytesToHex(schnorr.getPublicKey(hexToBytes(k.secretKey))) === k.Q && encodeCp1(Q) === k.cp1, 'key')
  const byDomain = new Map()
  for (const s of k.spends) {
    assert(s.normalisedDomain === s.domain.toLowerCase(), `${s.domain}: normalised`)
    assert(bytesToHex(spendPrevout(s.normalisedDomain)) === s.prevoutTxid, `${s.domain}: prevout`)
    const sighash = keyPathSighash(Q, s.normalisedDomain)
    assert(bytesToHex(sighash) === s.sighash, `${s.domain}: sighash`)
    assert(schnorr.verify(hexToBytes(s.signature), sighash, Q), `${s.domain}: signature`)
    assert(encodeCk1(Q, hexToBytes(s.signature)) === s.ck1, `${s.domain}: ck1`)
    assert(keyPathSpend(hexToBytes(k.secretKey), s.normalisedDomain) === s.ck1, `${s.domain}: not the zero-aux ck1`)
    byDomain.set(s.domain, s)
  }
  assert(byDomain.get('mint.example').ck1 === SPEC_TEXT.vector3.ck1, "mint.example's ck1 is not test vector 3's")
  assert(byDomain.get('MINT.EXAMPLE').ck1 === byDomain.get('mint.example').ck1, 'case changed the ck1')
  for (const c of k.crossDomain) {
    const signature = hexToBytes(byDomain.get(c.signedFor).signature)
    const verifies = schnorr.verify(signature, keyPathSighash(Q, c.verifiedAt.toLowerCase()), Q)
    assert(verifies === c.valid, `${c.signedFor} at ${c.verifiedAt}: ${verifies}`)
  }
})

check("spends: the tree's Q, control blocks and cw1s recompute, and each leaf gets its verdict", () => {
  const tree = spends.tree
  const internalKey = hexToBytes(tree.internalKey)
  assert(bytesToHex(schnorr.getPublicKey(hexToBytes(tree.internalSecretKey))) === tree.internalKey, 'internal key')
  const leaves = tree.leaves.map(l => ({script: hexToBytes(l.script), version: l.version}))
  const hashes = leaves.map(l => tapLeafHash(l.script, l.version))
  hashes.forEach((h, i) => assert(bytesToHex(h) === tree.leaves[i].tapleafHash, `leaf ${i}: tapleaf hash`))
  assert(bytesToHex(tapBranchHash(tapBranchHash(hashes[0], hashes[1]), hashes[2])) === tree.merkleRoot, 'merkle root')
  const built = scriptTree(internalKey, leaves)
  assert(bytesToHex(built.outputKey) === tree.Q, 'Q')
  assert(built.tweak.toString(16).padStart(64, '0') === tree.tweak, 'tweak')
  assert(encodeCp1(built.outputKey) === tree.cp1, 'cp1')
  tree.leaves.forEach((leaf, i) => {
    assert(bytesToHex(built.controlBlock(i)) === leaf.controlBlock, `leaf ${i}: control block`)
    assert(built.spend(i, leaf.witness.map(hexToBytes)) === leaf.cw1, `leaf ${i}: cw1`)
    assert(bytesToHex(decodeSpend(leaf.cw1).outputKey) === tree.Q, `leaf ${i}: the cw1 opens another Q`)
    const judged = judgeLeaf(leaf.version, hexToBytes(leaf.script))
    if (leaf.verdict === 'accept') {
      assert(judged.verdict === 'allowed', `leaf ${i}: refused by ${judged.reason}`)
      const script = hexToBytes(leaf.script)
      assert(bytesToHex(sha256(hexToBytes(leaf.witness[0]))) === bytesToHex(script.subarray(2, 34)), `leaf ${i}: the witness does not open the hashlock`)
    } else {
      assert(judged.verdict === 'refused' && judged.reason === leaf.reason, `leaf ${i}: ${judged.verdict} (${judged.reason}), expected ${leaf.reason}`)
    }
  })
})

check("spends: the tree's key path signs for the tweaked Q", () => {
  const tree = spends.tree
  const k = tree.keyPath
  const tweaked = tweakSecretKey(hexToBytes(tree.internalSecretKey), BigInt(`0x${tree.tweak}`))
  assert(bytesToHex(tweaked) === k.tweakedSecretKey, 'tweaked secret key')
  assert(bytesToHex(schnorr.getPublicKey(tweaked)) === tree.Q, 'tweaked key is not Q')
  const Q = hexToBytes(tree.Q)
  const sighash = keyPathSighash(Q, k.domain)
  assert(bytesToHex(sighash) === k.sighash, 'sighash')
  assert(schnorr.verify(hexToBytes(k.signature), sighash, Q), 'signature')
  assert(encodeCk1(Q, hexToBytes(k.signature)) === k.ck1, 'ck1')
})

check("spends: the CHECKSIG leaf's signatures verify over its script-path sighash", () => {
  const c = spends.checksig
  const key = hexToBytes(c.pubkey)
  assert(bytesToHex(schnorr.getPublicKey(hexToBytes(c.secretKey))) === c.pubkey, 'key')
  const leaf = hexToBytes(c.leaf)
  assert(bytesToHex(leaf) === '20' + c.pubkey + 'ac', 'leaf is not <key> OP_CHECKSIG')
  const tweaked = taprootTweak(NUMS_H, tapLeafHash(leaf))
  assert(bytesToHex(tweaked.outputKey) === c.Q, 'Q')
  assert(bytesToHex(outputKeyOf(leaf, hexToBytes(c.controlBlock))) === c.Q, 'control block')
  const Q = hexToBytes(c.Q)
  for (const s of c.spends) {
    const sigMsg = spendSigMsg({outputKey: Q, domain: c.domain, locktime: s.locktime, sequence: s.sequence, leafScript: leaf})
    assert(sigMsg.length === 211 && bytesToHex(sigMsg) === s.sigMsg, `${s.locktime}: SigMsg`)
    const sighash = scriptPathSighash(Q, c.domain, leaf, s.locktime, s.sequence)
    assert(bytesToHex(sighash) === s.sighash, `${s.locktime}: sighash`)
    assert(schnorr.verify(hexToBytes(s.signature), sighash, key), `${s.locktime}: signature`)
    assert(!schnorr.verify(hexToBytes(s.signature), keyPathSighash(Q, c.domain), key), `${s.locktime}: signs the key path`)
    const cw1 = encodeCw1({locktime: s.locktime, sequence: s.sequence, script: leaf, controlBlock: hexToBytes(c.controlBlock), witness: [hexToBytes(s.signature)]})
    assert(cw1 === s.cw1, `${s.locktime}: cw1`)
    const decoded = decodeSpend(s.cw1)
    assert(decoded.locktime === s.locktime && decoded.sequence === s.sequence, `${s.locktime}: the claimed time`)
  }
  assert(c.spends[0].sighash !== c.spends[1].sighash, 'the claimed time is not signed')
})

check('spends: every time claim gets its verdict from an independent reading of the rules', () => {
  for (const t of spends.timeClaims) {
    assert(judgeTime(t) === t.verdict, `${t.name}: ${judgeTime(t)}, expected ${t.verdict}`)
    assert(typeof t.why === 'string' && t.why.length > 0, `${t.name}: no reason given`)
  }
  for (const verdict of ['accept', 'reject']) {
    assert(spends.timeClaims.some(t => t.verdict === verdict), `no ${verdict} case`)
  }
  assert(spends.conventions.timeClaims.locktimeThreshold === 500_000_000, 'threshold')
})

check('spends: every leaf-policy case gets its verdict from an independent scanner', () => {
  for (const l of spends.leafPolicy) {
    const judged = judgeLeaf(l.version, hexToBytes(l.script))
    assert(judged.verdict === l.verdict, `${l.name}: ${judged.verdict}, expected ${l.verdict}`)
  }
})

check('spends: no malformed cw1 decodes to a note', () => {
  for (const m of spends.malformedCw1) {
    assert(decodeSpend(m.value) === null, `${m.name} decoded`)
    assert(typeof m.why === 'string' && m.why.length > 0, `${m.name}: no reason given`)
  }
})

check('spends: no off-curve cp1 decodes', () => {
  for (const c of spends.invalidCp1) {
    let onCurve = true
    try {
      secp256k1.Point.fromBytes(cat(Uint8Array.of(0x03), hexToBytes(c.x)))
    } catch {
      onCurve = false
    }
    assert(!onCurve, `${c.x} is on the curve`)
    assert(decode2('cp', c.cp1, 32) !== null, `${c.x}: the cp1 itself is malformed, so it proves nothing`)
    assert(decodeCp1(c.cp1) === null && decodeNoteRef(c.cp1) === null, `${c.x}: decoded`)
  }
})

check('spends: each short form names the same note as its long form', () => {
  for (const f of spends.shortForms) {
    assert(decodeNoteRef(f.cp1Slot.hex) === f.Q && decodeNoteRef(f.cp1Slot.sameAs) === f.Q, `${f.Q}: cp1 slot`)
    assert(bytesToHex(decodeSpend(f.k1Slot.hex).outputKey) === f.Q, `${f.Q}: preimage`)
    assert(bytesToHex(decodeSpend(f.k1Slot.sameAs).outputKey) === f.Q, `${f.Q}: cw1`)
    assert(bearerSpend(hexToBytes(f.k1Slot.hex)) === f.k1Slot.sameAs, `${f.Q}: the preimage is not that cw1`)
  }
})

// ---- the runner ----

check("the runner's own ck1 is test vector 3's, and binds its domain", () => {
  const sk0 = hexToBytes(SPEC_TEXT.vector3.sk)
  const ck1 = keyPathSpend(sk0, 'mint.example')
  assert(ck1 === SPEC_TEXT.vector3.ck1, 'keyPathSpend(sk_0, "mint.example") is not vector 3\'s ck1')
  const proof = decode2('ck', ck1, 96)
  assert(proof, 'the runner ck1 does not decode')
  const pk = proof.subarray(0, 32)
  assert(!schnorr.verify(proof.subarray(32), keyPathSighash(pk, 'moneyer.dev'), pk), 'verifies at another domain')
  assert(
    !schnorr.verify(proof.subarray(32), sha256(utf8ToBytes('LNURLcash')), pk),
    'still signs the retired fixed message'
  )
})

console.log(
  failures === 0
    ? '\nvectors are self-consistent'
    : `\n${failures} check(s) failed`
)
process.exit(failures === 0 ? 0 : 1)
