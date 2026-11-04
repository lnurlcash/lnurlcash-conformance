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
import {decodeCx1 as graderDecodeCx1, encodeCx1 as graderEncodeCx1, registrationMessage, signRegistration, verifyRegistration} from '../runner/share.mjs'
import {readFeeAdvertisement} from '../runner/index.mjs'

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

// The grader reads Mint fees with its own parser; it must read every case
// exactly as the vectors say a WALLET does.
check("the grader's Mint fees parser reads every parse case as fees.json says", () => {
  for (const c of fees.parse) {
    const got = readFeeAdvertisement(c.metadata)
    assert(
      JSON.stringify(got.fee) === JSON.stringify(c.expect),
      `${c.metadata}: expected ${JSON.stringify(c.expect)}, the grader reads ${JSON.stringify(got.fee)}`
    )
    assert(got.unknown === Boolean(c.unknown), `${c.metadata}: unknown is ${got.unknown}`)
  }
})

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

// ---- LUD-26 key-path notes (part2.json) ----

const part2 = load('part2.json')
const N2 = secp256k1.Point.Fn.ORDER
const HARD = 0x80000000
const toNum = bytes => BigInt(`0x${bytesToHex(bytes)}`)
const to32 = n => hexToBytes(n.toString(16).padStart(64, '0'))
const be32 = n => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}
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
// A cx1 is chainCode || P with P a valid compressed point.
const decodeCx1 = value => {
  const bytes = decode2('cx', value, 65)
  if (!bytes || (bytes[32] !== 2 && bytes[32] !== 3)) return null
  try {
    secp256k1.Point.fromBytes(bytes.subarray(32))
  } catch {
    return null
  }
  return {chainCode: bytes.slice(0, 32), publicKey: bytes.slice(32)}
}
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
  return signature && signature[64] <= 3 ? {amountMsat, signature} : null
}
const lsmDigest = message =>
  sha256(sha256(cat(utf8ToBytes('Lightning Signed Message:'), utf8ToBytes(message))))
const recoverX = (signature, digest) => {
  const recIdFirst = cat(signature.subarray(64), signature.subarray(0, 64))
  return secp256k1.recoverPublicKey(recIdFirst, digest, {prehash: false}).slice(1)
}
const pubOf = key => secp256k1.Point.BASE.multiply(toNum(key)).toBytes(true)

// BIP-32, written again here so every key is re-derived by code the
// generator never ran.
const ckd = (node, index) => {
  const data = index >= HARD ? cat(Uint8Array.of(0), node.key) : pubOf(node.key)
  const I = hmac(sha512, node.chainCode, cat(data, be32(index)))
  const key = (toNum(I.subarray(0, 32)) + toNum(node.key)) % N2
  return {key: to32(key), chainCode: I.slice(32)}
}
const ckdPub = ({publicKey, chainCode}, index) => {
  assert(index < HARD, `CKDpub at hardened ${index}`)
  const I = hmac(sha512, chainCode, cat(publicKey, be32(index)))
  const point = secp256k1.Point.fromBytes(publicKey).add(secp256k1.Point.BASE.multiply(toNum(I.subarray(0, 32))))
  return {publicKey: point.toBytes(true), chainCode: I.slice(32)}
}
const masterOf = seed => {
  const I = hmac(sha512, utf8ToBytes('Bitcoin seed'), seed)
  return {key: I.slice(0, 32), chainCode: I.slice(32)}
}
// LUD-26's root S for a domain: LUD-05's steps 1-3 under m/139'.
const rootOf = (seed, domain) => {
  const cashRoot = ckd(masterOf(seed), HARD + 139)
  const hashingKey = ckd(cashRoot, 0).key
  const material = hmac(sha256, hashingKey, utf8ToBytes(domain))
  const view = new DataView(material.buffer, material.byteOffset, material.byteLength)
  const indices = [0, 4, 8, 12].map(offset => view.getUint32(offset, false))
  return {hashingKey, indices, node: indices.reduce(ckd, cashRoot)}
}
const pathString = (indices, below) =>
  `m/139'/${indices.join('/')}` + below.map(i => (i >= HARD ? `/${i - HARD}'` : `/${i}`)).join('')

// Some other domain the branch is not at, to prove a signature is bound.
const elsewhere = domain => (domain === 'moneyer.dev' ? 'mint.example' : 'moneyer.dev')

// Every note record, in part2.json's and nostr-seed.json's shape.
const checkNote = (label, root, below, n, domain) => {
  const node = below.concat(n.index).reduce(ckd, root.node)
  assert(n.index < HARD, `${label}: a hardened note index`)
  assert(n.path === pathString(root.indices, below.concat(n.index)), `${label}: path ${n.path}`)
  assert(bytesToHex(node.key) === n.noteSecretKey, `${label}: noteSecretKey`)
  const pk = pubOf(node.key)
  assert(bytesToHex(pk) === n.notePubkeyCompressed, `${label}: notePubkeyCompressed`)
  assert(bytesToHex(pk.slice(1)) === n.notePubkey, `${label}: Q is not x(pk)`)
  assert(encodeCp1(pk.slice(1)) === n.cp1, `${label}: cp1`)
  const sighash = keyPathSighash(pk.slice(1), domain)
  assert(bytesToHex(sighash) === n.sighash, `${label}: sighash`)
  const ck1 = decode2('ck', n.ck1, 96)
  assert(ck1 && bytesToHex(ck1.subarray(0, 32)) === n.notePubkey, `${label}: ck1 key`)
  assert(bytesToHex(ck1.subarray(32)) === n.keyPathSignature, `${label}: ck1 signature`)
  assert(schnorr.verify(ck1.subarray(32), sighash, pk.slice(1)), `${label}: does not verify at ${domain}`)
  assert(
    !schnorr.verify(ck1.subarray(32), keyPathSighash(pk.slice(1), elsewhere(domain)), pk.slice(1)),
    `${label}: verifies at ${elsewhere(domain)} too`
  )
  assert(keyPathSpend(node.key, domain) === n.ck1, `${label}: not the zero-aux ck1`)
}

const checkAccounts = (label, root, accounts, domain) => {
  const keys = []
  for (const a of accounts) {
    for (const [chain, notes] of [[0, a.wallet], [1, a.change]]) {
      for (const n of notes) {
        checkNote(`${label} ${a.account}'/${chain}/${n.index}`, root, [a.account + HARD, chain], n, domain)
        keys.push(n.notePubkey)
      }
    }
    for (const s of a.shares) {
      const below = [a.account + HARD, 2, s.share + HARD]
      const SL = `${label} ${a.account}'/2/${s.share}'`
      assert(s.path === pathString(root.indices, below), `${SL}: path`)
      const node = below.reduce(ckd, root.node)
      assert(bytesToHex(node.key) === s.sharePrivateKey, `${SL}: sharePrivateKey`)
      assert(bytesToHex(pubOf(node.key)) === s.sharePubkey, `${SL}: sharePubkey`)
      assert(bytesToHex(node.chainCode) === s.chainCode, `${SL}: chainCode`)
      const cx1 = decodeCx1(s.cx1)
      assert(cx1, `${SL}: cx1 does not decode as 65 bytes`)
      assert(bytesToHex(cx1.chainCode) === s.chainCode && bytesToHex(cx1.publicKey) === s.sharePubkey, `${SL}: cx1 is not chainCode || P`)
      assert(s.cx1.length === 113, `${SL}: cx1 is ${s.cx1.length} characters`)
      for (const n of s.notes) {
        checkNote(`${SL}/${n.index}`, root, below, n, domain)
        // what a SERVICE holding only the cx1 derives
        assert(bytesToHex(ckdPub(cx1, n.index).publicKey) === n.notePubkeyCompressed, `${SL}/${n.index}: CKDpub from the cx1`)
        keys.push(n.notePubkey)
      }
    }
  }
  assert(new Set(keys).size === keys.length, `${label}: two notes share a key`)
}

check('part2: every branch is bound to its host without the port, and its root re-derives', () => {
  assert(/TapSighash/.test(part2.conventions.ck1Signs), 'ck1Signs does not name the sighash')
  for (const b of part2.branches) {
    assert(b.domain === spendDomainOf(`http://${b.host}`), `${b.host}: domain ${b.domain}`)
    assert(!b.domain.includes(':'), `${b.host}: the domain carries a port`)
    const seed = mnemonicToSeedSync(b.mnemonic)
    assert(bytesToHex(seed) === b.seedHex, `${b.host}: seed`)
    const root = rootOf(seed, b.domain)
    assert(bytesToHex(root.hashingKey) === b.cashHashingKey, `${b.host}: cashHashingKey`)
    assert(root.indices.join() === b.domainIndices.join(), `${b.host}: domain indices`)
    assert(bytesToHex(root.node.key) + bytesToHex(root.node.chainCode) === b.serviceRoot, `${b.host}: serviceRoot`)
  }
  assert(part2.branches.some(b => b.host !== b.domain), 'no branch host carries a port, so the stripping goes untested')
})

check('part2: every wallet, change and share note re-derives, and every share note from its cx1 alone', () => {
  for (const b of part2.branches) {
    checkAccounts(b.host, rootOf(hexToBytes(b.seedHex), b.domain), b.accounts, b.domain)
  }
})

check('part2: both y parities, a second account, two shares and the largest note index are exercised', () => {
  const notes = part2.branches.flatMap(b =>
    b.accounts.flatMap(a => [...a.wallet, ...a.change, ...a.shares.flatMap(s => s.notes)])
  )
  assert(notes.some(n => n.notePubkeyCompressed.startsWith('02')), 'no even-y note')
  assert(notes.some(n => n.notePubkeyCompressed.startsWith('03')), 'no odd-y note, so the signer negation goes untested')
  assert(notes.some(n => n.index === HARD - 1), 'no note at index 2^31 - 1')
  for (const b of part2.branches) {
    assert(b.accounts.some(a => a.account === 1), `${b.host}: no second account`)
    assert(b.accounts[0].shares.length >= 2, `${b.host}: fewer than two shares`)
  }
})

check('part2: every certificate is the mint key over its domain, amount and Q', () => {
  const mintX = bytesToHex(hexToBytes(part2.mint.mintPubkey).slice(1))
  assert(
    bytesToHex(secp256k1.getPublicKey(hexToBytes(part2.mint.privateKey), true)) === part2.mint.mintPubkey,
    'mint key pair'
  )
  for (const c of part2.certificates) {
    assert(c.message === `LNURLcash:${c.domain}:${c.amountMsat}:${c.notePubkey}`, `${c.amountMsat}: message`)
    assert(bytesToHex(lsmDigest(c.message)) === c.digest, `${c.amountMsat}: digest`)
    const decoded = decodeCertificate(c.cs1)
    assert(decoded && decoded.amountMsat === c.amountMsat, `${c.amountMsat}: cs1 amount`)
    assert(bytesToHex(decoded.signature) === c.signature, `${c.amountMsat}: cs1 signature`)
    assert(bytesToHex(recoverX(decoded.signature, hexToBytes(c.digest))) === mintX, `${c.amountMsat}: recovers to the mint key`)
    // bound to its domain: the same signature recovers elsewhere to another key
    const other = lsmDigest(`LNURLcash:${elsewhere(c.domain)}:${c.amountMsat}:${c.notePubkey}`)
    assert(bytesToHex(recoverX(decoded.signature, other)) !== mintX, `${c.amountMsat}: verifies at ${elsewhere(c.domain)} too`)
  }
  const [first] = part2.certificates
  assert(
    part2.certificates.some(c => c.notePubkey === first.notePubkey && c.amountMsat === first.amountMsat && c.domain !== first.domain),
    'no certificate for the same note and amount at a second domain'
  )
  for (const c of part2.legacyCertificates) {
    assert(c.superseded === true, 'a legacy certificate is not marked superseded')
    assert(c.message === `LNURLcash:${c.amountMsat}:${c.notePubkey}`, `legacy ${c.amountMsat}: message`)
    const decoded = decodeCertificate(c.cs1)
    assert(decoded && bytesToHex(recoverX(decoded.signature, lsmDigest(c.message))) === mintX, `legacy ${c.amountMsat}: recovers`)
  }
})

check("part2: every address proof is by the share's own key, over action, domain, lowercased username and cx1", () => {
  const share = cx1 =>
    part2.branches.flatMap(b => b.accounts.flatMap(a => a.shares)).find(s => s.cx1 === cx1)
  for (const p of part2.addressProofs) {
    const label = `${p.action} ${p.username}@${p.domain}${p.role ? ` (${p.role})` : ''}`
    const expected =
      p.action === 'unregister'
        ? `LNURLcash:unregister:${p.domain}:${p.username.toLowerCase()}`
        : `LNURLcash:${p.action}:${p.domain}:${p.username.toLowerCase()}:${p.cx1}`
    assert(['register', 'update', 'unregister'].includes(p.action), `${label}: action`)
    assert(p.message === expected, `${label}: message`)
    assert(bytesToHex(sha256(utf8ToBytes(p.message))) === p.digest, `${label}: digest`)
    const signer = share(p.signerCx1)
    assert(signer, `${label}: signerCx1 names no share`)
    assert(p.signerPubkey === signer.sharePubkey.slice(2), `${label}: signerPubkey is not x(P)`)
    assert(schnorr.verify(hexToBytes(p.signature), hexToBytes(p.digest), hexToBytes(p.signerPubkey)), `${label}: does not verify`)
    assert(
      bytesToHex(schnorr.sign(hexToBytes(p.digest), hexToBytes(signer.sharePrivateKey), new Uint8Array(32))) === p.signature,
      `${label}: not the zero-aux signature by the share key`
    )
    if (p.action !== 'unregister') {
      // the superseded message without the cx1 must not verify
      const old = sha256(utf8ToBytes(`LNURLcash:${p.action}:${p.domain}:${p.username.toLowerCase()}`))
      assert(!schnorr.verify(hexToBytes(p.signature), old, hexToBytes(p.signerPubkey)), `${label}: verifies without the cx1`)
    }
  }
  const proofs = part2.addressProofs
  const by = (action, username, domain, role) =>
    proofs.find(p => p.action === action && p.username === username && p.domain === domain && p.role === role)
  const register = by('register', 'alice', 'mint.example')
  const update = by('update', 'alice', 'mint.example', 'sig')
  const newsig = by('register', 'alice', 'mint.example', 'newsig')
  assert(register && update && newsig, 'no register, update and newsig for alice@mint.example')
  assert(update.signerCx1 === register.cx1 && update.cx1 === newsig.cx1 && newsig.signerCx1 === newsig.cx1, 'the update is not by the key on file to the new cx1')
  assert(register.signature !== by('register', 'bob', 'mint.example').signature, 'username separation')
  assert(register.signature !== by('register', 'alice', 'moneyer.dev').signature, 'domain separation')
  assert(register.signature === by('register', 'Alice', 'mint.example').signature, 'the username is not lowercased before signing')
})

check('part2: the legacy schemes recompute and match no LUD-26 key', () => {
  const tag = sha256(utf8ToBytes('LNURLcash/derive'))
  const current = new Set(
    part2.branches.flatMap(b => b.accounts.flatMap(a => [...a.wallet, ...a.change, ...a.shares.flatMap(s => s.notes)])).map(n => n.notePubkey)
  )
  assert(part2.legacy.superseded === true, 'the legacy record is not marked superseded')
  assert(part2.legacy.branches.some(b => b.branchParity === 'odd'), 'no odd-parity legacy branch, so its negation goes untested')
  for (const b of part2.legacy.branches) {
    // the node hashed the host as stored, port included
    const cashRoot = ckd(masterOf(mnemonicToSeedSync(b.mnemonic)), HARD + 139)
    const material = hmac(sha256, ckd(cashRoot, 0).key, utf8ToBytes(b.host))
    const view = new DataView(material.buffer, material.byteOffset, material.byteLength)
    const node = [0, 4, 8, 12].map(o => view.getUint32(o, false)).reduce(ckd, cashRoot)
    assert(bytesToHex(node.key) + bytesToHex(node.chainCode) === b.addressNode, `legacy ${b.host}: node`)
    const P = secp256k1.Point.BASE.multiply(toNum(node.key))
    const x = P.toBytes(true).slice(1)
    assert(bytesToHex(x) === b.branchPubkey && (P.y % 2n === 0n ? 'even' : 'odd') === b.branchParity, `legacy ${b.host}: P`)
    assert(bytesToHex(decode2('cx', b.cx1, 64) ?? new Uint8Array()) === b.branchPubkey + b.chainCode, `legacy ${b.host}: 64-byte cx1`)
    const lifted = secp256k1.Point.fromBytes(cat(Uint8Array.of(0x02), x))
    const p = toNum(node.key)
    const derive = (label, parts, n) => {
      const t = toNum(sha256(cat(tag, tag, x, node.chainCode, ...parts))) % N2
      assert(bytesToHex(lifted.add(secp256k1.Point.BASE.multiply(t)).toBytes(true).slice(1)) === n.notePubkey, `${label}: watch-only pk`)
      const sk = ((P.y % 2n === 0n ? p : N2 - p) + t) % N2
      assert(bytesToHex(to32(sk)) === n.noteSecretKey, `${label}: sk`)
      assert(encodeCp1(hexToBytes(n.notePubkey)) === n.cp1, `${label}: cp1`)
      assert(!current.has(n.notePubkey), `${label}: collides with a LUD-26 key`)
    }
    for (const n of b.notes) derive(`legacy ${b.host} ${n.purpose}/${n.index}`, [be32(n.purpose), be32(n.index)], n)
    for (const n of b.prePurpose) derive(`pre-purpose ${b.host} ${n.index}`, [be32(n.index)], n)
  }
})

check('part2: the valid strings decode and the invalid ones do not, for the reason given', () => {
  const decodeAs = (type, value) => {
    if (type === 'cs1') return decodeCertificate(value)?.signature ?? null
    if (type === 'cx1') {
      const cx1 = decodeCx1(value)
      return cx1 ? cat(cx1.chainCode, cx1.publicKey) : null
    }
    const [hrp, length] = {cp1: ['cp', 32], ck1: ['ck', 96]}[type]
    return decode2(hrp, value, length)
  }
  for (const v of part2.valid) {
    const bytes = decodeAs(v.type, v.value)
    assert(bytes && bytesToHex(bytes) === v.bytes, `valid ${v.type}: ${v.why}`)
  }
  for (const v of part2.invalid) {
    assert(decodeAs(v.type, v.value) === null, `invalid ${v.type} decoded: ${v.why}`)
    assert(typeof v.why === 'string' && v.why.length > 0, `invalid ${v.type}: no reason given`)
  }
})

// ---- the Nostr-key branch extension ----

const nostrSeed = load('nostr-seed.json')

check('nostr-seed: marked as an extension, not LUD-25/26', () => {
  assert(nostrSeed.extension === true && nostrSeed.label === 'LNURLcash/nostr-seed', 'extension/label')
})

check('nostr-seed: every seed, root and note recomputes', () => {
  for (const c of nostrSeed.cases) {
    const identity = hexToBytes(c.identity)
    const seed = hmac(sha256, identity, utf8ToBytes(nostrSeed.label))
    assert(bytesToHex(seed) === c.seed, `${c.host}: seed`)
    assert(bytesToHex(pubOf(identity).slice(1)) === c.identityPubkey, `${c.host}: identityPubkey`)
    assert(c.domain === spendDomainOf(`http://${c.host}`), `${c.host}: domain ${c.domain}`)
    const root = rootOf(seed, c.domain)
    assert(bytesToHex(root.node.key) + bytesToHex(root.node.chainCode) === c.serviceRoot, `${c.host}: serviceRoot`)
    checkAccounts(`nostr ${c.host}`, root, c.accounts, c.domain)
  }
})

// ---- LUD-25's and LUD-26's own test vectors ----
//
// spec-vectors.json is produced by the generator from the primitives. Two
// independent checks hold it to the spec: every value is compared with the
// typed copy of lnurl/luds' own 25-vectors.json and 26-vectors.json in
// tools/luds/ (the one place in this repo those numbers are written down
// rather than computed), and every value is recomputed with the grader's own
// primitives and the code here.

const LUDS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'luds')
const LUDS_25 = JSON.parse(readFileSync(join(LUDS_DIR, '25-vectors.json'), 'utf8'))
const LUDS_26 = JSON.parse(readFileSync(join(LUDS_DIR, '26-vectors.json'), 'utf8'))
const specVectors = load('spec-vectors.json')

// Every value luds publishes must be in the file with the same value;
// descriptions are prose and may differ.
const sameAsSpec = (label, fromFile, fromSpec) => {
  if (Array.isArray(fromSpec)) {
    assert(Array.isArray(fromFile) && fromFile.length === fromSpec.length, `${label}: length`)
    fromSpec.forEach((value, i) => sameAsSpec(`${label}[${i}]`, fromFile[i], value))
  } else if (fromSpec !== null && typeof fromSpec === 'object') {
    assert(fromFile !== null && typeof fromFile === 'object', `${label}: missing`)
    for (const key of Object.keys(fromSpec)) {
      if (key !== 'description') sameAsSpec(`${label}.${key}`, fromFile[key], fromSpec[key])
    }
  } else {
    assert(fromFile === fromSpec, `${label}: ${JSON.stringify(fromFile)}, luds says ${JSON.stringify(fromSpec)}`)
  }
}

check("spec-vectors: lud25 is luds' 25-vectors.json", () => {
  sameAsSpec('lud25', specVectors.lud25, LUDS_25)
})
check("spec-vectors: lud26 is luds' 26-vectors.json", () => {
  sameAsSpec('lud26', specVectors.lud26, LUDS_26)
})

check('spec-vectors: lud26 derivation re-derives from its seeds, every share note from its cx1', () => {
  for (const dv of LUDS_26.derivation) {
    const root = rootOf(hexToBytes(dv.seed), dv.domain)
    assert(bytesToHex(root.hashingKey) === dv.cashHashingKey, `${dv.domain}: cashHashingKey`)
    assert(root.indices.join() === dv.d.join(), `${dv.domain}: d`)
    const checkLudNote = (label, below, n) => {
      const node = below.concat(n.i).reduce(ckd, root.node)
      assert(n.path === pathString(root.indices, below.concat(n.i)), `${label}: path`)
      assert(bytesToHex(node.key) === n.sk, `${label}: sk`)
      const pk = pubOf(node.key)
      assert(bytesToHex(pk) === n.pk && bytesToHex(pk.slice(1)) === n.Q, `${label}: pk/Q`)
      assert(encodeCp1(pk.slice(1)) === n.cp1, `${label}: cp1`)
    }
    for (const a of dv.accounts) {
      for (const [chain, c] of [[0, a.wallet], [1, a.change]]) {
        assert(c.path === `${pathString(root.indices, [a.account + HARD, chain])}/i`, `${dv.domain} ${a.account}/${chain}: path`)
        for (const n of c.notes) checkLudNote(`${dv.domain} ${a.account}'/${chain}/${n.i}`, [a.account + HARD, chain], n)
      }
      for (const s of a.shareable) {
        const below = [a.account + HARD, 2, s.share + HARD]
        const node = below.reduce(ckd, root.node)
        assert(bytesToHex(node.key) === s.p && bytesToHex(pubOf(node.key)) === s.P && bytesToHex(node.chainCode) === s.chaincode, `${dv.domain} share ${s.share}: p/P/chaincode`)
        const cx1 = decodeCx1(s.cx1)
        assert(cx1 && bytesToHex(cx1.publicKey) === s.P && bytesToHex(cx1.chainCode) === s.chaincode, `${dv.domain} share ${s.share}: cx1`)
        for (const n of s.notes) {
          checkLudNote(`${dv.domain} share ${s.share}/${n.i}`, below, n)
          assert(bytesToHex(ckdPub(cx1, n.i).publicKey) === n.pk, `${dv.domain} share ${s.share}/${n.i}: CKDpub`)
        }
      }
    }
  }
  const parities = LUDS_26.derivation.flatMap(dv => dv.accounts.flatMap(a => a.wallet.notes.map(n => n.pk.slice(0, 2))))
  assert(parities.includes('02') && parities.includes('03'), 'the wallet notes do not cover both y parities')
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

const checkKeyPathSpend = (label, v, sk) => {
  const Q = hexToBytes(v.Q)
  assert(bytesToHex(schnorr.getPublicKey(sk)) === v.Q, `${label}: Q is not x(sk·G)`)
  assert(encodeCp1(Q) === v.cp1, `${label}: cp1`)
  assert(bytesToHex(spendPrevout(v.domain)) === v.prevout_txid, `${label}: prevout`)
  assert(v.spent_script_pubkey === `5120${v.Q}`, `${label}: spent scriptPubKey`)
  const sigMsg = spendSigMsg({outputKey: Q, domain: v.domain, locktime: 0, sequence: 0xffffffff})
  assert(sigMsg.length === 174, `${label}: SigMsg is ${sigMsg.length} bytes`)
  assert(bytesToHex(sigMsg) === v.sigmsg, `${label}: SigMsg`)
  assert(Object.values(v.sigmsg_fields).join('') === v.sigmsg, `${label}: the named fields do not concatenate to SigMsg`)
  const sighash = keyPathSighash(Q, v.domain)
  assert(bytesToHex(sighash) === v.sighash, `${label}: sighash`)
  assert(bytesToHex(schnorr.sign(sighash, sk, new Uint8Array(32))) === v.sig, `${label}: zero-aux signature`)
  assert(schnorr.verify(hexToBytes(v.sig), sighash, Q), `${label}: signature`)
  assert(bytesToHex(canonicalTx(v.domain, 0, 0xffffffff, [hexToBytes(v.sig)])) === v.spend_tx, `${label}: spend transaction`)
  assert(encodeCk1(Q, hexToBytes(v.sig)) === v.ck1, `${label}: ck1`)
  assert(keyPathSpend(sk, v.domain) === v.ck1, `${label}: the grader's own ck1 differs`)
  assert(!schnorr.verify(hexToBytes(v.sig), keyPathSighash(Q, elsewhere(v.domain)), Q), `${label}: verifies at another domain`)
}

check('spec-vectors: lud25 key_path_spend recomputes, from the prevout to the serialised spend', () => {
  checkKeyPathSpend('lud25', LUDS_25.key_path_spend, hexToBytes(LUDS_25.key_path_spend.sk))
})

check('spec-vectors: lud26 key_path_spend signs with the negated key of an odd-y note', () => {
  const v = LUDS_26.key_path_spend
  const note = LUDS_26.derivation[0].accounts[0].wallet.notes.find(n => n.path === v.path)
  assert(note && note.sk === v.sk && note.pk === v.pk, 'key_path_spend names no derived note')
  assert(v.pk.startsWith('03'), 'the spend vector pk has even y, so the negation goes untested')
  assert(bytesToHex(to32(N2 - toNum(hexToBytes(v.sk)))) === v.signing_sk, 'signing_sk is not n - sk')
  checkKeyPathSpend('lud26', v, hexToBytes(v.sk))
})

const checkCertificate = (label, c, domain, qHex, mintPubkey) => {
  assert(c.message === `LNURLcash:${domain}:${c.amount_msat}:${qHex}`, `${label}: message`)
  assert(bytesToHex(lsmDigest(c.message)) === c.digest, `${label}: digest`)
  const decoded = decodeCertificate(c.cs1)
  assert(decoded && decoded.amountMsat === c.amount_msat && bytesToHex(decoded.signature) === c.signature, `${label}: cs1`)
  assert(bytesToHex(recoverX(decoded.signature, hexToBytes(c.digest))) === mintPubkey.slice(2), `${label}: recovers`)
}

check("spec-vectors: lud25's certificates recover to its mintPubkey and bind the domain", () => {
  const v = LUDS_25.certificates
  assert(bytesToHex(secp256k1.getPublicKey(hexToBytes(v.service_sk), true)) === v.mintPubkey, 'mint key pair')
  assert(bytesToHex(sha256(utf8ToBytes('LUD-25 test vector mint node'))) === v.service_sk, 'mint seed label')
  for (const c of v.cases) checkCertificate(`certificate ${c.amount_msat}`, c, v.domain, v.Q, v.mintPubkey)
})

check('spec-vectors: lud25 bearer note recomputes, and its certificate is over hex(Q) at its domain', () => {
  const v = LUDS_25.bearer_note
  const preimage = hexToBytes(v.preimage)
  assert(bytesToHex(sha256(preimage)) === v.h, 'h')
  const note = bearerNote(hexToBytes(v.h))
  assert(bytesToHex(note.leaf) === v.leaf, 'leaf')
  assert(bytesToHex(tapLeafHash(note.leaf)) === v.tapleaf_hash, 'tapleaf hash')
  assert(bytesToHex(NUMS_H) === v.H, 'H')
  const tweaked = taprootTweak(NUMS_H, tapLeafHash(note.leaf))
  assert(tweaked.tweak.toString(16).padStart(64, '0') === v.tweak, 'tweak')
  assert(bytesToHex(note.outputKey) === v.Q, 'Q')
  assert(bytesToHex(note.controlBlock) === v.control_block, 'control block')
  assert(encodeCp1(note.outputKey) === v.cp1, 'cp1')
  assert(bearerSpend(preimage) === v.cw1, 'cw1')
  assert(bytesToHex(decodeSpend(v.cw1).outputKey) === v.Q, 'the cw1 opens another Q')
  assert(bytesToHex(decodeSpend(v.preimage).outputKey) === v.Q, 'the preimage opens another Q')
  assert(decodeNoteRef(v.h) === v.Q && decodeNoteRef(v.cp1) === v.Q, 'the short forms name another note')
  const url = new URL(v.note_url.replace(/^lnurlw:/, 'https:'))
  checkCertificate('bearer certificate', v.certificate, url.hostname, v.Q, LUDS_25.certificates.mintPubkey)
  assert(url.searchParams.get('k1') === v.preimage && url.searchParams.get('c') === v.certificate.cs1, 'certified note URL')
  assert(!url.searchParams.has('sig'), 'the certified note URL still carries the pre-50d740a sig')
})

check("spec-vectors: lud26 registration proofs verify under each share's x(P), bound to domain and cx1", () => {
  const r = LUDS_26.registration
  const shares = LUDS_26.derivation[1].accounts[0].shareable
  const [old, renewed] = shares
  assert(r.domain === LUDS_26.derivation[1].domain && r.cx1 === old.cx1 && r.new_cx1 === renewed.cx1, 'proofs name other shares')
  const verify = (label, proof, message, share) => {
    assert(proof.message === message, `${label}: message`)
    assert(bytesToHex(sha256(utf8ToBytes(message))) === proof.digest, `${label}: digest`)
    assert(schnorr.verify(hexToBytes(proof.sig), hexToBytes(proof.digest), hexToBytes(share.P).slice(1)), `${label}: does not verify`)
    assert(bytesToHex(schnorr.sign(hexToBytes(proof.digest), hexToBytes(share.p), new Uint8Array(32))) === proof.sig, `${label}: not zero-aux`)
  }
  const at = `${r.domain}:${r.username}`
  verify('register', r.register, `LNURLcash:register:${at}:${r.cx1}`, old)
  verify('update sig', r.update.sig, `LNURLcash:update:${at}:${r.new_cx1}`, old)
  verify('update newsig', r.update.newsig, `LNURLcash:register:${at}:${r.new_cx1}`, renewed)
  verify('unregister', r.unregister, `LNURLcash:unregister:${at}`, renewed)
})

// The grader's own LUD-26 reading, held to luds' numbers: every share's cx1
// and every registration proof, reproduced byte for byte with the zero
// aux_rand 26-vectors.json signs with.
check("the grader's cx1s and registration proofs are luds' own", () => {
  for (const derivation of LUDS_26.derivation) {
    for (const account of derivation.accounts) {
      for (const share of account.shareable) {
        assert(graderEncodeCx1(hexToBytes(share.chaincode), hexToBytes(share.P)) === share.cx1, `${share.path}: cx1`)
        const decoded = graderDecodeCx1(share.cx1)
        assert(decoded && bytesToHex(decoded.chainCode) === share.chaincode && bytesToHex(decoded.pubkey) === share.P, `${share.path}: cx1 decodes`)
      }
    }
  }
  const r = LUDS_26.registration
  const [old, renewed] = LUDS_26.derivation[1].accounts[0].shareable
  const zero = new Uint8Array(32)
  for (const [label, proof, message, share] of [
    ['register', r.register, registrationMessage('register', r.domain, r.username, r.cx1), old],
    ['update sig', r.update.sig, registrationMessage('update', r.domain, r.username, r.new_cx1), old],
    ['update newsig', r.update.newsig, registrationMessage('register', r.domain, r.username, r.new_cx1), renewed],
    ['unregister', r.unregister, registrationMessage('unregister', r.domain, r.username), renewed]
  ]) {
    assert(message === proof.message, `${label}: message`)
    assert(signRegistration(message, hexToBytes(share.p), zero) === proof.sig, `${label}: signature`)
    assert(verifyRegistration(message, proof.sig, hexToBytes(share.P).slice(1)), `${label}: does not verify`)
  }
  assert(registrationMessage('register', 'Cash.Example.COM', 'Alice', r.cx1) === r.register.message, 'domain and username are lowercased')
  assert(graderDecodeCx1(bech32m.encode('cx', bech32m.toWords(hexToBytes(old.chaincode + old.P.slice(2))), 200)) === null, 'the 64-byte pre-a6c4652 shape decodes as a cx1')
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
  assert(byDomain.get('mint.example').ck1 === LUDS_25.key_path_spend.ck1, "mint.example's ck1 is not LUD-25's key_path_spend")
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

check("the runner's own ck1 is LUD-25's key_path_spend, and binds its domain", () => {
  const sk0 = hexToBytes(LUDS_25.key_path_spend.sk)
  const ck1 = keyPathSpend(sk0, 'mint.example')
  assert(ck1 === LUDS_25.key_path_spend.ck1, 'keyPathSpend(sk, "mint.example") is not LUD-25\'s key_path_spend ck1')
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
