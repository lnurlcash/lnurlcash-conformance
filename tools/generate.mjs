// Generates the LNURLcash conformance vectors.
//
// Deliberately written against @noble/@scure directly rather than against
// any lnurlcash library: these vectors exist to catch an implementation
// disagreeing with the spec, which they cannot do if they were produced by
// one of the implementations under test. Every value here is derived from
// the LUD-25 draft text and the LUD-01/03/06/16/21 primitives it builds on.
//
// Deterministic by construction - fixed keys, fixed secrets, no randomness -
// so regenerating produces a byte-identical tree and a diff means a real
// change.

import {writeFileSync, mkdirSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {bech32, bech32m, base64urlnopad} from '@scure/base'
import {sha256, sha512} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {hmac} from '@noble/hashes/hmac.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {mnemonicToSeedSync} from '@scure/bip39'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = join(HERE, '..', 'vectors')
mkdirSync(OUT, {recursive: true})

const VERSION = 1
const SPEC = 'LUD-25 draft (lnurl/luds#301)'

const write = (name, body) => {
  const path = join(OUT, name)
  writeFileSync(path, JSON.stringify(body, null, 2) + '\n')
  return name
}

// ---- fixed test material -------------------------------------------------

// a mint's identity key. Fixed, obviously not secret, and never to be used
// for anything but producing these vectors.
const MINT_PRIV = hexToBytes(
  '1111111111111111111111111111111111111111111111111111111111111111'
)
const MINT_PUB = bytesToHex(secp256k1.getPublicKey(MINT_PRIV, true))
const OTHER_PRIV = hexToBytes(
  '2222222222222222222222222222222222222222222222222222222222222222'
)
const OTHER_PUB = bytesToHex(secp256k1.getPublicKey(OTHER_PRIV, true))
// the key this mint signed under before it rotated. Still published, so
// notes it issued before the rotation still verify.
const PREV_PRIV = hexToBytes(
  '3333333333333333333333333333333333333333333333333333333333333333'
)
const PREV_PUB = bytesToHex(secp256k1.getPublicKey(PREV_PRIV, true))

const K1_A = 'a'.repeat(64)
const K1_B = 'b'.repeat(64)
const K1_C = '0f'.repeat(32)

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

// ---- the signature scheme ------------------------------------------------

const LSM_PREFIX = 'Lightning Signed Message:'
const DOMAIN_TAG = 'LNURLcash'

const sigMessage = (k1, amountMsat) =>
  `${DOMAIN_TAG}:${amountMsat}:${noteId(k1)}`

const sigDigest = (k1, amountMsat) =>
  sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes(LSM_PREFIX),
        ...utf8ToBytes(sigMessage(k1, amountMsat))
      ])
    )
  )

// @noble's 'recovered' format is recovery-id-leading (recid || r || s).
// LUD-25's wire format is r || s || recid, matching a raw BOLT-11
// signature - so the canonical vector reorders, and the leading form is
// emitted separately as the interop case some mints have actually sent.
const signLeading = (priv, k1, amountMsat) =>
  secp256k1.sign(sigDigest(k1, amountMsat), priv, {
    format: 'recovered',
    prehash: false
  })

const signTrailing = (priv, k1, amountMsat) => {
  const lead = signLeading(priv, k1, amountMsat)
  return new Uint8Array([...lead.subarray(1), lead[0]])
}

// ---- vectors: signature --------------------------------------------------

const sigCase = (name, opts) => ({
  name,
  k1: opts.k1,
  noteId: noteId(opts.k1),
  amountMsat: opts.amountMsat,
  message: sigMessage(opts.k1, opts.amountMsat),
  digest: bytesToHex(sigDigest(opts.k1, opts.amountMsat)),
  signature: opts.signature,
  mintPubkey: opts.mintPubkey,
  valid: opts.valid,
  note: opts.note
})

const signature = {
  version: VERSION,
  spec: SPEC,
  description:
    'Offline verification of a note (LUD-25). A SERVICE signs (note id, amount) with a stable secp256k1 key it controls; this should be the funding node identity where compatible signing exists, or may be a dedicated persistent SERVICE key otherwise. A holder recovers the pubkey and compares it to the pinned current or previous mintPubkey without contacting the SERVICE.',
  scheme: {
    domainTag: DOMAIN_TAG,
    lightningSignedMessagePrefix: LSM_PREFIX,
    message: '"LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))',
    digest: 'sha256(sha256(prefix_utf8 || message_utf8))',
    signature: '65 bytes, r || s || recovery_id, hex encoded',
    pubkey: '33-byte compressed secp256k1 point, hex encoded',
    verification:
      'recover the pubkey from digest with NO further hashing (prehash must be off) and compare to mintPubkey. A verifier MUST also accept recovery_id || r || s, which some SERVICEs emit; trying both is safe because the wrong ordering recovers an unrelated key that cannot match.'
  },
  mintPubkey: MINT_PUB,
  otherPubkey: OTHER_PUB,
  cases: [
    sigCase('valid, canonical trailing recovery id', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'the wire format LUD-25 specifies'
    }),
    sigCase('valid, leading recovery id (real-world interop)', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signLeading(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'lnurl-mint once forwarded its node signmessage output unreordered; a verifier must tolerate this layout'
    }),
    sigCase('valid, zero amount', {
      k1: K1_C,
      amountMsat: 0,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_C, 0)),
      mintPubkey: MINT_PUB,
      valid: true
    }),
    sigCase('valid, large amount', {
      k1: K1_B,
      amountMsat: 2100000000000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_B, 2100000000000)),
      mintPubkey: MINT_PUB,
      valid: true,
      note: 'above 2^32 msat - implementations must not truncate the amount to 32 bits'
    }),
    sigCase('invalid: amount does not match what was signed', {
      k1: K1_A,
      amountMsat: 21001,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'the whole point of signing the amount: a note cannot be inflated after issuance'
    }),
    sigCase('invalid: different k1 than was signed', {
      k1: K1_B,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signed by a different key', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(OTHER_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signature is not hex', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'not-hex-at-all',
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'must return false, never throw'
    }),
    sigCase('invalid: signature too short', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'ab'.repeat(10),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: signature too long', {
      k1: K1_A,
      amountMsat: 21000,
      signature: 'ab'.repeat(70),
      mintPubkey: MINT_PUB,
      valid: false
    }),
    sigCase('invalid: empty signature', {
      k1: K1_A,
      amountMsat: 21000,
      signature: '',
      mintPubkey: MINT_PUB,
      valid: false
    }),
    {
      name: 'invalid: k1 is not hex',
      k1: 'zzzz',
      noteId: null,
      amountMsat: 21000,
      message: null,
      digest: null,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: MINT_PUB,
      valid: false,
      note: 'a malformed stored k1 must verify as false rather than crash the caller'
    },
    sigCase('invalid: mintPubkey is not a point', {
      k1: K1_A,
      amountMsat: 21000,
      signature: bytesToHex(signTrailing(MINT_PRIV, K1_A, 21000)),
      mintPubkey: 'ff'.repeat(33),
      valid: false
    })
  ],
  // Signing-key rotation. A SERVICE that rotates its signing key keeps
  // publishing the old public keys, so the notes it already issued do not
  // all stop verifying at once. These cases carry a LIST of acceptable
  // keys rather than the single mintPubkey the cases above carry, and
  // live in their own block for exactly that reason: a verifier that
  // knows nothing about rotation reads `cases` and is unaffected.
  rotation: {
    description:
      'A note signed under a key the SERVICE has since rotated away from. Valid means the signature recovers a key that appears anywhere in mintPubkeys - the current key first, then any previously published one. The same signature against a list that no longer names the old key is invalid, which is what makes the published list load-bearing rather than decorative: a SERVICE cannot retire a key and still have its old notes verify, and an attacker cannot have a key accepted by asserting it.',
    currentPubkey: MINT_PUB,
    previousPubkey: PREV_PUB,
    cases: [
      {
        name: 'valid: signed under a previous key, both keys published',
        k1: K1_A,
        noteId: noteId(K1_A),
        amountMsat: 21000,
        message: sigMessage(K1_A, 21000),
        digest: bytesToHex(sigDigest(K1_A, 21000)),
        signature: bytesToHex(signTrailing(PREV_PRIV, K1_A, 21000)),
        mintPubkeys: [MINT_PUB, PREV_PUB],
        valid: true,
        note: 'the note was issued before the rotation; grading it as forged would punish a SERVICE for rotating properly'
      },
      {
        name: 'invalid: the same signature with only the current key published',
        k1: K1_A,
        noteId: noteId(K1_A),
        amountMsat: 21000,
        message: sigMessage(K1_A, 21000),
        digest: bytesToHex(sigDigest(K1_A, 21000)),
        signature: bytesToHex(signTrailing(PREV_PRIV, K1_A, 21000)),
        mintPubkeys: [MINT_PUB],
        valid: false,
        note: 'byte for byte the signature above - only the published list changed, and that alone decides it'
      },
      {
        name: 'valid: signed under the current key while a previous one is published',
        k1: K1_B,
        noteId: noteId(K1_B),
        amountMsat: 21000,
        message: sigMessage(K1_B, 21000),
        digest: bytesToHex(sigDigest(K1_B, 21000)),
        signature: bytesToHex(signTrailing(MINT_PRIV, K1_B, 21000)),
        mintPubkeys: [MINT_PUB, PREV_PUB],
        valid: true,
        note: 'a longer list must not stop the current key from verifying'
      },
      {
        name: 'invalid: signed under a key that was never published',
        k1: K1_A,
        noteId: noteId(K1_A),
        amountMsat: 21000,
        message: sigMessage(K1_A, 21000),
        digest: bytesToHex(sigDigest(K1_A, 21000)),
        signature: bytesToHex(signTrailing(OTHER_PRIV, K1_A, 21000)),
        mintPubkeys: [MINT_PUB, PREV_PUB],
        valid: false,
        note: 'accepting a list must not become accepting anything'
      }
    ]
  }
}

// ---- vectors: derivation (deterministic note secrets) --------------------

// A note's k1 is WALLET-generated: LUD-25 says nothing about how, so a
// wallet is free to derive it. Deriving it from a seed is what makes a
// wallet restorable from words alone, and makes two implementations of the
// same wallet agree on the same notes. The scheme is HMAC-SHA256 twice: a
// domain-separated root over the seed bytes, then one secret per
// "host:index". Nothing here goes on the wire; the mint only ever sees
// sha256(k1), exactly as before.

const DERIVE_ROOT_KEY = 'lnurlcash-note-v1'

const deriveRoot = seed => hmac(sha256, utf8ToBytes(DERIVE_ROOT_KEY), seed)

const deriveSecret = (root, host, index) =>
  bytesToHex(hmac(sha256, root, utf8ToBytes(`${host}:${index}`)))

// The two standard BIP39 test mnemonics, so a reader can sanity-check the
// seed half of the vector against any BIP39 implementation before trusting
// the derivation half.
const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const MNEMONIC_B =
  'legal winner thank year wave sausage worth useful legal winner thank yellow'

const seedOf = mnemonic => mnemonicToSeedSync(mnemonic)

const derivationCase = (name, mnemonic, host, index) => {
  const seed = seedOf(mnemonic)
  const k1 = deriveSecret(deriveRoot(seed), host, index)
  return {
    name,
    mnemonic,
    seedHex: bytesToHex(seed),
    host,
    index,
    k1,
    noteId: noteId(k1)
  }
}

const derivation = {
  version: VERSION,
  spec: SPEC,
  description:
    'Deterministic note secrets from a BIP39 seed. k1 is WALLET-generated in LUD-25, so a wallet may derive it rather than draw it at random; deriving it is what lets a wallet be restored from words alone and lets two implementations of the same wallet agree on the same notes. Both steps are HMAC-SHA256: root = HMAC-SHA256(key = utf8("lnurlcash-note-v1"), msg = seed bytes), then k1 = HMAC-SHA256(key = root, msg = utf8(host + ":" + index)), 32 bytes, lowercase hex. host is the mint host exactly as the wallet stores it, lowercase, with the port when there is one; index is decimal ASCII counting from 0. seedHex is the 64-byte BIP39 seed with no passphrase, included so an implementation with no BIP39 library can still test the derivation. The mint sees only sha256(k1) as before, so nothing about this is observable on the wire.',
  scheme: {
    rootKey: DERIVE_ROOT_KEY,
    rootMsg: 'seed bytes',
    secretMsg: 'host:index'
  },
  cases: [
    derivationCase('standard mnemonic, index 0', MNEMONIC_A, 'mint.example', 0),
    derivationCase('standard mnemonic, index 1', MNEMONIC_A, 'mint.example', 1),
    derivationCase('standard mnemonic, index 2', MNEMONIC_A, 'mint.example', 2),
    derivationCase('standard mnemonic, index 19', MNEMONIC_A, 'mint.example', 19),
    derivationCase(
      'standard mnemonic, index 20 (one past a 20-index gap limit)',
      MNEMONIC_A,
      'mint.example',
      20
    ),
    derivationCase('a second mnemonic, same host and index', MNEMONIC_B, 'mint.example', 0),
    derivationCase('a host carrying a port', MNEMONIC_A, '127.0.0.1:8899', 0)
  ]
}


// ---- vectors: cash derivation (LUD-25's own m/139' scheme) ----------------

// The scheme LUD-25's "Seed-recoverable note secrets" section actually
// specifies, as opposed to the HMAC one above, which predates it and is kept
// only so notes minted under it stay findable:
//
//   cashHashingKey   = derive(masterKey, m/139'/0)
//   domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//   (d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//   secret_i         = derive(masterKey, m/139'/d1/d2/d3/d4/i')
//
// The one thing that has to be pinned, and the reason `hardened` is spelled
// out per case below: d1..d4 are RAW uint32, and BIP-32 already reads any
// index >= 2^31 as hardened. They are used exactly as they fall - nothing
// masked, nothing forced - so which levels are hardened is decided by the
// mint's own host name. That is "exactly as LUD-05" and it is what the
// reference wallet does. An implementation that masks the top bit, or that
// hardens all four, derives a different tree and restores nothing.
//
// BIP-32 is implemented here from its own primitives rather than pulled in,
// for the reason at the top of this file: a vector produced by the same
// library an implementation uses proves nothing. `bip32Vector1` below is
// BIP-32's own published test vector, so the primitive is checkable before
// any of the LUD-25 values are.

const HARDENED = 0x80000000
const CURVE_N = secp256k1.Point.Fn.ORDER
const bytesToNumber = bytes => BigInt(`0x${bytesToHex(bytes)}`)
const numberTo32 = value => hexToBytes(value.toString(16).padStart(64, '0'))

const ckdPriv = ({privateKey, chainCode}, index) => {
  const data = new Uint8Array(37)
  if (index >= HARDENED) {
    data.set(privateKey, 1)
  } else {
    data.set(secp256k1.Point.BASE.multiply(bytesToNumber(privateKey)).toBytes(true), 0)
  }
  new DataView(data.buffer).setUint32(33, index, false)
  const material = hmac(sha512, chainCode, data)
  const left = bytesToNumber(material.subarray(0, 32))
  const key = (left + bytesToNumber(privateKey)) % CURVE_N
  if (left >= CURVE_N || key === 0n) throw new Error(`invalid child at ${index}`)
  return {privateKey: numberTo32(key), chainCode: material.slice(32)}
}

const masterOf = seed => {
  const material = hmac(sha512, utf8ToBytes('Bitcoin seed'), seed)
  return {privateKey: material.slice(0, 32), chainCode: material.slice(32)}
}

const nodeHex = node => bytesToHex(node.privateKey) + bytesToHex(node.chainCode)

const cashRootOf = seed => ckdPriv(masterOf(seed), 139 + HARDENED)

const readUint32BE = (bytes, offset) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false)

const cashDomainIndices = (cashRoot, host) => {
  const material = hmac(sha256, ckdPriv(cashRoot, 0).privateKey, utf8ToBytes(host))
  return [0, 4, 8, 12].map(offset => readUint32BE(material, offset))
}

const cashDomainNode = (cashRoot, host) =>
  cashDomainIndices(cashRoot, host).reduce(ckdPriv, cashRoot)

const cashCase = (name, mnemonic, host, index) => {
  const seed = seedOf(mnemonic)
  const cashRoot = cashRootOf(seed)
  const indices = cashDomainIndices(cashRoot, host)
  const k1 = bytesToHex(
    ckdPriv(cashDomainNode(cashRoot, host), index + HARDENED).privateKey
  )
  return {
    name,
    mnemonic,
    seedHex: bytesToHex(seed),
    host,
    index,
    cashRoot: nodeHex(cashRoot),
    domainIndices: indices,
    hardened: indices.map(i => i >= HARDENED),
    domainNode: nodeHex(cashDomainNode(cashRoot, host)),
    k1,
    noteId: noteId(k1)
  }
}

// BIP-32 test vector 1, chain m -> m/0' -> m/0'/1 -> ... Included so an
// implementation can prove its CKDpriv before blaming the LUD-25 path for a
// mismatch, and because the chain alternates hardened and unhardened, which
// is exactly the pair of legs the domain levels can land on.
const bip32Vector1 = () => {
  let node = masterOf(hexToBytes('000102030405060708090a0b0c0d0e0f'))
  const steps = [{index: null, node: nodeHex(node)}]
  for (const index of [HARDENED, 1, HARDENED + 2, 2, 1000000000]) {
    node = ckdPriv(node, index)
    steps.push({index, hardened: index >= HARDENED, node: nodeHex(node)})
  }
  return steps
}

const cashDerivation = {
  version: VERSION,
  spec: SPEC,
  description:
    "LUD-25's specified seed-recoverable note secrets, the BIP-32 scheme under m/139'. cashRoot is m/139' as privateKey||chainCode hex (64 bytes, no version/depth/fingerprint framing). domainIndices are the four raw uint32 read big-endian from the first 16 bytes of HMAC-SHA256(key = the private key at m/139'/0, msg = utf8(host)); they are used as BIP-32 child indices exactly as they fall, so `hardened` records which of them land >= 2^31 by magnitude - an implementation that masks the top bit or hardens all four derives a different tree and will restore nothing. domainNode is m/139'/d1/d2/d3/d4. k1 is the private key at the hardened child `index` of that node, 32 bytes lowercase hex, and the mint sees only sha256(k1) as ever. host is the mint host exactly as the wallet stores it, with the port when there is one. seedHex is the 64-byte BIP39 seed with no passphrase. bip32Vector1 is BIP-32's own published test vector 1, so CKDpriv itself can be checked first.",
  scheme: {
    purpose: "m/139'",
    hashingKey: "m/139'/0",
    domainMsg: 'host',
    secretPath: "m/139'/d1/d2/d3/d4/i'",
    hardenedByMagnitudeOnly: true
  },
  bip32Vector1: bip32Vector1(),
  cases: [
    cashCase("standard mnemonic, index 0", MNEMONIC_A, 'mint.example', 0),
    cashCase("standard mnemonic, index 1", MNEMONIC_A, 'mint.example', 1),
    cashCase("standard mnemonic, index 20 (one past a 20-index gap limit)", MNEMONIC_A, 'mint.example', 20),
    cashCase('a second mnemonic, same host and index', MNEMONIC_B, 'mint.example', 0),
    cashCase('a host carrying a port', MNEMONIC_A, '127.0.0.1:8899', 0)
  ]
}

// ---- vectors: Part 2, recoverable signatures -----------------------------
//
// LUD-25 Part 2 keys a note by a public key. The holder keeps sk, discloses
// `cp1<pk>`, and spends the note with `ck1`, a recoverable signature by sk
// over the fixed message "LNURLcash"; the mint recovers pk from it. The mint
// certifies each note with `cs1`, the same 65-byte shape over
// "LNURLcash:<amount_msat>:<hex(pk)>". A watch-only `cx1` (the branch's
// x-only key and chain code) lets a mint derive every pk on a branch and so
// mint straight to a holder's next key.
//
// Built from the primitives like everything else here. The address branch
// follows the reference wallet (lnurl-wallet cashSecrets.ts): m/139'/1' with
// the hashing key at m/139'/1'/0. The draft text roots it at m/139'/d1..d4,
// the node the Part 1 ladder already uses, and a wallet following the text
// finds none of the reference wallet's notes. `conventions` records both.

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

const bech32mOf = (hrp, bytes) => bech32m.encode(hrp, bech32m.toWords(bytes), false)

const taggedHash = (tag, ...parts) => {
  const t = sha256(utf8ToBytes(tag))
  return sha256(concat(t, t, ...parts))
}

const lightningSignedDigest = message =>
  sha256(sha256(concat(utf8ToBytes('Lightning Signed Message:'), utf8ToBytes(message))))

// r || s || recovery id. noble puts the recovery id first; the wire puts it last.
const signRecoverable = (secretKey, digest) => {
  const sig = secp256k1.sign(digest, secretKey, {format: 'recovered', prehash: false})
  return concat(sig.subarray(1), sig.subarray(0, 1))
}

const OWNERSHIP_DIGEST = lightningSignedDigest('LNURLcash')

const addressRootOf = seed => ckdPriv(cashRootOf(seed), 1 + HARDENED)

const addressDomainIndices = (addressRoot, host) => {
  const material = hmac(sha256, ckdPriv(addressRoot, 0).privateKey, utf8ToBytes(host))
  return [0, 4, 8, 12].map(offset => readUint32BE(material, offset))
}

const ser32 = index => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, index, false)
  return out
}

// BIP-341's tweak, so a watcher holding only the cx1 derives the same pk the
// holder does. i is any uint32 and is never hardened.
const noteKeysAt = (node, index) => {
  const p = bytesToNumber(node.privateKey)
  const P = secp256k1.Point.BASE.multiply(p)
  const Px = P.toBytes(true).slice(1)
  const t = bytesToNumber(taggedHash('LNURLcash/derive', Px, node.chainCode, ser32(index)))
  if (t >= CURVE_N) throw new Error(`unusable tweak at ${index}`)
  const even = P.y % 2n === 0n
  const sk = ((even ? p : CURVE_N - p) + t) % CURVE_N
  const watched = secp256k1.Point.fromBytes(concat(Uint8Array.of(0x02), Px))
    .add(secp256k1.Point.BASE.multiply(t))
    .toBytes(true)
    .slice(1)
  const held = secp256k1.Point.BASE.multiply(sk).toBytes(true).slice(1)
  if (bytesToHex(watched) !== bytesToHex(held)) throw new Error(`watch-only and held keys disagree at ${index}`)
  return {secretKey: numberTo32(sk), pubkey: held}
}

const PART2_INDICES = [0, 1, 2, 1000, HARDENED - 1, HARDENED, 0xffffffff]
const PART2_HOSTS = ['mint.example', 'mint.lnurlcash.com', 'moneyer.dev', 'localhost:3338']

const part2Branch = (mnemonic, host) => {
  const seed = seedOf(mnemonic)
  const addressRoot = addressRootOf(seed)
  const domainIndices = addressDomainIndices(addressRoot, host)
  const node = domainIndices.reduce(ckdPriv, addressRoot)
  const P = secp256k1.Point.BASE.multiply(bytesToNumber(node.privateKey))
  const branchPubkey = P.toBytes(true).slice(1)
  return {
    mnemonic,
    seedHex: bytesToHex(seed),
    host,
    cashRoot: nodeHex(cashRootOf(seed)),
    domainIndices,
    addressNode: nodeHex(node),
    branchPubkey: bytesToHex(branchPubkey),
    branchParity: P.y % 2n === 0n ? 'even' : 'odd',
    chainCode: bytesToHex(node.chainCode),
    cx1: bech32mOf('cx', concat(branchPubkey, node.chainCode)),
    notes: PART2_INDICES.map(index => {
      const {secretKey, pubkey} = noteKeysAt(node, index)
      const ownershipSignature = signRecoverable(secretKey, OWNERSHIP_DIGEST)
      return {
        index,
        notePubkey: bytesToHex(pubkey),
        cp1: bech32mOf('cp', pubkey),
        noteSecretKey: bytesToHex(secretKey),
        ownershipSignature: bytesToHex(ownershipSignature),
        ck1: bech32mOf('ck', ownershipSignature)
      }
    })
  }
}

const part2Branches = [MNEMONIC_A, MNEMONIC_B].flatMap(m => PART2_HOSTS.map(h => part2Branch(m, h)))

const PART2_MINT_KEY = hexToBytes('da6ec5c4342514114ee493a55ddc06d085d61eb78f0b7163e07cdb7f1f66ac05')

const part2Certificate = (notePubkey, amountMsat) => {
  const message = `LNURLcash:${amountMsat}:${notePubkey}`
  const digest = lightningSignedDigest(message)
  const signature = signRecoverable(PART2_MINT_KEY, digest)
  return {
    notePubkey,
    amountMsat,
    message,
    digest: bytesToHex(digest),
    signature: bytesToHex(signature),
    cs1: bech32mOf('cs', signature)
  }
}

const firstNotes = part2Branches[0].notes
const samplePubkey = hexToBytes(firstNotes[0].notePubkey)
const sampleCp1 = firstNotes[0].cp1
const mixedCase = value => value.slice(0, 8) + value.slice(8, 20).toUpperCase() + value.slice(20)

const part2 = {
  version: VERSION,
  spec: SPEC,
  description:
    'LUD-25 Part 2: notes keyed by a public key and spent by a recoverable signature. Every branch is the reference wallet\'s address path under a BIP39 seed (no passphrase): cashRoot is m/139\', domainIndices are the four raw uint32 read big-endian from HMAC-SHA256(key = the private key at m/139\'/1\'/0, msg = utf8(host)), and addressNode is m/139\'/1\'/d1/d2/d3/d4 as privateKey||chainCode hex. branchPubkey is its x-only key (branchParity says whether the full point has even y) and cx1 is bech32m("cx", branchPubkey || chainCode). Each note: t = tagged_hash("LNURLcash/derive", branchPubkey || chainCode || ser32_be(index)); notePubkey = x(lift_x(branchPubkey) + t*G), which a watcher holding only the cx1 computes; noteSecretKey = ((branchParity even ? p : n - p) + t) mod n. ownershipSignature is RFC6979 ECDSA, low-S, over sha256(sha256("Lightning Signed Message:" || "LNURLcash")), laid out r || s || recovery id, and ck1 is its bech32m("ck") encoding: the value that spends the note. A certificate is the same signature shape by the mint key over sha256(sha256("Lightning Signed Message:" || "LNURLcash:<amount_msat>:<hex(notePubkey)>")), encoded bech32m("cs"). All four strings are bech32m with no length limit; all-uppercase is valid and mixed case is not (BIP-350). Values match vectors generated from lnurl-wallet src/lib and confirmed against lnurl-mint.',
  conventions: {
    addressBranch: "m/139'/1'/d1/d2/d3/d4",
    hashingKey: "m/139'/1'/0",
    specTextSays: "m/139'/d1/d2/d3/d4 with the hashing key at m/139'/0 - the Part 1 ladder's node; every implementation follows the reference wallet instead",
    noteTweak: 'tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i)); pk_i = x(lift_x(P) + t*G); sk_i = (P even ? p : n - p) + t mod n; t >= n is unusable, use the next index',
    indexWidth: '4 bytes, big-endian, any uint32, never hardened',
    ownershipMessage: 'LNURLcash',
    ownershipDigest: bytesToHex(OWNERSHIP_DIGEST),
    signatureLayout: 'r || s || recovery id (0..3), RFC6979, low-S',
    certificateMessage: 'LNURLcash:<amount_msat>:<hex(pk)>'
  },
  mint: {
    privateKey: bytesToHex(PART2_MINT_KEY),
    mintPubkey: bytesToHex(secp256k1.getPublicKey(PART2_MINT_KEY, true))
  },
  branches: part2Branches,
  certificates: [
    part2Certificate(firstNotes[0].notePubkey, 1000),
    part2Certificate(firstNotes[1].notePubkey, 21000),
    part2Certificate(firstNotes[2].notePubkey, 99999),
    part2Certificate(firstNotes[3].notePubkey, 100000000)
  ],
  valid: [
    {type: 'cp1', value: sampleCp1.toUpperCase(), bytes: bytesToHex(samplePubkey), why: 'all uppercase is the same string (BIP-350)'}
  ],
  invalid: [
    {type: 'cp1', value: bech32mOf('ck', samplePubkey), why: 'the ck human-readable part on a cp1 payload'},
    {type: 'cp1', value: bech32mOf('cp', concat(samplePubkey, Uint8Array.of(0))), why: '33 bytes, not 32'},
    {type: 'cp1', value: bech32.encode('cp', bech32.toWords(samplePubkey), false), why: 'a bech32 checksum, not bech32m'},
    {type: 'cp1', value: sampleCp1.slice(0, -1) + (sampleCp1.endsWith('q') ? 'p' : 'q'), why: 'the checksum does not verify'},
    {type: 'cp1', value: mixedCase(sampleCp1), why: 'mixed case (BIP-350)'},
    {type: 'ck1', value: sampleCp1, why: 'a cp1 is not a ck1'},
    {type: 'ck1', value: bech32mOf('ck', hexToBytes(firstNotes[0].ownershipSignature).slice(0, 64)), why: '64 bytes, not 65'},
    {type: 'cs1', value: firstNotes[0].ck1, why: 'a ck1 is not a cs1'},
    {type: 'cx1', value: bech32mOf('cx', samplePubkey), why: '32 bytes, not 64'}
  ]
}

// ---- vectors: Nostr-key address branches (an extension, not LUD-25) -------
//
// A holder with no BIP39 words - a hardware signer that keeps only its
// identity key, or a wallet that never made any - can still be paid to keys
// of its own: seed = HMAC-SHA256(key = the Nostr identity's secret key,
// msg = "LNURLcash/nostr-seed"), then the Part 2 address path above from
// that seed, unchanged. heartwood-esp32 derives this on the device and
// lnurlcash-kit exports it. A mint only ever sees a cx1, so nothing here
// changes what a mint does.

const NOSTR_SEED_LABEL = 'LNURLcash/nostr-seed'

const nostrSeedCase = (identityHex, host) => {
  const seed = hmac(sha256, hexToBytes(identityHex), utf8ToBytes(NOSTR_SEED_LABEL))
  const addressRoot = addressRootOf(seed)
  const node = addressDomainIndices(addressRoot, host).reduce(ckdPriv, addressRoot)
  const branchPubkey = secp256k1.Point.BASE.multiply(bytesToNumber(node.privateKey)).toBytes(true).slice(1)
  return {
    identity: identityHex,
    identityPubkey: bytesToHex(secp256k1.Point.BASE.multiply(bytesToNumber(hexToBytes(identityHex))).toBytes(true).slice(1)),
    host,
    seed: bytesToHex(seed),
    addressNode: nodeHex(node),
    cx1: bech32mOf('cx', concat(branchPubkey, node.chainCode)),
    notes: [0, 1, 7].map(index => {
      const {secretKey, pubkey} = noteKeysAt(node, index)
      return {
        index,
        noteSecretKey: bytesToHex(secretKey),
        notePubkey: bytesToHex(pubkey),
        cp1: bech32mOf('cp', pubkey),
        ck1: bech32mOf('ck', signRecoverable(secretKey, OWNERSHIP_DIGEST))
      }
    })
  }
}

const IDENTITY_ONE = '0000000000000000000000000000000000000000000000000000000000000001'
const IDENTITY_TWO = '7f4c11a9742721d66e40e321ca70b682c27f7422190c84a187525e69e6038369'

const nostrSeed = {
  version: VERSION,
  spec: SPEC,
  extension: true,
  description:
    'An extension, not LUD-25: a Part 2 address branch rooted in a Nostr identity key, for a holder with no BIP39 words. seed = HMAC-SHA256(key = identity (the 32-byte secret key), msg = utf8("LNURLcash/nostr-seed")); the branch is then the reference wallet\'s m/139\'/1\'/d1..d4 from that seed exactly as in part2.json, and every note field means what it means there. identityPubkey is the identity\'s x-only public key, the npub a lightning address belongs to. heartwood-esp32 derives this on the device and lnurlcash-kit exports it (deriveNostrAddressNode); a mint sees an ordinary cx1.',
  label: NOSTR_SEED_LABEL,
  cases: [
    nostrSeedCase(IDENTITY_ONE, 'moneyer.dev'),
    nostrSeedCase(IDENTITY_ONE, 'mint.example'),
    nostrSeedCase(IDENTITY_TWO, 'moneyer.dev'),
    nostrSeedCase(IDENTITY_TWO, '127.0.0.1:8899')
  ]
}

// ---- vectors: bech32 (LUD-01) --------------------------------------------

const lnurlEncode = url =>
  bech32.encode('lnurl', bech32.toWords(utf8ToBytes(url)), 2048).toUpperCase()

const bech32Urls = [
  'https://mint.example/w?k1=' + K1_A,
  'https://mint.example/.well-known/lnurlp/mint',
  'https://mint.example/w?k1=' + K1_A + '&amount=21000',
  'http://localhost:8000/w?k1=' + K1_C
]

const bech32Vectors = {
  version: VERSION,
  spec: 'LUD-01',
  description:
    'bech32 encoding of LNURLs. The hrp is "lnurl"; the limit is raised well above bech32 default because a note URL carrying k1, amount and sig is long.',
  encode: bech32Urls.map(url => ({url, lnurl: lnurlEncode(url)})),
  decodeInvalid: [
    {input: '', why: 'empty'},
    {input: 'LNURL1', why: 'no data part'},
    {input: 'https://mint.example/w', why: 'not bech32 at all'},
    {
      input: lnurlEncode('https://mint.example/w').slice(0, -1) + 'q',
      why: 'checksum corrupted'
    },
    {input: 'LNBC1QQQQ', why: 'wrong hrp'}
  ],
  caseInsensitive: {
    note: 'bech32 is case-insensitive; a decoder must accept either casing and produce the same URL',
    lower: lnurlEncode('https://mint.example/w').toLowerCase(),
    upper: lnurlEncode('https://mint.example/w'),
    url: 'https://mint.example/w'
  }
}

// ---- vectors: URL admission ----------------------------------------------

const urlAdmission = {
  version: VERSION,
  spec: SPEC,
  description:
    'Which URLs an implementation may fetch. Applies to every URL, whether scanned/pasted by a user or handed over by a SERVICE in its own response (callback, verify, payLink). https always; http only for loopback and .onion. Anything else is refused, so a crafted note cannot answer its own informational GET (a data: URL carrying withdrawRequest JSON would otherwise mint a self-contained fake note) and a SERVICE cannot redirect a k1-bearing callback onto cleartext.',
  allowed: [
    'https://mint.example/w',
    'https://mint.example:8443/w?k1=' + K1_A,
    'http://localhost:8000/w',
    'http://127.0.0.1:8000/w',
    'http://0.0.0.0:8000/w',
    'http://mint.onion/w',
    'http://sub.domain.onion/w?k1=' + K1_A
  ],
  rejected: [
    {url: 'http://mint.example/w', why: 'cleartext to a clearnet host'},
    {url: 'data:application/json,{"tag":"withdrawRequest"}', why: 'data: URL - a note that answers itself'},
    {url: 'file:///etc/passwd', why: 'file: URL'},
    {url: 'javascript:alert(1)', why: 'javascript: URL'},
    {url: 'ftp://mint.example/w', why: 'unsupported scheme'},
    {url: 'not a url at all', why: 'unparseable'},
    {url: '', why: 'empty'}
  ]
}

// ---- vectors: input resolution -------------------------------------------

const inputResolution = {
  version: VERSION,
  spec: 'LUD-01, LUD-16, LUD-17, LUD-25',
  description:
    'Resolving user-supplied text down to a fetchable URL. Every branch that produces a URL must also pass the url-admission rules.',
  lnurl: [
    {input: 'https://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'lnurlw://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'LNURLW://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A, why: 'scheme is case-insensitive'},
    {input: 'lnurlp://mint.example/p', expect: 'https://mint.example/p'},
    {input: 'lnurlw://localhost:8000/w', expect: 'http://localhost:8000/w', why: 'loopback resolves to http'},
    {input: 'lnurlw://mint.onion/w', expect: 'http://mint.onion/w'},
    {input: lnurlEncode('https://mint.example/w'), expect: 'https://mint.example/w'},
    {input: '  https://mint.example/w  ', expect: 'https://mint.example/w', why: 'surrounding whitespace trimmed'},
    {input: 'mint@mint.example', expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'http://mint.example/w', expect: null, why: 'cleartext clearnet'},
    {input: '', expect: null},
    {input: 'gibberish', expect: null}
  ],
  mint: [
    {input: 'mint@mint.example', expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'alice@mint.example', expect: 'https://mint.example/.well-known/lnurlp/alice'},
    {input: '_@mint.example', expect: 'https://mint.example/.well-known/lnurlp/_', why: 'LUD-16 bare-domain reserved name'},
    {input: 'mint@localhost:8000', expect: 'http://localhost:8000/.well-known/lnurlp/mint'},
    {input: lnurlEncode('https://mint.example/.well-known/lnurlp/mint'), expect: 'https://mint.example/.well-known/lnurlp/mint'},
    {input: 'https://mint.example/w?k1=' + K1_A, expect: null, why: 'a raw URL is not a mint address'},
    {input: '', expect: null}
  ],
  note: [
    {input: 'lnurlw://mint.example/w?k1=' + K1_A, expect: 'https://mint.example/w?k1=' + K1_A},
    {input: 'https://mint.example/w?k1=' + K1_A.toUpperCase(), expect: 'https://mint.example/w?k1=' + K1_A.toUpperCase(), why: 'resolution preserves the URL; k1 casing is normalised on extraction, not here'},
    {input: 'https://mint.example/w', expect: null, why: 'no k1 - not a note'},
    {input: 'https://mint.example/w?k1=short', expect: null, why: 'k1 must be 32 bytes hex'},
    {input: 'https://mint.example/w?k1=' + 'z'.repeat(64), expect: null, why: 'k1 must be hex'},
    {input: lnurlEncode('https://mint.example/w?k1=' + K1_A), expect: 'https://mint.example/w?k1=' + K1_A}
  ],
  mintAddressUrl: [
    {payUrl: 'https://mint.example/.well-known/lnurlp/mint', expect: 'https://mint.example/.well-known/lnurlw/mint'},
    {payUrl: 'https://mint.example/.well-known/lnurlp/_', expect: 'https://mint.example/.well-known/lnurlw/_'},
    {payUrl: 'https://mint.example/p', expect: null, why: 'not at the conventional well-known path'}
  ],
  lightningAddressUsername: [
    {payUrl: 'https://mint.example/.well-known/lnurlp/mint', expect: 'mint'},
    {payUrl: 'https://mint.example/.well-known/lnurlp/_', expect: '_'},
    {payUrl: 'https://mint.example/p', expect: null}
  ]
}

// ---- vectors: note URLs --------------------------------------------------

const noteUrl = {
  version: VERSION,
  spec: SPEC,
  description:
    'A note is an ordinary LUD-03 withdrawRequest URL whose k1 IS the asset. `amount` alongside it is only a claim by whoever encoded the note - the authoritative value is always maxWithdrawable from an informational GET. A SERVICE returning a rotate, split or merge MUST include the offline-verification signature in `sig` (and `sig2` for the second split output).',
  parse: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000',
      k1: K1_A,
      declaredAmountMsat: 21000,
      signature: null
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A.toUpperCase(),
      k1: K1_A,
      declaredAmountMsat: null,
      signature: null,
      why: 'k1 is bytes, not text: normalise to lowercase so the same secret in two casings is one note'
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      k1: K1_A,
      declaredAmountMsat: 21000,
      signature: 'ab'.repeat(65)
    },
    {
      url: 'https://mint.example/w',
      k1: null,
      declaredAmountMsat: null,
      signature: null
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=notanumber',
      k1: K1_A,
      declaredAmountMsat: null,
      signature: null,
      why: 'an unparseable declared amount is absent, not zero'
    },
    {
      url: 'not a url',
      k1: null,
      declaredAmountMsat: null,
      signature: null
    }
  ],
  build: [
    {
      withdrawLink: 'lnurlw://mint.example/w',
      k1: K1_A,
      amountMsat: 21000,
      expect: 'https://mint.example/w?k1=' + K1_A + '&amount=21000'
    },
    {
      withdrawLink: 'https://mint.example/w',
      k1: K1_A.toUpperCase(),
      amountMsat: null,
      expect: 'https://mint.example/w?k1=' + K1_A,
      why: 'omit amount entirely when the real value is not known yet; some SERVICEs validate it strictly rather than ignoring it'
    },
    {
      withdrawLink: 'lnurlw://localhost:8000/w',
      k1: K1_C,
      amountMsat: 1000,
      expect: 'http://localhost:8000/w?k1=' + K1_C + '&amount=1000'
    }
  ],
  withNewK1: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      k1: K1_B,
      amountMsat: 5000,
      signature: null,
      expect: 'https://mint.example/w?k1=' + K1_B + '&amount=5000',
      why: 'a stale signature must be dropped: it no longer matches the new secret'
    },
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000',
      k1: K1_B,
      amountMsat: 5000,
      signature: 'cd'.repeat(65),
      expect: 'https://mint.example/w?k1=' + K1_B + '&amount=5000&sig=' + 'cd'.repeat(65)
    }
  ],
  withoutK1: [
    {
      url: 'https://mint.example/w?k1=' + K1_A + '&amount=21000&sig=' + 'ab'.repeat(65),
      amountMsat: 5000,
      signature: null,
      expect: 'https://mint.example/w?amount=5000',
      why: 'a device-backed note keeps the URL template but never the secret'
    }
  ]
}

// ---- vectors: mint fees --------------------------------------------------

const meta = entries => JSON.stringify(entries)

// The normative formula, straight from the LUD-25 text:
//   note value = amount - base_fee_msat - amount * fee_percent_ppm / 1_000_000
// floored, since msat are integers, and never negative.
//
// The proportional term is split rather than computed as (g * ppm) / 1e6,
// because that product overflows 64-bit unsigned at realistic amounts: 21M
// BTC is 2.1e15 msat, and 2.1e15 * 999_999 is about 2.1e21, well past
// 1.8e19. Splitting keeps both halves small: the quotient half reaches at
// most 2.1e15, the remainder half at most 1e12. Implementations in Go and
// Rust that multiply naively pass every small vector and then silently
// mangle a large one, which is exactly what the large case below catches.
const proportional = (g, ppm) =>
  Math.floor(g / 1e6) * ppm + Math.floor(((g % 1e6) * ppm) / 1e6)

const applyFee = (g, f) => Math.max(0, g - f.baseFeeMsat - proportional(g, f.feePpm))

// The inverse: the SMALLEST gross amount that nets `net` after the fee.
//
// applyFee is non-decreasing in gross with per-msat steps of 0 or 1 (the
// proportional term grows by at most 1 per msat, since ppm < 1_000_000), so
// the minimal such gross exists and binary search finds it exactly. The
// obvious alternative - estimate linearly, then walk one msat at a time -
// is what the reference wallet does, and it is both unbounded and wrong at
// the edge: for a 99.9999% fee the walk is around a million steps, so any
// sane guard trips and returns a non-minimal answer. A SERVICE can advertise
// such a fee, so the walk is a hostile-input hazard as well as an accuracy
// one. Binary search has neither problem.
const grossUpFee = (net, f) => {
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

const FEE_A = {baseFeeMsat: 1000, feePpm: 2000}
const FEE_FREE = {baseFeeMsat: 0, feePpm: 0}
const FEE_FLAT = {baseFeeMsat: 2000, feePpm: 0}
const FEE_TINY = {baseFeeMsat: 0, feePpm: 1}
const FEE_PCT = {baseFeeMsat: 0, feePpm: 10000}
const FEE_HOSTILE = {baseFeeMsat: 3, feePpm: 999999}
// the whole-sat trap: a gross where msat-exact and round-to-sat fees differ
const FEE_SAT_TRAP = {baseFeeMsat: 1000, feePpm: 1000}

const applyCase = (grossMsat, fee, why) => ({
  grossMsat,
  fee,
  expect: applyFee(grossMsat, fee),
  why
})

const grossUpCase = (netMsat, fee, why) => ({
  netMsat,
  fee,
  expect: grossUpFee(netMsat, fee),
  why
})

const fees = {
  version: VERSION,
  spec: SPEC,
  description:
    'Optional mint fees (LUD-25). A SERVICE advertises what it withholds on minting via an extra ["text/plain", "Mint fees: <base_fee_msat>,<fee_percent_ppm>"] entry in the payRequest metadata, so a WALLET can warn the payer that the note it ends up holding is worth less than the invoice it paid. A SERVICE that omits the entry is fee-free, not unknown.',
  formula: {
    apply: 'max(0, gross - base_fee_msat - floor(gross * fee_percent_ppm / 1_000_000))',
    grossUp: 'the smallest gross for which apply(gross) == net',
    overflowWarning:
      'compute the proportional term as floor(gross/1e6)*ppm + floor((gross%1e6)*ppm/1e6). A direct gross*ppm overflows 64-bit unsigned at realistic amounts (2.1e15 msat is 21M BTC; times 999999 ppm is ~2.1e21, past the 1.8e19 limit).',
    minimality:
      'grossUp must return the exact minimum. A linear estimate followed by a one-msat walk is unbounded for a near-100% fee - about a million steps at 999999 ppm - so any guard on that walk yields a non-minimal answer on input a hostile SERVICE can choose. Use binary search: apply is non-decreasing with steps of 0 or 1.'
  },
  parse: [
    {
      metadata: meta([['text/plain', 'a mint'], ['text/plain', 'Mint fees: 1000,2000']]),
      expect: FEE_A
    },
    {
      metadata: meta([['text/plain', 'Mint fees:1000,2000']]),
      expect: FEE_A,
      why: 'whitespace after the colon is optional'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000 , 2000 ']]),
      expect: FEE_A
    },
    {
      metadata: meta([['text/plain', 'a mint']]),
      expect: null,
      why: 'no fee entry - read as fee-free'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,0']]),
      expect: null,
      why: 'an explicit zero fee is identical to no fee; callers should not have to special-case it'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,1000000']]),
      expect: null,
      why: 'a fee of 100% or more can never net anything, and would make a naive gross-up walk hang - refuse it as no valid entry'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,2000000']]),
      expect: null,
      why: 'above 100%'
    },
    {
      metadata: meta([['text/identifier', 'Mint fees: 1000,2000']]),
      expect: null,
      why: 'only text/plain entries carry the fee advertisement'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: -1,2000']]),
      expect: null,
      why: 'negative components are not a valid advertisement'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000']]),
      expect: null,
      why: 'both components are required'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000,2000,3000']]),
      expect: null,
      why: 'exactly two components'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 99999999999999999999,2000']]),
      expect: null,
      why: 'digits past 2^53 lose integer precision in most languages - refuse rather than estimate with a mangled fee'
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 1000,99999999999999999999']]),
      expect: null,
      why: 'the same for the ppm component (a ppm this large fails the 100% rule regardless)'
    },
    {metadata: 'not json', expect: null},
    {metadata: '{}', expect: null, why: 'metadata must be an array'},
    {metadata: '[]', expect: null},
    {
      metadata: meta([['text/plain', 'Mint fees: 500,0']]),
      expect: {baseFeeMsat: 500, feePpm: 0}
    },
    {
      metadata: meta([['text/plain', 'Mint fees: 0,5000']]),
      expect: {baseFeeMsat: 0, feePpm: 5000}
    },
    {
      metadata: meta([
        ['text/plain', 'Mint fees: 500,0'],
        ['text/plain', 'Mint fees: 1000,2000']
      ]),
      expect: {baseFeeMsat: 500, feePpm: 0},
      why: 'the first valid advertisement wins'
    }
  ],
  apply: [
    applyCase(100000, FEE_A),
    applyCase(100000, FEE_FREE),
    applyCase(1000, FEE_FLAT, 'never negative'),
    applyCase(1001, FEE_TINY, 'the proportional part floors to zero'),
    applyCase(2000000, FEE_TINY),
    applyCase(0, {baseFeeMsat: 0, feePpm: 1000}),
    applyCase(21000, FEE_PCT),
    applyCase(
      2100000000000000,
      FEE_HOSTILE,
      '21M BTC in msat at a 99.9999% fee: a naive gross*ppm multiply overflows 64-bit unsigned here and produces a wrong answer'
    ),
    applyCase(
      2100000000000000,
      FEE_TINY,
      'same magnitude, ordinary fee - still past the naive-multiply limit'
    ),
    applyCase(
      500000,
      FEE_SAT_TRAP,
      'nets 498500 msat. A fee implementation that works in whole sats rounds the withheld fee up to 2000 msat here and mints a 498000 msat note - half a sat short of conformant. The formula is msat-exact; a minted note is worth apply(gross) to the msat'
    )
  ],
  grossUp: [
    grossUpCase(98800, FEE_A),
    grossUpCase(100000, FEE_FREE),
    grossUpCase(1, {baseFeeMsat: 1000, feePpm: 0}),
    grossUpCase(10000, FEE_PCT),
    grossUpCase(21000, FEE_A),
    grossUpCase(
      1,
      FEE_HOSTILE,
      'a 99.9999% fee: the answer is far below the linear estimate, so an estimate-then-walk implementation returns a non-minimal gross unless its guard is around a million steps'
    ),
    grossUpCase(1000000, FEE_HOSTILE),
    grossUpCase(0, FEE_A, 'nothing to gross up')
  ],
  grossUpRoundTrip: {
    note: 'for every fee and net amount below, apply(grossUp(net, fee), fee) must equal net exactly, and apply(grossUp(net, fee) - 1, fee) must be strictly less than net - that is, the result is the true minimum, not merely sufficient',
    fees: [FEE_FREE, {baseFeeMsat: 1000, feePpm: 0}, {baseFeeMsat: 0, feePpm: 2000}, FEE_A, FEE_HOSTILE, FEE_TINY],
    netAmountsMsat: [1, 2, 999, 1000, 1001, 21000, 100000, 1000000, 123456789]
  },
  formatPercent: [
    {ppm: 2000, expect: '0.2'},
    {ppm: 10000, expect: '1'},
    {ppm: 1, expect: '0.0001'},
    {ppm: 0, expect: '0'},
    {ppm: 999999, expect: '99.9999'},
    {ppm: 12345, expect: '1.2345'}
  ]
}

// ---- vectors: bolt11 -----------------------------------------------------

const bolt11 = {
  version: VERSION,
  spec: 'BOLT-11',
  description:
    'Only what a WALLET needs to bind a SERVICE response to the payment it asked for: the amount out of the human-readable part, a loose shape check, and case-insensitive equality. No full TLV decode is required.',
  decodeAmountMsat: [
    {pr: 'lnbc210n1pjqrstuvwxyz', expect: 21000},
    {pr: 'lnbc1u1pjqrstuvwxyz', expect: 100000},
    {pr: 'lnbc1m1pjqrstuvwxyz', expect: 100000000},
    {pr: 'lnbc10p1pjqrstuvwxyz', expect: 1},
    {pr: 'lnbc1pjqrstuvwxyz', expect: null, why: 'amountless invoice'},
    {pr: 'lntb210n1pjqrstuvwxyz', expect: 21000, why: 'testnet prefix'},
    {pr: 'lnbcrt210n1pjqrstuvwxyz', expect: 21000, why: 'regtest prefix'},
    {pr: 'LNBC210N1PJQRSTUVWXYZ', expect: 21000, why: 'bech32 is case-insensitive'},
    {pr: 'lnbc1p1pjqrstuvwxyz', expect: null, why: '1 pico-BTC is 0.1 msat - not an integer number of msat'},
    {pr: 'not an invoice', expect: null},
    {pr: '', expect: null},
    {pr: 'lnurl1dp68gurn8ghj7', expect: null, why: 'an LNURL is not an invoice'}
  ],
  isInvoice: [
    {pr: 'lnbc210n1pjqrstuvwxyz', expect: true},
    {pr: 'lnbc1pjqrstuvwxyz', expect: true},
    {pr: 'lntb1pjqrstuvwxyz', expect: true},
    {pr: 'lnurl1dp68gurn8ghj7', expect: false, why: 'must not match a bech32 LNURL'},
    {pr: 'lnbc', expect: false},
    {pr: '', expect: false}
  ],
  sameInvoice: [
    {a: 'lnbc210n1pjq', b: 'LNBC210N1PJQ', expect: true},
    {a: ' lnbc210n1pjq ', b: 'lnbc210n1pjq', expect: true},
    {a: 'lnbc210n1pjq', b: 'lnbc220n1pjq', expect: false}
  ],
  isPreimage: [
    {value: K1_A, expect: true},
    {value: K1_A.toUpperCase(), expect: true},
    {value: 'z'.repeat(64), expect: false},
    {value: 'ab'.repeat(31), expect: false, why: '31 bytes'},
    {value: '', expect: false}
  ]
}

// ---- vectors: callback requests ------------------------------------------

const CB = 'https://mint.example/w/cb'

const callbacks = {
  version: VERSION,
  spec: SPEC,
  description:
    'The mutating callback. Every operation is a GET on the `callback` from the note\'s own withdrawRequest response. `h`/`h2` are hashes of secrets the WALLET generates - never the SERVICE - so the SERVICE never sees, generates or persists a replacement note\'s spend secret. Query parameter ORDER is not significant; the expected query below is one valid serialisation and implementations should compare parsed parameters, honouring repeats.',
  cases: [
    {
      name: 'melt',
      op: 'melt',
      callback: CB,
      params: {k1: [K1_A], pr: 'lnbc210n1pjqrstuvwxyz'},
      expectQuery: [['k1', K1_A], ['pr', 'lnbc210n1pjqrstuvwxyz']]
    },
    {
      name: 'rotate',
      op: 'rotate',
      callback: CB,
      params: {k1: [K1_A], h: noteId(K1_B)},
      expectQuery: [['k1', K1_A], ['h', noteId(K1_B)]]
    },
    {
      name: 'split one note',
      op: 'split',
      callback: CB,
      params: {k1: [K1_A], amountMsat: 5000, h: noteId(K1_B), h2: noteId(K1_C)},
      expectQuery: [['k1', K1_A], ['amount', '5000'], ['h', noteId(K1_B)], ['h2', noteId(K1_C)]]
    },
    {
      name: 'split several notes at once',
      op: 'split',
      callback: CB,
      params: {k1: [K1_A, K1_B], amountMsat: 5000, h: noteId(K1_C), h2: noteId(K1_A)},
      expectQuery: [['k1', K1_A], ['k1', K1_B], ['amount', '5000'], ['h', noteId(K1_C)], ['h2', noteId(K1_A)]],
      why: 'LUD-25 allows one or many k1 on a split - no prior merge required'
    },
    {
      name: 'merge',
      op: 'merge',
      callback: CB,
      params: {k1: [K1_A, K1_B, K1_C], h: noteId(K1_A)},
      expectQuery: [['k1', K1_A], ['k1', K1_B], ['k1', K1_C], ['h', noteId(K1_A)]],
      why: 'k1 repeats rather than being comma-joined: append, never set'
    },
    {
      name: 'callback that already carries query parameters',
      op: 'rotate',
      callback: 'https://mint.example/w/cb?token=abc',
      params: {k1: [K1_A], h: noteId(K1_B)},
      expectQuery: [['token', 'abc'], ['k1', K1_A], ['h', noteId(K1_B)]],
      why: 'existing parameters must be preserved, not overwritten'
    }
  ],
  rejected: [
    {
      name: 'melt with several k1',
      op: 'melt',
      params: {k1: [K1_A, K1_B], pr: 'lnbc210n1pjq'},
      why: 'LUD-25: pr MUST NOT be combined with multiple k1. Merge first, then melt.'
    },
    {
      name: 'melt with an amount',
      op: 'melt',
      params: {k1: [K1_A], pr: 'lnbc210n1pjq', amountMsat: 5000},
      why: 'LUD-25: pr MUST NOT be combined with amount'
    },
    {
      name: 'rotate without h',
      op: 'rotate',
      params: {k1: [K1_A]},
      why: 'h is required whenever pr is absent - a SERVICE must never generate the secret'
    },
    {
      name: 'split without h2',
      op: 'split',
      params: {k1: [K1_A], amountMsat: 5000, h: noteId(K1_B)},
      why: 'h2 is required whenever amount is present'
    },
    {
      name: 'no k1 at all',
      op: 'rotate',
      params: {k1: [], h: noteId(K1_B)},
      why: 'nothing to burn'
    }
  ]
}

// ---- vectors: responses --------------------------------------------------

const responses = {
  version: VERSION,
  spec: SPEC,
  description:
    'Classifying a SERVICE response. The distinction that matters for funds is definitive-rejection versus ambiguous-outcome: a parsed {"status":"ERROR"} means the request was processed and refused, while a transport failure, an unparseable body, or a 200 that does not confirm means the mutation MAY have landed - and for rotate/split/merge the WALLET-generated secrets are then the only copy of the outputs, so they must ride the error rather than be discarded. A confirmed mutation carrying no signature is its own outcome: it definitely landed, so the secrets matter more than ever, and the SERVICE is non-conforming. `op` says which call each case is driven through - a melt is the one mutation with no signature to return.',
  outcomes: {
    ok: 'the operation is confirmed',
    unverifiable: 'the mutation is confirmed but carries no signature. LUD-25 requires one on every rotate, split and merge, so this SERVICE is non-conforming - but the note EXISTS at the hash the WALLET disclosed, and its secret is the only key to that value. Keep the secret; report the mint',
    pending: 'this k1 has another operation in flight (a melt); retry shortly',
    spent: 'the SERVICE is authoritative that the note is already burned; a holder may lock it as spent',
    unknown: 'the SERVICE does not recognise this note; surface it, do not silently lock it',
    error: 'definitively rejected for some other stated reason',
    ambiguous: 'the outcome is not known - preserve any fresh secrets'
  },
  cases: [
    {
      name: 'plain success',
      op: 'mutation',
      http: 200,
      body: {status: 'OK'},
      expect: 'unverifiable',
      why: 'a bare OK was a conforming rotate answer while offline verification was optional. It is not one now: the note is real and the WALLET must keep its secret, but nobody the holder hands it to can check it'
    },
    {
      name: 'success with an offline-verification signature',
      op: 'mutation',
      http: 200,
      body: {status: 'OK', sig: 'ab'.repeat(65)},
      expect: 'ok',
      signature: 'ab'.repeat(65)
    },
    {
      name: 'split success with both signatures',
      op: 'split',
      http: 200,
      body: {status: 'OK', sig: 'ab'.repeat(65), sig2: 'cd'.repeat(65)},
      expect: 'ok',
      signature: 'ab'.repeat(65),
      changeSignature: 'cd'.repeat(65)
    },
    {
      name: 'a split that signs only its first output',
      op: 'split',
      http: 200,
      body: {status: 'OK', sig: 'ab'.repeat(65)},
      expect: 'unverifiable',
      why: 'both outputs of a split are notes and both need a signature; the change is not a lesser note'
    },
    {
      name: 'melt success with a LUD-21 style proof',
      op: 'melt',
      http: 200,
      body: {status: 'OK', pr: 'lnbc210n1pjq', verify: 'https://mint.example/verify/abc'},
      expect: 'ok',
      why: 'OK on a melt means the payment is in flight, NOT that the note is confirmed spent. A melt mints nothing, so it has no signature to return and none is required'
    },
    {
      name: 'pending',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'pending'},
      expect: 'pending',
      why: 'the exact reason string LUD-25 specifies for a k1 mid-melt'
    },
    {
      name: 'already spent',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'Note already spent.'},
      expect: 'spent'
    },
    {
      name: 'unknown note',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'Unknown note.'},
      expect: 'unknown'
    },
    {
      name: 'not found wording',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'k1 not found'},
      expect: 'unknown'
    },
    {
      name: 'ambiguous callback wording is treated as spent',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'Invalid or already spent k1.'},
      expect: 'spent',
      why: 'an atomic multi-k1 callback cannot say which k1 failed; the spent reading is the safe one'
    },
    {
      name: 'some other refusal',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR', reason: 'This mint is sunsetting - splits are disabled.'},
      expect: 'error'
    },
    {
      name: 'error with no reason',
      op: 'mutation',
      http: 200,
      body: {status: 'ERROR'},
      expect: 'error'
    },
    {
      name: '200 with neither OK nor ERROR',
      op: 'mutation',
      http: 200,
      body: {something: 'else'},
      expect: 'ambiguous',
      why: 'the mutation was not confirmed and may still have landed'
    },
    {
      name: 'unparseable body',
      op: 'mutation',
      http: 200,
      bodyRaw: 'not json at all',
      expect: 'ambiguous'
    },
    {
      name: 'server error',
      op: 'mutation',
      http: 500,
      bodyRaw: 'upstream failure',
      expect: 'ambiguous'
    },
    {
      name: 'transport failure',
      op: 'mutation',
      transportError: true,
      expect: 'ambiguous'
    },
    {
      name: 'timeout',
      op: 'mutation',
      timeout: true,
      expect: 'ambiguous'
    }
  ]
}

// ---- vectors: withdrawRequest info ---------------------------------------

const withdrawInfo = {
  version: VERSION,
  spec: 'LUD-03, LUD-25',
  description:
    'The informational GET on a note. Never burns, rotates or alters it. maxWithdrawable is the ONLY authoritative statement of what a note is worth - the URL\'s own `amount` is a claim and the SERVICE ignores it here. The response\'s k1 MUST be the bearer secret itself, never a derived or opaque id. Offline verification is mandatory in the current draft, so the response MUST also carry `mintPubkey`, the stable compressed secp256k1 key the SERVICE\'s note signatures verify against; without it a holder handed a note has nothing to check it against.',
  queriedUrl: 'https://mint.example/w?k1=' + K1_A + '&amount=99999&sig=' + 'ab'.repeat(65),
  requestMustNotSend: ['sig'],
  requestMustSendUnchanged: ['k1'],
  accepted: [
    {
      name: 'minimal valid',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 0, maxWithdrawable: 21000, mintPubkey: MINT_PUB},
      maxWithdrawable: 21000
    },
    {
      name: 'minWithdrawable omitted',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000, mintPubkey: MINT_PUB},
      maxWithdrawable: 21000
    },
    {
      name: 'echoed k1 in a different casing',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A.toUpperCase(), maxWithdrawable: 21000, mintPubkey: MINT_PUB},
      maxWithdrawable: 21000,
      why: 'k1 is bytes; casing carries no meaning'
    },
    {
      name: 'mintPubkey in a different casing',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000, mintPubkey: MINT_PUB.toUpperCase()},
      maxWithdrawable: 21000,
      why: 'a pubkey is bytes too, and a SERVICE that upper-cases its hex is still naming the same key'
    },
    {
      name: 'zero value note',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 0, mintPubkey: MINT_PUB},
      maxWithdrawable: 0
    }
  ],
  rejected: [
    {name: 'wrong tag', body: {tag: 'payRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000, mintPubkey: MINT_PUB}},
    {name: 'no callback', body: {tag: 'withdrawRequest', k1: K1_A, maxWithdrawable: 21000, mintPubkey: MINT_PUB}},
    {name: 'no k1', body: {tag: 'withdrawRequest', callback: CB, maxWithdrawable: 21000, mintPubkey: MINT_PUB}},
    {name: 'no maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, mintPubkey: MINT_PUB}},
    {name: 'maxWithdrawable is a string', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: '21000', mintPubkey: MINT_PUB}},
    {name: 'negative maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: -1, mintPubkey: MINT_PUB}},
    {
      name: 'fractional maxWithdrawable',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000.5, mintPubkey: MINT_PUB},
      why: 'msat are integers'
    },
    {
      name: 'maxWithdrawable past 2^63',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 2 ** 64, mintPubkey: MINT_PUB},
      why: 'no common integer type holds it and a double rounds it - refuse rather than guess the amount'
    },
    {name: 'minWithdrawable above maxWithdrawable', body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 30000, maxWithdrawable: 21000, mintPubkey: MINT_PUB}},
    {
      name: 'echoed a different k1 than queried',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_B, maxWithdrawable: 21000, mintPubkey: MINT_PUB},
      why: 'spec MUST: the response k1 is the bearer secret itself. A SERVICE returning something else is non-compliant, or the note was rotated by someone else'
    },
    {
      name: 'no mintPubkey',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, minWithdrawable: 0, maxWithdrawable: 21000},
      why: 'offline verification is mandatory. Without the key a note signature verifies against nothing, and whoever is handed the note is back to the leap of faith the signature exists to remove'
    },
    {
      name: 'mintPubkey that is not a compressed secp256k1 key',
      body: {tag: 'withdrawRequest', callback: CB, k1: K1_A, maxWithdrawable: 21000, mintPubkey: MINT_PUB.slice(2)},
      why: 'an x-only key, a node URI or a truncated hex string verifies nothing. Refused at the response rather than at the first signature check, where the same fault would look like a forged note'
    }
  ]
}

// ---- vectors: payRequest -------------------------------------------------

const payRequest = {
  version: VERSION,
  spec: 'LUD-06, LUD-11, LUD-16, LUD-21, LUD-25',
  description:
    'Minting. A LUD-06 payRequest MAY advertise `withdrawLink`, the raw LUD-17 URL of the withdraw endpoint, and MUST then advertise `commentAllowed: 64`. Before paying, WALLET generates and persists a 32-byte secret and sends `comment=hex(sha256(secret))`; SERVICE rejects a missing or malformed comment before issuing an invoice. The payment preimage is settlement proof, never the bearer k1.',
  accepted: [
    {
      name: 'a minting payRequest',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/identifier', 'mint@mint.example']]),
        commentAllowed: 64,
        withdrawLink: 'lnurlw://mint.example/w'
      },
      withdrawLink: 'lnurlw://mint.example/w',
      commentAllowed: 64,
      mintFee: null
    },
    {
      name: 'withdrawLink in plain URL form',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/identifier', 'mint@mint.example']]),
        commentAllowed: 64,
        withdrawLink: 'https://mint.example/w'
      },
      withdrawLink: 'https://mint.example/w',
      commentAllowed: 64,
      mintFee: null,
      why: 'LUD-25 says a raw, non-bech32 URL "as described in LUD-17", and LUD-17 describes both the lnurlw:// scheme and the plain URL it stands for. lnurl-mint, and the spec diagram, use this form; moneyer uses lnurlw://. A WALLET MUST accept either, unchanged, and resolve it through the same LUD-17 rule as any other input'
    },
    {
      name: 'withdrawLink on an onion service',
      body: {
        tag: 'payRequest',
        callback: 'http://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint']]),
        commentAllowed: 64,
        withdrawLink: 'lnurlw://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/w'
      },
      withdrawLink: 'lnurlw://mintmintmintmintmintmintmintmintmintmintmintmintmintmi.onion/w',
      commentAllowed: 64,
      mintFee: null,
      why: 'the parser passes the link through; resolution to http:// happens when a note is built from it (see note-url.json build)'
    },
    {
      name: 'with an advertised fee',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a mint'], ['text/plain', 'Mint fees: 1000,2000']]),
        commentAllowed: 64,
        withdrawLink: 'lnurlw://mint.example/w'
      },
      withdrawLink: 'lnurlw://mint.example/w',
      commentAllowed: 64,
      mintFee: {baseFeeMsat: 1000, feePpm: 2000}
    },
    {
      name: 'an ordinary payRequest with no minting',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'not a mint']])
      },
      withdrawLink: null,
      mintFee: null
    }
  ],
  rejected: [
    {name: 'wrong tag', body: {tag: 'withdrawRequest', callback: 'https://mint.example/p/cb'}},
    {name: 'no callback', body: {tag: 'payRequest', minSendable: 1000, maxSendable: 1000}},
    {
      name: 'minting payRequest without room for the required hash comment',
      body: {
        tag: 'payRequest',
        callback: 'https://mint.example/p/cb',
        minSendable: 1000,
        maxSendable: 100000000,
        metadata: meta([['text/plain', 'a broken mint']]),
        withdrawLink: 'lnurlw://mint.example/w'
      },
      why: 'current LUD-25 draft: minting is unavailable unless commentAllowed can carry exactly the 64-character hash commitment'
    }
  ],
  mintCallback: {
    accepted: [
      {
        name: 'wallet names the freshly minted note before invoice creation',
        amountMsat: 21000,
        comment: noteId(K1_A),
        result: 'invoice',
        noteId: noteId(K1_A),
        bearerK1: K1_A,
        paymentPreimageIsBearerK1: false
      }
    ],
    rejected: [
      {
        name: 'missing comment',
        amountMsat: 21000,
        comment: null,
        result: 'error-before-invoice',
        why: 'an unnamed mint would make the payment preimage the money, which the current draft no longer permits'
      },
      {
        name: 'malformed comment',
        amountMsat: 21000,
        comment: 'not-a-32-byte-hash',
        result: 'error-before-invoice',
        why: 'comment must be bare hex encoding of a 32-byte SHA-256 output'
      }
    ]
  },
  invoice: {
    accepted: [
      {
        name: 'invoice for the amount requested',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz'},
        disposable: true,
        why: 'LUD-11: disposable absent MUST be read as true'
      },
      {
        name: 'explicitly reusable address',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz', disposable: false},
        disposable: false
      },
      {
        name: 'with a LUD-21 verify url',
        requestedMsat: 21000,
        body: {pr: 'lnbc210n1pjqrstuvwxyz', verify: 'https://mint.example/verify/abc'},
        disposable: true,
        verify: 'https://mint.example/verify/abc'
      },
      {
        name: 'amountless invoice passes through',
        requestedMsat: 21000,
        body: {pr: 'lnbc1pjqrstuvwxyz'},
        disposable: true,
        why: 'nothing to check it against here; the SERVICE judges it later'
      }
    ],
    rejected: [
      {
        name: 'invoice for a different amount',
        requestedMsat: 21000,
        body: {pr: 'lnbc220n1pjqrstuvwxyz'},
        why: 'a SERVICE answering with an invoice for another amount is broken or hostile'
      },
      {name: 'no invoice', requestedMsat: 21000, body: {}}
    ]
  },
  verify: {
    accepted: [
      {
        name: 'settled, preimage disclosed',
        body: {status: 'OK', settled: true, preimage: K1_A, pr: 'lnbc210n1pjq'},
        settled: true,
        preimage: K1_A,
        why: 'the payment preimage proves settlement but cannot redeem the comment-bound bearer note'
      },
      {
        name: 'settled, preimage withheld',
        body: {status: 'OK', settled: true, preimage: null, pr: 'lnbc210n1pjq'},
        settled: true,
        preimage: null
      },
      {
        name: 'not yet settled',
        body: {status: 'OK', settled: false, preimage: null, pr: 'lnbc210n1pjq'},
        settled: false,
        preimage: null
      }
    ],
    rejected: [
      {name: 'no settled field', body: {status: 'OK', pr: 'lnbc210n1pjq'}},
      {name: 'settled is a string', body: {status: 'OK', settled: 'true', pr: 'lnbc210n1pjq'}},
      {name: 'no pr to bind the result to', body: {status: 'OK', settled: true}}
    ]
  }
}

// ---- vectors: note lifecycle ---------------------------------------------

const lifecycle = {
  version: VERSION,
  spec: SPEC,
  description:
    'The state machine a holder must implement, and the transitions that are fund-critical. These are behavioural requirements rather than pure functions, so they are expressed as scenarios the mock mint can drive.',
  states: ['pending', 'confirmed', 'spent'],
  scenarios: [
    {
      name: 'mint to a wallet-generated secret',
      steps: ['persist a fresh secret', 'send its hash as the LUD-12 comment', 'pay the invoice', 'claim with the persisted secret'],
      requirement:
        'a SERVICE MUST reject a missing or malformed comment before invoicing. The payment preimage is only settlement proof; the freshly minted bearer k1 is the WALLET-generated secret whose hash was carried in comment.'
    },
    {
      name: 'melt is not settlement',
      steps: ['melt', 'receive OK', 'observe the note still reserved'],
      requirement:
        'OK on a melt means the payment is in flight. The note MUST NOT be treated as confirmed spent until settlement, and a failed payment restores it to outstanding. A holder locking it optimistically must be able to unlock on a confirmed failure.'
    },
    {
      name: 'pending lockout',
      steps: ['melt k1', 'attempt a rotate on the same k1 before settlement'],
      requirement: 'the second call fails with reason "pending" and MUST be retried, never read as spent'
    },
    {
      name: 'ambiguous rotate',
      steps: ['rotate', 'the connection drops before a response'],
      requirement:
        'the fresh secret MUST be preserved, because the SERVICE may have minted it. Probe the input k1 with an informational GET: still live means the request never landed and the secret can be dropped; spent or unknown means the burn landed and the preserved secret is the only remaining money; a failed probe means keep everything.'
    },
    {
      name: 'ambiguous split',
      steps: ['split', 'the response is unparseable'],
      requirement: 'BOTH fresh secrets must be preserved, in output order: the split-off note first, then the change'
    },
    {
      name: 'a retried mutation',
      steps: [
        'rotate',
        'the connection drops after the SERVICE applied it',
        'the HTTP stack silently resends the identical request'
      ],
      requirement:
        'a SERVICE MUST recognize the byte-identical retry from the same k1 set, h, h2 and amount, and return the original success with the same sig and sig2 without moving balance again. A WALLET still persists every fresh output secret before sending the first request and keeps it across an ambiguous transport failure. A request that changes any recorded field is a genuine double-spend attempt and gets the ordinary already-spent refusal.'
    },
    {
      name: 'settle a merge or split output',
      steps: ['merge', 'informational GET on the new note', 'rotate'],
      requirement:
        'neither response carries the output amount, and a fee-charging SERVICE may have deducted from a split\'s change or refunded into a merge\'s result. The authoritative value comes from the informational GET, and that GET puts k1 on the wire, so a rotate should follow.'
    },
    {
      name: 'a duplicated k1',
      steps: ['merge with the same k1 given twice', 'observe the refusal'],
      requirement:
        'a SERVICE MUST refuse a mutation that names the same k1 more than once, atomically and before burning anything - counting one note\'s value twice into a merge or split output creates money from nothing. The reference mint refuses (inside its transaction, the second burn of a duplicate finds the first already spent it, and everything rolls back); a SERVICE that instead deduplicates and proceeds at the note\'s true value conserves funds only by accident, and the grader marks it with a warning rather than a pass.'
    },
    {
      name: 'an output hash already in use',
      steps: [
        'rotate with h set to the id of an existing note, or to the payment hash of an invoice the SERVICE issued',
        'observe the refusal'
      ],
      requirement:
        'a SERVICE MUST refuse h/h2 values that collide with any note id it has ever minted or any invoice payment hash it has ever issued, before burning anything. Minting over an existing id hands the output to whoever already knows that id\'s preimage - for a pending mint invoice that is its future payer, and for a burned note it is every previous holder - or it bricks a paid mint whose settlement can no longer register under that key. A WALLET drawing fresh 32-byte secrets never collides honestly, so a collision is always adversarial. Refuse with the same reason as any dead k1: which table the id collided with is an oracle nobody is owed.'
    },
    {
      name: 'a split into the same hash twice',
      steps: ['split with h2 equal to h', 'observe the refusal'],
      requirement:
        'a SERVICE MUST refuse a split whose two output hashes are equal - one id cannot carry two notes, so accepting it either destroys the change or double-mints a single id.'
    }
  ]
}

// ---- vectors: threat suite -------------------------------------------------

// Not conformance data in the usual sense: the transport/exposure scorecard
// from the LUD-25 design debate, written down as scenarios so candidate spec
// changes are measured against the same attacks instead of argued about in
// the abstract. NON-NORMATIVE - every option but A is a proposal, and rows
// pinning today's vulnerable behavior exist to be INVERTED by the PR that
// lands the named option. The executable twin of this file is lnurl-mint's
// tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22).

// T10's merge-budget arithmetic, computed against the same example callback
// the callback vectors use, so the scenario's numbers recompute rather than
// being asserted.
const URL_BUDGET = 2000 // the practical GET budget LUD-12 itself notes
const ENCRYPTED_K1_BYTES = 33 + 12 + 32 + 16 // ephemeral pubkey + nonce + ciphertext + tag
const ENCRYPTED_K1_B64_CHARS = 4 * Math.ceil(ENCRYPTED_K1_BYTES / 3)
const mergeUrl = (param, secretChars, n) =>
  CB +
  '?' +
  Array.from({length: n}, () => `${param}=${'a'.repeat(secretChars)}`).join('&') +
  '&h=' +
  'a'.repeat(64)
const mergeCapacity = (param, secretChars) => {
  let n = 0
  while (mergeUrl(param, secretChars, n + 1).length <= URL_BUDGET) n++
  return n
}

const threatSuite = {
  version: VERSION,
  spec: SPEC,
  description:
    'The transport/exposure scorecard from the LUD-25 design debate: candidate spec options measured against a fixed set of attacks, so proposed changes are argued against the same scenarios instead of in the abstract. NON-NORMATIVE - option A is the current draft and every other option is a proposal, marked as such below; only rows with status "pins-current" describe behavior the draft already requires, and rows pinning today\'s vulnerable behavior exist to be INVERTED by the PR landing the named option. The executable twin of this file is lnurl-mint\'s tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22).',
  options: {
    A: {name: 'status quo', status: 'current-draft', summary: 'lnurl/luds#301 as drafted'},
    B: {
      name: 'comment-secret',
      status: 'proposal',
      summary:
        'A + a secret the WALLET attaches to the payRequest (LUD-12 comment), encrypted to the mint; the note\'s k1 becomes "<secret>:<preimage>" and the public LUD-21 preimage alone no longer redeems'
    },
    C: {
      name: '?p= everywhere',
      status: 'proposal',
      summary: 'every k1 replaced in transport by that k1 encrypted to the mint'
    },
    D: {
      name: 'hash-keyed informational GET',
      status: 'proposal',
      summary: 'A + poll /w by sha256(k1), never k1'
    },
    E: {name: 'blinded signatures', status: 'proposal', summary: 'the chaumian model'},
    F: {name: 'B + D', status: 'proposal', summary: 'comment-secret plus the hash-keyed informational GET'},
    G: {
      name: 'locked notes',
      status: 'proposal',
      summary:
        'a second asset class, not a bearer variant: redemption requires an LUD-04 signature from the LUD-05/LUD-13 linkingKey registered at mint/rotate time, over the FULL redemption request (k1, h/h2, amount/pr), so logged signatures are not replayable. Scored separately per scenario as lockedNotes, because the trades differ by note type'
    }
  },
  policy: {
    redGreen:
      'Scenarios asserting today\'s vulnerable behavior are pins that must be INVERTED by the PR landing the named option, mirroring the INVERTS WHEN policy in this file\'s executable companion, lnurl-mint\'s tests/test_bearer_threat_suite_poc.py (dni/lnurl-mint#22): that PR flips the pin red and forces the assertion to be rewritten against the fixed behavior. Controls (T4, T5) assert behavior that must never change.',
    coreTheorem:
      'Re-encrypting a bearer credential to the party that redeems it never shrinks its exposure set: the mint honors the ciphertext, so the ciphertext IS the note. The only encryption that helps is encrypting to the holder, which kills bearer-ness - option G takes that trade deliberately, via signatures rather than ciphertext.',
    seedRecoverableNotes:
      'A WALLET deriving note secrets deterministically (BIP85, or an LUD-05-style HMAC path plus a counter) can restore outstanding notes from the seed via hash-keyed lookup - option D doubles as the restore API. Restore covers device loss, NOT theft: anyone who copied a circulating note may have spent it long before the restore runs. One derivation convention must be pinned in the spec, or wallets fragment and restores silently miss notes.'
  },
  scenarios: [
    {
      id: 'T1',
      name: 'verify race',
      kind: 'attack',
      adversary: 'anyone who saw the unpaid mint invoice - the payment hash travels inside it',
      steps: [
        'observe an unpaid mint invoice and extract its payment hash',
        'poll the LUD-21 verify endpoint until the invoice settles',
        'take the disclosed preimage the moment it settles',
        'rotate the note before the payer does'
      ],
      currentBehavior: 'succeeds when verify is on',
      options: {
        closedBy: ['B', 'F'],
        notClosedBy: ['C', 'E'],
        lockedNotes: 'closed - the note is locked to its linkingKey from birth, so a racer holding only P cannot redeem'
      },
      status: 'inverts-when-option-B',
      notes:
        'C does not close it: encrypting to the mint is a public operation (mintPubkey is advertised), so the racer wraps the leaked preimage himself and replays. E does not either: the race becomes "whoever presents P plus a blinded B first gets the signature".'
    },
    {
      id: 'T2',
      name: 'routing-node race',
      kind: 'attack',
      adversary: 'every routing hop on the mint payment\'s path - each learns the preimage as the HTLC settles',
      steps: [
        'sit on the payment path of a mint invoice',
        'learn the preimage as the settling HTLC propagates back',
        'rotate before the payer'
      ],
      currentBehavior: 'succeeds even with VERIFY_ENABLED=false - no spec endpoint is involved',
      options: {
        closedBy: ['B', 'F'],
        lockedNotes: 'closed for locked notes only'
      },
      status: 'inverts-when-option-B',
      notes:
        'The same outcome as T1 with no verify at all: the preimage leaks from the payment protocol itself, not from any endpoint.'
    },
    {
      id: 'T3',
      name: 'poll-log replay',
      kind: 'attack',
      adversary: 'anyone reading whatever retains request URLs - a proxy, an access log, browser history',
      steps: [
        'the holder polls the informational GET /w?k1=<live note>',
        'the poll burns nothing, so the SPENDABLE k1 is left in the log',
        'the reader replays it into a rotate'
      ],
      currentBehavior: 'succeeds - every value poll leaves the SPENDABLE k1 in whatever retains request URLs',
      options: {
        closedBy: ['D', 'F'],
        notClosedBy: ['C'],
        lockedNotes: 'closed - a logged k1 is useless without the key'
      },
      status: 'inverts-when-option-D',
      notes:
        'D leaves only a harmless hash in those logs. C does not close it: a logged p redeems exactly like a logged k1 - the mint honors the ciphertext, so the ciphertext IS the note.'
    },
    {
      id: 'T4',
      name: 'callback-log replay',
      kind: 'control',
      adversary: 'anyone reading a logged mutating callback URL',
      steps: [
        'a k1 is captured from a MUTATING callback URL',
        'the request it rode in on already burned it',
        'replay it later'
      ],
      currentBehavior:
        'fails with "Invalid or already spent k1." - the burn from the original request is the protection',
      options: {holdsUnder: ['A', 'B', 'C', 'D', 'E', 'F', 'G']},
      status: 'pins-current',
      notes:
        'Must hold under every option. A replay landing in the same millisecond as the original is a plain race, not a logging problem.'
    },
    {
      id: 'T5',
      name: 'note at rest',
      kind: 'control',
      adversary: 'whoever finds the note URL - chat history, a screenshot, a printed QR',
      steps: ['find a note URL at rest', 'spend it'],
      currentBehavior: 'the finder spends it - a note URL at rest IS the money',
      options: {
        notClosedBy: ['A', 'B', 'C', 'D', 'E', 'F'],
        lockedNotes: 'beaten - the only option that beats the at-rest axiom, precisely because it surrenders bearer-ness'
      },
      status: 'pins-current',
      notes:
        'The bearer axiom: every bearer option "fails" this by design, and the all-minus row is deliberate. Any future option claiming to fix at-rest exposure has to answer this scenario first.'
    },
    {
      id: 'T6',
      name: 'operator correlation',
      kind: 'property',
      adversary: 'the mint operator',
      steps: [
        'at rotate, the WALLET discloses h = sha256(new_k1)',
        'the mint keys its storage by h',
        'a later spend of new_k1 matches the recorded h'
      ],
      currentBehavior: 'issuance links to redemption - a full transaction graph at the operator',
      options: {
        closedBy: ['E'],
        notClosedBy: ['A', 'B', 'C', 'D', 'F'],
        lockedNotes: 'open - the operator knows exactly which key owns which notes'
      },
      status: 'privacy-axis',
      notes:
        'h-preimages give log confidentiality (T4) but not unlinkability from the operator; only blinded issuance closes this.'
    },
    {
      id: 'T7',
      name: 'legacy LUD-03 melt',
      kind: 'property',
      adversary: 'none - a compatibility property',
      steps: ['a wallet that knows nothing of LNURLcash melts a note to a BOLT-11 pr, as plain LUD-03'],
      currentBehavior: 'works - the note melts to a BOLT-11 pr as plain LUD-03',
      options: {
        preservedBy: ['A', 'B', 'D', 'E', 'F'],
        brokenBy: ['C'],
        lockedNotes: 'broken - a plain LUD-03 wallet cannot lnurl-auth, so locked notes have no legacy story'
      },
      status: 'pins-current',
      notes:
        'C breaks it because legacy wallets cannot encrypt - unless mixed mode re-admits plaintext k1, which voids C\'s only claim.'
    },
    {
      id: 'T8',
      name: 'first-contact offline verify',
      kind: 'gap',
      adversary: 'an attacker who self-signs a note and supplies their own key',
      steps: [
        'a recipient who has never interacted with this mint receives a note',
        'it has no mintPubkey on record, so it cannot verify the note\'s sig offline',
        'embedding the pubkey in the note URL proves nothing - an attacker self-signs and supplies their own key'
      ],
      currentBehavior: 'no offline verification on first contact - a spec-level gap, no endpoint to hit',
      options: {closedBy: []},
      status: 'spec-gap',
      notes:
        'No option on the scorecard addresses this; it needs a key-distribution story, not a transport change.'
    },
    {
      id: 'T9',
      name: 'comment silently ignored',
      kind: 'gap',
      adversary: 'none - a silent downgrade hazard, not an attacker',
      steps: [
        'a wallet already sending a LUD-12 comment calls the payRequest callback',
        'the callback takes no comment param and unknown query params are dropped silently',
        'the wallet gets a bare k1=P note with verify advertised anyway'
      ],
      currentBehavior: 'a silent downgrade with no signal to the wallet',
      options: {closedBy: ['B', 'F']},
      status: 'inverts-when-option-B',
      notes:
        'Option B must define semantics - fail-closed (reject the callback) or fallback (k1=P, no verify for that invoice) - never silent.'
    },
    {
      id: 'T10',
      name: 'merge URL budget',
      kind: 'property',
      adversary: 'none - pure URL arithmetic',
      steps: [
        'build a merge callback carrying one k1 per input note plus h for the result',
        'compare its length against the ~2000-character practical GET budget LUD-12 itself notes'
      ],
      currentBehavior: 'a merge of 25 notes fits in plaintext hex k1s (64 chars each)',
      options: {
        preservedBy: ['A', 'B', 'D', 'E', 'F'],
        brokenBy: ['C']
      },
      arithmetic: {
        budgetChars: URL_BUDGET,
        exampleCallback: CB,
        plaintextK1Chars: 64,
        encryptedK1: {
          layout: '33-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag',
          bytes: ENCRYPTED_K1_BYTES,
          base64Chars: ENCRYPTED_K1_B64_CHARS
        },
        mergeOf25: {
          plaintextChars: mergeUrl('k1', 64, 25).length,
          plaintextFits: mergeUrl('k1', 64, 25).length <= URL_BUDGET,
          encryptedChars: mergeUrl('p', ENCRYPTED_K1_B64_CHARS, 25).length,
          encryptedFits: mergeUrl('p', ENCRYPTED_K1_B64_CHARS, 25).length <= URL_BUDGET
        },
        mergeCapacity: {
          plaintext: mergeCapacity('k1', 64),
          encrypted: mergeCapacity('p', ENCRYPTED_K1_B64_CHARS),
          advertisedMaxK1s: 100
        }
      },
      status: 'arithmetic',
      notes:
        'The same merge with every k1 swapped for an encrypted-to-the-mint blob (option C) does not fit. max_k1s=100 is unreachable in BOTH variants under the budget - plaintext caps at 28, blobs at 15 - so C would halve the merge ceiling in exchange for nothing, per T1/T2/T3.'
    },
    {
      id: 'T11',
      name: 'offline handoff',
      kind: 'property',
      adversary: 'none - the bearer property itself',
      steps: ['hand a bearer note to its next holder with no mint contact at handoff time'],
      currentBehavior: 'works - the spec\'s Offline circulation section',
      options: {
        preservedBy: ['A', 'B', 'C', 'D', 'E', 'F'],
        lockedNotes: 'lost - transfer requires an online re-lock via the mint'
      },
      status: 'pins-current',
      notes:
        'Structural, no endpoint. Locked notes are registered claims, not cash; the bearer core and locked notes are complements, not competitors.'
    }
  ]
}

// ---- vectors: the retried mutation ---------------------------------------

// Every mutation in LUD-25 is a GET, and HTTP stacks retry a GET when the
// connection they used is dropped: Go's net/http retries one that failed
// on a reused idle connection, the JDK's HttpClient retries idempotent
// methods with no switch to turn it off. The SERVICE therefore sees the
// byte-identical request twice, and by the time the second arrives its
// inputs are burned. Answering it as an already-spent input tells the
// holder the mutation never happened, and a holder that believes that
// discards the only copy of a secret the SERVICE really did mint a note
// against.
//
// Which makes "identical" a wire question, not an implementation detail:
// two SERVICEs that draw the line differently give the same wallet two
// different answers to the same dropped connection.

const RETRY_IN_A = K1_A
const RETRY_IN_B = K1_B
const RETRY_OUT = noteId(K1_C)
const RETRY_OUT_2 = noteId('0e'.repeat(32))
const RETRY_OTHER = noteId('0d'.repeat(32))

const sameInputs = (a, b) =>
  a.length === b.length && [...a].sort().join(',') === [...b].sort().join(',')

const retryOutcome = (recorded, retry) =>
  sameInputs(recorded.k1, retry.k1) &&
  recorded.h === retry.h &&
  (recorded.h2 ?? null) === (retry.h2 ?? null) &&
  (recorded.amount ?? null) === (retry.amount ?? null)
    ? 'replay'
    : 'double-spend'

const retryCase = (name, recorded, retry, note) => ({
  name,
  recorded,
  retry,
  outcome: retryOutcome(recorded, retry),
  ...(note ? {note} : {})
})

const ROTATE = {k1: [RETRY_IN_A], h: RETRY_OUT}
const SPLIT = {k1: [RETRY_IN_A], h: RETRY_OUT, h2: RETRY_OUT_2, amount: 5000}
const MERGE = {k1: [RETRY_IN_A, RETRY_IN_B], h: RETRY_OUT}

const retriedMutation = {
  version: VERSION,
  spec: SPEC,
  description:
    'What counts as a retry of a mutation, and what is still a double-spend attempt. Every mutation in LUD-25 is a GET, and HTTP stacks retry a GET when the connection they used is dropped, so a SERVICE sees the byte-identical request twice and the second one arrives with its inputs already burned. A SERVICE that answers the retry as an already-spent input tells the holder the mutation never happened, and the holder discards the only copy of a secret the SERVICE really did mint a note against. Replaying the original success is therefore a MUST. The replay path is a read: it burns nothing, mints nothing and moves no balance, and returns the same signature or signatures. Anything that is NOT a retry and names a burned input is refused exactly as an ordinary double-spend is, with the same reason string, so no oracle appears for whoever is holding a burned secret.',
  identity: [
    'the same input k1 set, compared as a SET: a merge naming the same notes in a different order is the same merge',
    'the same h',
    'the same h2, present or absent alike',
    'the same amount, present or absent alike'
  ],
  provenance:
    'Recorded, never inferred. A SERVICE links the burned inputs to the outputs they minted and matches against that. Matching on "a note exists at h" alone would let anyone holding a burned k1 and any outstanding note id pull a success out of the SERVICE.',
  outcomes: {
    replay:
      'the original success, byte for byte: the same status, the same sig and sig2, and no balance moved',
    'double-spend':
      'refused exactly as any other attempt to spend a burned secret, with the reason string unchanged'
  },
  cases: [
    retryCase('a rotate, retried unchanged', ROTATE, {...ROTATE}),
    retryCase('a split, retried unchanged', SPLIT, {...SPLIT}),
    retryCase('a merge, retried unchanged', MERGE, {...MERGE}),
    retryCase(
      'a merge retried with its inputs in the other order',
      MERGE,
      {k1: [RETRY_IN_B, RETRY_IN_A], h: RETRY_OUT},
      'the inputs are a set, not a sequence: this is the same merge'
    ),
    retryCase(
      'the same input with a different h',
      ROTATE,
      {k1: [RETRY_IN_A], h: RETRY_OTHER},
      'this is the ordinary double-spend attempt, and the existing refusal covers it unchanged'
    ),
    retryCase('a split retried with a different h2', SPLIT, {...SPLIT, h2: RETRY_OTHER}),
    retryCase(
      'a split retried with a different amount',
      SPLIT,
      {...SPLIT, amount: 6000},
      'the same outputs for a different amount is not the same request; a SERVICE that replayed it would be asked to mint two different splits over one pair of ids'
    ),
    retryCase(
      'a split retried with no h2 at all',
      SPLIT,
      {k1: [RETRY_IN_A], h: RETRY_OUT, amount: 5000},
      'absent is not the same as present, in either direction'
    ),
    retryCase('a rotate retried with an amount added', ROTATE, {...ROTATE, amount: 5000}),
    retryCase(
      'a split retried with h and h2 swapped',
      SPLIT,
      {...SPLIT, h: RETRY_OUT_2, h2: RETRY_OUT},
      'the outputs carry different amounts, so swapping them is a different request'
    ),
    retryCase('a merge retried naming only one of its inputs', MERGE, {
      k1: [RETRY_IN_A],
      h: RETRY_OUT
    }),
    retryCase('a merge retried with an extra input', MERGE, {
      k1: [RETRY_IN_A, RETRY_IN_B, K1_C],
      h: RETRY_OUT
    })
  ]
}

// ---- vectors: naming the note you are buying -----------------------------

// Current LUD-25 minting names every new output with the wallet's mandatory
// LUD-12 comment commitment. The payment preimage is ordinary settlement
// proof and never the bearer secret. ForgeSworn/Moneyer implementations that
// shipped the earlier `h` spelling repeat the same commitment in both fields;
// `h` is an additive capability and receipt vocabulary, never a substitute.
//
// What has to be pinned is the parameter name, what counts as well-formed,
// and the two refusal reasons - or two mints answer the same wallet two
// different ways, and a wallet cannot tell "this mint has not implemented
// it" from "this mint refused my hash".

const MTH_SECRET = '05'.repeat(32)
const MTH_H = noteId(MTH_SECRET)
const MTH_PREIMAGE = '06'.repeat(32)
const MTH_PAYMENT_HASH = noteId(MTH_PREIMAGE)
const MTH_AMOUNT = 21000
const MTH_RECEIPT_SIG = bytesToHex(signTrailing(MINT_PRIV, MTH_SECRET, MTH_AMOUNT))

// Ids that are already spoken for on the mint the cases below run against:
// one note, one payment hash of an invoice it issued, and one output
// another quote is already waiting to credit.
const MTH_NOTE_ID = noteId(K1_A)
const MTH_INVOICE_HASH = noteId('07'.repeat(32))
const MTH_QUOTE_OUTPUT = noteId('08'.repeat(32))
const MTH_IN_USE = [MTH_NOTE_ID, MTH_INVOICE_HASH, MTH_QUOTE_OUTPUT]

const MTH_REASONS = {
  malformed: 'Invalid h.',
  collision: 'Invalid or already spent k1.'
}

// Hex is case-insensitive, so an `h` is well formed on its bytes and the
// SERVICE compares the lowercase form. The producer rule stays strict -
// a WALLET sends lowercase - but a SERVICE that keys the string it was
// handed would file the note under the upper-case spelling and never find
// it again when the wallet asks for its own lowercase secret.
const mthWellFormed = h => typeof h === 'string' && /^[0-9a-f]{64}$/i.test(h)
const mthComparedAs = h => (mthWellFormed(h) ? h.toLowerCase() : null)

const mintToHashOutcome = h => {
  if (h === null) return 'comment-only'
  if (!mthWellFormed(h)) return 'malformed-h'
  if (MTH_IN_USE.includes(mthComparedAs(h))) return 'collision'
  return 'extension-bound'
}

const mintToHashCase = (name, h, why) => {
  const outcome = mintToHashOutcome(h)
  const comparedAs = mthComparedAs(h)
  return {
    name,
    amountMsat: MTH_AMOUNT,
    // Current LUD-25 commitment. The extension may repeat the same output
    // in `h`, but it never substitutes for this field.
    comment: mthWellFormed(h) ? comparedAs : MTH_H,
    h,
    // what the SERVICE compares and keys by: the same 32 bytes, lowercase
    comparedAs,
    outcome,
    invoiced: outcome === 'extension-bound' || outcome === 'comment-only',
    // the pay callback's own response says whether THIS quote was bound
    echo: outcome === 'extension-bound',
    noteId: outcome === 'extension-bound' ? comparedAs : outcome === 'comment-only' ? MTH_H : null,
    reason:
      outcome === 'malformed-h'
        ? MTH_REASONS.malformed
        : outcome === 'collision'
          ? MTH_REASONS.collision
          : null,
    ...(why ? {why} : {})
  }
}

// Only the boolean true is the capability, wherever it is read. A wallet
// that accepts the string "true" will pay a mint that never implemented
// it, and a wallet that reads an absent field as anything but false will
// do the same.
const mintToHashAdvertised = value => value === true

const advertisementCase = (where, name, value, why) => {
  const field = value === undefined ? {} : {mintToHash: value}
  const body =
    where === 'payRequest'
      ? {
          tag: 'payRequest',
          callback: 'https://mint.example/p/cb',
          minSendable: 1000,
          maxSendable: 100000000,
          metadata: meta([['text/plain', 'a mint']]),
          commentAllowed: 64,
          withdrawLink: 'https://mint.example/w',
          ...field
        }
      : where === 'mintAddress'
        ? {
            tag: 'withdrawRequest',
            callback: 'https://mint.example/w',
            minWithdrawable: 1000,
            maxWithdrawable: 100000000,
            payLink: 'https://mint.example/.well-known/lnurlp/mint',
            mintPubkey: MINT_PUB,
            ...field
          }
        : {
            pr: 'lnbc210n1pjqrstuvwxyz',
            verify: 'https://mint.example/verify/' + MTH_PAYMENT_HASH,
            disposable: false,
            ...field
          }
  return {
    name,
    where,
    body,
    offered: mintToHashAdvertised(value),
    ...(why ? {why} : {})
  }
}

const advertisementCases = where => [
  advertisementCase(where, 'advertised', true),
  advertisementCase(
    where,
    'absent',
    undefined,
    'the ordinary case, and not a defect: absence means no, and a mint without the feature says nothing anywhere'
  ),
  advertisementCase(where, 'the boolean false', false),
  advertisementCase(
    where,
    'the string "true"',
    'true',
    'only the boolean true is the capability. A wallet that accepts the string will pay a mint that never implemented it'
  ),
  advertisementCase(where, 'the number 1', 1)
]

const mintToHash = {
  version: VERSION,
  spec: 'LUD-06, LUD-21, LUD-25 plus ForgeSworn mintToHash extension',
  description:
    'ForgeSworn compatibility profile layered on current LUD-25 minting. The normative output commitment is always `comment=hex(sha256(secret))`. A WALLET MAY repeat that same 64-hex hash as `h` for services and sealed-signer receipts that shipped before the comment spelling. `h` never replaces comment; if present it must be well formed and identify the same output. With or without the extension, the payment preimage is settlement proof and never a valid bearer k1.',
  parameter: {
    name: 'h',
    on: 'the LUD-06 pay callback, alongside amount and the mandatory identical comment',
    value: 'the same sha256 commitment already carried in comment, 32 bytes as 64 lowercase hex',
    optional: true,
    absent: 'current LUD-25 behaviour: comment alone names the wallet-generated bearer secret'
  },
  caseRule: {
    wallet:
      'A WALLET using this extension MUST send the same commitment in `comment` and `h`, each as 64 lowercase hex.',
    service:
      'A SERVICE MUST require the normative comment, SHOULD normalise hex case before comparing, MUST reject a mismatched h, and MUST NOT treat upper- and lower-case spellings as different outputs.',
    whyItMatters:
      'A SERVICE that keys the string it was handed files the note under the upper-case spelling, and then cannot find it when the wallet asks the withdraw endpoint for its own lowercase secret. The money is not stolen, it is simply lost, and nobody is told. A SERVICE that instead refuses an upper-case `h` outright is being strict rather than wrong, and loses nobody anything - the wallet learns before it pays.',
    comparedAs:
      'Every case below carries `comparedAs`: the value a SERVICE compares and keys by, which is `h` lowercased, or null when `h` is absent or malformed.'
  },
  advertisement: {
    field: 'mintToHash',
    value: true,
    rule: 'Anything that is not exactly the boolean true is false, in all three places. An absent field means no, and a mint without the feature says nothing anywhere.',
    places: [
      {
        where: 'payRequest',
        means: 'I accept an `h` on my pay callback',
        read: 'the LUD-06 payRequest at /.well-known/lnurlp/<user>',
        why: 'the universal one. Every mint has a payRequest and the mint address document is experimental, so this is the one a wallet should decide from.'
      },
      {
        where: 'mintAddress',
        means: 'the same fact, again',
        read: 'the experimental mint address document at /.well-known/lnurlw/<user>',
        why: 'corroboration, kept for consistency with the other capability fields published there. A mint that publishes no mint address document is not saying no.'
      },
      {
        where: 'quoteResponse',
        means: 'I bound THIS quote to the hash you named',
        read: 'the pay callback\'s own JSON response, alongside pr and verify',
        why: 'per quote, and the one that matters at the moment money moves. A wallet reads it just before it parts with anything, and unlike the other two it cannot be cached or stale.'
      }
    ],
    why: 'A wallet has to know before it asks rather than after it pays. A SERVICE that does not advertise it MAY still be sent `h`, and will ignore it - so a wallet that assumed otherwise has paid for a note whose secret the SERVICE generated.'
  },
  reasons: MTH_REASONS,
  outcomes: {
    'extension-bound':
      'comment and h name the same output; an invoice is issued carrying `mintToHash: true`, and settlement credits that committed hash. The payment preimage names nothing',
    'comment-only':
      'no h was sent: the mandatory comment still names the output, and the payment preimage names nothing',
    'malformed-h':
      'not 32 bytes of hex in any casing: refused before any invoice exists, so a wallet never pays for a quote the SERVICE was always going to reject',
    collision:
      'refused before any invoice exists, with the same reason a colliding output hash gets on the withdraw callback, so a probe learns nothing about which ids exist'
  },
  idsAlreadyInUse: {
    note: MTH_NOTE_ID,
    invoicePaymentHash: MTH_INVOICE_HASH,
    pendingQuoteOutput: MTH_QUOTE_OUTPUT,
    why: 'An id already spoken for must never be minted over. A note\'s id has a preimage every previous holder knows; an invoice\'s payment hash points a future payer\'s money at a stranger\'s note, since its verify endpoint serves the preimage that IS the k1 of whatever sits under that id; and a second quote at an id another quote is already waiting to credit means whichever settles first takes it and the other payment lands nowhere.'
  },
  cases: [
    mintToHashCase('no h at all', null, 'the current LUD-25 flow: the mandatory comment names the output without the extension'),
    mintToHashCase('a well-formed h', MTH_H),
    mintToHashCase(
      'an h that is not hex',
      'z'.repeat(64),
      'the value is 32 bytes; a string that is not hex is not 32 bytes of anything'
    ),
    mintToHashCase('an h one character short', '0'.repeat(63)),
    mintToHashCase('an h one character long', '0'.repeat(65)),
    mintToHashCase(
      'an empty h',
      '',
      'present and empty is not the same as absent. A wallet that sent `h=` meant to bind, and handing it an unbound quote in silence is how it pays for a note whose secret the SERVICE generated'
    ),
    mintToHashCase(
      'an h in upper case hex',
      MTH_H.toUpperCase(),
      'the same 32 bytes as the lowercase case above, so it names the same output and lands at the same id. A WALLET still MUST send lowercase; a SERVICE that keys the upper-case string instead has filed the note where the wallet will never look for it'
    ),
    mintToHashCase(
      'an h that already names a note',
      MTH_NOTE_ID,
      'every previous holder of that note knows the preimage of its id'
    ),
    mintToHashCase(
      'an h in upper case hex that already names a note',
      MTH_NOTE_ID.toUpperCase(),
      'case is normalised BEFORE the collision check, or an upper-case spelling walks straight past it and mints over a live note'
    ),
    mintToHashCase(
      'an h that already names an invoice this SERVICE issued',
      MTH_INVOICE_HASH,
      'that invoice\'s verify endpoint serves the preimage which IS the k1 of whatever sits under the id'
    ),
    mintToHashCase(
      'an h another quote is already waiting to credit',
      MTH_QUOTE_OUTPUT,
      'two payments, one output id: whichever settles first takes it and the other payer has bought nothing'
    )
  ],
  settlement: {
    description:
      'One worked settlement, both ways round, so an implementation can check where the note landed rather than only that an invoice came back.',
    walletSecret: MTH_SECRET,
    comment: MTH_H,
    h: MTH_H,
    preimage: MTH_PREIMAGE,
    paymentHash: MTH_PAYMENT_HASH,
    extensionBound: {
      noteId: MTH_H,
      k1: MTH_SECRET,
      preimageIsAValidK1: false,
      note: 'a software wallet can claim by asking the withdraw endpoint for its own secret directly. A sealed signer that will not export that secret instead uses the optional bound receipt below to confirm the note without revealing k1'
    },
    commentOnly: {
      noteId: MTH_H,
      k1: MTH_SECRET,
      preimageIsAValidK1: false,
      note: 'without h, the mandatory comment still binds the freshly minted note to the wallet secret'
    }
  },
  receipt: {
    description:
      'An optional LUD-21 settlement receipt for a bound quote. This is needed by a sealed signer that generated k1 but will not export it merely so its companion app can probe the withdraw endpoint. The quote commits to the exact output id and net amount before payment. Once settled, verify repeats that commitment and adds the ordinary LUD-25 note signature. No field changes the legacy LUD-21 meaning of preimage: it remains payment proof and still does not open the bound note.',
    optional: true,
    field: 'mint',
    keyEstablishment: {
      rule: 'The WALLET must know the receipt verification key before it pays: recover the signing node identity from the BOLT-11 invoice, or read mintPubkey from the payRequest under the wallet\'s existing trust/pinning policy.',
      payRequest: {commentAllowed: 64, mintToHash: true, mintPubkey: MINT_PUB}
    },
    commitment: {
      h: 'the normalised output id committed by this quote; 32 bytes as 64 lowercase hex',
      amount: 'the exact net note value in millisatoshis after fees',
      sig: 'absent before settlement; after settlement, the ordinary recoverable LUD-25 signature over LNURLcash:<amount>:<h>'
    },
    quote: {
      pr: 'lnbc210n1pjqrstuvwxyz',
      verify: 'https://mint.example/verify/' + MTH_PAYMENT_HASH,
      mintToHash: true,
      mint: {h: MTH_H, amount: MTH_AMOUNT}
    },
    unsettled: {
      status: 'OK',
      settled: false,
      preimage: null,
      pr: 'lnbc210n1pjqrstuvwxyz',
      mint: {h: MTH_H, amount: MTH_AMOUNT}
    },
    settled: {
      status: 'OK',
      settled: true,
      preimage: MTH_PREIMAGE,
      pr: 'lnbc210n1pjqrstuvwxyz',
      mint: {h: MTH_H, amount: MTH_AMOUNT, sig: MTH_RECEIPT_SIG}
    },
    walletRules: [
      'A WALLET that requires a receipt MUST refuse to show or pay an invoice unless quote.mintToHash is exactly true and quote.mint matches the h it requested and the exact amount it expects to receive.',
      'Before accepting settlement, it MUST match verify.pr to quote.pr, match verify.mint.h and verify.mint.amount to the quote commitment, require settled to be exactly true, and verify mint.sig with the mint public key and its locally held k1.',
      'A SERVICE MUST NOT return mint.sig before settlement. An unsettled response MAY repeat h and amount so a wallet can diagnose a mismatch, but that repetition is not a receipt.',
      'Absence of quote.mint means the optional receipt is not offered. A software wallet still claims the comment-bound note with its own k1; a sealed signer must use another authenticated confirmation path or decline before payment.'
    ],
    invalid: [
      {
        name: 'quote commits a different h',
        quote: {mintToHash: true, mint: {h: MTH_NOTE_ID, amount: MTH_AMOUNT}},
        reason: 'the invoice is not demonstrably buying the output the wallet named'
      },
      {
        name: 'verify changes the net amount',
        verify: {settled: true, mint: {h: MTH_H, amount: MTH_AMOUNT - 1, sig: MTH_RECEIPT_SIG}},
        reason: 'the settled receipt is not the commitment shown before payment'
      },
      {
        name: 'signature appears before settlement',
        verify: {settled: false, mint: {h: MTH_H, amount: MTH_AMOUNT, sig: MTH_RECEIPT_SIG}},
        reason: 'a note signature is evidence of minted value and cannot be issued speculatively'
      },
      {
        name: 'settled response has the wrong signature',
        verify: {settled: true, mint: {h: MTH_H, amount: MTH_AMOUNT, sig: '00'.repeat(65)}},
        reason: 'the signer cannot confirm a note the mint has not authenticated'
      }
    ]
  },
  normalisation: {
    description:
      'One worked pair, so an implementation can check that the two spellings name one output rather than two.',
    sent: MTH_H.toUpperCase(),
    comparedAs: MTH_H,
    outputId: MTH_H,
    sameOutputAs: MTH_H,
    walletSecret: MTH_SECRET,
    note: 'A quote sent with the upper-case spelling settles into a note the wallet opens with its own secret, exactly as the lowercase spelling does. Two spellings, 32 bytes, one output.'
  },
  advertisements: [
    ...advertisementCases('payRequest'),
    ...advertisementCases('mintAddress'),
    ...advertisementCases('quoteResponse')
  ],
  contradictions: [
    {
      name: 'claims the capability and does not bind',
      what: 'any of the three says `mintToHash: true`, but the service ignores h or lets it disagree with the mandatory comment',
      verdict: 'broken',
      why: 'the extension claim is false and any receipt commitment may authenticate a different output from the mandatory comment.'
    },
    {
      name: 'binds and says nothing on the quote',
      what: 'the payRequest advertises it, the quote carries `h`, and the response omits `mintToHash`',
      verdict: 'safe but unconfirmable',
      why: 'the comment-bound note remains safe, but the wallet cannot rely on extension-specific receipt semantics for this quote.'
    },
    {
      name: 'says nothing anywhere and ignores `h`',
      what: 'no extension advertisement or echo; the mandatory comment still names the note',
      verdict: 'not implemented',
      why: 'the additive extension is absent; current LUD-25 comment minting remains fully implemented.'
    }
  ],
  walletRules: [
    'A WALLET MUST persist its chosen secret BEFORE asking for the invoice, then send its hash in the mandatory comment.',
    'A WALLET using the extension MUST repeat that same hash as 64 lowercase hex in h; it MUST NOT send two different output commitments.',
    'A WALLET decides whether the additive h and receipt fields are supported from mintToHash on the payRequest; absence affects only the extension, never the mandatory comment-bound note.',
    'A WALLET requiring a bound receipt MUST check the pay callback\'s own mintToHash and mint commitment before paying. If absent, it declines or uses another authenticated confirmation path; it never falls back to a preimage-backed mint.',
    'A software WALLET needs no verify preimage to claim a comment-bound note: it already knows its secret. A sealed signer MAY require the optional receipt and use verify as authenticated settlement evidence.',
    'A comment-bound note belongs to the WALLET from birth. Seed-derived secrets make it recoverable without relying on payment history.'
  ]
}

// ---- vectors: payment requests -------------------------------------------

// "Send me 500 sat" as a string a payer's wallet can act on: the amount,
// the mints the payee will take, where to deliver it, and when the ask
// stops being live. Not to be confused with pay-request.json, which is
// the LUD-06 payRequest a mint publishes; this is one holder asking
// another for value, and no mint is involved in reading it.
//
// The encoding is the NUT-18 creqA idiom with our own prefix: a fixed
// human-readable prefix, then the request object canonicalised under
// RFC 8785 (JCS) and carried as unpadded base64url. Canonical because two
// wallets building the same request must produce the same string, or a
// payee cannot match what came back to what they asked for.

const REQ_PREFIX = 'lnurlcashreq1'

// RFC 8785. Object keys sorted by UTF-16 code unit, no whitespace, no
// insignificant zeros, strings serialised as ECMAScript JSON.stringify
// does (which leaves non-ASCII alone rather than escaping it). Every
// value in a payment request is a string, an integer or an array of
// strings, so this is the whole of it.
const jcs = value => {
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']'
  if (value !== null && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .filter(key => value[key] !== undefined)
        .sort()
        .map(key => JSON.stringify(key) + ':' + jcs(value[key]))
        .join(',') +
      '}'
    )
  }
  return JSON.stringify(value)
}

const encodeRequest = request =>
  REQ_PREFIX + base64urlnopad.encode(utf8ToBytes(jcs(request)))

// a payee's Nostr identity, as a real npub rather than a plausible one
const NPUB = bech32.encode('npub', bech32.toWords(new Uint8Array(32).fill(7)), 200)

// Fixed, so an expiry case means the same thing every time it is run. A
// consumer evaluates the decode cases as if the clock read exactly this.
const REQ_NOW = 1787000000
const REQ_FUTURE = REQ_NOW + 3600
const REQ_PAST = REQ_NOW - 3600

const MINIMAL_REQUEST = {
  v: 1,
  id: '0123456789abcdef',
  amount: '500',
  currency: 'sat',
  methodDetails: {mints: ['mint.example']}
}

const FULL_REQUEST = {
  v: 1,
  id: 'a1b2c3d4e5f60718',
  amount: '21000',
  currency: 'sat',
  methodDetails: {mints: ['mint.example', '127.0.0.1:8899']},
  to: NPUB,
  memo: 'lunch at the café',
  expires: REQ_FUTURE
}

const EXPIRED_REQUEST = {...FULL_REQUEST, id: 'dead0000beef0001', expires: REQ_PAST}

const decodeCase = (name, input, valid, extra = {}) => ({
  name,
  input,
  valid,
  ...extra
})

const paymentRequest = {
  version: VERSION,
  spec: SPEC,
  description:
    'Payment requests: one holder asking another for value. Distinct from pay-request.json, which is the LUD-06 payRequest a mint publishes. A request names an amount in whole sat (as a decimal string, because that is what the 402 payment-method schemas carry), the mints the payee will accept a note from, optionally who to deliver it to, a memo and an expiry. Encoding is the NUT-18 creqA idiom with our own prefix: "lnurlcashreq1" followed by the request object canonicalised under RFC 8785 (JCS) and carried as unpadded base64url. Canonical, because two wallets building the same request must produce the same string or the payee cannot match what came back to what they asked for. The decode cases are evaluated as if the clock read evaluatedAt exactly, so an expiry means the same thing on every run.',
  prefix: REQ_PREFIX,
  encoding: {
    canonicalisation: 'RFC 8785 (JCS)',
    payload: 'base64url of the canonical UTF-8 JSON, no padding',
    layout: 'prefix || base64url(JCS(request))'
  },
  evaluatedAt: REQ_NOW,
  fields: {
    v: 'protocol version, the integer 1',
    id: '16 lowercase hex characters, the payee\'s handle on this request',
    amount: 'whole sat as a decimal string. The payer sends amount * 1000 msat exactly; sub-sat requests are not a thing',
    currency: 'the string "sat"',
    methodDetails: '{mints: string[]} - the hosts a note must come from, at least one',
    to: 'optional. An npub, or a Lightning Address shaped name@domain',
    memo: 'optional free text, shown to the payer and carried back with the note',
    expires: 'optional unix seconds. At or after this the request is no longer payable'
  },
  reasons: {
    'wrong-prefix': 'the string does not begin with lnurlcashreq1',
    'not-base64url': 'the payload is not decodable as unpadded base64url',
    'not-json': 'the payload decodes to bytes that are not a JSON object',
    'unknown-version': 'v is not 1',
    'bad-id': 'id is not 16 lowercase hex characters',
    'amount-not-an-integer': 'amount is not a decimal string naming a whole number of sat above zero',
    'wrong-currency': 'currency is not "sat"',
    'no-mints': 'methodDetails.mints is missing or empty, so no note can satisfy it',
    'unroutable-to': 'to is present but is neither an npub nor name@domain',
    expired: 'expires is at or before the moment the request was read'
  },
  encode: [
    {
      name: 'minimal request',
      request: MINIMAL_REQUEST,
      canonical: jcs(MINIMAL_REQUEST),
      encoded: encodeRequest(MINIMAL_REQUEST)
    },
    {
      name: 'request with a recipient, a memo and an expiry',
      request: FULL_REQUEST,
      canonical: jcs(FULL_REQUEST),
      encoded: encodeRequest(FULL_REQUEST),
      note: 'the memo carries a non-ASCII character on purpose: JCS leaves it alone rather than escaping it, and a canonicaliser that escapes it produces a different string for the same request'
    },
    {
      name: 'keys in a different order encode identically',
      request: {
        methodDetails: {mints: ['mint.example']},
        currency: 'sat',
        amount: '500',
        id: '0123456789abcdef',
        v: 1
      },
      canonical: jcs(MINIMAL_REQUEST),
      encoded: encodeRequest(MINIMAL_REQUEST),
      note: 'the point of canonicalising: the same request built in any order is the same string'
    }
  ],
  decode: [
    decodeCase('minimal request round-trips', encodeRequest(MINIMAL_REQUEST), true, {
      request: MINIMAL_REQUEST
    }),
    decodeCase(
      'request with a recipient, a memo and an expiry round-trips',
      encodeRequest(FULL_REQUEST),
      true,
      {request: FULL_REQUEST}
    ),
    decodeCase(
      'an expiry still in the future is payable',
      encodeRequest({...FULL_REQUEST, id: 'dead0000beef0002', expires: REQ_NOW + 1}),
      true,
      {request: {...FULL_REQUEST, id: 'dead0000beef0002', expires: REQ_NOW + 1}}
    ),
    decodeCase('expired', encodeRequest(EXPIRED_REQUEST), false, {reason: 'expired'}),
    decodeCase(
      'expiring exactly now is expired',
      encodeRequest({...FULL_REQUEST, id: 'dead0000beef0003', expires: REQ_NOW}),
      false,
      {reason: 'expired'}
    ),
    decodeCase(
      'a bad prefix',
      'creqA' + base64urlnopad.encode(utf8ToBytes(jcs(MINIMAL_REQUEST))),
      false,
      {reason: 'wrong-prefix'}
    ),
    decodeCase(
      'the right payload with no prefix at all',
      base64urlnopad.encode(utf8ToBytes(jcs(MINIMAL_REQUEST))),
      false,
      {reason: 'wrong-prefix'}
    ),
    decodeCase(
      'the payload is not base64url',
      REQ_PREFIX + 'not base64url at all!!',
      false,
      {reason: 'not-base64url'}
    ),
    decodeCase(
      'the payload is not a JSON object',
      REQ_PREFIX + base64urlnopad.encode(utf8ToBytes('["a request"]')),
      false,
      {reason: 'not-json'}
    ),
    decodeCase(
      'a version nobody has published',
      encodeRequest({...MINIMAL_REQUEST, v: 2}),
      false,
      {reason: 'unknown-version'}
    ),
    decodeCase(
      'a non-integer amount',
      encodeRequest({...MINIMAL_REQUEST, amount: '500.5'}),
      false,
      {reason: 'amount-not-an-integer'}
    ),
    decodeCase(
      'an amount in exponent notation',
      encodeRequest({...MINIMAL_REQUEST, amount: '5e2'}),
      false,
      {reason: 'amount-not-an-integer'}
    ),
    decodeCase(
      'an amount of zero',
      encodeRequest({...MINIMAL_REQUEST, amount: '0'}),
      false,
      {reason: 'amount-not-an-integer'}
    ),
    decodeCase(
      'an amount that is a number rather than a string',
      encodeRequest({...MINIMAL_REQUEST, amount: 500}),
      false,
      {reason: 'amount-not-an-integer'}
    ),
    decodeCase(
      'an empty mints array',
      encodeRequest({...MINIMAL_REQUEST, methodDetails: {mints: []}}),
      false,
      {reason: 'no-mints'}
    ),
    decodeCase(
      'no methodDetails at all',
      encodeRequest({v: 1, id: '0123456789abcdef', amount: '500', currency: 'sat'}),
      false,
      {reason: 'no-mints'}
    ),
    decodeCase(
      'a to that is neither an npub nor address-shaped',
      encodeRequest({...MINIMAL_REQUEST, to: 'send it to dave'}),
      false,
      {reason: 'unroutable-to'}
    ),
    decodeCase(
      'a to that looks like an npub but does not decode',
      encodeRequest({...MINIMAL_REQUEST, to: 'npub1thisisnotarealkeyatall'}),
      false,
      {reason: 'unroutable-to'}
    ),
    decodeCase(
      'a Lightning Address shaped to is fine',
      encodeRequest({...MINIMAL_REQUEST, to: 'alice@mint.example'}),
      true,
      {request: {...MINIMAL_REQUEST, to: 'alice@mint.example'}}
    ),
    decodeCase(
      'a currency that is not sat',
      encodeRequest({...MINIMAL_REQUEST, currency: 'msat'}),
      false,
      {reason: 'wrong-currency'}
    ),
    decodeCase(
      'an id that is not 16 hex characters',
      encodeRequest({...MINIMAL_REQUEST, id: 'lunch'}),
      false,
      {reason: 'bad-id'}
    ),
    decodeCase('an empty string', '', false, {reason: 'wrong-prefix'}),
    decodeCase('the prefix and nothing else', REQ_PREFIX, false, {reason: 'not-json'})
  ]
}

// ---- vectors: settling a note for value ----------------------------------

// What a server does when a bearer note arrives as payment. The whole of
// it is a decision table, and the ORDER of the table is the interesting
// part: a note that is wrong in two ways must be refused for the first
// reason, or two servers give a payer two different explanations for the
// same note.
//
// The rotate that settles the note is deliberately last. It is both the
// ownership transfer and the double-spend check, and it must not happen
// until every other reason to refuse has been ruled out - a server that
// rotates first and checks the amount second has taken the money and
// refused the request.

const SETTLE_ORDER = [
  'the note URL parses and names a host',
  'the host is one of acceptedMints',
  'the mint is asked what the note is worth, which is where a spent or in-flight note surfaces',
  'when requireSignature, the note carries a sig and it verifies against the mint pubkey',
  'the value the mint reports is at least minMsat',
  'rotate: the settlement and the double-spend check in one call'
]

const SETTLE_OUTCOMES = {
  accept: 'the note settles and the server grants what was paid for',
  'wrong-host': 'the note is from a mint this server does not accept, or the server accepts none',
  spent: 'the mint no longer knows the secret - somebody has already had this value',
  pending: 'the note is mid-melt, so its value is committed but not yet gone; a server must not treat this as spent OR as available',
  'missing-signature': 'a signature was required and the note carries none',
  'bad-signature': 'a signature was required and it does not verify against the mint pubkey',
  insufficient: 'the note is worth less than the price'
}

const settleOutcome = c => {
  const hosts = c.acceptedMints.map(h => h.toLowerCase())
  if (!hosts.includes(c.noteHost.toLowerCase())) return 'wrong-host'
  if (c.noteState === 'spent') return 'spent'
  if (c.noteState === 'pending') return 'pending'
  if (c.requireSignature && !c.hasSig) return 'missing-signature'
  if (c.requireSignature && !c.sigValid) return 'bad-signature'
  if (c.maxWithdrawableMsat < c.minMsat) return 'insufficient'
  return 'accept'
}

const settleCase = (name, overrides, note) => {
  const c = {
    name,
    noteHost: 'mint.example',
    acceptedMints: ['mint.example'],
    maxWithdrawableMsat: 21000,
    minMsat: 21000,
    hasSig: true,
    sigValid: true,
    requireSignature: false,
    noteState: 'live',
    ...overrides
  }
  return {...c, outcome: settleOutcome(c), ...(note ? {note} : {})}
}

const settleForValue = {
  version: VERSION,
  spec: SPEC,
  description:
    'The decision table a server works through when a LUD-25 bearer note arrives as payment. Every field is what the server knows at that point: the host the note names, the mints it accepts, what the mint says the note is worth, the price, whether the note carries a signature and whether that signature verifies, whether the server requires one, and what state the mint reports. The order matters as much as the answers: a note wrong in two ways is refused for the first reason in order, or two servers explain the same note two different ways. The rotate that settles the note comes last of all, because it is both the ownership transfer and the double-spend check, and a server that rotates before checking the amount has taken the money and refused the request.',
  order: SETTLE_ORDER,
  outcomes: SETTLE_OUTCOMES,
  hostComparison:
    'Hosts are compared lowercased, port included. A note from mint.example:8899 does not satisfy a server accepting mint.example, because they are not the same service.',
  signaturePolicy:
    'The signature is only consulted when the server requires one. Without requireSignature a note carrying a signature that does not verify is still accepted, and that is not a hole: the value came from asking the mint, which is authoritative, and the signature would only have saved a round trip. A server that wants offline refusal sets requireSignature.',
  cases: [
    settleCase('a good note at an accepted mint', {}),
    settleCase('worth more than the price', {maxWithdrawableMsat: 100000}),
    settleCase('worth exactly the price', {maxWithdrawableMsat: 21000}, 'the boundary: at the price is paid, not short'),
    settleCase('one msat short', {maxWithdrawableMsat: 20999}),
    settleCase('no signature, and none required', {hasSig: false, sigValid: false}),
    settleCase(
      'a signature that does not verify, with none required',
      {hasSig: true, sigValid: false},
      'accepted: the value came from asking the mint, which is authoritative. A server that wants to refuse this sets requireSignature'
    ),
    settleCase('a signature that verifies, and one required', {requireSignature: true}),
    settleCase('no signature, and one required', {requireSignature: true, hasSig: false, sigValid: false}),
    settleCase(
      'a signature that does not verify, and one required',
      {requireSignature: true, sigValid: false}
    ),
    settleCase('a note from a mint this server does not accept', {noteHost: 'other.example'}),
    settleCase(
      'a server that accepts no mints at all',
      {acceptedMints: []},
      'not a wildcard: a server with an empty list takes nothing'
    ),
    settleCase(
      'the same host on a different port',
      {noteHost: 'mint.example:8899'},
      'a port is part of the host; these are two services, not one'
    ),
    settleCase(
      'the same host in a different case',
      {noteHost: 'MINT.EXAMPLE'},
      'hosts are compared lowercased, so this is the same service'
    ),
    settleCase('an already spent note', {noteState: 'spent'}),
    settleCase(
      'a note mid-melt',
      {noteState: 'pending'},
      'not spent and not available: the melt may still fail and hand the value back, so a server must refuse without recording it as burned'
    ),
    settleCase(
      'spent, and from a mint this server does not accept',
      {noteState: 'spent', noteHost: 'other.example'},
      'the host is checked before the mint is asked anything, so this is wrong-host'
    ),
    settleCase(
      'spent, and too small anyway',
      {noteState: 'spent', maxWithdrawableMsat: 1},
      'the mint answers before the amount is compared, so this is spent'
    ),
    settleCase(
      'unsigned, required, and too small anyway',
      {requireSignature: true, hasSig: false, sigValid: false, maxWithdrawableMsat: 1},
      'the signature is checked before the amount'
    ),
    settleCase(
      'accepted from the second mint in the list',
      {noteHost: '127.0.0.1:8899', acceptedMints: ['mint.example', '127.0.0.1:8899']}
    )
  ]
}

// ---- write ---------------------------------------------------------------

const files = [
  write('signature.json', signature),
  write('derivation.json', derivation),
  write('cash-derivation.json', cashDerivation),
  write('bech32.json', bech32Vectors),
  write('url-admission.json', urlAdmission),
  write('input-resolution.json', inputResolution),
  write('note-url.json', noteUrl),
  write('fees.json', fees),
  write('bolt11.json', bolt11),
  write('callbacks.json', callbacks),
  write('responses.json', responses),
  write('withdraw-info.json', withdrawInfo),
  write('pay-request.json', payRequest),
  write('lifecycle.json', lifecycle),
  write('threat-suite.json', threatSuite),
  write('payment-request.json', paymentRequest),
  write('settle-for-value.json', settleForValue),
  write('retried-mutation.json', retriedMutation),
  write('mint-to-hash.json', mintToHash),
  write('part2.json', part2),
  write('nostr-seed.json', nostrSeed)
]

write('index.json', {
  version: VERSION,
  spec: SPEC,
  generatedBy: 'tools/generate.mjs',
  description:
    'Language-neutral conformance vectors for LNURLcash (LUD-25). Every implementation is expected to load these files directly rather than transcribe them.',
  files: files.filter(f => f !== 'index.json')
})

console.log(`wrote ${files.length + 1} vector files to vectors/`)
