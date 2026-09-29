// The grader's own reading of LUD-25 notes and spends.
//
// Every note is a BIP-341 taproot output key Q. A spend opens it by its key
// path (a ck1: Q and a BIP-340 signature) or by one leaf of its script tree
// (a cw1: the leaf, its control block, the witness), and every signature in
// either signs the BIP-341 sighash of input 0 of one fixed, never-broadcast
// transaction whose prevout is bound to the mint's domain.
//
// Written from the spec text and @noble alone, like everything else in the
// grader, and deliberately not shared with the mock mint or the vector
// generator: three readings that must agree with each other and with the
// numbers 25.md itself publishes (the selfcheck holds this one to them).
//
// Nothing here is secret apart from the keys the grader makes for itself,
// and those are thrown away with the run, so none of it is constant-time.

import {bech32m} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {schnorr, secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

export const TAPLEAF_VERSION = 0xc0
// BIP-341's nothing-up-my-sleeve point: nobody knows its discrete log, so a
// note built on it has no key path at all.
export const NUMS_H = hexToBytes('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
export const KEY_PATH_LOCKTIME = 0
export const KEY_PATH_SEQUENCE = 0xffffffff

const N = secp256k1.Point.Fn.ORDER
// No URL gets near this; it only bounds the work a hostile string can cost.
const BECH32M_LIMIT = 8192
const HEX32 = /^[0-9a-f]{64}$/i

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

const u32le = n => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, true)
  return out
}

const toBig = bytes => BigInt(`0x${bytesToHex(bytes)}`)

export const taggedHash = (tag, ...parts) => {
  const t = sha256(utf8ToBytes(tag))
  return sha256(concat(t, t, ...parts))
}

// The even-y point with this x, or null if x is not on the curve.
const liftX = x => {
  if (x.length !== 32) return null
  try {
    return secp256k1.Point.fromBytes(concat(Uint8Array.of(0x02), x))
  } catch {
    return null
  }
}

export const isXOnlyPoint = x => liftX(x) !== null

const compactSize = n =>
  n < 0xfd ? Uint8Array.of(n) : Uint8Array.of(0xfd, n & 0xff, n >> 8)

export const tapLeafHash = (script, version = TAPLEAF_VERSION) =>
  taggedHash('TapLeaf', Uint8Array.of(version), compactSize(script.length), script)

// BIP-341 sorts the two children before hashing, so a branch has one hash
// whichever side each came from.
export const tapBranchHash = (a, b) =>
  bytesToHex(a) < bytesToHex(b) ? taggedHash('TapBranch', a, b) : taggedHash('TapBranch', b, a)

// Q = lift_x(P) + tagged_hash("TapTweak", P || root)·G, with Q's parity and
// the tweak itself (a holder of P's key needs it to sign for Q).
export const taprootTweak = (internalKey, merkleRoot) => {
  const P = liftX(internalKey)
  if (!P) return null
  const t = toBig(taggedHash('TapTweak', internalKey, merkleRoot))
  if (t >= N) return null
  const Q = P.add(secp256k1.Point.BASE.multiply(t))
  if (Q.equals(secp256k1.Point.ZERO)) return null
  return {outputKey: Q.toBytes(true).slice(1), parity: Q.y % 2n === 0n ? 0 : 1, tweak: t}
}

// The Q a leaf and its control block commit to, or null if the control
// block is malformed or its parity bit is wrong.
export const outputKeyOf = (script, controlBlock) => {
  if (controlBlock.length < 33 || (controlBlock.length - 33) % 32 !== 0) return null
  if ((controlBlock.length - 33) / 32 > 128) return null
  let node = tapLeafHash(script, controlBlock[0] & 0xfe)
  for (let i = 33; i < controlBlock.length; i += 32) {
    node = tapBranchHash(node, controlBlock.subarray(i, i + 32))
  }
  const tweaked = taprootTweak(controlBlock.subarray(1, 33), node)
  if (!tweaked || tweaked.parity !== (controlBlock[0] & 1)) return null
  return tweaked.outputKey
}

// ---- the bearer note ----

// OP_SHA256 <h> OP_EQUAL
export const bearerLeaf = h => {
  if (h.length !== 32) throw new Error('h must be 32 bytes')
  return concat(Uint8Array.of(0xa8, 0x20), h, Uint8Array.of(0x87))
}

export const bearerNote = h => {
  const leaf = bearerLeaf(h)
  const tweaked = taprootTweak(NUMS_H, tapLeafHash(leaf))
  return {
    leaf,
    outputKey: tweaked.outputKey,
    controlBlock: concat(Uint8Array.of(TAPLEAF_VERSION | tweaked.parity), NUMS_H)
  }
}

// ---- what a signature signs ----

// The bare lowercase hostname a spend at `url` is bound to: never the
// scheme, never the port.
export const spendDomainOf = url => new URL(url).hostname.toLowerCase()

export const spendPrevout = domain => {
  if (!domain) throw new Error('a spend domain is required')
  return taggedHash('LNURLcash/mint', utf8ToBytes(domain.toLowerCase()))
}

// BIP-341's SigMsg for input 0 of the canonical spend transaction under
// SIGHASH_DEFAULT, with BIP-342's extension when a leaf is given.
export const spendSigMsg = ({outputKey, domain, locktime, sequence, leafScript}) => {
  const spk = concat(Uint8Array.of(0x51, 0x20), outputKey)
  const zero64 = new Uint8Array(8)
  return concat(
    Uint8Array.of(0x00), // hash_type
    u32le(2), // nVersion
    u32le(locktime),
    sha256(concat(spendPrevout(domain), u32le(0))), // sha_prevouts
    sha256(zero64), // sha_amounts
    sha256(concat(Uint8Array.of(spk.length), spk)), // sha_scriptpubkeys
    sha256(u32le(sequence)), // sha_sequences
    sha256(concat(zero64, Uint8Array.of(0x00))), // sha_outputs
    Uint8Array.of(leafScript ? 0x02 : 0x00), // spend_type, no annex
    u32le(0), // input_index
    ...(leafScript ? [tapLeafHash(leafScript), Uint8Array.of(0x00), u32le(0xffffffff)] : [])
  )
}

const tapSighash = sigMsg => taggedHash('TapSighash', Uint8Array.of(0x00), sigMsg)

export const keyPathSighash = (outputKey, domain) =>
  tapSighash(spendSigMsg({outputKey, domain, locktime: KEY_PATH_LOCKTIME, sequence: KEY_PATH_SEQUENCE}))

export const scriptPathSighash = (outputKey, domain, leafScript, locktime, sequence) =>
  tapSighash(spendSigMsg({outputKey, domain, locktime, sequence, leafScript}))

// ---- the wire values ----

const encode = (hrp, bytes) => bech32m.encode(hrp, bech32m.toWords(bytes), BECH32M_LIMIT)

const decode = (hrp, value) => {
  if (typeof value !== 'string') return null
  try {
    const {prefix, words} = bech32m.decode(value.trim(), BECH32M_LIMIT)
    return prefix === hrp ? bech32m.fromWords(words) : null
  } catch {
    return null
  }
}

export const encodeCp1 = outputKey => encode('cp', outputKey)
export const encodeCk1 = (outputKey, signature) => encode('ck', concat(outputKey, signature))

// u32 locktime || u32 sequence || (u16 len || item)* over the script, the
// control block and the witness items bottom of stack first. Big-endian.
export const encodeCw1 = ({locktime, sequence, script, controlBlock, witness}) => {
  const head = new Uint8Array(8)
  new DataView(head.buffer).setUint32(0, locktime, false)
  new DataView(head.buffer).setUint32(4, sequence, false)
  const items = [script, controlBlock, ...witness].map(item => {
    const len = new Uint8Array(2)
    new DataView(len.buffer).setUint16(0, item.length, false)
    return concat(len, item)
  })
  return encode('cw', concat(head, ...items))
}

// A cp1's Q, only if it is on the curve.
export const decodeCp1 = value => {
  const q = decode('cp', value)
  return q && q.length === 32 && isXOnlyPoint(q) ? q : null
}

// hex(Q) of whatever goes where a cp1 goes: a cp1, or a bearer note's
// 64-hex h. Null if it is neither.
export const decodeNoteRef = value => {
  if (typeof value !== 'string') return null
  const v = value.trim()
  if (HEX32.test(v)) return bytesToHex(bearerNote(hexToBytes(v.toLowerCase())).outputKey)
  const q = decodeCp1(v)
  return q ? bytesToHex(q) : null
}

// What a k1 spends: a 64-hex preimage (a bearer note's short form), a ck1
// or a cw1. Null if it is none of them. Checks shape only; whether the
// spend really opens its Q is the mint's to decide.
export const decodeSpend = value => {
  if (typeof value !== 'string') return null
  const v = value.trim()
  if (HEX32.test(v)) {
    const preimage = hexToBytes(v.toLowerCase())
    const h = sha256(preimage)
    const note = bearerNote(h)
    return {
      kind: 'script',
      outputKey: note.outputKey,
      locktime: KEY_PATH_LOCKTIME,
      sequence: KEY_PATH_SEQUENCE,
      script: note.leaf,
      controlBlock: note.controlBlock,
      witness: [preimage],
      preimage,
      h
    }
  }
  const ck1 = decode('ck', v)
  if (ck1) {
    return ck1.length === 96 ? {kind: 'key', outputKey: ck1.slice(0, 32), signature: ck1.slice(32)} : null
  }
  const data = decode('cw', v)
  if (!data || data.length < 8) return null
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const parts = []
  let i = 8
  while (i < data.length) {
    if (i + 2 > data.length) return null
    const n = view.getUint16(i, false)
    i += 2
    if (i + n > data.length) return null
    parts.push(data.slice(i, i + n))
    i += n
  }
  if (parts.length < 2) return null
  const outputKey = outputKeyOf(parts[0], parts[1])
  if (!outputKey) return null
  const [script, controlBlock, ...witness] = parts
  return {
    kind: 'script',
    outputKey,
    locktime: view.getUint32(0, false),
    sequence: view.getUint32(4, false),
    script,
    controlBlock,
    witness
  }
}

// ---- spending ----

// BIP-340 with an all-zero aux_rand, as 25.md has a WALLET sign: the ck1
// is then a deterministic function of the key and the domain.
const AUX_ZERO = new Uint8Array(32)

// The ck1 that spends the key-path note x(sk·G) at `domain`.
export const keyPathSpend = (secretKey, domain) => {
  const outputKey = schnorr.getPublicKey(secretKey)
  return encodeCk1(outputKey, schnorr.sign(keyPathSighash(outputKey, domain), secretKey, AUX_ZERO))
}

// The secret key that signs for Q = P + t·G, given P's secret key. BIP-340
// negates the key of an odd-y P before tweaking; noble negates the result
// for an odd-y Q itself when it signs.
export const tweakSecretKey = (secretKey, tweak) => {
  const d = toBig(secretKey)
  const P = secp256k1.Point.BASE.multiply(d)
  const even = P.y % 2n === 0n ? d : N - d
  return hexToBytes(((even + tweak) % N).toString(16).padStart(64, '0'))
}

// A bearer note's full cw1 for this preimage, with the claimed time.
export const bearerSpend = (preimage, {locktime = KEY_PATH_LOCKTIME, sequence = KEY_PATH_SEQUENCE} = {}) => {
  const note = bearerNote(sha256(preimage))
  return encodeCw1({locktime, sequence, script: note.leaf, controlBlock: note.controlBlock, witness: [preimage]})
}

// A note of three leaves under an internal key the caller holds:
//
//     root = branch(branch(leaves[0], leaves[1]), leaves[2])
//
// and a cw1 builder for each leaf. `leaves` are {script, version}.
export const scriptTree = (internalKey, leaves) => {
  if (leaves.length !== 3) throw new Error('scriptTree takes exactly three leaves')
  const hashes = leaves.map(leaf => tapLeafHash(leaf.script, leaf.version))
  const left = tapBranchHash(hashes[0], hashes[1])
  const root = tapBranchHash(left, hashes[2])
  const tweaked = taprootTweak(internalKey, root)
  if (!tweaked) throw new Error('the tree does not tweak to a point')
  const paths = [[hashes[1], hashes[2]], [hashes[0], hashes[2]], [left]]
  const controlBlock = i =>
    concat(Uint8Array.of(leaves[i].version | tweaked.parity), internalKey, ...paths[i])
  return {
    outputKey: tweaked.outputKey,
    tweak: tweaked.tweak,
    controlBlock,
    spend: (i, witness, {locktime = KEY_PATH_LOCKTIME, sequence = KEY_PATH_SEQUENCE} = {}) =>
      encodeCw1({locktime, sequence, script: leaves[i].script, controlBlock: controlBlock(i), witness})
  }
}
