// The mock mint's reading of LUD-25 notes and spends.
//
// Kept apart from the grader's own (runner/spend.mjs) on purpose: the mock
// is what the grader is graded against, and two copies of one mistake would
// agree with each other. Both are held to the numbers 25.md publishes, the
// grader's by the selfcheck and this one by the self-grade.
//
// A real mint hands any leaf it cannot judge to Bitcoin Core's interpreter.
// The mock has none, so it judges exactly what the grader sends it - a
// bearer hashlock under any internal key and at any depth - and refuses
// every other script as one it cannot verify. That refusal is honest, and
// nothing in the grade needs more.

import {bech32m} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {schnorr, secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, concatBytes, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

const LIMIT = 8192
const ORDER = secp256k1.Point.Fn.ORDER
const H = hexToBytes('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
const FINAL = 0xffffffff

const tagged = (tag, ...parts) => schnorr.utils.taggedHash(tag, ...parts)

const le32 = n => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n >>> 0, true)
  return out
}

const pointAt = x => {
  try {
    return schnorr.utils.lift_x(BigInt(`0x${bytesToHex(x)}`))
  } catch {
    return null
  }
}

const leafHash = (script, version) =>
  tagged('TapLeaf', Uint8Array.of(version), script.length < 0xfd ? Uint8Array.of(script.length) : Uint8Array.of(0xfd, script.length & 0xff, script.length >> 8), script)

const tweakTo = (internal, root) => {
  const P = internal.length === 32 ? pointAt(internal) : null
  if (!P) return null
  const t = BigInt(`0x${bytesToHex(tagged('TapTweak', internal, root))}`)
  if (t >= ORDER) return null
  const Q = P.add(secp256k1.Point.BASE.multiply(t))
  return {x: schnorr.utils.pointToBytes(Q), odd: Q.y & 1n ? 1 : 0}
}

const committedKey = (script, control) => {
  if (control.length < 33 || (control.length - 33) % 32 || control.length > 33 + 32 * 128) return null
  let node = leafHash(script, control[0] & 0xfe)
  for (let i = 33; i < control.length; i += 32) {
    const other = control.subarray(i, i + 32)
    const [a, b] = bytesToHex(node) <= bytesToHex(other) ? [node, other] : [other, node]
    node = tagged('TapBranch', a, b)
  }
  const q = tweakTo(control.subarray(1, 33), node)
  return q && q.odd === (control[0] & 1) ? q.x : null
}

export const bearer = h => {
  const leaf = concatBytes(Uint8Array.of(0xa8, 0x20), h, Uint8Array.of(0x87))
  const q = tweakTo(H, leafHash(leaf, 0xc0))
  return {q: bytesToHex(q.x), leaf, control: concatBytes(Uint8Array.of(0xc0 | q.odd), H)}
}

const unbech = (hrp, value) => {
  try {
    const d = bech32m.decode(value, LIMIT)
    return d.prefix === hrp ? bech32m.fromWords(d.words) : null
  } catch {
    return null
  }
}

const isHex32 = v => /^[0-9a-f]{64}$/i.test(v)

export const encodeCp1 = qHex => bech32m.encode('cp', bech32m.toWords(hexToBytes(qHex)), LIMIT)

// hex(Q) of a cp1 or a bearer note's hex h, or null. `offCurveOk` is the
// misbehaviour of a mint that skips the curve check LUD-25 requires.
export const noteOf = (value, {offCurveOk = false} = {}) => {
  if (typeof value !== 'string') return null
  const v = value.trim()
  if (isHex32(v)) return bearer(hexToBytes(v.toLowerCase())).q
  const q = unbech('cp', v)
  if (!q || q.length !== 32) return null
  return offCurveOk || pointAt(q) ? bytesToHex(q) : null
}

// The h a 64-hex short form names, when that is what it is.
export const hOf = value => (typeof value === 'string' && isHex32(value.trim()) ? value.trim().toLowerCase() : null)

// A k1, decoded: {kind: 'key', q, sig} or {kind: 'script', q, locktime,
// sequence, script, control, witness}. Null if it is no spend at all.
export const spendOf = value => {
  if (typeof value !== 'string') return null
  const v = value.trim()
  if (isHex32(v)) {
    const preimage = hexToBytes(v.toLowerCase())
    const note = bearer(sha256(preimage))
    return {kind: 'script', q: note.q, locktime: 0, sequence: FINAL, script: note.leaf, control: note.control, witness: [preimage]}
  }
  const key = unbech('ck', v)
  if (key) return key.length === 96 ? {kind: 'key', q: bytesToHex(key.subarray(0, 32)), sig: key.subarray(32)} : null
  const data = unbech('cw', v)
  if (!data || data.length < 8) return null
  const items = []
  let at = 8
  while (at < data.length) {
    if (at + 2 > data.length) return null
    const len = (data[at] << 8) | data[at + 1]
    at += 2
    if (at + len > data.length) return null
    items.push(data.subarray(at, at + len))
    at += len
  }
  if (items.length < 2) return null
  const q = committedKey(items[0], items[1])
  if (!q) return null
  const view = new DataView(data.buffer, data.byteOffset)
  return {
    kind: 'script',
    q: bytesToHex(q),
    locktime: view.getUint32(0, false),
    sequence: view.getUint32(4, false),
    script: items[0],
    control: items[1],
    witness: items.slice(2)
  }
}

export const keyPathSighash = (qHex, domain) => {
  const q = hexToBytes(qHex)
  const spk = concatBytes(Uint8Array.of(0x51, 0x20), q)
  const msg = concatBytes(
    Uint8Array.of(0),
    le32(2),
    le32(0),
    sha256(concatBytes(tagged('LNURLcash/mint', utf8ToBytes(domain.toLowerCase())), le32(0))),
    sha256(new Uint8Array(8)),
    sha256(concatBytes(Uint8Array.of(spk.length), spk)),
    sha256(le32(FINAL)),
    sha256(new Uint8Array(9)),
    Uint8Array.of(0),
    le32(0)
  )
  return tagged('TapSighash', Uint8Array.of(0), msg)
}

// BIP-342's OP_SUCCESSx, found by walking the opcodes so pushed data is
// skipped rather than read as code.
const SUCCESS = new Set([80, 98, 126, 127, 128, 129, 131, 132, 133, 134, 137, 138, 141, 142, 149, 150, 151, 152, 153])
for (let op = 187; op <= 254; op++) SUCCESS.add(op)
const usesOpSuccess = script => {
  for (let i = 0; i < script.length; ) {
    const op = script[i++]
    // A truncated push ends the walk: Core fails such a script by itself.
    if (op >= 1 && op <= 75) i += op
    else if (op === 0x4c) {
      if (i + 1 > script.length) return false
      i += 1 + script[i]
    } else if (op === 0x4d) {
      if (i + 2 > script.length) return false
      i += 2 + (script[i] | (script[i + 1] << 8))
    } else if (op === 0x4e) {
      if (i + 4 > script.length) return false
      i += 4 + new DataView(script.buffer, script.byteOffset + i, 4).getUint32(0, true)
    } else if (SUCCESS.has(op)) return true
  }
  return false
}

// The redeemer's signed time claim, against the mock's own clock: which
// rule it breaks, and why, or null. `skip` names rules a misbehaving mock
// does not apply (true for all of them).
const TIME_RULES = ['blockHeight', 'future', 'blockCount', 'relative']
const timeProblem = ({locktime, sequence}, now, lockedAt, skip) => {
  const applies = rule => !(skip === true || (Array.isArray(skip) && skip.includes(rule)))
  if (locktime !== 0) {
    if (locktime < 500_000_000) {
      if (applies('blockHeight')) return 'block-height locktimes have no meaning without a chain'
    } else if (locktime > now && applies('future')) return `locktime ${locktime} is in the future`
  }
  if (sequence & 0x80000000) return null
  if (!(sequence & 0x400000)) {
    return applies('blockCount') ? 'block-count relative locks have no meaning without a chain' : null
  }
  const needed = (sequence & 0xffff) * 512
  return now - lockedAt < needed && applies('relative') ? `relative lock of ${needed}s not yet satisfied` : null
}

// true, false, one rule's name, or a comma-separated list of them.
export const timeRulesSkipped = option =>
  option === true || option === 'true'
    ? true
    : typeof option === 'string'
      ? option.split(',').map(rule => rule.trim()).filter(rule => TIME_RULES.includes(rule))
      : Array.isArray(option)
        ? option
        : []

// Does `spend` open its note? {ok: true}, or {ok: false, reason, specific}
// where only a script path's reason is safe to hand back: a cw1 discloses
// everything it has already, while explaining a failed key-path signature
// would only help someone guess. `lax` names the rules a misbehaving mock
// skips.
export const judge = (spend, {domains, now, lockedAt, lax = {}}) => {
  if (spend.kind === 'key') {
    if (lax.unverifiedCk1) return {ok: true}
    const sig = spend.sig
    for (const domain of domains) {
      try {
        if (schnorr.verify(sig, keyPathSighash(spend.q, domain), hexToBytes(spend.q))) return {ok: true}
      } catch {
        // not a signature by this key at this domain
      }
    }
    return {ok: false, reason: 'invalid', specific: false}
  }
  const refuse = reason => ({ok: false, reason, specific: true})
  const version = spend.control[0] & 0xfe
  if (version !== 0xc0 && !lax.leafVersion) return refuse('unknown tapleaf version')
  if (usesOpSuccess(spend.script) && !lax.opSuccess) return refuse('leaf uses a reserved OP_SUCCESS opcode')
  const problem = timeProblem(spend, now, lockedAt, lax.timeClaims ?? [])
  if (problem) return refuse(problem)
  // Consensus: an unknown leaf version, or any OP_SUCCESSx, succeeds
  // unconditionally. Only reachable when the mock is told to skip the
  // policy that closes those hooks.
  if (version !== 0xc0 || usesOpSuccess(spend.script)) return {ok: true}
  const s = spend.script
  if (s.length === 35 && s[0] === 0xa8 && s[1] === 0x20 && s[34] === 0x87) {
    const [preimage, ...rest] = spend.witness
    const ok = preimage && rest.length === 0 && preimage.length <= 520 && bytesToHex(sha256(preimage)) === bytesToHex(s.subarray(2, 34))
    return ok ? {ok: true} : refuse('the witness does not satisfy the leaf')
  }
  return refuse('this mock cannot evaluate that script')
}

// cs1: bech32m under "cs" plus the amount in BOLT-11's units, over the
// 65-byte r || s || recovery-id signature.
const hrpAmount = msat => {
  for (const [unit, per] of [['', 100_000_000_000], ['m', 100_000_000], ['u', 100_000], ['n', 100]]) {
    if (msat % per === 0) return `${msat / per}${unit}`
  }
  return `${msat * 10}p`
}
export const encodeCs1 = (amountMsat, signature) =>
  bech32m.encode(`cs${hrpAmount(amountMsat)}`, bech32m.toWords(signature), LIMIT)
