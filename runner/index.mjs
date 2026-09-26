// Grades a live LNURLcash SERVICE against the spec.
//
// Deliberately written with nothing but fetch and @noble - no lnurlcash
// library of any kind. A conformance runner that shared an implementation
// with the thing it grades would agree with that implementation's mistakes,
// which is the one thing it must never do.

import {bech32, bech32m} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {schnorr, secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {randomBytes} from 'node:crypto'
import {
  bearerLeaf,
  bearerNote,
  bearerSpend,
  decodeSpend,
  encodeCk1,
  encodeCp1,
  isXOnlyPoint,
  keyPathSpend,
  scriptTree,
  tweakSecretKey
} from './spend.mjs'

export {keyPathSpend}

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

// The "Lightning Signed Message" digest every LUD-25 certificate is over.
const signedMessageDigest = message =>
  sha256(sha256(new Uint8Array([...utf8ToBytes('Lightning Signed Message:'), ...utf8ToBytes(message)])))

// Does a 65-byte recoverable signature recover to that key? Both byte
// orderings are tried: the spec wants r || s || recovery-id, a node's
// signmessage emits the recovery id first, and a mint that forgot to
// reorder is still signing with its own key.
const recoversTo = (digest, sig, pubkeyHex) => {
  if (sig.length !== 65) return false
  const leading = new Uint8Array([sig[64], ...sig.subarray(0, 64)])
  for (const candidate of [leading, sig]) {
    try {
      const recovered = secp256k1.recoverPublicKey(candidate, digest, {
        prehash: false
      })
      if (bytesToHex(recovered) === pubkeyHex.toLowerCase()) return true
    } catch {
      // wrong ordering - try the other
    }
  }
  return false
}

// A certificate: cs1 over "LNURLcash:<amount_msat>:<hex(Q)>". Every note
// has a public Q, a bearer note included, so this is the one message a
// certificate signs (luds 6e865b1). `subjectHex` is hex(Q), or a bearer
// note's h when the grader is naming the pre-taproot mistake.
const verifyCertificate = (subjectHex, amountMsat, sig, mintPubkeyHex) =>
  recoversTo(signedMessageDigest(`LNURLcash:${amountMsat}:${subjectHex}`), sig, mintPubkeyHex)

// cs1 and cx1 are bech32m. cs1 has a variable HRP: "cs" plus the amount
// under BOLT-11's amount rules. Longer than BIP-173's 90 characters by
// design.
const BECH32M_LIMIT = 200
const decodeCash = (hrp, value, length) => {
  if (typeof value !== 'string') return null
  try {
    const {prefix, words} = bech32m.decode(value, BECH32M_LIMIT)
    if (prefix !== hrp) return null
    const bytes = bech32m.fromWords(words)
    return bytes.length === length ? bytes : null
  } catch {
    return null
  }
}

const AMOUNT_MSAT_PER_UNIT = {'': 1e11, m: 1e8, u: 1e5, n: 100, p: 0.1}
const amountSuffixMsat = suffix => {
  const match = suffix.match(/^(\d+)([munp])?$/)
  if (!match) return null
  const amount = Number(match[1]) * AMOUNT_MSAT_PER_UNIT[match[2] ?? '']
  return Number.isSafeInteger(amount) ? amount : null
}

const decodeCertificate = value => {
  if (typeof value !== 'string') return null
  const lower = value.trim().toLowerCase()
  const sep = lower.lastIndexOf('1')
  if (sep < 3 || !lower.startsWith('cs')) return null
  const amountMsat = amountSuffixMsat(lower.slice(2, sep))
  if (amountMsat === null) return null
  const signature = decodeCash(lower.slice(0, sep), lower, 65)
  return signature ? {amountMsat, signature} : null
}

// An x that is on no curve point: the cp1 of it names a note nobody could
// ever spend, which LUD-25 has a SERVICE refuse wherever a cp1 goes. Probed
// only as a mint comment, before any invoice exists: as a p1 it would
// destroy the note under grade on a mint that got it wrong.
const OFF_CURVE_CP1 = (() => {
  for (let i = 1; ; i++) {
    const x = new Uint8Array(32)
    x[31] = i
    if (!isXOnlyPoint(x)) return encodeCp1(x)
  }
})()

// LUD-17: lnurlw://host/path is https://host/path, or http:// when the host
// is an onion service (the spec) or loopback (development). A plain
// https:// or http:// URL passes through untouched, so a caller can hand
// this either form a SERVICE emits.
export const fromLud17 = value => {
  const v = String(value).trim()
  if (!/^lnurl[wpc]:\/\//i.test(v)) return v
  const rest = v.slice(v.indexOf('://') + 3)
  const host = rest.split(/[/?#]/, 1)[0].replace(/:\d+$/, '').toLowerCase()
  const plain = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host) || host.endsWith('.onion')
  return (plain ? 'http://' : 'https://') + rest
}

const isAllowedUrl = value => {
  let url
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol === 'https:') return true
  if (url.protocol !== 'http:') return false
  const host = url.hostname
  return (
    ['127.0.0.1', '0.0.0.0', 'localhost'].includes(host) || host.endsWith('.onion')
  )
}

// A 33-byte compressed secp256k1 point in hex, which is what every pubkey
// on this wire is.
const isCompressedPubkey = value =>
  typeof value === 'string' && /^0[23][0-9a-f]{64}$/i.test(value)

// NIP-19 npub: bech32 with the npub hrp over exactly 32 bytes. Decoded
// rather than pattern-matched, because a string that merely starts with
// "npub1" is not a key anyone can send to.
const isNpub = value => {
  if (typeof value !== 'string' || !value.toLowerCase().startsWith('npub1')) return false
  try {
    const {prefix, words} = bech32.decode(value.toLowerCase(), 200)
    return prefix === 'npub' && bech32.fromWords(words).length === 32
  } catch {
    return false
  }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

// A mint may rate limit, and the good ones do: every mint quote issues a
// real invoice on a real node, so a grader firing a dozen of them looks
// exactly like the abuse the limiter exists to stop. An HTTP 429 is the
// grade failing to complete, NOT a verdict on the mint, so it is waited
// out (honouring Retry-After) and retried. Without this the mint is
// accused of whatever the check happened to be probing when the bucket
// ran dry - a conforming mint graded as broken, which is worse than no
// grade at all.
const get = async (url, timeoutMs = 15_000, retriesLeft = 2) => {
  const res = await fetch(url.toString(), {signal: AbortSignal.timeout(timeoutMs)})
  const text = await res.text()
  let body
  try {
    body = JSON.parse(text)
  } catch {
    throw new Error(`response was not JSON: ${text.slice(0, 120)}`)
  }
  if (res.status === 429) {
    if (retriesLeft > 0) {
      const after = Number(res.headers.get('retry-after'))
      const waitMs = Math.min(Number.isFinite(after) && after > 0 ? after * 1000 : 10_000, 30_000)
      await sleep(waitMs + 250)
      return get(url, timeoutMs, retriesLeft - 1)
    }
    throw soft(
      `the mint rate limited this grade (HTTP 429${body?.reason ? `: ${body.reason}` : ''}) - space the run out and grade again; nothing here is a verdict on the mint`
    )
  }
  return body
}

export const createReport = () => {
  const results = []
  return {
    results,
    pass: (name, detail) => results.push({status: 'pass', name, detail}),
    fail: (name, detail) => results.push({status: 'fail', name, detail}),
    warn: (name, detail) => results.push({status: 'warn', name, detail}),
    skip: (name, detail) => results.push({status: 'skip', name, detail}),
    async check(name, fn) {
      try {
        const detail = await fn()
        results.push({status: 'pass', name, detail})
      } catch (err) {
        results.push({
          status: err.warning ? 'warn' : 'fail',
          name,
          detail: err.message
        })
      }
    },
    get failed() {
      return results.filter(r => r.status === 'fail').length
    }
  }
}

const soft = message => {
  const err = new Error(message)
  err.warning = true
  return err
}

const assert = (condition, message) => {
  if (!condition) throw new Error(message)
}

// The msat amount encoded in a bolt11 invoice's human-readable part, or
// null when the invoice carries none (or none expressible in whole msat).
export const invoiceAmountMsat = pr => {
  if (typeof pr !== 'string') return null
  const lower = pr.toLowerCase()
  const sep = lower.lastIndexOf('1')
  if (sep < 0) return null
  const m = lower.slice(0, sep).match(/^ln(?:bc|tb|bcrt|tbs|sb)(\d+)?([munp])?$/)
  if (!m?.[1]) return null
  const per = {'': 1e11, m: 1e8, u: 1e5, n: 100, p: 0.1}[m[2] || '']
  const msat = Number(m[1]) * per
  return Number.isInteger(msat) ? msat : null
}

// The LUD-25 fee formula, msat-exact. The proportional term is split so it
// cannot overflow at realistic amounts - see the fees vectors.
const proportionalFee = (gross, ppm) =>
  Math.floor(gross / 1e6) * ppm + Math.floor(((gross % 1e6) * ppm) / 1e6)
export const applyMintFee = (gross, fee) =>
  Math.max(0, gross - (fee?.baseFeeMsat ?? 0) - proportionalFee(gross, fee?.feePpm ?? 0))

// The LUD-25 fee advertisement, parsed from payRequest metadata: null for
// a fee-free (or silent) mint. The grader needs it because the spec's fee
// algebra changes what a compliant split and merge return.
export const parseAdvertisedMintFee = metadata => {
  let entries
  try {
    entries = JSON.parse(metadata)
  } catch {
    return null
  }
  if (!Array.isArray(entries)) return null
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry[0] !== 'text/plain') continue
    const match = typeof entry[1] === 'string' && entry[1].match(/^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$/)
    if (!match) continue
    const baseFeeMsat = Number(match[1])
    const feePpm = Number(match[2])
    if (baseFeeMsat === 0 && feePpm === 0) return null
    return {baseFeeMsat, feePpm}
  }
  return null
}

// A registered Part 2 address advertises the safe-to-share branch and its
// best-known next index as ["text/xpub", "cx1...:<i>"]. Parsing it here
// makes --address assert the actual discovery signal rather than merely
// trusting the operator's flag.
export const parseInternalTransferHint = metadata => {
  let entries
  try {
    entries = JSON.parse(metadata)
  } catch {
    return null
  }
  if (!Array.isArray(entries)) return null
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry[0] !== 'text/xpub' || typeof entry[1] !== 'string') continue
    const sep = entry[1].lastIndexOf(':')
    if (sep < 0) continue
    const cx1 = entry[1].slice(0, sep)
    const index = Number(entry[1].slice(sep + 1))
    const branch = decodeCash('cx', cx1.toLowerCase(), 64)
    if (!branch || !Number.isInteger(index) || index < 0 || index > 0xffffffff) continue
    return {cx1, index, pubkeyXOnly: branch.slice(0, 32), chainCode: branch.slice(32)}
  }
  return null
}

// Resolves what the user typed - a Lightning Address, a bare domain, or a
// URL - to the payRequest URL to grade.
export const resolveMint = input => {
  const trimmed = input.trim().replace(/^@/, '')
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  const [name, domain] = trimmed.includes('@')
    ? trimmed.split('@')
    : ['mint', trimmed]
  const host = domain.split(':')[0]
  const scheme =
    ['127.0.0.1', '0.0.0.0', 'localhost'].includes(host) || host.endsWith('.onion')
      ? 'http'
      : 'https'
  return `${scheme}://${domain}/.well-known/lnurlp/${name}`
}

// ---- read-only checks -----------------------------------------------------

// `registeredAddress` grades the target as a LUD-25 Part 2 Lightning
// Address rather than a mint payLink. The two are the same document to a
// wallet - both advertise commentAllowed and a withdrawLink, and both
// mint on payment - but the draft's comment rules are written for the
// payLink, which has no key to mint under but the one the comment names.
// A cx1-registered address always has one, the next unused key on its
// branch, so there a comment naming no output is the ordinary free text
// LUD-12 invites and is ignored rather than refused (lnurl-mint #46,
// after every Wallet of Satoshi and Primal payment to such an address
// failed on a typed message).
//
// Deliberately a flag and not a probe. "Returned an invoice for a comment
// naming no output" is also exactly what a mint falling back to a
// preimage-keyed note does, and that mint is dangerous - the preimage
// race the draft's Security considerations describes. Nothing on the wire
// tells the two apart before settlement: they differ only in what key the
// note lands under. Guessing would wave the dangerous one through, so the
// strict payLink rules stay the default and an address is declared.
//
// The cost of that is real and worth stating: this flag takes the
// operator's word, and a preimage-keyed fallback passes under it. It
// relaxes the comment rules and nothing else, and the draft gives an
// address no way to say what it is on the wire. A signal it could
// advertise - so this became detectable rather than declared - is worth
// raising against LUD-25 Part 2.
export const gradeMint = async (payUrl, report, {registeredAddress = false} = {}) => {
  let pay
  let mintAddress
  await report.check('payRequest resolves and is well-formed', async () => {
    pay = await get(payUrl)
    assert(pay.tag === 'payRequest', `tag was ${JSON.stringify(pay.tag)}`)
    assert(typeof pay.callback === 'string', 'no callback')
    assert(isAllowedUrl(pay.callback), `callback is not a fetchable URL: ${pay.callback}`)
    assert(typeof pay.metadata === 'string', 'no metadata')
    assert(Number.isFinite(pay.minSendable), 'no minSendable')
    assert(Number.isFinite(pay.maxSendable), 'no maxSendable')
    assert(pay.minSendable <= pay.maxSendable, 'minSendable exceeds maxSendable')
    return `${pay.minSendable}-${pay.maxSendable} msat`
  })
  if (!pay) return

  await report.check('advertises a withdrawLink (LUD-25)', async () => {
    assert(
      typeof pay.withdrawLink === 'string',
      'no withdrawLink - this is an ordinary payRequest, not an LNURLcash mint'
    )
    const link = pay.withdrawLink.trim()
    assert(
      !/^lnurl1/i.test(link),
      'withdrawLink is bech32-encoded - LUD-25 wants the raw URL, not an LNURL'
    )
    // Both forms are in the wild: lnurl-mint emits the plain https:// URL
    // (as the spec's own diagram does), moneyer the lnurlw:// LUD-17 form.
    // Either is a raw, non-bech32 URL; a WALLET has to take both.
    const form = /^lnurlw:\/\//i.test(link) ? 'lnurlw:// form' : 'plain URL form'
    assert(
      /^(lnurlw|https?):\/\//i.test(link),
      `withdrawLink has an unexpected scheme: ${link}`
    )
    assert(isAllowedUrl(fromLud17(link)), `withdrawLink is not fetchable: ${link}`)
    return `${link} (${form})`
  })

  await report.check('metadata parses, and any fee advertisement is valid', async () => {
    const entries = JSON.parse(pay.metadata)
    assert(Array.isArray(entries), 'metadata is not an array')
    const fee = entries.find(
      e => Array.isArray(e) && e[0] === 'text/plain' && /^Mint fees:/.test(e[1] ?? '')
    )
    if (!fee) return 'no fee advertised (fee-free)'
    const match = fee[1].match(/^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$/)
    assert(match, `malformed fee entry: ${JSON.stringify(fee[1])}`)
    assert(
      Number(match[2]) < 1_000_000,
      `fee of ${match[2]} ppm is 100% or more - no amount can ever net anything`
    )
    return `${match[1]} msat + ${match[2]} ppm`
  })

  if (registeredAddress) {
    await report.check('advertises its cx1 and next index for internal transfers', async () => {
      const hint = parseInternalTransferHint(pay.metadata)
      assert(hint, 'no valid ["text/xpub", "cx1...:<i>"] metadata entry')
      return `index ${hint.index}`
    })
  }

  let verifyUrl
  await report.check('issues an invoice for the amount requested', async () => {
    const amount = Math.max(pay.minSendable, 1000)
    const url = new URL(pay.callback)
    url.searchParams.set('amount', String(amount))
    // A mint advertising comment protection requires a named quote (see
    // docs/COMMENT-IS-MANDATORY.md), so the plain LUD-06 request an
    // ordinary wallet would send is refused there by design. Name it the
    // way a LUD-25 wallet does, or this check grades the mandate rather
    // than the invoice.
    if (Number.isFinite(pay.commentAllowed) && pay.commentAllowed >= 64) {
      url.searchParams.set('comment', noteId(bytesToHex(randomBytes(32))))
    }
    const body = await get(url)
    assert(body.status !== 'ERROR', `refused: ${body.reason}`)
    assert(typeof body.pr === 'string', 'no pr in the response')
    const invoiced = invoiceAmountMsat(body.pr)
    if (invoiced !== null) {
      assert(
        invoiced === amount,
        `asked for ${amount} msat, invoiced ${invoiced} msat`
      )
    }
    if (body.verify) {
      assert(isAllowedUrl(body.verify), `verify URL is not fetchable: ${body.verify}`)
      verifyUrl = body.verify
    }
    return `${amount} msat${body.verify ? ', with LUD-21 verify' : ''}`
  })

  await report.check('verify serves no secret before settlement', async () => {
    // The payment preimage is safe from bearer-note use once comment-bound,
    // but it is still a settlement proof and must not exist before payment.
    if (!verifyUrl) throw soft('no LUD-21 verify URL to probe')
    const body = await get(verifyUrl)
    assert(body.status !== 'ERROR', `refused its own verify URL: ${body.reason}`)
    assert(
      body.settled === false,
      `an invoice nothing has paid reports settled: ${JSON.stringify(body.settled)}`
    )
    assert(
      body.preimage == null,
      'served a payment preimage before the invoice settled'
    )
    return 'settled: false, no preimage'
  })

  await report.check('reports an unknown note distinguishably', async () => {
    const withdrawUrl = pay.withdrawLink ? fromLud17(pay.withdrawLink) : ''
    if (!withdrawUrl) throw soft('no withdrawLink to probe')
    const url = new URL(withdrawUrl)
    url.searchParams.set('k1', bytesToHex(randomBytes(32)))
    const body = await get(url)
    assert(body.status === 'ERROR', `a note that cannot exist was accepted: ${JSON.stringify(body).slice(0, 120)}`)
    assert(typeof body.reason === 'string' && body.reason.length > 0, 'ERROR carried no reason')
    assert(
      /unknown|not found/i.test(body.reason),
      `reason ${JSON.stringify(body.reason)} does not identify the note as unknown - a holder cannot tell this apart from "already spent"`
    )
    return body.reason
  })

  await report.check('publishes a mint address (experimental, optional)', async () => {
    const mirror = payUrl.replace('/.well-known/lnurlp/', '/.well-known/lnurlw/')
    // The document only has a canonical location on a LUD-16 Lightning
    // Address, where it mirrors the payRequest's own well-known path. A
    // mint served from a plain path - an LNbits extension, say - has
    // nowhere to publish it, and the swap above leaves the URL untouched:
    // probing it anyway re-fetches the payRequest and reads its
    // tag as a malformed mint address.
    if (mirror === payUrl) {
      throw soft('not published - this mint is not served from a Lightning Address, so there is no well-known lnurlw path to mirror')
    }
    let body
    try {
      body = await get(mirror)
    } catch {
      throw soft('not published - optional, and carries no LUD number')
    }
    if (body.status === 'ERROR') throw soft(`not published: ${body.reason}`)
    assert(body.tag === 'withdrawRequest', 'wrong tag')
    assert(typeof body.payLink === 'string', 'no payLink back to the payRequest')
    mintAddress = body

    // Mint info: who runs this, how to reach them, the terms, the message
    // of the day, the structured fee, and the keys this mint has signed
    // under before. Every one is optional and none is in any LUD, so
    // absence is never a failure - but a field that IS published and is
    // the wrong shape is worth saying out loud, because a wallet will try
    // to render it. Malformed means a warning, not a fail.
    //
    // previousPubkeys in particular: LUD-25 carried it briefly and dropped
    // it on 2026-09-04, replacing it with "SERVICE SHOULD NOT rotate
    // mintPubkey" plus a WALLET-side MUST to pin per origin and require
    // explicit holder approval for any replacement. So it is now purely a
    // convention between the implementations that already emit and read it,
    // and it is graded here as one: shape only, never presence. Nothing in
    // this suite asks a SERVICE to publish it, and a wallet must not treat
    // it as permission to move a pin by itself.
    const problems = []
    for (const key of ['name', 'description', 'tosUrl', 'motd', 'version']) {
      const value = body[key]
      if (value === undefined) continue
      if (typeof value !== 'string' || value === '') problems.push(`${key} is not a non-empty string`)
    }
    if (typeof body.tosUrl === 'string' && body.tosUrl && !isAllowedUrl(body.tosUrl)) {
      problems.push('tosUrl is not a fetchable URL')
    }
    if (body.contact !== undefined) {
      if (typeof body.contact !== 'object' || body.contact === null || Array.isArray(body.contact)) {
        problems.push('contact is not an object')
      } else {
        if (body.contact.nostr !== undefined && !isNpub(body.contact.nostr)) {
          problems.push('contact.nostr does not decode as an npub')
        }
        if (
          body.contact.email !== undefined &&
          !(typeof body.contact.email === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.contact.email))
        ) {
          problems.push('contact.email is not an address')
        }
        if (body.contact.url !== undefined && !isAllowedUrl(body.contact.url)) {
          problems.push('contact.url is not a fetchable URL')
        }
      }
    }
    if (body.fees !== undefined) {
      const fees = body.fees
      if (
        typeof fees !== 'object' ||
        fees === null ||
        !Number.isFinite(fees.baseFeeMsat) ||
        !Number.isFinite(fees.feePpm)
      ) {
        problems.push('fees is not {baseFeeMsat, feePpm} in numbers')
      } else if (fees.baseFeeMsat < 0 || fees.feePpm < 0) {
        problems.push('fees are negative')
      }
    }
    if (body.previousPubkeys !== undefined) {
      if (!Array.isArray(body.previousPubkeys)) {
        problems.push('previousPubkeys is not an array')
      } else if (!body.previousPubkeys.every(isCompressedPubkey)) {
        problems.push('previousPubkeys holds something that is not a 33-byte compressed pubkey in hex')
      } else if (body.mintPubkey && body.previousPubkeys.includes(body.mintPubkey)) {
        problems.push('previousPubkeys lists the current mintPubkey, which says nothing')
      }
    }
    // The node capacity is msat like every other amount here, and the wire
    // name carries no suffix. A mint spelling it nodeCapacityMsat reads as
    // undefined to anything mapping the documented name.
    if (body.nodeCapacityMsat !== undefined && body.nodeCapacity === undefined) {
      problems.push('node capacity is published as nodeCapacityMsat; the wire name is nodeCapacity')
    }
    if (problems.length > 0) throw soft(problems.join('; '))

    const published = [
      'name',
      'description',
      'contact',
      'tosUrl',
      'motd',
      'version',
      'fees',
      'previousPubkeys'
    ].filter(key => body[key] !== undefined)
    const base = body.mintPubkey ? `node ${body.mintPubkey.slice(0, 16)}...` : 'published'
    return published.length > 0 ? `${base}, info: ${published.join(', ')}` : base
  })

  // Liabilities. Outside LUD-25 entirely, and a mint that publishes
  // nothing is not being graded down for it. Notes here are not blinded,
  // so a mint that wants to can state what it owes exactly, and a holder
  // can compare that against what the node behind it holds.
  await report.check('publishes liabilities (optional)', async () => {
    const stats = new URL(payUrl)
    stats.pathname = '/stats'
    stats.search = ''
    let body
    try {
      body = await get(stats)
    } catch {
      throw soft('no /stats endpoint - optional, and outside LUD-25')
    }
    if (body?.status === 'ERROR') throw soft(`not published: ${body.reason}`)
    // /stats is a common enough path that something unrelated may answer
    // on it. Nothing here treats that as a broken liabilities endpoint.
    if (typeof body !== 'object' || body === null || body.outstandingMsat === undefined) {
      throw soft('/stats answered without an outstandingMsat - not a liabilities endpoint')
    }
    assert(
      Number.isFinite(body.outstandingMsat) && body.outstandingMsat >= 0,
      `outstandingMsat was ${JSON.stringify(body.outstandingMsat)}`
    )
    if (body.coverage !== undefined) {
      assert(Number.isFinite(body.coverage), `coverage was ${JSON.stringify(body.coverage)}`)
    }
    if (body.localBalanceMsat !== undefined) {
      assert(
        Number.isFinite(body.localBalanceMsat),
        `localBalanceMsat was ${JSON.stringify(body.localBalanceMsat)}`
      )
    }
    const detail =
      `owes ${body.outstandingMsat} msat` +
      (Number.isFinite(body.localBalanceMsat) ? `, node holds ${body.localBalanceMsat}` : '') +
      (Number.isFinite(body.coverage) ? `, coverage ${body.coverage}` : '')
    // Under-coverage is a warning and never a failure. Whether a mint is
    // fully backed is the operator's to disclose, and a mint that
    // publishes an uncomfortable number is behaving better than one that
    // publishes nothing at all.
    if (
      Number.isFinite(body.localBalanceMsat) &&
      body.localBalanceMsat < body.outstandingMsat
    ) {
      throw soft(`${detail} - the node holds less than the mint owes`)
    }
    return detail
  })

  // Naming the note being bought is mandatory in the current LUD-25 draft:
  // `comment = hex(sha256(secret))`, with `commentAllowed` large enough for
  // all 64 characters. `mintToHash` is the additive parameter spelling one
  // mint shipped first. It may corroborate the comment, never replace it.
  //
  // The claim lives in three places. The payRequest is the one to decide
  // from, since every mint publishes one while the mint address document
  // is experimental; the mint address repeats it as corroboration; and the
  // pay callback's own response echoes `mintToHash` when THAT quote was
  // bound. LUD-25 defines no echo for the comment spelling, so a missing
  // echo is only held against a mint claiming `mintToHash`.
  //
  // The two spellings are not symmetric:
  //
  //   `h` is a parameter invented for exactly this purpose, so a malformed
  //   one is a wallet error and MUST be refused before an invoice exists.
  //
  //   `comment` is the normative commitment and MUST be present and valid
  //   before any invoice exists. For an `h` probe the same hash is therefore
  //   carried in both fields.
  await report.check('requires comment-bound minting and honours the mintToHash extension', async () => {
    const amount = Math.max(pay.minSendable, 1000)

    assert(
      Number.isFinite(pay.commentAllowed) && pay.commentAllowed >= 64,
      `minting payRequest must advertise commentAllowed: 64, got ${JSON.stringify(pay.commentAllowed)}`
    )

    // Current LUD-25 minting requires commentAllowed of at least 64.
    // Anything shorter cannot carry the output commitment at all.
    const spellingsOf = source => {
      const found = []
      if (source?.mintToHash === true) found.push('h')
      if (Number.isFinite(source?.commentAllowed) && source.commentAllowed >= 64) found.push('comment')
      return found
    }
    const quoteAt = async (spelling, value, msat = amount) => {
      const url = new URL(pay.callback)
      url.searchParams.set('amount', String(msat))
      url.searchParams.set(spelling, value)
      if (spelling === 'h') {
        // `h` is an additive compatibility field. A conforming quote still
        // carries the mandatory LUD-12 comment, and both name one output.
        url.searchParams.set(
          'comment',
          /^[0-9a-f]{64}$/i.test(value) ? value : noteId(bytesToHex(randomBytes(32)))
        )
      }
      return get(url)
    }
    const spelt = spelling => (spelling === 'comment' ? 'a LUD-12 comment' : 'an h parameter')

    // The behaviour #46 fixed, asserted rather than assumed. Asked once,
    // not once per malformed value: on an address a quote claims the next
    // branch index as it is issued, so every probe costs the holder a key
    // whether or not anyone pays. `gm` is short enough that no mint could
    // read it as a commitment of any spelling.
    if (registeredAddress) {
      const freeText = await quoteAt('comment', 'gm')
      assert(
        freeText.status !== 'ERROR' && typeof freeText.pr === 'string',
        `refused a comment naming no output: ${freeText.reason} - this address mints on its own branch, so an ordinary LUD-12 message must not fail the payment`
      )
    }

    const advertised = spellingsOf(pay)
    const corroborated = spellingsOf(mintAddress)
    const claimed = [...new Set([...advertised, ...corroborated])]

    // Asked of every mint, advertisement or not: a mint that echoes the
    // capability without publishing it is still claiming it, and a wallet
    // reading the echo would believe it. Nothing pays the invoice that
    // comes back, so this is read-only - an unpaid quote costs a mint an
    // invoice and nothing else.
    // A fresh secret per spelling, never one shared between them: a mint
    // that accepts both and binds an output id uniquely - as it should,
    // and as the repeat probe below asserts - would rightly refuse the
    // second spelling for naming an output the first just took.
    // Probe h even when it was not advertised: a quote echoing mintToHash
    // is itself a claim, and is otherwise impossible to discover.
    const probed = [...new Set([...claimed, 'h'])]
    const named = Object.fromEntries(
      probed.map(spelling => {
        const secret = bytesToHex(randomBytes(32))
        return [spelling, {secret, h: noteId(secret)}]
      })
    )
    const bound = {}
    for (const spelling of probed) bound[spelling] = await quoteAt(spelling, named[spelling].h)
    const echoedIn = probed.filter(spelling => bound[spelling].mintToHash === true)
    const hClaimed = claimed.includes('h') || echoedIn.includes('h')

    const problems = []
    const claimedBy = [
      advertised.length > 0 && `the payRequest (${advertised.join(', ')})`,
      corroborated.length > 0 && `the mint address (${corroborated.join(', ')})`,
      echoedIn.length > 0 && 'the quote itself'
    ].filter(Boolean)

    for (const spelling of probed) {
      const body = bound[spelling]
      assert(
        body.status !== 'ERROR',
        `claims this capability (${claimedBy.join(', ')}) and refused a well-formed hash sent as ${spelt(spelling)}: ${body.reason}`
      )
      assert(typeof body.pr === 'string', `no pr in the response to ${spelt(spelling)}`)
      const invoiced = invoiceAmountMsat(body.pr)
      if (invoiced !== null) {
        assert(invoiced === amount, `asked for ${amount} msat, invoiced ${invoiced} msat`)
      }
    }

    // A quote is not a note. Crediting one before its invoice settles
    // would hand out money for nothing.
    const withdrawUrl = pay.withdrawLink ? fromLud17(pay.withdrawLink) : null
    if (withdrawUrl) {
      for (const spelling of probed) {
        const probe = new URL(withdrawUrl)
        probe.searchParams.set('k1', named[spelling].secret)
        const early = await get(probe)
        assert(
          early.status === 'ERROR',
          'the note exists before anything paid for it - a quote is not a note'
        )
      }
    }

    // Malformed means not 32 bytes of hex, in any casing. Upper case is a
    // spelling, not a defect, and it is deliberately not probed: a WALLET
    // MUST send lowercase and every client here does, a SERVICE SHOULD
    // normalise before comparing, and one that refuses upper case outright
    // is strict rather than wrong - the wallet learns before it pays.
    const malformed = [
      ['not hex', 'z'.repeat(64)],
      ['a character short', '0'.repeat(63)],
      ['a character long', '0'.repeat(65)],
      ['empty', ''],
      // LUD-25: a cp1 whose Q is not the x coordinate of a curve point
      // names a note no spend could ever open, and MUST be refused.
      ['a cp1 whose key is not on the curve', OFF_CURVE_CP1]
    ]

    for (const spelling of probed) {
      for (const [what, value] of malformed) {
        // Every one of these names no output, which on an address is free
        // text, already covered above. `h` stays probed either way: it is
        // a parameter invented for this one purpose, so a malformed one is
        // a wallet error wherever it is sent.
        if (spelling === 'comment' && registeredAddress) continue
        const body = await quoteAt(spelling, value)
        if (spelling === 'h') {
          if (!hClaimed) continue
          // A wallet that pays a quote the mint was always going to reject
          // has bought nothing, and the mint keeps the sats.
          assert(
            body.status === 'ERROR' && !body.pr,
            `issued an invoice for an h that is ${what} - a wallet would pay for a quote this mint cannot honour`
          )
          continue
        }
        // The normative comment spelling. A malformed commitment is refused
        // before invoice creation; there is no preimage-backed fallback.
        assert(
          body.status === 'ERROR' && !body.pr,
          `issued an invoice for a comment that is ${what} - current LUD-25 requires a well-formed wallet commitment before invoice creation`
        )
      }
    }

    // The canonical spelling of the comment is cp1<Q>; the 64-hex h probed
    // above is only a bearer note's short form. A note keyed from a seed
    // has nothing but its cp1, so a mint taking only hex cannot mint one.
    // An address is left out, as for the malformed values: what it does
    // with a comment naming an output is its own branch's business.
    if (!registeredAddress) {
      const keyed = await quoteAt('comment', encodeCp1(schnorr.getPublicKey(secp256k1.utils.randomSecretKey())))
      assert(
        keyed.status !== 'ERROR' && typeof keyed.pr === 'string',
        `refused a comment naming its note as cp1<Q>: ${keyed.reason} - LUD-25 mints to a cp1 or a bearer note's hex h, and a note keyed from a seed has only the first`
      )
    }

    // The malformed loop can only probe values; explicitly cover absence.
    const bare = new URL(pay.callback)
    bare.searchParams.set('amount', String(amount))
    const unnamed = await get(bare)
    if (registeredAddress) {
      // The draft is explicit that a registered address needs no comment
      // at all: it derives the next key from its own cx1. Refusing here
      // would break every plain Lightning payment to the address.
      assert(
        unnamed.status !== 'ERROR' && typeof unnamed.pr === 'string',
        `refused a quote carrying no comment: ${unnamed.reason} - a registered address mints on its own branch, so a payment to it must not need one`
      )
    } else {
      assert(
        unnamed.status === 'ERROR' && !unnamed.pr,
        'issued an invoice for a quote carrying no comment - current LUD-25 requires rejection before invoicing'
      )
    }

    if (hClaimed) {
      const mismatch = new URL(pay.callback)
      mismatch.searchParams.set('amount', String(amount))
      mismatch.searchParams.set('comment', noteId(bytesToHex(randomBytes(32))))
      mismatch.searchParams.set('h', noteId(bytesToHex(randomBytes(32))))
      const body = await get(mismatch)
      assert(
        body.status === 'ERROR' && !body.pr,
        'issued an invoice when h and the mandatory comment named different outputs'
      )
    }

    // The claims must agree. None of these disagreements loses anyone
    // money on its own - a wallet reading a missing field as false falls
    // back to the preimage flow, which is safe - so each is named rather
    // than failed. Whether the mint really binds is the one thing this
    // check cannot see, because that needs a settlement: it is graded
    // separately, and failed rather than warned.
    if (advertised.includes('h') && !echoedIn.includes('h')) {
      problems.push(
        'bound quotes carry no mintToHash in the response, so a wallet cannot confirm at the one moment it is worth confirming, and falls back to racing the preimage'
      )
    }
    if (echoedIn.includes('h') && !advertised.includes('h')) {
      problems.push(
        'echoes mintToHash on a quote but does not advertise it on the payRequest, which is the endpoint every mint publishes and the one a wallet decides from'
      )
    }
    // Only the `mintToHash` spelling belongs in both documents. LUD-25 asks
    // a mint *payLink* to advertise `commentAllowed`, and the mint address
    // document is a withdrawRequest, where a LUD-12 comment has nowhere to
    // go - its absence there is correct, not a disagreement.
    if (advertised.includes('h') && mintAddress && !corroborated.includes('h')) {
      problems.push('the payRequest advertises mintToHash and the mint address document does not')
    }

    // The same output id asked for twice. The amount differs, so a mint
    // that answers an identical repeat with the original invoice cannot
    // hide behind that: this is genuinely two payments pointed at one id,
    // and whichever settles first takes it. Soft, because the draft says
    // nothing here and the refusal is an inference from the collision
    // rule the withdraw callback already enforces.
    const otherAmount = Math.min(pay.maxSendable, amount * 2)
    if (otherAmount !== amount) {
      for (const spelling of probed) {
        if (spelling === 'h' && !hClaimed) continue
        const twice = await quoteAt(spelling, named[spelling].h, otherAmount)
        if (twice.status !== 'ERROR') {
          problems.push(
            `issued a second quote against an output already named by ${spelt(spelling)} - whichever payment settles first takes the id, and the other payer has bought nothing`
          )
        }
      }
    }
    if (problems.length > 0) throw soft(problems.join('; '))
    if (registeredAddress) {
      return `registered Lightning Address, minting on its own branch: named by ${probed.join(' and ')}; claimed by ${claimedBy.join(', ')}; bound a quote to a hash of the runner's own secret, and honoured one carrying free text and one carrying no comment at all`
    }
    return `named by ${probed.join(' and ')}; claimed by ${claimedBy.join(', ')}; bound a quote to a hash of the runner's own secret and to a cp1, and refused five malformed ones as the draft requires`
  })

  // The payRequest, with the mint address the checks above fetched hung
  // off it: a caller grading a note afterwards needs previousPubkeys from
  // it, and fetching the same endpoint twice to get them would be silly.
  if (pay && mintAddress) pay.mintAddress = mintAddress
  return pay
}

// ---- the minted-value check ----------------------------------------------
//
// Read-only, but it needs something the runner cannot make on its own: a
// real payment. Given a freshly minted, not-yet-rotated note and the gross
// msat its mint invoice was paid at, checks the note is worth exactly what
// the LUD-25 formula says. This is where a fee implementation that works
// in whole sats - rounding the withheld fee up - shows itself: the note
// mints short of the formula and no other check can see it.
export const gradeMintedValue = async (noteUrl, report, {mintFee = null, paidMsat}) => {
  await report.check('a minted note is worth the amount paid minus the fee', async () => {
    assert(Number.isFinite(paidMsat) && paidMsat > 0, `paidMsat was ${paidMsat}`)
    const url = new URL(fromLud17(noteUrl))
    const info = await get(url)
    assert(info.status !== 'ERROR', `refused: ${info.reason}`)
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')
    const exact = applyMintFee(paidMsat, mintFee)
    const feeText = mintFee
      ? `${mintFee.baseFeeMsat} msat + ${mintFee.feePpm} ppm`
      : 'no advertised fee'
    // LUD-25 gives the fee as base plus a ppm cut and says nothing about
    // rounding, and the two live implementations read that differently:
    // dni's lnurl-mint - the reference, and what every public mint but
    // moneyer runs - ceilings the fee to a whole sat on purpose, moneyer
    // is msat-exact. Grading either as a failure would be this repo
    // picking a side the draft has not picked. So the compliant answer is
    // a band: the formula is the most a holder can be credited, the
    // sat-ceilinged fee the least. Anything outside is still wrong, which
    // is what this check is for.
    const exactFee = paidMsat - exact
    const ceilinged = Math.max(0, paidMsat - Math.ceil(exactFee / 1000) * 1000)
    assert(
      info.maxWithdrawable <= exact,
      `paid ${paidMsat} msat against ${feeText}: the note holds ${info.maxWithdrawable} msat, more than the ${exact} the formula allows`
    )
    assert(
      info.maxWithdrawable >= ceilinged,
      `paid ${paidMsat} msat against ${feeText}: the note holds ${info.maxWithdrawable} msat, short of ${ceilinged} - beyond even a fee ceilinged to a whole sat`
    )
    const how =
      info.maxWithdrawable === exact
        ? 'msat-exact'
        : info.maxWithdrawable === ceilinged
          ? 'fee ceilinged to a whole sat, as the reference mint does'
          : 'inside the band'
    return `${paidMsat} msat paid -> ${info.maxWithdrawable} msat note (${feeText}, ${how})`
  })
}

// ---- the bound mint check -------------------------------------------------
//
// Read-only, and like the minted-value check it needs something the runner
// cannot make on its own: a note somebody has actually paid for. Given a
// note minted against a hash the WALLET chose - the note URL carries the
// wallet's own secret - and the payment preimage of the invoice that funded
// it, this checks the two things binding exists to buy: the note really is
// at the secret the wallet named, and the preimage is not a second key to
// it. The preimage matters because everyone on the payment's route learns
// it, and so does anyone who saw the invoice and polled LUD-21 verify.
//
// options.payCallback: the mint's LUD-06 callback, when the caller has it.
// With it, the runner also checks that the id the note now occupies cannot
// be sold again as a mint quote.
export const gradeBoundMint = async (noteUrl, report, {preimage, payCallback = null}) => {
  await report.check('a bound mint credits the hash the wallet named (optional)', async () => {
    const url = new URL(fromLud17(noteUrl))
    const k1 = url.searchParams.get('k1')?.toLowerCase()
    assert(k1 && /^[0-9a-f]{64}$/.test(k1), 'that note carries no 32-byte hex k1')
    assert(
      typeof preimage === 'string' && /^[0-9a-f]{64}$/i.test(preimage),
      'pass the payment preimage of the invoice that minted this note'
    )
    const paid = preimage.toLowerCase()
    assert(
      paid !== k1,
      'the note secret IS the payment preimage - this note was never bound to a hash the wallet named'
    )

    const info = await get(url)
    assert(
      info.status !== 'ERROR',
      `there is no note at the secret the wallet named its hash for: ${info.reason}. A mint claiming mintToHash and crediting somewhere else has taken money for a note the wallet cannot spend`
    )
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')

    const byPreimage = new URL(url)
    byPreimage.searchParams.set('k1', paid)
    const leaked = await get(byPreimage)
    assert(
      leaked.status === 'ERROR',
      'the payment preimage is still a valid secret for this payment - a mint that claims mintToHash and then does not bind is worse than one that never claimed it, because the wallet stopped rotating on sight. Every routing node on the route, and anyone who saw the invoice, can spend this note'
    )

    // The id is now a live note. Selling a mint quote against it would
    // point a payer's money at somebody else's money.
    let quoteDetail = ''
    if (payCallback) {
      const quote = new URL(payCallback)
      quote.searchParams.set('amount', '1000')
      quote.searchParams.set('comment', noteId(k1))
      quote.searchParams.set('h', noteId(k1))
      const body = await get(quote)
      assert(
        body.status === 'ERROR' && !body.pr,
        'sold a mint quote against an h that already names a live note - the payer would be buying a note somebody else can spend'
      )
      quoteDetail = `, and refused a quote at the id it occupies (${body.reason})`
    }

    return `${info.maxWithdrawable} msat at the wallet's own secret, and the preimage opens nothing${quoteDetail}`
  })
}

// ---- mutating checks ------------------------------------------------------
//
// These SPEND. They burn the note they are given and leave the value in a
// fresh note the runner prints at the end.
//
// Every note is a taproot output key Q (luds 6e865b1). The note given may
// be named by any spend of it - a bearer note's 64-hex preimage, a ck1 or a
// cw1 - and every note the grader makes along the way is its own: bearer
// notes it holds the preimage of, a three-leaf script tree, and a key-path
// note. It never holds anything the mint generated, and whatever happens it
// ends holding a spend of all the value it started with.

// options.mintFee: the service's advertised fee ({baseFeeMsat, feePpm}),
// null for known-fee-free, or leave the key absent when unknown - the
// split/merge conservation checks are exact when the fee is known and
// bounded when it is not. LUD-25's fee algebra: base_fee_msat comes out of
// every split's change, and a merge of n notes refunds (n - 1) base fees.
//
// options.previousPubkeys: keys this mint has signed under before, from
// the discovery endpoint. A note issued before a signing-key rotation
// still verifies against one of them, and grading that as a bad signature
// would punish a mint for rotating properly. Not a LUD-25 field - the spec
// dropped it on 2026-09-04 and now says a SERVICE SHOULD NOT rotate at all
// - so this is a convention the grader honours where a mint offers it,
// never something it asks for.
export const gradeNote = async (noteUrl, report, options = {}) => {
  const knownBaseFee = 'mintFee' in options ? (options.mintFee?.baseFeeMsat ?? 0) : null
  const previousPubkeys = Array.isArray(options.previousPubkeys)
    ? options.previousPubkeys.filter(isCompressedPubkey)
    : []
  const url = new URL(fromLud17(noteUrl))
  const k1 = url.searchParams.get('k1')?.trim()
  const given = k1 ? decodeSpend(k1) : null
  assert(given, 'that note carries no spend: its k1 must be a 64-hex preimage, a ck1 or a cw1')
  // A signature in a spend is bound to the domain of the note's own URL:
  // its lowercase hostname, never the scheme or the port.
  const domain = url.hostname.toLowerCase()
  const originalQ = bytesToHex(given.outputKey)
  // The note given, in every spelling the grader can name it by: its cp1,
  // and its hex h when it is a bearer note given by its preimage.
  const originalRefs = [
    ['cp1', encodeCp1(given.outputKey)],
    ...(given.h ? [['hex h', bytesToHex(given.h)]] : [])
  ]

  // The note URL with nothing on it, for every lookup that follows. The
  // amount and any sig are claims the informational GET ignores anyway.
  const base = new URL(url)
  for (const key of ['k1', 'amount', 'sig', 'p', 'h']) base.searchParams.delete(key)
  const infoBy = (key, value) => {
    const u = new URL(base)
    u.searchParams.set(key, value)
    return get(u)
  }
  const lookup = spend => infoBy('k1', spend)
  const lookupRef = ref => infoBy('p', ref)

  // Every bearer note the grader makes, so a certificate over its h (the
  // pre-taproot message) can be named for what it is.
  const hOfQ = new Map(given.h ? [[originalQ, bytesToHex(given.h)]] : [])
  const freshBearer = () => {
    const preimage = randomBytes(32)
    const h = sha256(preimage)
    const q = bytesToHex(bearerNote(h).outputKey)
    hOfQ.set(q, bytesToHex(h))
    return {k1: bytesToHex(preimage), h: bytesToHex(h), q, cp1: encodeCp1(hexToBytes(q))}
  }
  // A bearer note's full cw1, the long form of its 64-hex preimage.
  const respell = spend => {
    const decoded = decodeSpend(spend)
    return decoded?.preimage ? bearerSpend(decoded.preimage) : null
  }

  // The note the grader holds right now: a spend of it, and its Q.
  let current = k1
  let currentQ = originalQ
  const adopt = spend => {
    current = spend
    currentQ = bytesToHex(decodeSpend(spend).outputKey)
  }

  // Every certificate the mint hands back, with the note it should be for:
  // graded where it arrives when a check is about it, and all together at
  // the end.
  const certificates = []
  const noteCertificate = (where, sig, qHex, amountMsat) => {
    certificates.push({where, sig: sig ?? null, qHex, amountMsat})
  }

  let info
  await report.check('informational GET echoes the k1 it was queried with', async () => {
    info = await get(url)
    assert(info.status !== 'ERROR', `refused: ${info.reason}`)
    assert(info.tag === 'withdrawRequest', `tag was ${JSON.stringify(info.tag)}`)
    assert(typeof info.callback === 'string', 'no callback')
    assert(isAllowedUrl(info.callback), `callback is not fetchable: ${info.callback}`)
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')
    assert(
      String(info.k1 ?? '').toLowerCase() === k1.toLowerCase(),
      'the response k1 differs from the one queried - it must be the spend itself, echoed, never a derived id'
    )
    noteCertificate('the informational GET of the note given', info.sig, originalQ, info.maxWithdrawable)
    return `${info.maxWithdrawable} msat`
  })
  if (!info?.callback) return

  const value = info.maxWithdrawable
  const callback = ({k1s, p1, p2, amount}) => {
    const cb = new URL(info.callback)
    for (const spend of k1s) cb.searchParams.append('k1', spend)
    if (amount !== undefined) cb.searchParams.append('amount', String(amount))
    if (p1 !== undefined) cb.searchParams.append('p1', p1)
    if (p2 !== undefined) cb.searchParams.append('p2', p2)
    return cb
  }
  const call = params => get(callback(params))

  // A mint that has rotated its signing key may publish the old ones as
  // previousPubkeys, so notes it issued before the rotation still verify.
  // Any key it currently stands behind is an acceptable signer for grading
  // purposes. That is a narrower claim than it looks: it says the
  // signature is genuine, not that a wallet should accept the new key -
  // LUD-25 puts that decision with the holder.
  const signers = () => [info.mintPubkey, ...previousPubkeys].filter(isCompressedPubkey)
  const describeSigner = signedBy =>
    signedBy === info.mintPubkey
      ? 'verified offline'
      : `verified offline against a previous signing key (${signedBy.slice(0, 16)}...)`
  const unverified = () =>
    previousPubkeys.length > 0
      ? 'the certificate verifies against neither the advertised mintPubkey nor any published previous key'
      : 'the certificate does not verify against the advertised mintPubkey'
  // Is `sig` a cs1 for this note at this value? {signedBy} or {problem}.
  const judgeCertificate = (sig, qHex, amountMsat) => {
    if (!isCompressedPubkey(info.mintPubkey)) {
      return {problem: 'a certificate with no 33-byte compressed mintPubkey advertised verifies against nothing'}
    }
    const certificate = decodeCertificate(sig)
    if (!certificate) {
      return {problem: `sig is not an amount-bearing cs1 certificate (got ${JSON.stringify(sig).slice(0, 48)})`}
    }
    if (certificate.amountMsat !== amountMsat) {
      return {problem: `the cs1 says ${certificate.amountMsat} msat but the note is worth ${amountMsat} msat`}
    }
    const signedBy = signers().find(key => verifyCertificate(qHex, amountMsat, certificate.signature, key))
    if (signedBy) return {signedBy}
    const h = hOfQ.get(qHex)
    if (h && signers().some(key => verifyCertificate(h, amountMsat, certificate.signature, key))) {
      return {
        problem:
          "the cs1 signs the bearer note's h, the pre-taproot message - LUD-25 certifies every note over hex(Q), so a wallet checking this one offline rejects it"
      }
    }
    return {problem: unverified()}
  }

  await report.check('the informational GET does not burn the note', async () => {
    const again = await get(url)
    assert(again.status !== 'ERROR', `the second GET was refused: ${again.reason}`)
    assert(
      again.maxWithdrawable === value,
      `value changed between two informational GETs: ${value} then ${again.maxWithdrawable}`
    )
    return 'idempotent'
  })

  await report.check('ignores the amount in the note URL', async () => {
    const lying = new URL(url)
    lying.searchParams.set('amount', String(value * 100 + 1))
    const body = await get(lying)
    assert(body.status !== 'ERROR', `refused when amount was inflated: ${body.reason}`)
    assert(
      body.maxWithdrawable === value,
      `the URL's own amount changed the reported value: ${body.maxWithdrawable}`
    )
    return 'maxWithdrawable is authoritative'
  })

  // LUD-25 "Checking a note without exposing it": `?p=` takes a cp1, or a
  // bearer note's hex h, in place of k1, so a holder can look a note up
  // without putting its spend in a query string every proxy between it and
  // the mint may log. A MUST since the draft renamed `h` to `p`.
  let lookupOffered = false
  await report.check('answers a note lookup by p without the spend', async () => {
    const answered = []
    for (const [spelling, ref] of originalRefs) {
      const body = await lookupRef(ref)
      assert(
        body.status !== 'ERROR' && body.tag === 'withdrawRequest',
        `refused ?p= naming the note by its ${spelling}: ${body.reason ?? JSON.stringify(body).slice(0, 80)} - LUD-25 has a SERVICE accept a cp1 or a bearer note's hex h there`
      )
      // A holder asking by p already has the spend, or asks for someone
      // who does, so the field buys it nothing, and filling it in puts the
      // spend back on the wire this lookup exists to keep it off.
      assert(
        body.k1 === undefined,
        `the lookup by ${spelling} carried a k1 - it must omit it, or it puts the spend back in the reply the holder asked by p to avoid`
      )
      assert(
        body.maxWithdrawable === value,
        `the same note is worth ${body.maxWithdrawable} by its ${spelling} and ${value} by k1`
      )
      noteCertificate(`the lookup by ${spelling}`, body.sig, originalQ, body.maxWithdrawable)
      answered.push(spelling)
    }
    lookupOffered = true
    // A note it never registered gets the unknown-note answer, the same
    // one a spend of that note gets. One that answers anyway reports a
    // note where none exists, and a wallet restoring from seed reads that
    // as a note it has lost the spend of.
    const nobody = freshBearer()
    const invented = await lookupRef(nobody.h)
    const ordinaryUnknown = await lookup(nobody.k1)
    assert(
      invented.status === 'ERROR' || invented.tag !== 'withdrawRequest',
      'answered for a note it never registered - an unrecognised p must get the answer an unknown k1 would'
    )
    assert(
      invented.status === ordinaryUnknown.status && invented.reason === ordinaryUnknown.reason,
      `an unknown p answered ${JSON.stringify(invented)} but an unknown k1 answered ${JSON.stringify(ordinaryUnknown)}`
    )
    const unknownKey = await lookupRef(encodeCp1(schnorr.getPublicKey(secp256k1.utils.randomSecretKey())))
    assert(
      unknownKey.status === 'ERROR' || unknownKey.tag !== 'withdrawRequest',
      'answered for a cp1 it never registered'
    )

    // `p` is accepted in place of `k1`, not alongside it. Accepting both
    // lets an intermediary add a second lookup identity and leaves clients
    // unable to know which note the response describes.
    const both = new URL(url)
    both.searchParams.set('p', originalRefs[0][1])
    const ambiguous = await get(both)
    assert(
      ambiguous.status === 'ERROR',
      'accepted both k1 and p on one informational lookup - exactly one lookup identity is allowed'
    )
    return `by ${answered.join(' and by ')}, with no k1 in the reply; unknown and mixed lookups refused`
  })

  // The merge cap. LUD-25 bounds a merge by URL length rather than by the
  // protocol, and a request past that is truncated somewhere upstream into
  // a malformed one. Probed with fabricated inputs: nothing here is a real
  // note, so a compliant SERVICE has two acceptable answers and no third.
  await report.check('refuses an oversized merge cleanly (optional cap)', async () => {
    const cb = new URL(info.callback)
    // Enough repeated k1 to carry the whole URL past the ~2000 characters
    // browsers, servers and proxies commonly stop at.
    const many = Math.ceil((2400 - cb.href.length) / 68)
    for (let i = 0; i < many; i++) {
      cb.searchParams.append('k1', bytesToHex(randomBytes(32)))
    }
    cb.searchParams.append('p1', freshBearer().h)
    const body = await get(cb)
    // Whatever else it does, it must not say yes. Every input was invented
    // by this runner and names no note anywhere.
    assert(
      body.status !== 'OK',
      `answered OK to a merge of ${many} notes it has never held - a truncated k1 list read as a shorter merge mints an output against inputs the SERVICE never saw`
    )
    return /too many k1/i.test(body.reason ?? '')
      ? `capped: "${body.reason}"`
      : `no explicit cap - refused as "${body.reason}", so an oversized merge is indistinguishable from an invalid one and a wallet must batch by URL length`
  })

  await report.check('refuses a rotate with no p1', async () => {
    const body = await call({k1s: [current]})
    assert(
      body.status === 'ERROR',
      'accepted a mutation with no p1 - a SERVICE must never generate the replacement note'
    )
    return body.reason
  })

  await report.check('refuses a split with no p2', async () => {
    const body = await call({k1s: [current], amount: Math.max(1, Math.floor(value / 2)), p1: freshBearer().h})
    assert(
      body.status === 'ERROR',
      'accepted a split with only one output - the change note has nowhere to go but a SERVICE-generated one'
    )
    const still = await lookup(current)
    assert(still.status !== 'ERROR', `a refused split burned the note anyway: ${still.reason}`)
    return body.reason
  })

  await report.check('rotate mints a note the service never saw the secret of', async () => {
    const fresh = freshBearer()
    const body = await call({k1s: [current], p1: fresh.h})
    assert(body.status === 'OK', `refused: ${body.reason}`)
    // Adopt the new note BEFORE asserting anything about compliance. The
    // mutation has already happened, so a runner that throws first would
    // leave every later check pointed at a note this service just burned,
    // and report a pile of cascading failures that say nothing.
    adopt(fresh.k1)
    noteCertificate('the first rotate', body.sig, fresh.q, value)
    assert(
      body.k1 === undefined && body.change === undefined,
      'the response carried a secret - a compliant SERVICE returns none, since it generated none'
    )

    const after = await lookup(fresh.k1)
    assert(after.status !== 'ERROR', `the rotated note is not spendable: ${after.reason}`)
    assert(after.maxWithdrawable === value, `value changed across a rotate: ${value} -> ${after.maxWithdrawable}`)

    const dead = await lookup(k1)
    assert(dead.status === 'ERROR', 'the rotated-away note is still spendable')
    return 'burned the old note, minted the new'
  })

  // LUD-25 has a SERVICE certify every note it issues, a bearer note
  // included, since every note now has a public Q to certify. A SHOULD, so
  // an uncertified output warns; a certificate that is there and wrong is
  // worse than none, because a wallet checking it offline refuses a good
  // note, and fails.
  await report.check('certifies a bearer output over hex(Q)', async () => {
    const first = certificates.find(c => c.where === 'the first rotate')
    if (!first) throw soft('the rotate did not complete, so there is no output to check')
    if (first.sig === null) {
      throw soft('the rotate returned no certificate - LUD-25 says a SERVICE SHOULD certify every note, a bearer note included')
    }
    const verdict = judgeCertificate(first.sig, first.qHex, first.amountMsat)
    assert(verdict.signedBy, verdict.problem)
    return `cs1 over hex(Q), ${describeSigner(verdict.signedBy)}`
  })

  await report.check('reports a spent note distinguishably from an unknown one', async () => {
    if (!lookupOffered) throw soft('the lookup by p is not offered')
    for (const [spelling, ref] of originalRefs) {
      const burned = await lookupRef(ref)
      assert(
        burned.status === 'ERROR' && typeof burned.reason === 'string' &&
          /spent/i.test(burned.reason) && !/unknown|not found/i.test(burned.reason),
        `a spent note asked for by its ${spelling} must be identified as spent, got ${JSON.stringify(burned)}`
      )
    }
    const unknown = await lookupRef(freshBearer().h)
    assert(
      unknown.status === 'ERROR' && typeof unknown.reason === 'string' &&
        /unknown|not found/i.test(unknown.reason) && !/spent/i.test(unknown.reason),
      `an unregistered note must be identified as unknown, got ${JSON.stringify(unknown)}`
    )
    return 'spent and unknown notes are distinguishable without disclosing a spend'
  })

  // The informational GET hands out the queried note's certificate, so a
  // holder need not rotate just to get one. Optional there; but a sig that
  // is there must be a cs1 for exactly this note, or a wallet treating it
  // as an offline proof is misled.
  await report.check('a certificate on the informational GET verifies over hex(Q)', async () => {
    const body = await lookup(current)
    assert(body.status !== 'ERROR', `informational GET refused: ${body.reason}`)
    if (body.sig === undefined || body.sig === null) return 'no certificate offered here'
    const verdict = judgeCertificate(body.sig, currentQ, body.maxWithdrawable)
    assert(verdict.signedBy, verdict.problem)
    return `cs1 for the queried note, ${describeSigner(verdict.signedBy)}`
  })

  // The still-alive probe the adversarial checks below share: a compliant
  // refusal is ATOMIC, so the note it refused to touch must still be
  // spendable afterwards, and worth what it was.
  const assertStillLive = async () => {
    const still = await lookup(current)
    assert(still.status !== 'ERROR', `the refusal burned the note anyway: ${still.reason}`)
    assert(still.maxWithdrawable === value, `the refusal changed the note's value: ${value} -> ${still.maxWithdrawable}`)
  }

  await report.check('refuses a duplicated k1', async () => {
    // One note named twice in a merge-shaped request. Counting its value
    // twice into the output creates money from nothing - and matching on
    // strings rather than notes misses the same note spelt two ways.
    const probes = [['the same k1 twice', [current, current]]]
    const spelt = respell(current)
    if (spelt) probes.push(['one note as its preimage and its full cw1', [current, spelt]])
    const reasons = []
    for (const [what, k1s] of probes) {
      const fresh = freshBearer()
      const body = await call({k1s, p1: fresh.h})
      if (body.status === 'OK') {
        // the mutation landed - adopt the output first, so later checks
        // keep pointing at live money whatever the verdict
        adopt(fresh.k1)
        const output = await lookup(fresh.k1)
        assert(
          output.maxWithdrawable !== value * 2,
          `${what} was counted twice - the output is worth double the note`
        )
        throw soft(
          `accepted ${what} (deduplicated to ${output.maxWithdrawable} msat) - an atomic refusal is the safer answer`
        )
      }
      await assertStillLive()
      reasons.push(`${what}: ${body.reason}`)
    }
    return reasons.join('; ')
  })

  // A p1 naming a note that already exists, outstanding or burned, would
  // credit value into a note someone else may hold the spend of - here the
  // note given at the start, whose spend every previous holder knows.
  // LUD-25 fixes the refusal as exactly "already in use": a WALLET paying
  // someone's next key reads it as "try the next index".
  await report.check('refuses a p1 naming a burned note, as "already in use"', async () => {
    const reasons = []
    for (const [spelling, ref] of originalRefs) {
      const body = await call({k1s: [current], p1: ref})
      if (body.status === 'OK') {
        // the output IS the note given at the start: adopt it by that
        // note's own spend, and say so
        adopt(k1)
        throw new Error(
          `minted into a burned note named by its ${spelling} - the output is spendable by a spend every previous holder already knows`
        )
      }
      await assertStillLive()
      assert(
        body.reason === 'already in use',
        `refused a p1 naming the burned note by its ${spelling}, but as ${JSON.stringify(body.reason)} - LUD-25 fixes the reason as exactly "already in use"`
      )
      reasons.push(spelling)
    }
    return `refused as "already in use" by its ${reasons.join(' and by its ')}`
  })

  await report.check('refuses a split whose p1 equals p2', async () => {
    const half = Math.floor(value / 2)
    if (half < 1) throw soft('note too small to attempt')
    const twin = freshBearer()
    const probes = [
      ['the same h twice', twin.h, twin.h],
      ['one note as its hex h and its cp1', twin.h, twin.cp1]
    ]
    const reasons = []
    for (const [what, p1, p2] of probes) {
      const body = await call({k1s: [current], amount: half, p1, p2})
      if (body.status === 'OK') {
        adopt(twin.k1)
        const output = await lookup(twin.k1)
        throw new Error(
          `accepted ${what} - one note now carries ${output.maxWithdrawable ?? 'nothing'} msat of what should be two notes`
        )
      }
      await assertStillLive()
      reasons.push(`${what}: ${body.reason}`)
    }
    return reasons.join('; ')
  })

  await report.check('never mutates on a non-GET request', async () => {
    // LNURL endpoints are GETs. An OPTIONS preflight or a stray POST
    // carrying the callback's query string must leave the note untouched -
    // real HTTP stacks send both on their own initiative.
    for (const method of ['POST', 'OPTIONS']) {
      const fresh = freshBearer()
      // the response - even an error - is not the assertion; the store is
      await fetch(callback({k1s: [current], p1: fresh.h}).toString(), {method, signal: AbortSignal.timeout(15_000)})
        .then(res => res.arrayBuffer())
        .catch(() => {})
      const still = await lookup(current)
      assert(still.status !== 'ERROR', `a ${method} request burned the note - the mutating callback must answer GET only`)
      const output = await lookup(fresh.k1)
      assert(output.status === 'ERROR', `a ${method} request minted its output - the mutating callback must answer GET only`)
    }
    return 'POST and OPTIONS left the note untouched'
  })

  await report.check('refuses a split whose change cannot cover the base fee', async () => {
    if (knownBaseFee === null) throw soft('fee unknown - pass --paid to grade the fee rules')
    if (knownBaseFee === 0) throw soft('no base fee advertised, so the rule cannot bite')
    // Leave the change one msat short of the base fee. LUD-25 says fail the
    // whole split rather than hand back a change note worth less than the
    // fee that was meant to come out of it.
    const amount = value - knownBaseFee + 1
    if (amount < 1 || amount >= value) {
      throw soft('note too small to leave change short of the base fee')
    }
    const body = await call({k1s: [current], amount, p1: freshBearer().h, p2: freshBearer().h})
    assert(
      body.status === 'ERROR',
      `accepted a split leaving ${value - amount} msat of change against a ${knownBaseFee} msat base fee`
    )
    await assertStillLive()
    return body.reason
  })

  await report.check('split conserves value', async () => {
    const half = Math.floor(value / 2)
    if (half < 1) throw soft('note too small to split')
    if (knownBaseFee !== null && value - half < knownBaseFee + 1) {
      throw soft('note too small to split past the advertised base fee')
    }
    const a = freshBearer()
    const b = freshBearer()
    const body = await call({k1s: [current], amount: half, p1: a.h, p2: b.h})
    assert(body.status === 'OK', `refused: ${body.reason}`)

    const valueOf = async note => {
      const r = await lookup(note.k1)
      assert(r.status !== 'ERROR', `split output is not spendable: ${r.reason}`)
      return r.maxWithdrawable
    }
    const [va, vb] = [await valueOf(a), await valueOf(b)]
    noteCertificate('a split, first output', body.sig, a.q, va)
    noteCertificate('a split, change', body.sig2, b.q, vb)
    assert(
      va === half,
      `asked to split off ${half}, got ${va} - any split fee comes out of change, never the requested amount`
    )
    if (knownBaseFee !== null) {
      const expectedChange = value - half - knownBaseFee
      assert(
        vb === expectedChange,
        `change was ${vb} msat - LUD-25 says total minus amount minus the base fee, ${expectedChange}`
      )
    } else {
      assert(va + vb <= value, `split created value: ${va} + ${vb} > ${value}`)
    }

    // put it back together so the runner ends holding one note
    const merged = freshBearer()
    const mbody = await call({k1s: [a.k1, b.k1], p1: merged.h})
    assert(mbody.status === 'OK', `merge refused: ${mbody.reason}`)
    adopt(merged.k1)
    const total = await valueOf(merged)
    noteCertificate('a merge', mbody.sig, merged.q, total)
    if (knownBaseFee !== null) {
      assert(
        total === va + vb + knownBaseFee,
        `a merge of 2 notes refunds one base fee per LUD-25: expected ${va + vb + knownBaseFee}, got ${total}`
      )
    } else {
      assert(total >= va + vb && total <= value, `merge did not conserve value: ${va} + ${vb} became ${total}`)
    }
    return `${va} + ${vb}, merged back to ${total}`
  })

  // A rotate, split or merge is a GET, and HTTP stacks retry a GET when
  // the connection they used is dropped: Go's net/http retries one that
  // failed on a reused idle connection, the JDK's HttpClient retries
  // idempotent methods with no switch to turn it off. The retry is byte
  // identical. A SERVICE that answers it as an already-spent input tells
  // the holder the mutation never happened, and a holder that believes it
  // discards the only copy of a spend the SERVICE really did mint a note
  // against. Nobody is told; the money is simply gone.
  //
  // This is a MUST. A retry must replay the original success and must not
  // burn or alter either output. And it is matched on the notes the
  // request names, not the strings naming them: a wallet that rebuilt the
  // request, or a proxy that normalised it, may spell the same spend or the
  // same output another way (luds 6e865b1).
  await report.check('replays a retried mutation rather than refusing it', async () => {
    const liveValue = async spend => {
      const r = await lookup(spend)
      return r.status === 'ERROR' ? null : r.maxWithdrawable
    }

    // --- a rotate, retried ---
    const prior = current
    const fresh = freshBearer()
    const first = await call({k1s: [prior], p1: fresh.h})
    assert(first.status === 'OK', `the rotate itself was refused: ${first.reason}`)
    adopt(fresh.k1)
    const minted = await liveValue(fresh.k1)
    assert(minted !== null, 'the rotate reported OK but minted nothing')
    noteCertificate('a rotate', first.sig, fresh.q, minted)

    const retried = await call({k1s: [prior], p1: fresh.h})
    const stillThere = await liveValue(fresh.k1)
    assert(stillThere !== null, 'the retried rotate burned the note the first one minted - a retry must never destroy value')
    assert(stillThere === minted, `the retried rotate changed the note's value: ${minted} -> ${stillThere}`)
    assert(
      retried.status === 'OK',
      `a retried rotate is answered "${retried.reason}" while the note it minted is live and worth ${stillThere} msat`
    )
    assert(retried.sig === first.sig, 'a retried rotate returned a different sig than the original')

    // --- the same rotate, retried in other spellings ---
    const respelt = [
      ...(respell(prior) ? [['its note by the full cw1 rather than the preimage', {k1s: [respell(prior)], p1: fresh.h}]] : []),
      ['its output by cp1 rather than hex h', {k1s: [prior], p1: fresh.cp1}]
    ]
    for (const [what, params] of respelt) {
      const again = await call(params)
      const unchanged = await liveValue(fresh.k1)
      assert(unchanged === minted, `a retried rotate naming ${what} changed the note it minted: ${minted} -> ${unchanged}`)
      assert(
        again.status === 'OK',
        `a retried rotate naming ${what} is answered "${again.reason}" - LUD-25 matches a retry on the notes it names, not the strings naming them`
      )
      assert(again.sig === first.sig, `a retried rotate naming ${what} returned a different certificate than the original`)
    }

    // --- a split, retried ---
    // p2 and the change amount are part of what makes a request the same
    // request, so a rotate on its own does not cover it.
    const half = Math.floor(minted / 2)
    if (half < 1 || (knownBaseFee !== null && minted - half < knownBaseFee + 1)) {
      throw soft('a rotate replays, in every spelling; note too small to exercise a split retry')
    }
    const a = freshBearer()
    const b = freshBearer()
    const split = {k1s: [current], amount: half, p1: a.h, p2: b.h}
    const splitFirst = await call(split)
    if (splitFirst.status !== 'OK') {
      throw new Error(`the split itself was refused: ${splitFirst.reason}`)
    }
    const [va, vb] = [await liveValue(a.k1), await liveValue(b.k1)]
    noteCertificate('a split, first output', splitFirst.sig, a.q, va)
    noteCertificate('a split, change', splitFirst.sig2, b.q, vb)
    const splitRetried = await call(split)
    const [va2, vb2] = [await liveValue(a.k1), await liveValue(b.k1)]
    assert(va2 === va && vb2 === vb, `the retried split changed its outputs: ${va}/${vb} -> ${va2}/${vb2}`)
    assert(
      splitRetried.status === 'OK',
      `a retried split is answered "${splitRetried.reason}" while both its outputs are live`
    )
    assert(splitRetried.sig === splitFirst.sig, 'a retried split returned a different sig than the original')
    assert(splitRetried.sig2 === splitFirst.sig2, 'a retried split returned a different sig2 than the original')

    // put the two halves back together, so the runner ends holding one note
    const merged = freshBearer()
    const mergeBody = await call({k1s: [a.k1, b.k1], p1: merged.h})
    if (mergeBody.status === 'OK') {
      adopt(merged.k1)
      noteCertificate('a merge', mergeBody.sig, merged.q, await liveValue(merged.k1))
    }

    return 'a rotate replays byte for byte and respelt, and so does a split'
  })

  await report.check('refuses a replayed burn', async () => {
    const probes = [['the spend it was given', k1], ...(respell(k1) ? [['its full cw1', respell(k1)]] : [])]
    const reasons = []
    for (const [what, spend] of probes) {
      const fresh = freshBearer()
      const body = await call({k1s: [spend], p1: fresh.h})
      if (body.status === 'OK') {
        adopt(fresh.k1)
        throw new Error(`a note burned earlier was spent again by ${what}`)
      }
      reasons.push(body.reason)
    }
    return reasons.join('; ')
  })

  // ---- script paths: one note, several ways to open it -------------------
  //
  // The value goes into a note of three leaves under an internal key the
  // grader holds:
  //
  //   0  OP_SHA256 <h> OP_EQUAL, leaf version 0xc0  - the way home
  //   1  the same shape at leaf version 0xc2        - an upgrade hook
  //   2  OP_SHA256 <h> OP_EQUAL OP_SUCCESS80        - another
  //
  // Consensus accepts leaves 1 and 2 unconditionally; LUD-25 has a mint
  // refuse both, since anyone who saw one could spend it. Each is in the
  // note's own tree, so its refusal proves a rule rather than an unknown
  // note. The time claims ride on leaf 0, whose script checks no time at
  // all: only the mint's own clock rules can refuse them. And whatever the
  // mint gets wrong, leaf 0 and then the key path bring the value home.
  let tree = null
  const assertTreeLive = async () => {
    const still = lookupOffered ? await lookupRef(tree.cp1) : await lookup(tree.home)
    assert(still.status !== 'ERROR', `the refusal burned the script-tree note anyway: ${still.reason}`)
    assert(still.maxWithdrawable === tree.value, `the refusal changed the note's value: ${tree.value} -> ${still.maxWithdrawable}`)
  }
  // Brings the tree note's value home to a fresh bearer note by the first
  // of `ways` the mint accepts. Returns which, or null if none did.
  const leaveTree = async ways => {
    for (const [what, spend] of ways) {
      const home = freshBearer()
      const body = await call({k1s: [spend], p1: home.h})
      if (body.status === 'OK') {
        adopt(home.k1)
        noteCertificate('the rotate out of the script tree', body.sig, home.q, tree.value)
        tree = null
        return what
      }
    }
    return null
  }

  await report.check("a bearer note's full cw1 is the same spend as its preimage", async () => {
    const decoded = decodeSpend(current)
    if (!decoded?.preimage) throw soft('the note held here is not a bearer preimage, so it has no long form to compare')
    const cw1 = bearerSpend(decoded.preimage)
    const [short, long] = [await lookup(current), await lookup(cw1)]
    assert(short.status !== 'ERROR', `the preimage no longer opens the note: ${short.reason}`)
    assert(
      long.status !== 'ERROR',
      `refused the note's own full cw1 on the informational GET: ${long.reason} - LUD-25 makes the 64-hex preimage nothing but a short form of exactly this spend`
    )
    assert(long.maxWithdrawable === short.maxWithdrawable, `the note is worth ${long.maxWithdrawable} by its cw1 and ${short.maxWithdrawable} by its preimage`)
    assert(String(long.k1 ?? '').toLowerCase() === cw1, 'the informational GET by cw1 did not echo the cw1 it was queried with')

    // Spend it by the cw1, into the three-leaf tree.
    const internal = secp256k1.utils.randomSecretKey()
    const secrets = [randomBytes(32), randomBytes(32), randomBytes(32)]
    const built = scriptTree(schnorr.getPublicKey(internal), [
      {script: bearerLeaf(sha256(secrets[0])), version: 0xc0},
      {script: bearerLeaf(sha256(secrets[1])), version: 0xc2},
      {script: new Uint8Array([...bearerLeaf(sha256(secrets[2])), 0x50]), version: 0xc0}
    ])
    const cp1 = encodeCp1(built.outputKey)
    const body = await call({k1s: [cw1], p1: cp1})
    assert(body.status === 'OK', `refused a rotate spent by the note's full cw1: ${body.reason}`)
    const home = built.spend(0, [secrets[0]])
    const q = bytesToHex(built.outputKey)
    tree = {
      cp1,
      q,
      value: short.maxWithdrawable,
      home,
      secrets,
      built,
      keyPath: keyPathSpend(tweakSecretKey(internal, built.tweak), domain)
    }
    adopt(home)
    noteCertificate('the rotate into the script tree', body.sig, q, tree.value)

    const inTree = await lookup(home)
    if (inTree.status === 'ERROR') {
      // It took the value but cannot open the leaf meant to bring it back.
      // Get it home by any other path before saying so.
      const via = await leaveTree([
        ['the hashlock leaf', home],
        ['the key path', tree.keyPath]
      ])
      throw new Error(
        `credited the script-tree note but refused its own hashlock leaf, two levels down under an internal key: ${inTree.reason} - LUD-25 accepts every spend consensus does. ${via ? `The value came home by ${via}` : `The value is still at ${cp1}, spendable by ${home}`}`
      )
    }
    assert(inTree.maxWithdrawable === tree.value, `value changed going into the script tree: ${tree.value} -> ${inTree.maxWithdrawable}`)
    return 'answered as the preimage does, then spent it into a three-leaf script tree'
  })

  // A spend a mint must refuse, tried at the informational GET and at the
  // callback. The GET must refuse it too: LUD-25 has it verify the spend in
  // full, so a holder checking a note it was handed learns whether the
  // spend really opens it.
  const refusedOnTree = (name, why, spendOf) =>
    report.check(name, async () => {
      if (!tree) throw soft('there is no script-tree note to probe - see the check above')
      const spend = spendOf(tree)
      const asked = await lookup(spend)
      const out = freshBearer()
      const body = await call({k1s: [spend], p1: out.h})
      if (body.status === 'OK') {
        const lost = tree.value
        adopt(out.k1)
        noteCertificate('a rotate the mint should have refused', body.sig, out.q, lost)
        tree = null
        throw new Error(`spent the note by ${why} - anyone who saw that spend could have taken the value`)
      }
      assert(
        asked.status === 'ERROR',
        `the callback refused ${why}, but the informational GET answered for it as though it opened the note - LUD-25 has that GET verify the spend in full`
      )
      await assertTreeLive()
      return body.reason
    })

  await refusedOnTree('refuses a leaf version other than 0xc0', 'a leaf at version 0xc2', t => t.built.spend(1, [t.secrets[1]]))
  await refusedOnTree('refuses a leaf carrying an OP_SUCCESS opcode', 'a leaf carrying OP_SUCCESS80', t => t.built.spend(2, [t.secrets[2]]))
  await refusedOnTree(
    'refuses a block-height locktime',
    'a spend claiming locktime 800000, a block height',
    t => t.built.spend(0, [t.secrets[0]], {locktime: 800_000, sequence: 0xfffffffe})
  )
  // Ten years out: well clear of any mint's clock skew, and still a u32.
  const future = Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 3600
  await refusedOnTree(
    'refuses a locktime still in the future',
    `a spend claiming locktime ${future}, ten years from now`,
    t => t.built.spend(0, [t.secrets[0]], {locktime: future, sequence: 0xfffffffe})
  )
  await refusedOnTree(
    'refuses a block-count relative lock',
    'a spend claiming a relative lock of 6 blocks',
    t => t.built.spend(0, [t.secrets[0]], {sequence: 6})
  )
  // BIP-68's time flag with the largest count: 0xffff units of 512 s, some
  // 388 days from when the mint credited the note a moment ago.
  await refusedOnTree(
    'refuses a relative lock that has not yet run',
    'a spend claiming a relative lock of 0xffff 512-second units, not yet elapsed',
    t => t.built.spend(0, [t.secrets[0]], {sequence: (1 << 22) | 0xffff})
  )

  // The time rules refuse block heights and the future, nothing else. A
  // mint refusing every non-zero locktime passes all the probes above for
  // the wrong reason, so the way home claims one already past: 500000000,
  // the smallest value that is a Unix time (5 November 1985).
  await report.check('accepts a locktime already past', async () => {
    if (!tree) throw soft('there is no script-tree note to spend - see the checks above')
    const past = tree.built.spend(0, [tree.secrets[0]], {locktime: 500_000_000, sequence: 0xfffffffe})
    const asked = await lookup(past)
    const {cp1, home} = tree
    const first = 'its hashlock leaf, claiming locktime 500000000'
    const via = await leaveTree([
      [first, past],
      ['its hashlock leaf, claiming no time', tree.home],
      ['its key path', tree.keyPath]
    ])
    assert(via, `could not spend the script-tree note by any of its paths - the value is still at ${cp1}, spendable by ${home}`)
    assert(
      via === first,
      `refused a spend claiming locktime 500000000, a Unix time already past - LUD-25 refuses only block heights and the future. The value came home by ${via}`
    )
    assert(
      asked.status !== 'ERROR',
      `the callback took a spend claiming locktime 500000000, but the informational GET refused it: ${asked.reason}`
    )
    return `spent the script-tree note by ${first} (5 November 1985)`
  })

  // ---- key paths: a ck1 is bound to one mint -----------------------------
  //
  // A key-path note is x(sk·G) itself, untweaked, as a WALLET deriving its
  // notes from a seed makes them. Its ck1 signs the canonical transaction
  // whose prevout commits to the note URL's domain, so a signature one mint
  // has seen can never be replayed at another.
  let keyNote = null
  await report.check('credits a key-path note named by its cp1', async () => {
    const secretKey = secp256k1.utils.randomSecretKey()
    const pk = schnorr.getPublicKey(secretKey)
    const q = bytesToHex(pk)
    const before = await lookup(current)
    assert(before.status !== 'ERROR', `the note held here no longer opens: ${before.reason}`)
    const body = await call({k1s: [current], p1: encodeCp1(pk)})
    assert(body.status === 'OK', `refused a rotate into a cp1: ${body.reason} - LUD-25 has a SERVICE credit any cp1 it is given`)
    keyNote = {
      secretKey,
      q,
      value: before.maxWithdrawable,
      ck1: keyPathSpend(secretKey, domain),
      elsewhere: keyPathSpend(secretKey, 'other.invalid'),
      // the right key named, but signed by another key over another message
      forged: encodeCk1(pk, schnorr.sign(sha256(utf8ToBytes('not the sighash')), secp256k1.utils.randomSecretKey()))
    }
    adopt(keyNote.ck1)
    noteCertificate('the rotate into a key-path note', body.sig, q, keyNote.value)
    return `rotated into cp1<${q.slice(0, 12)}...>`
  })

  await report.check('the informational GET refuses a spend that does not verify', async () => {
    if (!keyNote) throw soft('there is no key-path note to probe - see the check above')
    for (const [what, spend] of [
      ['a ck1 signed for another domain', keyNote.elsewhere],
      ['a ck1 whose signature is by another key', keyNote.forged]
    ]) {
      const body = await lookup(spend)
      assert(
        body.status === 'ERROR',
        `answered for ${what} as though it opened the note - LUD-25 has the informational GET verify the spend in full, so a holder learns whether the spend it holds really opens the note`
      )
    }
    return 'refused a ck1 signed for another domain and one signed by another key'
  })

  await report.check('refuses a ck1 bound to another domain', async () => {
    if (!keyNote) throw soft('there is no key-path note to probe - see the check above')
    const out = freshBearer()
    const body = await call({k1s: [keyNote.elsewhere], p1: out.h})
    if (body.status === 'OK') {
      adopt(out.k1)
      noteCertificate('a rotate the mint should have refused', body.sig, out.q, keyNote.value)
      keyNote = null
      throw new Error(`spent the note by a ck1 signed for other.invalid, not ${domain} - a signature any mint has seen can be replayed here`)
    }
    const still = await lookup(keyNote.ck1)
    assert(still.status !== 'ERROR', `the refusal burned the key-path note anyway: ${still.reason}`)
    return body.reason
  })

  await report.check('spends a key-path note by a ck1 bound to its own domain', async () => {
    if (!keyNote) throw soft('there is no key-path note to spend - see the checks above')
    const byKey = await lookup(keyNote.ck1)
    const home = freshBearer()
    const body = await call({k1s: [keyNote.ck1], p1: home.h})
    if (body.status === 'OK') {
      adopt(home.k1)
      noteCertificate('the rotate out of the key-path note', body.sig, home.q, keyNote.value)
    } else {
      // Bring the value home before failing. The fixed-message ck1 LUD-25
      // has since dropped is tried only as a rescue: a mint that still
      // reads it is not graded for doing so.
      const legacy = encodeCk1(
        hexToBytes(keyNote.q),
        schnorr.sign(sha256(utf8ToBytes('LNURLcash')), keyNote.secretKey, new Uint8Array(32))
      )
      const rescue = freshBearer()
      const rescued = await call({k1s: [legacy], p1: rescue.h})
      if (rescued.status === 'OK') adopt(rescue.k1)
      throw new Error(
        `refused a ck1 signed over the canonical spend transaction for ${domain}: ${body.reason}. ${rescued.status === 'OK' ? 'The value came home only by the deprecated fixed-message ck1' : `The value is still at cp1<${keyNote.q}>, spendable by ${keyNote.ck1}`}`
      )
    }
    assert(byKey.status !== 'ERROR', `the callback took the ck1, but the informational GET refused it: ${byKey.reason}`)
    assert(byKey.maxWithdrawable === keyNote.value, `the key-path note is worth ${byKey.maxWithdrawable} by its ck1, not ${keyNote.value}`)
    assert(String(byKey.k1 ?? '').toLowerCase() === keyNote.ck1, 'the informational GET by ck1 did not echo the ck1 it was queried with')
    noteCertificate('the informational GET of the key-path note', byKey.sig, keyNote.q, byKey.maxWithdrawable)
    keyNote = null
    return `bound to ${domain}, and spent home to a bearer note`
  })

  // Every certificate the mint handed back, wherever it came from. LUD-25
  // has a SERVICE certify every note (a SHOULD), and a certificate is only
  // any use offline if it signs exactly (hex(Q), value): one that does not
  // is a wallet rejecting a good note, so it fails.
  await report.check('every certificate verifies over hex(Q) and the note value', async () => {
    const present = certificates.filter(c => c.sig !== null)
    const wrong = []
    const signedBy = new Set()
    for (const c of present) {
      const verdict = judgeCertificate(c.sig, c.qHex, c.amountMsat)
      if (verdict.signedBy) signedBy.add(verdict.signedBy)
      else wrong.push(`${c.where}: ${verdict.problem}`)
    }
    assert(wrong.length === 0, wrong.join('; '))
    const missing = certificates.length - present.length
    if (missing > 0) {
      throw soft(
        `${missing} of ${certificates.length} notes came back uncertified - LUD-25 says a SERVICE SHOULD certify every note it issues${present.length > 0 ? `; the ${present.length} certificates given all verify` : ''}`
      )
    }
    const keys = [...signedBy].map(key => (key === info.mintPubkey ? 'mintPubkey' : `previous key ${key.slice(0, 16)}...`))
    return `${present.length} certificates, every one over hex(Q) and the note's value, under ${keys.join(' and ') || 'nothing'}`
  })

  return {
    finalSecret: current,
    noteUrl: (() => {
      const u = new URL(url)
      u.searchParams.delete('sig')
      u.searchParams.delete('amount')
      u.searchParams.set('k1', current)
      return u.toString()
    })()
  }
}
