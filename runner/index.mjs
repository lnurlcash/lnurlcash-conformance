// Grades a live LNURLcash SERVICE against the spec.
//
// Deliberately written with nothing but fetch and @noble - no lnurlcash
// library of any kind. A conformance runner that shared an implementation
// with the thing it grades would agree with that implementation's mistakes,
// which is the one thing it must never do.

import {bech32} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {randomBytes} from 'node:crypto'

const noteId = k1 => bytesToHex(sha256(hexToBytes(k1)))

const verifySignature = (k1, amountMsat, signatureHex, pubkeyHex) => {
  let sig
  try {
    sig = hexToBytes(signatureHex)
  } catch {
    return false
  }
  if (sig.length !== 65) return false
  const digest = sha256(
    sha256(
      new Uint8Array([
        ...utf8ToBytes('Lightning Signed Message:'),
        ...utf8ToBytes(`LNURLcash:${amountMsat}:${noteId(k1)}`)
      ])
    )
  )
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

export const gradeMint = async (payUrl, report) => {
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
      ['empty', '']
    ]

    for (const spelling of probed) {
      for (const [what, value] of malformed) {
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

    // The malformed loop can only probe values; explicitly cover absence.
    const bare = new URL(pay.callback)
    bare.searchParams.set('amount', String(amount))
    const unnamed = await get(bare)
    assert(
      unnamed.status === 'ERROR' && !unnamed.pr,
      'issued an invoice for a quote carrying no comment - current LUD-25 requires rejection before invoicing'
    )

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
    return `named by ${probed.join(' and ')}; claimed by ${claimedBy.join(', ')}; bound a quote to a hash of the runner's own secret and handled four malformed ones as the draft requires`
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
  const k1 = url.searchParams.get('k1')?.toLowerCase()
  assert(k1 && /^[0-9a-f]{64}$/.test(k1), 'that note carries no 32-byte hex k1')

  let info
  await report.check('informational GET echoes the k1 it was queried with', async () => {
    info = await get(url)
    assert(info.status !== 'ERROR', `refused: ${info.reason}`)
    assert(info.tag === 'withdrawRequest', `tag was ${JSON.stringify(info.tag)}`)
    assert(typeof info.callback === 'string', 'no callback')
    assert(isAllowedUrl(info.callback), `callback is not fetchable: ${info.callback}`)
    assert(Number.isFinite(info.maxWithdrawable), 'no maxWithdrawable')
    assert(
      info.k1?.toLowerCase() === k1,
      'the response k1 differs from the one queried - it must be the bearer secret itself, never a derived id'
    )
    return `${info.maxWithdrawable} msat`
  })
  if (!info?.callback) return

  await report.check('the informational GET does not burn the note', async () => {
    const again = await get(url)
    assert(again.status !== 'ERROR', `the second GET was refused: ${again.reason}`)
    assert(
      again.maxWithdrawable === info.maxWithdrawable,
      `value changed between two informational GETs: ${info.maxWithdrawable} then ${again.maxWithdrawable}`
    )
    return 'idempotent'
  })

  await report.check('ignores the amount in the note URL', async () => {
    const lying = new URL(url)
    lying.searchParams.set('amount', String(info.maxWithdrawable * 100 + 1))
    const body = await get(lying)
    assert(body.status !== 'ERROR', `refused when amount was inflated: ${body.reason}`)
    assert(
      body.maxWithdrawable === info.maxWithdrawable,
      `the URL's own amount changed the reported value: ${body.maxWithdrawable}`
    )
    return 'maxWithdrawable is authoritative'
  })

  // LUD-25 "Checking a note without exposing it". Optional, and detected
  // rather than announced: the draft deliberately gives an unrecognized `h`
  // the same answer an unknown `k1` gets, so a mint that never implemented
  // it is indistinguishable from one asked about a note it does not hold.
  // A live note's own hash is therefore the only probe that separates them.
  let hashLookupOffered = false
  await report.check('answers a note lookup by hash without the secret (optional)', async () => {
    const byHash = new URL(url)
    byHash.searchParams.delete('k1')
    byHash.searchParams.delete('amount')
    byHash.searchParams.set('h', noteId(k1))
    const body = await get(byHash)
    if (body.status === 'ERROR' || body.tag !== 'withdrawRequest') {
      return 'not offered - every informational lookup puts the live secret in a query string, where any proxy that logs full URLs keeps it'
    }
    hashLookupOffered = true
    // The whole point of the lookup. A wallet asking by hash already holds
    // the secret - it could not have computed the hash otherwise - so the
    // field buys it nothing, and filling it in puts the note back on the
    // wire this lookup exists to keep it off.
    assert(
      body.k1 === undefined,
      'the response carried a k1 - a lookup by hash must omit it, or it puts the bearer secret back in the reply the wallet asked by hash to avoid'
    )
    assert(
      body.maxWithdrawable === info.maxWithdrawable,
      `the same note is worth ${body.maxWithdrawable} by hash and ${info.maxWithdrawable} by k1`
    )
    // An h it never registered must get the unknown-note answer. One that
    // answers anyway reports a note where none exists, and a wallet
    // restoring from seed reads that as a note it has lost the secret to.
    const unknownSecret = bytesToHex(randomBytes(32))
    const nobody = new URL(url)
    nobody.searchParams.delete('k1')
    nobody.searchParams.delete('amount')
    nobody.searchParams.set('h', noteId(unknownSecret))
    const invented = await get(nobody)
    const unknownK1 = new URL(url)
    unknownK1.searchParams.set('k1', unknownSecret)
    unknownK1.searchParams.delete('h')
    unknownK1.searchParams.delete('amount')
    const ordinaryUnknown = await get(unknownK1)
    assert(
      invented.status === 'ERROR' || invented.tag !== 'withdrawRequest',
      'answered for a hash it never registered - an unrecognized h must get the same response an unknown k1 would'
    )
    assert(
      invented.status === ordinaryUnknown.status && invented.reason === ordinaryUnknown.reason,
      `an unknown h answered ${JSON.stringify(invented)} but an unknown k1 answered ${JSON.stringify(ordinaryUnknown)}`
    )

    // `h` is accepted in place of `k1`, not alongside it. Accepting both
    // lets an intermediary add a second lookup identity and leaves clients
    // unable to know which note the response describes.
    const both = new URL(url)
    both.searchParams.set('h', noteId(k1))
    const ambiguous = await get(both)
    assert(
      ambiguous.status === 'ERROR',
      'accepted both k1 and h on one informational lookup - exactly one lookup identity is allowed'
    )
    return 'by hash, with no k1 in the reply; unknown and mixed lookups refused'
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
    cb.searchParams.append('h', noteId(bytesToHex(randomBytes(32))))
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

  await report.check('refuses a rotate with no h', async () => {
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', k1)
    const body = await get(cb)
    assert(
      body.status === 'ERROR',
      'accepted a mutation with no h - a SERVICE must never generate the replacement secret'
    )
    return body.reason
  })

  await report.check('refuses a split with no h2', async () => {
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', k1)
    cb.searchParams.append('amount', String(Math.max(1, Math.floor(info.maxWithdrawable / 2))))
    cb.searchParams.append('h', noteId(bytesToHex(randomBytes(32))))
    const body = await get(cb)
    assert(
      body.status === 'ERROR',
      'accepted a split with only one output hash - the change note has nowhere to go but a SERVICE-generated secret'
    )
    const after = new URL(url)
    after.searchParams.set('k1', k1)
    const still = await get(after)
    assert(still.status !== 'ERROR', `a refused split burned the note anyway: ${still.reason}`)
    return body.reason
  })

  let current = k1
  let currentSig = null
  await report.check('rotate mints a note the service never saw the secret of', async () => {
    const fresh = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(fresh))
    const body = await get(cb)
    assert(body.status === 'OK', `refused: ${body.reason}`)
    // Adopt the new secret BEFORE asserting anything about compliance. The
    // mutation has already happened, so a runner that throws first would
    // leave every later check pointed at a note this service just burned,
    // and report a pile of cascading failures that say nothing.
    current = fresh
    currentSig = body.sig ?? null
    assert(
      body.k1 === undefined && body.change === undefined,
      'the response carried a secret - a compliant SERVICE returns none, since it generated none'
    )

    const check = new URL(url)
    check.searchParams.set('k1', fresh)
    const after = await get(check)
    assert(after.status !== 'ERROR', `the rotated note is not spendable: ${after.reason}`)
    assert(
      after.maxWithdrawable === info.maxWithdrawable,
      `value changed across a rotate: ${info.maxWithdrawable} -> ${after.maxWithdrawable}`
    )

    const old = new URL(url)
    old.searchParams.set('k1', k1)
    const dead = await get(old)
    assert(dead.status === 'ERROR', 'the rotated-away secret is still spendable')
    return 'burned the old secret, minted the new'
  })

  await report.check('signs the notes it issues', async () => {
    assert(info.mintPubkey, 'no mintPubkey advertised - offline verification is mandatory')
    assert(isCompressedPubkey(info.mintPubkey), 'mintPubkey is not a 33-byte compressed secp256k1 key')
    assert(currentSig, 'the rotate returned no sig - offline verification is mandatory')
    // A mint that has rotated its signing key may publish the old ones as
    // previousPubkeys, so notes it issued before the rotation still
    // verify. Any key it currently stands behind is an acceptable signer
    // for grading purposes. That is a narrower claim than it looks: it
    // says the signature is genuine, not that a wallet should accept the
    // new key - LUD-25 puts that decision with the holder.
    const signedBy = [info.mintPubkey, ...previousPubkeys].find(key =>
      verifySignature(current, info.maxWithdrawable, currentSig, key)
    )
    assert(
      signedBy,
      previousPubkeys.length > 0
        ? 'the signature verifies against neither the advertised mintPubkey nor any published previous key'
        : 'the signature does not verify against the advertised mintPubkey and amount'
    )
    return signedBy === info.mintPubkey
      ? 'verified offline'
      : `verified offline against a previous signing key (${signedBy.slice(0, 16)}...)`
  })

  await report.check('reports a spent hash distinguishably from an unknown hash', async () => {
    if (!hashLookupOffered) throw soft('hash lookup is not offered')
    const burned = new URL(url)
    burned.searchParams.delete('k1')
    burned.searchParams.delete('amount')
    burned.searchParams.set('h', noteId(k1))
    const burnedResponse = await get(burned)
    assert(
      burnedResponse.status === 'ERROR' && typeof burnedResponse.reason === 'string' &&
        /spent/i.test(burnedResponse.reason) && !/unknown|not found/i.test(burnedResponse.reason),
      `a spent hash must be identified as spent, got ${JSON.stringify(burnedResponse)}`
    )

    const unknown = new URL(burned)
    unknown.searchParams.set('h', noteId(bytesToHex(randomBytes(32))))
    const unknownResponse = await get(unknown)
    assert(
      unknownResponse.status === 'ERROR' && typeof unknownResponse.reason === 'string' &&
        /unknown|not found/i.test(unknownResponse.reason) && !/spent/i.test(unknownResponse.reason),
      `an unregistered hash must be identified as unknown, got ${JSON.stringify(unknownResponse)}`
    )
    return 'spent and unknown hashes are distinguishable without disclosing k1'
  })

  await report.check('keeps signatures off the informational endpoint', async () => {
    // LUD-25: "Signatures are only ever delivered in the
    // withdrawSuccessResponse of a rotate, split or merge, the
    // informational endpoint never returns one." A mint that hands one out
    // here lets anyone holding only a note's PUBLIC url mint a certificate
    // for it, and invites a wallet to treat the informational answer as an
    // offline proof when it is an online one.
    const here = new URL(url)
    here.searchParams.set('k1', current)
    const body = await get(here)
    assert(body.status !== 'ERROR', `informational GET refused: ${body.reason}`)
    assert(body.sig === undefined, 'the informational GET returned a sig')
    assert(body.sig2 === undefined, 'the informational GET returned a sig2')
    return 'no signature where the spec forbids one'
  })

  // The still-alive probe the three adversarial checks below share: a
  // compliant refusal is ATOMIC, so the note it refused to touch must
  // still be spendable afterwards.
  const assertStillLive = async () => {
    const check = new URL(url)
    check.searchParams.set('k1', current)
    const still = await get(check)
    assert(still.status !== 'ERROR', `the refusal burned the note anyway: ${still.reason}`)
  }

  await report.check('refuses a duplicated k1', async () => {
    // One note named twice in a merge-shaped request. Counting its value
    // twice into the output creates money from nothing.
    const fresh = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(fresh))
    const body = await get(cb)
    if (body.status === 'OK') {
      // the mutation landed - adopt the output first, so later checks keep
      // pointing at live money whatever the verdict
      current = fresh
      currentSig = body.sig ?? null
      const after = new URL(url)
      after.searchParams.set('k1', fresh)
      const output = await get(after)
      assert(
        output.maxWithdrawable !== info.maxWithdrawable * 2,
        'a duplicated k1 was counted twice - the output is worth double the note'
      )
      throw soft(
        `accepted a duplicated k1 (deduplicated to ${output.maxWithdrawable} msat) - an atomic refusal is the safer answer`
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('refuses an output hash that already names a note', async () => {
    // The original note's id is a known existing (burned) id. Minting over
    // an existing id hands the output to whoever knows its preimage - here,
    // every previous holder of the original note.
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('h', noteId(k1))
    const body = await get(cb)
    if (body.status === 'OK') {
      // the output's secret IS the original k1 - adopt it and say so
      current = k1
      currentSig = body.sig ?? null
      throw new Error(
        'minted over an existing note id - the output is spendable with a secret every previous holder already knows'
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('refuses a split whose h equals h2', async () => {
    const half = Math.floor(info.maxWithdrawable / 2)
    if (half < 1) throw soft('note too small to attempt')
    const twin = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('amount', String(half))
    cb.searchParams.append('h', noteId(twin))
    cb.searchParams.append('h2', noteId(twin))
    const body = await get(cb)
    if (body.status === 'OK') {
      current = twin
      currentSig = body.sig ?? null
      const after = new URL(url)
      after.searchParams.set('k1', twin)
      const output = await get(after)
      throw new Error(
        `accepted h2 equal to h - one id now carries ${output.maxWithdrawable ?? 'nothing'} msat of what should be two notes`
      )
    }
    await assertStillLive()
    return body.reason
  })

  await report.check('never mutates on a non-GET request', async () => {
    // LNURL endpoints are GETs. An OPTIONS preflight or a stray POST
    // carrying the callback's query string must leave the note untouched -
    // real HTTP stacks send both on their own initiative.
    for (const method of ['POST', 'OPTIONS']) {
      const fresh = bytesToHex(randomBytes(32))
      const cb = new URL(info.callback)
      cb.searchParams.append('k1', current)
      cb.searchParams.append('h', noteId(fresh))
      // the response - even an error - is not the assertion; the store is
      await fetch(cb.toString(), {method, signal: AbortSignal.timeout(15_000)})
        .then(res => res.arrayBuffer())
        .catch(() => {})
      const stillUrl = new URL(url)
      stillUrl.searchParams.set('k1', current)
      const still = await get(stillUrl)
      assert(still.status !== 'ERROR', `a ${method} request burned the note - the mutating callback must answer GET only`)
      const probe = new URL(url)
      probe.searchParams.set('k1', fresh)
      const output = await get(probe)
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
    const amount = info.maxWithdrawable - knownBaseFee + 1
    if (amount < 1 || amount >= info.maxWithdrawable) {
      throw soft('note too small to leave change short of the base fee')
    }
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('amount', String(amount))
    cb.searchParams.append('h', noteId(bytesToHex(randomBytes(32))))
    cb.searchParams.append('h2', noteId(bytesToHex(randomBytes(32))))
    const body = await get(cb)
    assert(
      body.status === 'ERROR',
      `accepted a split leaving ${info.maxWithdrawable - amount} msat of change against a ${knownBaseFee} msat base fee`
    )
    const after = new URL(url)
    after.searchParams.set('k1', current)
    const still = await get(after)
    assert(still.status !== 'ERROR', `a refused split burned the note anyway: ${still.reason}`)
    assert(
      still.maxWithdrawable === info.maxWithdrawable,
      `a refused split changed the note's value: ${info.maxWithdrawable} -> ${still.maxWithdrawable}`
    )
    return body.reason
  })

  await report.check('split conserves value', async () => {
    const half = Math.floor(info.maxWithdrawable / 2)
    if (half < 1) throw soft('note too small to split')
    if (knownBaseFee !== null && info.maxWithdrawable - half < knownBaseFee + 1) {
      throw soft('note too small to split past the advertised base fee')
    }
    const a = bytesToHex(randomBytes(32))
    const b = bytesToHex(randomBytes(32))
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', current)
    cb.searchParams.append('amount', String(half))
    cb.searchParams.append('h', noteId(a))
    cb.searchParams.append('h2', noteId(b))
    const body = await get(cb)
    assert(body.status === 'OK', `refused: ${body.reason}`)

    const valueOf = async secret => {
      const u = new URL(url)
      u.searchParams.set('k1', secret)
      const r = await get(u)
      assert(r.status !== 'ERROR', `split output is not spendable: ${r.reason}`)
      return r.maxWithdrawable
    }
    const [va, vb] = [await valueOf(a), await valueOf(b)]
    assert(
      va === half,
      `asked to split off ${half}, got ${va} - any split fee comes out of change, never the requested amount`
    )
    if (knownBaseFee !== null) {
      const expectedChange = info.maxWithdrawable - half - knownBaseFee
      assert(
        vb === expectedChange,
        `change was ${vb} msat - LUD-25 says total minus amount minus the base fee, ${expectedChange}`
      )
    } else {
      assert(
        va + vb <= info.maxWithdrawable,
        `split created value: ${va} + ${vb} > ${info.maxWithdrawable}`
      )
    }

    // put it back together so the runner ends holding one note
    const merged = bytesToHex(randomBytes(32))
    const mcb = new URL(info.callback)
    mcb.searchParams.append('k1', a)
    mcb.searchParams.append('k1', b)
    mcb.searchParams.append('h', noteId(merged))
    const mbody = await get(mcb)
    assert(mbody.status === 'OK', `merge refused: ${mbody.reason}`)
    current = merged
    const total = await valueOf(merged)
    if (knownBaseFee !== null) {
      assert(
        total === va + vb + knownBaseFee,
        `a merge of 2 notes refunds one base fee per LUD-25: expected ${va + vb + knownBaseFee}, got ${total}`
      )
    } else {
      assert(
        total >= va + vb && total <= info.maxWithdrawable,
        `merge did not conserve value: ${va} + ${vb} became ${total}`
      )
    }
    return `${va} + ${vb}, merged back to ${total}`
  })

  // A rotate, split or merge is a GET, and HTTP stacks retry a GET when
  // the connection they used is dropped: Go's net/http retries one that
  // failed on a reused idle connection, the JDK's HttpClient retries
  // idempotent methods with no switch to turn it off. The retry is byte
  // identical. A SERVICE that answers it as an already-spent input tells
  // the holder the mutation never happened, and a holder that believes it
  // discards the only copy of a secret the SERVICE really did mint a note
  // against. Nobody is told; the money is simply gone.
  //
  // This is a MUST. A retry must replay the original success and must not
  // burn or alter either output.
  await report.check('replays a retried mutation rather than refusing it', async () => {
    const valueAt = async secret => {
      const u = new URL(url)
      u.searchParams.set('k1', secret)
      const r = await get(u)
      return r.status === 'ERROR' ? null : r.maxWithdrawable
    }

    // --- a rotate, retried ---
    const fresh = bytesToHex(randomBytes(32))
    const rotate = new URL(info.callback)
    rotate.searchParams.append('k1', current)
    rotate.searchParams.append('h', noteId(fresh))
    const first = await get(rotate)
    assert(first.status === 'OK', `the rotate itself was refused: ${first.reason}`)
    current = fresh
    currentSig = first.sig ?? null
    const minted = await valueAt(fresh)
    assert(minted !== null, 'the rotate reported OK but minted nothing')

    const retried = await get(rotate)
    const stillThere = await valueAt(fresh)
    assert(
      stillThere !== null,
      'the retried rotate burned the note the first one minted - a retry must never destroy value'
    )
    assert(
      stillThere === minted,
      `the retried rotate changed the note's value: ${minted} -> ${stillThere}`
    )

    assert(
      retried.status === 'OK',
      `a retried rotate is answered "${retried.reason}" while the note it minted is live and worth ${stillThere} msat`
    )
    assert(retried.sig === first.sig, 'a retried rotate returned a different sig than the original')

    // --- a split, retried ---
    // h2 and the change amount are part of what makes a request the same
    // request, so a rotate on its own does not cover it.
    const half = Math.floor(minted / 2)
    if (half < 1 || (knownBaseFee !== null && minted - half < knownBaseFee + 1)) {
      throw soft('a byte-identical rotate replays; note too small to exercise a split retry')
    }
    const a = bytesToHex(randomBytes(32))
    const b = bytesToHex(randomBytes(32))
    const split = new URL(info.callback)
    split.searchParams.append('k1', current)
    split.searchParams.append('amount', String(half))
    split.searchParams.append('h', noteId(a))
    split.searchParams.append('h2', noteId(b))
    const splitFirst = await get(split)
    if (splitFirst.status !== 'OK') {
      throw new Error(`the split itself was refused: ${splitFirst.reason}`)
    }
    const [va, vb] = [await valueAt(a), await valueAt(b)]
    const splitRetried = await get(split)
    const [va2, vb2] = [await valueAt(a), await valueAt(b)]
    assert(
      va2 === va && vb2 === vb,
      `the retried split changed its outputs: ${va}/${vb} -> ${va2}/${vb2}`
    )
    assert(
      splitRetried.status === 'OK',
      `a retried split is answered "${splitRetried.reason}" while both its outputs are live`
    )
    assert(splitRetried.sig === splitFirst.sig, 'a retried split returned a different sig than the original')
    assert(splitRetried.sig2 === splitFirst.sig2, 'a retried split returned a different sig2 than the original')

    // put the two halves back together, so the runner ends holding one note
    const merged = bytesToHex(randomBytes(32))
    const mergeBack = new URL(info.callback)
    mergeBack.searchParams.append('k1', a)
    mergeBack.searchParams.append('k1', b)
    mergeBack.searchParams.append('h', noteId(merged))
    const mergeBody = await get(mergeBack)
    if (mergeBody.status === 'OK') {
      current = merged
      currentSig = mergeBody.sig ?? null
    }

    return 'a byte-identical rotate and split both replay the original success'
  })

  await report.check('refuses a replayed burn', async () => {
    const cb = new URL(info.callback)
    cb.searchParams.append('k1', k1)
    cb.searchParams.append('h', noteId(bytesToHex(randomBytes(32))))
    const body = await get(cb)
    assert(body.status === 'ERROR', 'a secret burned earlier was accepted again')
    return body.reason
  })

  return {finalSecret: current, noteUrl: (() => {
    const u = new URL(url)
    u.searchParams.set('k1', current)
    return u.toString()
  })()}
}
