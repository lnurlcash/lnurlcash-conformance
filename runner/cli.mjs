#!/usr/bin/env node
import {
  createReport,
  gradeBoundMint,
  gradeMint,
  gradeMintedValue,
  gradeNote,
  gradeRegistration,
  invoiceAmountMsat,
  parseAdvertisedMintFee,
  resolveMint
} from './index.mjs'

const args = process.argv.slice(2)
const flags = new Set(args.filter(a => a.startsWith('--')))
const positional = args.filter(a => !a.startsWith('--'))
const value = name => args.find(a => a.startsWith(`--${name}=`))?.slice(name.length + 3)
const noteArg = value('note')
const paidArg = value('paid')
const prArg = value('pr')
const preimageArg = value('preimage')

if (positional.length === 0 && !noteArg) {
  console.error(`lnurlcash-conform - grade an LNURLcash service against LUD-25

  lnurlcash-conform <mint>                          read-only checks
  lnurlcash-conform <mint> --note=<url> --paid=<msat>   + the minted-value check
  lnurlcash-conform <mint> --note=<url> --pr=<invoice>  same, paid amount from the invoice
  lnurlcash-conform <mint> --note=<url> --preimage=<hex> + the bound-mint checks
  lnurlcash-conform <mint> --note=<url> --spend         + the full mutating checks
  lnurlcash-conform <address> --address              grade a cx1-registered address
  lnurlcash-conform <mint> --register                 + the LUD-26 registration checks

<mint> may be a Lightning Address (mint@example.com), a bare domain, or a
payRequest URL.

--address says the target is a LUD-26 Lightning Address with a cx1
registered against it, not a mint payLink. Such an address mints into its
share's next unused key, so it must not set commentAllowed and must take a
plain LUD-16 payment; it carries mint@'s withdrawLink and Mint fees, and a
+tag pays it too. Without this flag the payLink rules apply, which require
every quote to name its note. Declared rather than detected: a mint that
unsafely falls back to a preimage-keyed note looks the same before
settlement, so --address takes the operator's word for it. Use it on an
address you control or trust.

--register registers a throwaway username on the mint with a share only the
grader holds, probes every refusal LUD-26 requires, updates it to a second
share and unregisters it. The cx1s it used are spent for good - LUD-26
never accepts the same key twice - and hold nothing. Against a mint that
charges an address fee (a third value of Mint fees) the registration stays
held on an invoice the grader does not pay: the invoice is held to the
advertised fee, and the update and unregister checks are skipped.

--paid/--pr name what the note's mint invoice was paid at, and require the
note to be freshly minted and never rotated: the check compares its value
against the LUD-25 fee formula. It is read-only.

--preimage names the payment preimage of the invoice that minted the note,
for a mint advertising mintToHash and a note minted against a hash you chose
yourself: --note then carries YOUR secret, and the check confirms the note is
really there and that the preimage opens nothing. Also read-only.

The --spend checks SPEND: they burn the note given and leave its value in a
fresh note printed at the end. The note's k1 may be any spend of it: a
bearer note's 64-hex preimage, a ck1 or a cw1. Along the way the value
passes through a script-tree note and a key-path note the runner holds,
and every refusal it probes for is confirmed to have left the value where
it was. Use a small note, and pass --spend to confirm you meant it.`)
  process.exit(2)
}

const report = createReport()

let pay
if (positional[0]) {
  const payUrl = resolveMint(positional[0])
  console.log(`grading ${payUrl}\n`)
  pay = await gradeMint(payUrl, report, {registeredAddress: flags.has('--address')})
  if (flags.has('--register')) {
    console.log('running the registration checks - this registers, updates and unregisters a throwaway username\n')
    await gradeRegistration(payUrl, report)
  }
}

const mintFee =
  pay && typeof pay.metadata === 'string' ? parseAdvertisedMintFee(pay.metadata) : null

let paidMsat = null
if (paidArg !== undefined) {
  paidMsat = Number(paidArg)
} else if (prArg !== undefined) {
  paidMsat = invoiceAmountMsat(prArg)
  if (paidMsat === null) {
    console.error('--pr carries no amount - pass --paid=<msat> instead')
    process.exit(2)
  }
}

if (noteArg && paidMsat !== null) {
  await gradeMintedValue(noteArg, report, {mintFee, paidMsat})
}

if (noteArg && preimageArg !== undefined) {
  await gradeBoundMint(noteArg, report, {
    preimage: preimageArg,
    payCallback: typeof pay?.callback === 'string' ? pay.callback : null
  })
}

let finished
if (noteArg) {
  if (!flags.has('--spend')) {
    report.skip('note checks', 'pass --spend to run them - they burn the note')
  } else {
    console.log('running the mutating checks - this spends the note given\n')
    // knowing the advertised fee makes the conservation checks exact
    const options = pay && typeof pay.metadata === 'string' ? {mintFee} : {}
    // and knowing which keys the mint has signed under keeps a note issued
    // before a signing-key rotation from grading as a bad signature
    const previousPubkeys = pay?.mintAddress?.previousPubkeys
    if (Array.isArray(previousPubkeys)) options.previousPubkeys = previousPubkeys
    finished = await gradeNote(noteArg, report, options)
  }
}

const symbol = {pass: '  ok  ', fail: ' FAIL ', warn: ' warn ', skip: ' skip '}
for (const r of report.results) {
  console.log(`${symbol[r.status]} ${r.name}${r.detail ? ` - ${r.detail}` : ''}`)
}

const counts = report.results.reduce((acc, r) => {
  acc[r.status] = (acc[r.status] ?? 0) + 1
  return acc
}, {})
console.log(
  `\n${counts.pass ?? 0} passed, ${counts.fail ?? 0} failed, ${counts.warn ?? 0} warnings, ${counts.skip ?? 0} skipped`
)

if (finished) {
  console.log(`\nthe value now lives in:\n  ${finished.noteUrl}`)
}

process.exit(report.failed > 0 ? 1 : 0)
