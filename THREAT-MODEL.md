# Threat model

This repo is test infrastructure, not a wallet. Its risks are the risks of
test infrastructure that happens to speak a money protocol, and they are
mostly about the ways it could be mistaken for the real thing.

## What is here

**Vectors** — inert JSON. Data, loaded by test suites.

**The mock mint** — a real HTTP server that speaks LNURLcash and can be told
to misbehave.

**The grader** — a CLI that makes real requests to a service you name, and in
its full mode spends a note you give it.

## The mock mint

**It invents its invoices.** They are syntactically valid human-readable parts
plus deterministic filler. Nothing is payable, nothing routes, and no Lightning
node is involved. This is deliberate: a conformance run must never be
mistakable for a mainnet one, in either direction.

**Its signing key is fixed and public.** `1111...` and its counterpart appear
in this repo, in the generator, and in the vectors. They exist to make runs
reproducible. A signature that verifies against the mock's pubkey proves
nothing about anybody's money — and a service that ever used this key would be
handing out notes anyone here could forge.

**Its test hooks are off by default.** `/_test/credit`, `/_test/settle` and
`/_test/state` create notes and settle invoices on demand, and exist only so
out-of-process suites in other languages can set up the flows the in-process
one drives directly. They answer 404 unless `--testHooks` is passed. Never
enable them on anything reachable, and never run this server anywhere that
could be confused with a real mint.

**It is not hardened.** It has no rate limiting, no authentication, no size
limits worth the name, and it holds its entire state in memory. It binds to
loopback by default. Treat it as a fixture, because that is all it is.

## The grader

**Its full mode spends.** `--note=... --spend` burns the note it is given: it
rotates it, splits it, merges the halves back, and prints where the value
ended up. If the run dies partway, the value is in a secret only that process
knew, and it is gone. Use a small note. The `--spend` flag exists so this
cannot happen by accident.

**Its read-only mode still makes real requests** to whatever service you name,
including asking for an invoice. That is a request a mint may log or rate-limit.

**It refuses cleartext.** The same admission rule the libraries use — https
anywhere, http only for loopback and `.onion` — applies here, so a grader run
cannot be redirected onto a plaintext connection carrying a note secret.

**Its spend mode probes adversarial shapes on purpose.** A duplicated `k1`, an
output hash that collides with an existing note id, and a split whose `h`
equals `h2` are all sent to the service under grade, expecting atomic
refusals. A compliant mint refuses and the note is untouched (the grader
confirms this after every refusal); a non-compliant one has just demonstrated
a fund-inflation or note-planting defect on the note the operator chose to
spend — which is exactly what the flag consented to.

## What these vectors do not cover

**They are not a security audit.** They check that an implementation agrees
with the spec on the cases written down. Passing them means an implementation
does not have *these* bugs.

**They cannot check storage, key handling or transport.** A library can pass
every vector and still write note secrets to a log, generate them from a weak
RNG, or sit behind a retrying proxy. The lifecycle vectors name these as
requirements precisely because vectors cannot enforce them.

**They are only as right as this repo is.** Where a vector and an
implementation disagree, either may be wrong. The
[LUD-25 PR](https://github.com/lnurl/luds/pull/301) is where that gets settled,
and an ambiguity found there is worth more than a vector defending an accident.

## Supply chain

Three dependencies, all `@noble`/`@scure`, all already trusted by the
implementations under test. The generator and self-check use them directly
rather than through any LNURLcash library, so a compromised library cannot
launder its own mistakes through the vectors.

## Reporting

If a vector is wrong in a way that would lead an implementer to lose money,
that is worth reporting privately:

<https://github.com/lnurlcash/lnurlcash-conformance/security/advisories/new>

Ordinary disagreements about what the spec means belong in a public issue, or
on the LUD-25 PR.
