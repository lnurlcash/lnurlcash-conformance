# Security policy

This repo is test infrastructure. See [THREAT-MODEL.md](THREAT-MODEL.md) for
what that means in practice — particularly that the mock mint's signing key is
public by design, its invoices are not payable, and the grader's full mode
spends the note it is given.

## Reporting

If a vector is wrong in a way that would lead an implementer to lose money, or
the mock mint or grader can be made to do something harmful, report it
privately:

<https://github.com/lnurlcash/lnurlcash-conformance/security/advisories/new>

Ordinary disagreements about what the spec means belong in a public issue, or
on the [LUD-25 PR](https://github.com/lnurl/luds/pull/301).

## Scope

**In scope**: a vector that asserts something unsafe, a mock mint that fails to
reproduce the failure it claims to, a grader that passes a non-compliant
service or spends more than it said it would.

**Out of scope**: the mock mint's lack of hardening (it is a fixture, bound to
loopback, and says so), and the LUD-25 draft itself.
