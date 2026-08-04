<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Contributing to UST

Thanks for looking. UST is trust infrastructure, so the bar is correctness first — the checker is a TCB and the
spec has a formal model behind it. This guide is short and it is honest about the discipline.

## Two rules this protocol does not trade away

**1. A minor only ADDS.** A change that alters the meaning of anything an earlier minor already defines is a **MAJOR**. There is no third option, and the reason is not taste: an older verifier evaluating under older rules must still be **right** about what it evaluated. A minor that changed a meaning would make every deployed verifier quietly wrong rather than merely less informed.

**2. A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands. Material from a newer minor that it does not implement is reported as **NOT EVALUATED** — never as invalid, and never silently passed. Whether that reach is sufficient is the **consumer's** policy (the `--require-*` floors), not the protocol's coercion.

**Why the second rule is load-bearing for adoption.** People run old runtimes for years because upgrading means reworking a stack that works. A protocol whose adoption depends on synchronised upgrades across every consumer has chosen a property it cannot have — and a verifier that must be current in order to verify anything is a verifier that stops being run. Refusing politely is still refusing.

**And it is what makes CLOSED systems possible at all.** A consumer with no discovery surface has no way to learn that the world moved. Under a refusal design it sees only *invalid*, with nothing pointing at its own age; under this one it keeps working, keeps being honest about what it did and did not check, and can run for years without ever lying.

*Both rules hold today. A newer minor answers `INDETERMINATE(unsupported_minor)`, a different major `INDETERMINATE(unsupported_major)`; `INVALID` is reserved for its one meaning — the verifier applied ITS OWN rules and they were violated.*

## What we cannot do for ourselves

Most of this repository is checked by machinery we wrote. That machinery has been audited — by us — and the audit
found eleven defects in the gates themselves rather than in the code they guard (#110). Which is exactly why the
three things below cannot be closed from the inside, and why they are the most useful contributions available:

- **[#113](https://github.com/thelabmd/UST-Protocol/issues/113) — regrade the CI steps independently.** Every gate
  here carries a declared grade for *what decides its dispute*, and every one of those grades was written by the
  person who wrote the gate. The criterion is written down so a second grader answers the same question. **A
  disagreement is the finding**, not an error to correct: it marks a place where our model of our own instrument is
  wrong, which is the one thing the instrument cannot measure about itself.
- **[#83](https://github.com/thelabmd/UST-Protocol/issues/83) — read the formal model as an expert, and disagree.**
  The model and the code move in lockstep and each is checked against the other; neither is checked against a
  reviewer who has no stake in the design being right.
- **[#34](https://github.com/thelabmd/UST-Protocol/issues/34) — a third implementation, clean-room from the spec.**
  Two implementations already cross-verify byte-for-byte, and both were written here: a blind spot that runs through
  both is invisible to that check. A port from the spec alone — Go, Rust, anything — is the only thing that turns
  agreement into evidence. `PORTING.md` states what it must reproduce; `vectors/` is the arbiter.

If you take one, say so on the issue first — not for permission, but so two people do not spend a week on the same
disagreement.

## Ground rules

- **The conformance vectors are the canon.** `vectors/` (byte vectors + language-neutral conformance + arc vectors)
  are the cross-implementation arbiter. Any implementation — this one, a clean-room port, the `ust-light` subset —
  must pass them byte-for-byte. A behaviour that is not pinned by a vector is not a guarantee.
- **math → code → vector → test.** A change to a normative behaviour lands with its vector in the SAME commit:
  a new negative condition gets a byte vector; a resolver behaviour gets a conformance check. See `PORTING.md` for
  the value model and the vector arbiter.
- **Structural, not point-wise.** We fix a whole class, not one case (unify a duplicated path, harden the boundary,
  size to the norm) — no patches that leave the same footgun one call away.
- **Spec / model changes are issue-first.** Open an issue before a PR that touches `spec/` or the formal model:
  the model and the code move in lockstep, and a claim the model asserts but the code does not realize is a bug.

## Working locally

```bash
npm install
npm test                      # conformance + language-neutral arc contract
npm run test:byte-vectors     # the checker byte corpus + coverage manifest (regenerate == committed)
npm run test:reference-checker && npm run test:reference-checker-fuzz
```

Before you open a PR, run the **whole** gate set — the exact list is `.github/workflows/ci.yml`
(`npm test`, `test:model`, `test:vectors`, `test:spec-sync`, `test:parity`, `test:byte-vectors`, `test:cli`,
`test:lite`, `test:security`, `test:ssrf`, `test:connectors`, `test:web-signer`, drift). A local green on a subset
is not CI green. If you add a core export to `packages/ust-protocol/index.mjs`, triage it into `test:parity`
(`tools/capability-parity.mjs`) in the same commit.

## Pull requests

- Keep the diff focused; match the surrounding code's idiom and comment density.
- Regenerate any generated artifact (`vectors/`, `.github/*.svg`, spec registry) and commit it — the drift gates
  fail otherwise.
- A green CI is a hard requirement, not a nicety.

## Security

Do **not** open a public issue for a suspected vulnerability — see [`SECURITY.md`](SECURITY.md) (private reporting).

## Governance & license

How decisions are made: [`GOVERNANCE.md`](GOVERNANCE.md). By contributing you agree your code is under Apache-2.0
and your documentation prose under CC BY 4.0 (see [`LICENSE`](LICENSE) / [`LICENSE-SPEC`](LICENSE-SPEC)). The name
*UST* and the *UST-compatible* claim: [`TRADEMARK.md`](TRADEMARK.md).
