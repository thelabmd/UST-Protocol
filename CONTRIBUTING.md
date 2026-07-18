<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Contributing to UST

Thanks for looking. UST is trust infrastructure, so the bar is correctness first — the checker is a TCB and the
spec has a formal model behind it. This guide is short and it is honest about the discipline.

## Ground rules

- **The conformance vectors are the canon.** `vectors/` (byte vectors + language-neutral conformance + arc vectors)
  are the cross-implementation arbiter. Any implementation — this one, a clean-room port, the `ust-lite` subset —
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
