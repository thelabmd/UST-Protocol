<!-- Thanks for the PR. Keep the diff focused; match the surrounding code's idiom. -->

## What & why

<!-- One or two sentences: what changes and the reason. Link the issue if there is one (spec/model changes are issue-first). -->

## Checklist

- [ ] The **full** CI gate set passes locally (the list is `.github/workflows/ci.yml` — a subset is not enough).
- [ ] A normative-behaviour change lands with its **vector** in this PR (`math → code → vector → test`).
- [ ] Regenerated artifacts are committed (`vectors/`, `.github/*.svg`, spec registry) — the drift gates pass.
- [ ] A new core export in `packages/ust-protocol/index.mjs` is triaged into `test:parity`.
- [ ] The fix is **structural**, not a point patch that leaves the same footgun one call away.
- [ ] No suspected vulnerability is disclosed here (those go through private reporting — see `SECURITY.md`).
