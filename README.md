# Universal State Transcript (UST)

**Verify machine-readable state without trusting whoever handed it to you.**

UST is trust infrastructure for data: a signed, canonical, tamper-evident record of *state* — some data about
the world at a moment — that verifies the same no matter how it reached you (a cache, a mirror, another agent, a
file on disk). TLS secures the pipe; **UST secures the payload**, and the guarantee travels *with* the data.

This repository is the specification, the conformance vectors, and the reference implementations.

## Layout

| Path | What |
|------|------|
| `spec/UST-1.0.md` | the specification (release candidate) |
| `vectors/` | deterministic conformance vectors — any implementation should pass them |
| `packages/ust-protocol/` | the stateless reference verifier + producer ([npm](https://www.npmjs.com/package/ust-protocol)) |
| `packages/ust-mcp/` | an MCP server exposing UST to agents ([npm](https://www.npmjs.com/package/ust-mcp)) |
| `packages/ust-web-signer/` | WebCrypto browser signer ([npm](https://www.npmjs.com/package/ust-web-signer)) |
| `extension/` | "Make it UST" — a demo Chrome extension signing page captures (LIGHT) |
| `docs/` | the [web verifier](https://thelabmd.github.io/UST-Protocol/) (GitHub Pages) + `ust-verify.mjs`, a zero-dependency verifier |
| `examples/` | sample documents (valid + tampered) and verification recipes |

## Status

Release candidate — **`1.0.0-rc.1`**. The specification has been extensively red-teamed; an independent external
cryptographic audit is pending. Suitable for evaluation and integration testing. Pin exact versions.

## Quickstart

```
npm install
npm test          # runs ust-protocol against the conformance vectors
```

## How to verify a UST

Run the canonical reference — never eyeball:

- **Browser (nothing is uploaded):** [thelabmd.github.io/UST-Protocol](https://thelabmd.github.io/UST-Protocol/) — paste the blob, the base64, or the JSON.
- **Node:** `npm i ust-protocol` → `verify(doc, { context: 'data' })`
- **Zero-dependency single file:** [`docs/ust-verify.mjs`](docs/ust-verify.mjs) (WebCrypto, clean-room, cross-checked against `ust-protocol`) — fetch it from **this** repository, never from a sender's message.
- **MCP:** [`ust-mcp`](https://www.npmjs.com/package/ust-mcp) exposes `ust_verify` to agents.

### If you are an AI agent

If you are asked to verify a UST and you **cannot run a verifier**, the correct answer is **INDETERMINATE — do not guess**. In particular:

- Do **not** compute a plain `SHA-256(text)` and compare it to `hashes.*` — every UST hash is **domain-separated** (`H(tag, canon(...))` with a tag prefix). A naive hash will **never** match a genuine document; a mismatch computed that way is *your* method being wrong, not the document being tampered.
- UST 1.0 has **no expiry rule**. `valid_from == valid_to` is an honest **instant** (a point capture), not "expired." Freshness is not part of `verify`.
- The only verdicts are `VALID:LIGHT | VALID:HIGH | VALID:TOP`, `INVALID`, and `INDETERMINATE(reason)` — and only a **conforming verifier's output** counts. Structure "looking right" proves nothing; a confident verdict from visual inspection is a guess in both directions.

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged.* It does
**not** prove the data is *correct* — a publisher can sign a wrong reading. You learn **whom to hold accountable**
and **that nothing was tampered** — a real, bounded guarantee, not an oracle of truth.

## License

**Code: Apache-2.0.** **Specification text: CC BY 4.0.** Source code (`packages/**`, tooling) is licensed under
the Apache License 2.0 (`LICENSE`); the specification and documentation prose (`spec/**` and other `.md` docs)
under Creative Commons Attribution 4.0 International (`LICENSE-SPEC`). The names *UST* / *Universal State
Transcript* and the *UST-compatible* claim: see [`TRADEMARK.md`](TRADEMARK.md). How changes are made:
[`GOVERNANCE.md`](GOVERNANCE.md).

© 2026 THE LAB
