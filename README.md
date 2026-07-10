<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Universal State Transcript (UST)

**Verify machine-readable state without trusting whoever handed it to you.**

> **Status: `1.0.0-rc.6` — a RELEASE CANDIDATE, not a final 1.0.** Five external AI reviews are folded in; an
> independent human cryptographic audit is pending. Suitable for evaluation and integration testing. Pin exact
> versions. The wire format `ust: "1.0"` is stable across rc's.

## What this is

UST is a small open protocol for **tamper-evident records of state** — some data about the world, at a moment,
signed by whoever observed it. A transcript is a self-contained JSON object: canonical form, domain-separated
hashes, an Ed25519 signature, an explicit time frame, and (optionally) provenance links, privacy commitments and
an anchor proof. **TLS secures the pipe; UST secures the payload** — the guarantee travels *with* the data, so a
transcript verifies the same whether it arrived from the publisher, a cache, a mirror, a file, another agent, or
a chat paste.

That moves the trust boundary. Today's logging and tracing answer *"what happened inside my system?"* — and the
answer lives in a vendor's database, on the vendor's word. A UST answers a different question: *"how do I prove
to a **third party** that exactly these inputs, sources and results existed at that time, were signed by that
key, and were not changed since?"* Seal at creation → store anywhere → verify independently of the storage,
offline, with one library call. No blockchain required, no consensus, no per-record fees: the LIGHT tier is a
key, a canonical form and a signature.

Trust is **graduated, and the verdict carries its tier** — a conforming verifier never says a bare `VALID`:

| verdict | what is proven |
|---|---|
| `VALID:LIGHT` | the exact bytes · the signing key · the claimed time frame. Identity is the key itself (a self-certifying `sha256:` shard) or a *claimed* name — never a verified name. |
| `VALID:HIGH` | + the publisher's **name** is provably bound to the key (genesis + key log + no-fork witness) |
| `VALID:TOP` | + the document provably existed **by** a point in real time (anchor inclusion, e.g. Bitcoin/OTS). Stream *completeness* is a separate **range** verdict (`verifyStream`). |
| `INVALID` | a definite, deterministic failure (specific `E-*` codes) |
| `INDETERMINATE` | a dependency was unreachable, or an optional algorithm is unimplemented — *cannot decide* is never conflated with *forged* |

One signal the protocol never emits: **"true."** UST proves *fixation, not truth* — a publisher committed to
these bytes at this time and cannot silently rewrite them. Whether the reading was *correct* is out of scope by
construction; you learn whom to hold accountable and that nothing was tampered. The same discipline extends to
composition: a state can be published in **layers** with different visibility (public observation → blinded
commitment → encrypted detail → a partner's derived shard), each layer independently signed and provable to
exist, while its content is disclosed only to whom it is meant for.

## Layout

| Path | What |
|------|------|
| `spec/UST-1.0.md` | the specification (normative) |
| `spec/UST-1.0-formal-model.md` | a measure-theoretic semantics (non-normative appendix) |
| `vectors/` | deterministic conformance vectors — any implementation should pass them |
| `packages/ust-protocol/` | the stateless reference verifier + producer ([npm](https://www.npmjs.com/package/ust-protocol)) |
| `packages/ust-mcp/` | an MCP server exposing UST to agents ([npm](https://www.npmjs.com/package/ust-mcp)) |
| `packages/ust-web-signer/` | WebCrypto browser signer ([npm](https://www.npmjs.com/package/ust-web-signer)) |
| `extension/` | "Make it UST" — a demo Chrome extension: sign by selection, verify by selection (LIGHT) |
| `docs/` | the [web verifier](https://thelabmd.github.io/UST-Protocol/) (client-side, GitHub Pages) + `ust-verify.mjs`, a zero-dependency verifier + `llms.txt` |
| `examples/` | sample documents (valid + tampered) and verification recipes |

## Quickstart

```
npm install
npm test          # the conformance runner: 72 checks; asserts spec == package == vectors version
```

Produce and verify a LIGHT transcript:

```js
import { generateSigner, signObservation, nowFrame } from 'ust-web-signer';
import { verify } from 'ust-protocol';
const s = await generateSigner();                              // Ed25519, non-extractable
const { ust_id, time } = nowFrame();                           // instant capture frame
const doc = await signObservation(s, { ust_id, time, data: { capture: { kind: 'captured', value: { text: 'exact bytes' } } } });
console.log(verify(doc, { context: 'data' }).result);          // → VALID:LIGHT
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
