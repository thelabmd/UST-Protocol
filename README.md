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
construction; you learn whom to hold accountable and that nothing was tampered.

## Chains and layered shards — one state, graduated visibility

The part that makes UST more than "signed JSON": a single connected state does not have to be one document.
It can be a **chain of independently signed layers**, each a full transcript with its own key, time frame and
provenance — linked by content hashes (`based_on` + a recomputed `seed`), so the **existence, order and lineage
of every layer are publicly provable while each layer's content is disclosed only to whom it is meant for**:

```
L1  public observation            "geomagnetic activity: elevated"           anyone verifies
L2  blinded commitment            proof a value was fixed — value hidden      existence is public
L3  encrypted shard               AEAD ciphertext + commitment                key holders read & verify
L4  partner's derived shard       another publisher, another key, based_on →  cross-party, provable lineage
```

- **Blinded** (`privacy: "blinded"`): the value is replaced by a frame-bound commitment
  (`H(domain_shard, ust_id, nonce, name, value)`). Publish now, reveal later — and the revealed `{nonce, value}`
  provably reproduces the *original* commitment: it cannot be quietly swapped, moved to another hour, or
  re-attributed to another publisher. Embargoed results, private forecasts, positions, proof-of-priority.
- **Encrypted** (`privacy: "encrypted"`): ciphertext *and* commitment coexist; after decryption the verifier
  checks that the plaintext reproduces the same commitment (`E-COMMIT` on mismatch) — "the ciphertext really
  contains what was publicly committed" is a checked obligation, not a promise.
- **Cross-party derivation**: a partner who receives a layer can sign their own transcript on top
  (`class: "derivation"`, `based_on: [hash]`) under their own key — an auditor later walks the whole chain,
  verifying each available layer independently. Trust composes, but is **never inherited automatically**:
  holding an outer layer does not vouch for the inner ones; each signature is checked on its own.
- **Deletable without breaking the proof**: anchors commit to *hashes*, not contents — sensitive payloads can be
  destroyed later while "this existed, in this order, at this time" remains provable forever (and nothing can be
  forged back under the old hash).

Different consumers hold different depths of the same reality — the public sees L1, a client L1–L2, a partner
L1–L3, an auditor the whole chain — and every one of them can *verify* exactly what they hold. That is the
protocol's real subject: **differentiated, provable access to a shared machine state.**

## The time coordinate — `ust_id`

Before anything else, a UST is an address on **one shared time axis**. Every transcript carries a frame id,
`ust:YYYYMMDD.HH[MM[SS]]` (UTC): `ust:20260710.14` is an hour frame, `ust:20260710.1429` a minute,
`ust:20260710.142900` a second. This is not metadata — it is part of the document's *identity*, and the
per-partition hashes **bind** it: a signed value cannot be replayed into another hour or re-attributed to
another frame.

One coordinate system, shared by every publisher on Earth by construction (UTC), buys things no per-vendor
timestamp field can:

- **"What was the world doing at 14:29Z?" is a query, not a metaphor.** Transcripts from unrelated publishers
  carrying the same coordinate are claims about the *same moment*. Collect them and you hold a signed
  cross-section of the world at `t` — each slice independently verifiable.
- **Correlation without coordination.** Publishers never agree on anything except the grid. Space weather ×
  grid frequency × market state × an agent's decision — joinable *after the fact* by coordinate, across
  organizations that have never heard of each other. Pattern mining over independent signed sources, no shared
  platform required.
- **Containment is literal string prefixing.** A second nests in its minute, the minute in its hour:
  `ust:20260710.14` ⊃ `ust:20260710.1429` ⊃ `ust:20260710.142900`. Roll-ups and drill-downs are prefix scans;
  a parent frame can *attest* its children (attestation + Merkle root over their content hashes), so "the hour"
  becomes a signed aggregate of its seconds — provably complete over a closed range (`verifyStream`).
- **Sortable = streamable.** Fixed-width UTC fields sort lexicographically in time order; a time range is a
  string range. Storage keys, feeds and archives inherit chronology for free.

Honesty holds on this axis too: at LIGHT the coordinate is the publisher's **claimed** frame; a TOP anchor
proves the document existed **by** a real point in time (and `generated_at` may not postdate its own anchor).

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
- For the precise semantics of *what a verdict means*, read the **formal model**
  ([`spec/UST-1.0-formal-model.md`](spec/UST-1.0-formal-model.md), non-normative): verification is a
  **measurability test** — the three tiers are three nested σ-algebras (`𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP`), a verdict
  names the finest tier decidable from your information set, `INDETERMINATE` means the needed σ-algebra is not
  in it, and two conforming verifiers agree because the verdict is a total deterministic function of the §14a
  obligations table. If you reason about UST beyond running the verifier, reason from there — not from analogy
  to JWT, JWS, or blockchain receipts.

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
