<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Universal State Transcript | UST Protocol | UST

[![CI](https://img.shields.io/github/actions/workflow/status/thelabmd/UST-Protocol/ci.yml?branch=main&label=CI)](https://github.com/thelabmd/UST-Protocol/actions)
[![code license](https://img.shields.io/badge/code-Apache--2.0-blue)](./LICENSE)
[![docs license](https://img.shields.io/badge/docs-CC--BY--4.0-blue)](./LICENSE-SPEC)
[![ust-protocol](https://img.shields.io/npm/v/ust-protocol?label=ust-protocol)](https://www.npmjs.com/package/ust-protocol) [![pulls](https://img.shields.io/npm/dt/ust-protocol?label=pulls&color=informational)](https://www.npmjs.com/package/ust-protocol)
[![@ust-protocol/mcp](https://img.shields.io/npm/v/@ust-protocol/mcp?label=@ust-protocol/mcp)](https://www.npmjs.com/package/@ust-protocol/mcp) [![pulls](https://img.shields.io/npm/dt/@ust-protocol/mcp?label=pulls&color=informational)](https://www.npmjs.com/package/@ust-protocol/mcp)
[![@ust-protocol/cli](https://img.shields.io/npm/v/@ust-protocol/cli?label=@ust-protocol/cli)](https://www.npmjs.com/package/@ust-protocol/cli) [![pulls](https://img.shields.io/npm/dt/@ust-protocol/cli?label=pulls&color=informational)](https://www.npmjs.com/package/@ust-protocol/cli)

![UST status: `1.0.0-rc.36` — a release candidate, not a final 1.0. Verify machine-readable state without trusting whoever handed it to you. Multiple external AI reviews incorporated structurally; an independent human cryptographic audit is pending; suitable for evaluation and integration testing. The wire format ust:"1.0" is stable across rc's; pin exact versions.](.github/status.svg)

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

![Anatomy of a UST transcript — a self-contained signed JSON document: id (who + when), time frame, data partitions, domain-separated hashes, provenance links, Ed25519 signature. Seal at creation, store anywhere, verify offline.](.github/ust-anatomy.svg)

## The time coordinate — `ust_id`

Before anything else, a UST is an address on **one shared time axis**. Every transcript carries a frame id,
`ust:YYYYMMDD.HH[MM[SS]]` (UTC): `ust:20260710.14` is an hour frame, `ust:20260710.1429` a minute,
`ust:20260710.142900` a second. This is not metadata — it is part of the document's *identity*, and the
per-partition hashes **bind** it: a signed value cannot be replayed into another hour or re-attributed to
another frame.

![One time axis — ust:20260710.14 (hour) contains ust:20260710.1429 (minute) contains ust:20260710.142900 (second): containment is literal string prefixing, sortable equals streamable, one shared UTC grid for every publisher.](.github/ust-time.svg)

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

## What is a real truth in an agent world?

Trust is **graduated, and the verdict carries its tier** — a conforming verifier never says a bare `VALID`:

![The verdict ladder — VALID:LIGHT (key + canonical form + signature), VALID:HIGH (+ name provably bound to the key), VALID:TOP (+ existed by a real point in time). INVALID is a definite failure; INDETERMINATE is never conflated with forged; a tier is earned, no header claims it.](.github/ust-tiers.svg)

| verdict | what is proven |
|---|---|
| `VALID:LIGHT` | the exact bytes · the signing key · the claimed time frame. Identity is the key itself (a self-certifying `sha256:` shard) or a *claimed* name — never a verified name. |
| `VALID:HIGH` | + the publisher's **name** is provably bound to the key (genesis + key log). The reference verifiers collect this automatically from the standard surfaces (§20.1/§12.1a). Strength `corroborated` — the publisher's own witness shows no rival — or `authoritative` — **independent** non-membership (an anchored name-map inclusion, or a caller air-gap assertion); only `authoritative` names the definitive `publisher` and reaches TOP. |
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

![One state, graduated visibility — a hash-linked chain of independently signed layers: L1 public observation (anyone verifies), L2 blinded commitment (existence public, value hidden), L3 encrypted shard (key holders read and verify), L4 a partner's derived shard (cross-party provable lineage).](.github/ust-chain.svg)

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

## Layout

![Repository map — spec (normative + formal model), vectors (the cross-implementation arbiter), packages (reference verifier, CLI, MCP server, lite, web signer, anchor substrates), docs (web verifier), tools (drift gates).](.github/ust-map.svg)

| Path | What |
|------|------|
| `spec/UST-1.0.md` | the specification (normative) |
| `spec/UST-1.0-formal-model.md` | a measure-theoretic semantics (non-normative appendix) |
| `PORTING.md` | porting UST to another language — the narrowed value model, the vector arbiter, the crypto boundary |
| `vectors/` | deterministic conformance vectors — any implementation should pass them (the cross-language canon arbiter) |
| `packages/ust-protocol/` | the stateless reference verifier + producer ([npm](https://www.npmjs.com/package/ust-protocol)) |
| `packages/ust-mcp/` | an MCP server exposing UST to agents ([npm](https://www.npmjs.com/package/@ust-protocol/mcp)) |
| `packages/ust-web-signer/` | WebCrypto browser signer ([npm](https://www.npmjs.com/package/@ust-protocol/web-signer)) |
| `packages/ust-cli/` | the `ust` command — verify / canon / the HIGH genesis ceremony / witness ([npm](https://www.npmjs.com/package/@ust-protocol/cli)) |
| `packages/ust-ots-verify/` | opt-in Bitcoin (OpenTimestamps) anchor-substrate plugin ([npm](https://www.npmjs.com/package/@ust-protocol/ots-verify)) |
| `packages/ust-rekor-verify/` | opt-in Sigstore Rekor anchor-substrate plugin ([npm](https://www.npmjs.com/package/@ust-protocol/rekor-verify)) |
| `extension/` | "Make it UST" — a demo Chrome extension: sign by selection, verify by selection (LIGHT) |
| `docs/` | the [web verifier](https://thelabmd.github.io/UST-Protocol/) (client-side, GitHub Pages) + `ust-verify.mjs`, a zero-dependency verifier + `llms.txt` |
| `examples/` | sample documents (valid + tampered) and verification recipes |

## Quickstart

```
npm install
npm test          # the conformance runner: 130 checks; asserts spec == package == vectors version
```

Produce and verify a LIGHT transcript:

```js
import { generateSigner, signObservation, nowFrame } from '@ust-protocol/web-signer';
import { verify } from 'ust-protocol';
const s = await generateSigner();                              // Ed25519, non-extractable
const { ust_id, time } = nowFrame();                           // instant capture frame
const doc = await signObservation(s, { ust_id, time, data: { capture: { kind: 'captured', value: { text: 'exact bytes' } } } });
console.log(verify(doc, { context: 'data' }).result);          // → VALID:LIGHT
```

## The `ust` CLI

![The ust CLI — the full command surface parsed from the real binary's help: verify, canon, genesis, rotate, discovery, publish, mirror, stream, forkchoice, witness. Exit 0 = VALID with the tier in the verdict, 1 = not.](.github/ust-cli.svg)

```bash
npm i -g @ust-protocol/cli    # installs the `ust` command
ust verify doc.json           # exit 0 = VALID (tier in the verdict), 1 = not; auto-detects genesis/key context
                              #   auto-resolves discovery + witness → VALID:HIGH out of the box (no-fork as EVIDENCE)
ust canon  doc.json           # canonical bytes + hash — diff any other-language implementation against this
ust genesis --domain example.org --profile silver --dns cf-api   # the HIGH name-binding ceremony
ust witness rekor --domain example.org --deploy                  # log the genesis to Sigstore Rekor + serve the witness
```

One entrypoint; the planned Go binary reproduces this exact surface. The ceremony self-verifies its outputs
(fail-closed) and upserts the `_ust` DNS TXT with a DNS-over-HTTPS readback. Witness anchors are cross-checked
against their substrate (Bitcoin via `@ust-protocol/ots-verify`, Rekor via `@ust-protocol/rekor-verify` —
opt-in plugins; the core verifier embeds no blockchain).

## How to verify a UST

Run the canonical reference — never eyeball:

- **Browser (nothing is uploaded):** [thelabmd.github.io/UST-Protocol](https://thelabmd.github.io/UST-Protocol/) — paste the blob, the base64, or the JSON. Resolution + witness run automatically (Rekor and Bitcoin checked natively) — a publisher serving the standard surfaces reaches `VALID:HIGH` with zero clicks.
- **Node:** `npm i ust-protocol` → `verify(doc, { context: 'data' })`; automatic HIGH via `resolveByDiscovery(doc)`.
- **Zero-dependency single files:** [`docs/ust-verify.mjs`](docs/ust-verify.mjs) (the LIGHT floor) + [`docs/ust-resolve.mjs`](docs/ust-resolve.mjs) (authority resolution + witness) — WebCrypto, clean-room, cross-checked against `ust-protocol`; fetch them from **this** repository, never from a sender's message.
- **MCP:** [`@ust-protocol/mcp`](https://www.npmjs.com/package/@ust-protocol/mcp) exposes `ust_verify` to agents.

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

The precise semantics of every verdict — verification as a measurability test over three nested σ-algebras —
is the **formal model**: [`spec/UST-1.0-formal-model.md`](spec/UST-1.0-formal-model.md) (non-normative).

## Stability of assurance tiers

Not every rung is equally settled. The `STABILITY` export is the machine-readable map:

| tier / rung | status |
|---|---|
| `LIGHT`, `HIGH` | **stable** — three independent adversarial audit rounds left them intact |
| `corroborated` freshness | experimental-usable |
| `attested` freshness | **experimental extension** — the STABLE verifier does not emit it |

`attested` (independent anti-equivocation over a checkpoint) is being re-based on a closed verification kernel
(mandatory append-only consistency proof, scope-bound pinning, one shared node/browser core). Until those ship
gates pass, `deriveCheckpointFreshness` caps a would-be `attested` result at `corroborated` and names the withheld
rung (`attested_withheld: "experimental-gate"`); the top rung is reachable only with an explicit
`allowExperimentalAttested: true` opt-in. This keeps the whole protocol from inheriting the youngest layer's risk.

## License

**Code: Apache-2.0.** **Specification text: CC BY 4.0.** Source code (`packages/**`, tooling) is licensed under
the Apache License 2.0 (`LICENSE`); the specification and documentation prose (`spec/**` and other `.md` docs)
under Creative Commons Attribution 4.0 International (`LICENSE-SPEC`). The names *UST* / *Universal State
Transcript* and the *UST-compatible* claim: see [`TRADEMARK.md`](TRADEMARK.md). How changes are made:
[`GOVERNANCE.md`](GOVERNANCE.md).

© 2026 THE LAB
