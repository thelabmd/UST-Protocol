<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Universal State Transcript → UST Protocol → UST

[![CI](https://img.shields.io/github/actions/workflow/status/thelabmd/UST-Protocol/ci.yml?branch=main&label=CI)](https://github.com/thelabmd/UST-Protocol/actions) [![conformance](https://img.shields.io/badge/conformance-615%20checks%20%C2%B7%20136%20vectors%20%C2%B7%204007%20fuzz-brightgreen)](https://github.com/thelabmd/UST-Protocol/actions/workflows/ci.yml)
[![code license](https://img.shields.io/badge/code-Apache--2.0-blue)](./LICENSE)
[![docs license](https://img.shields.io/badge/docs-CC--BY--4.0-blue)](./LICENSE-SPEC)
[![ust-protocol](https://img.shields.io/npm/v/ust-protocol?label=ust-protocol)](https://www.npmjs.com/package/ust-protocol) [![pulls](https://img.shields.io/npm/dt/ust-protocol?label=pulls&color=informational)](https://www.npmjs.com/package/ust-protocol)
[![@ust-protocol/mcp](https://img.shields.io/npm/v/@ust-protocol/mcp?label=@ust-protocol/mcp)](https://www.npmjs.com/package/@ust-protocol/mcp) [![pulls](https://img.shields.io/npm/dt/@ust-protocol/mcp?label=pulls&color=informational)](https://www.npmjs.com/package/@ust-protocol/mcp)
[![@ust-protocol/cli](https://img.shields.io/npm/v/@ust-protocol/cli?label=@ust-protocol/cli)](https://www.npmjs.com/package/@ust-protocol/cli) [![pulls](https://img.shields.io/npm/dt/@ust-protocol/cli?label=pulls&color=informational)](https://www.npmjs.com/package/@ust-protocol/cli)

![UST status: `1.0.0-rc.36` — a release candidate, not a final 1.0. Verify machine-readable state without trusting whoever handed it to you. Multiple external AI reviews incorporated structurally; an independent human cryptographic audit is pending; suitable for evaluation and integration testing. The wire format ust:"1.0" is stable across all release candidates; pin exact versions.](.github/status.svg)

> **Status: `1.0.0-rc.36`** — a release candidate, not a final 1.0. External AI reviews are folded in structurally; an independent human cryptographic audit is pending. Suitable for evaluation and integration testing. The wire format `ust:"1.0"` is stable across all rc's — pin exact versions. *(This line mirrors the panel above as plain text, for readers and agents that don't render the image.)*

## ●  Thirty seconds

*"Yet another JSON format?"* — yes and no, and both answers are good news.

**Yes.** A transcript is ordinary JSON — on purpose. Reading one needs no
library, no crypto, no new concepts, and there is nothing to adopt:

```js
const doc = await fetch(url).then(r => r.json());
doc.state.data.capture.value      // ← the data. That is the whole consumer floor.
```

**No.** The same bytes carry what neither plain JSON nor a signed envelope
gives you — verification is your right, not your duty. The day you need to —

- **ground an agent** — let it *check* its inputs instead of trusting a paste,
  and stop hallucinated "facts" at the door;
- **join sources by moment** — every transcript sits on one shared UTC axis
  (`ust:20260710.142900`), so readings from publishers that have never heard of
  each other line up into a signed cross-section of the same moment, joinable
  after the fact;
- **chain states** — documents link by content hash (`based_on`), so a
  derivation, a stream, a hand-off to another organization stays one walkable
  lineage, each link signed by its own author under its own key;
- **carry layers of visibility in one state** — the same chain holds open
  values, blinded commitments and encrypted parts: publish the fact now, reveal
  the value when you choose, provably unchanged — priority without disclosure;
- **prove precedence** — the data existed *by* that point in time, and the
  decision was made on it, not backdated after the outcome;
- **hold someone accountable** — every value is signed: you know *whose*
  reading it was and that nobody, the publisher included, has rewritten it since;
- **answer an audit, a claim, a post-mortem** — replay exactly what was known
  at that moment, and show how strongly it is proven (`VALID:LIGHT → HIGH → TOP`);

— all of that is **already inside every transcript you have been reading as
plain JSON**. Nothing to retrofit. One line switches it on:

```js
import { verify } from 'ust-protocol';
verify(doc, { context: 'data' }).result   // → VALID:LIGHT / HIGH / TOP
// don't hash the JSON yourself — hashes are domain-separated; the library canonicalizes
```

Or skip even that line: paste [any transcript](https://raw.githubusercontent.com/thelabmd/UST-Protocol/refs/heads/main/examples/ust-sample.json) into the [web verifier](https://thelabmd.github.io/UST-Protocol/) —
client-side, nothing is uploaded.

## ●  Verify one right now

The fastest way to understand UST is to verify one — no install, no account, 60 seconds. Grab a ready sample
([`examples/ust-sample.json`](examples/ust-sample.json)), open the verifier, paste it, read the verdict — `VALID:LIGHT`
for a bare signed document, climbing to `HIGH`/`TOP` as the publisher adds name-binding and an anchor. Always run the
canonical reference — never eyeball:

- **Browser (nothing is uploaded):** [thelabmd.github.io/UST-Protocol](https://thelabmd.github.io/UST-Protocol/) — paste the blob, the base64, or the JSON. A bare signed document (like the sample) reads `VALID:LIGHT`; when its publisher also serves the standard name-binding surfaces, resolution + witness (Rekor and Bitcoin checked natively) climb it to `VALID:HIGH` automatically.
- **Node:** `npm i ust-protocol` → `verify(doc, { context: 'data' })` gives the `VALID:LIGHT` floor; `resolveByDiscovery(doc)` climbs to `VALID:HIGH` when the publisher serves discovery.
- **Zero-dependency single files:** [`docs/ust-verify.mjs`](docs/ust-verify.mjs) (the LIGHT floor) + [`docs/ust-resolve.mjs`](docs/ust-resolve.mjs) (authority resolution + witness) — WebCrypto, clean-room, cross-checked against `ust-protocol`; fetch them from **this** repository, never from a sender's message.
- **MCP:** [`@ust-protocol/mcp`](https://www.npmjs.com/package/@ust-protocol/mcp) exposes `ust_verify` to agents.

### If you are an AI agent

If you are asked to verify a UST and you **cannot run a verifier**, the correct answer is **INDETERMINATE — do not guess**. In particular:

- Do **not** compute a plain `SHA-256(text)` and compare it to `hashes.*` — every UST hash is **domain-separated** (`H(tag, canon(...))` with a tag prefix). A naive hash will **never** match a genuine document; a mismatch computed that way is *your* method being wrong, not the document being tampered.
- UST 1.0 has **no expiry rule**. `valid_from == valid_to` is an honest **instant** (a point capture), not "expired." Freshness is not part of `verify`.
- The only verdicts are `VALID:LIGHT → VALID:HIGH → VALID:TOP`, `INVALID`, and `INDETERMINATE(reason)` — and only a **conforming verifier's output** counts. Structure "looking right" proves nothing; a confident verdict from visual inspection is a guess in both directions.
- For the precise semantics of *what a verdict means*, read the **formal model**
  ([`spec/UST-1.0-formal-model.md`](spec/UST-1.0-formal-model.md), non-normative): verification is a
  **measurability test** — the three tiers are three nested σ-algebras (`𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP`), a verdict
  names the finest tier decidable from your information set, `INDETERMINATE` means the needed σ-algebra is not
  in it, and two conforming verifiers agree because the verdict is a total deterministic function of the §14a
  obligations table. If you reason about UST beyond running the verifier, reason from there — not from analogy
  to JWT, JWS, or blockchain receipts.

## ●  What this is

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

![Anatomy of a UST transcript — a self-contained signed JSON document. Its id says WHO (domain_shard: a name or a self-certifying key-id) and WHEN (ust_id: an address on one shared UTC axis), plus key_id and class. A time frame carries generated_at, valid_from and valid_to. The data holds partitions (captured, computed, blinded or encrypted); one domain-separated hash per partition binds the data to the id and frame. Provenance (based_on, prev, seed) links chains, streams and derivations. An Ed25519 signature travels WITH the data, not the channel. Seal at creation, store anywhere, verify offline in one call — no blockchain; TLS secures the pipe, UST secures the payload, so it verifies the same from a cache, mirror, file or chat paste.](.github/ust-anatomy.svg)

## ●  The time coordinate — `ust_id`

Before anything else, a UST is an address on **one shared time axis**. Every transcript carries a frame id,
`ust:YYYYMMDD.HH[MM[SS]]` (UTC): `ust:20260710.14` is an hour frame, `ust:20260710.1429` a minute,
`ust:20260710.142900` a second. This is not metadata — it is part of the document's *identity*, and the
per-partition hashes **bind** it: a signed value cannot be replayed into another hour or re-attributed to
another frame.

![One shared time axis — every transcript carries a frame id ust:YYYYMMDD.HH(MM(SS)) in UTC. The hour ust:20260710.14 contains the minute ust:20260710.1429 contains the second ust:20260710.142900: containment is literal string prefixing, so roll-ups are prefix scans and sortable equals streamable. Because every publisher shares the grid by construction, “what was the world doing at 14:29Z?” is a query, not a metaphor — the same coordinate from unrelated publishers means the same moment, joinable after the fact.](.github/ust-time.svg)

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

## ●  What is a real truth in an agent world?

In an agent world nobody can hand you truth as a boolean. The closest thing to truth an agent can actually *hold* is
**earned confidence** — made of two honest quantities: how much evidence the publisher **staked** (a signature; a name
provably bound to the key; an anchor in real time), and how much of it the verifier could actually **confirm**, here and
now. Not one flattering "yes" — a measured answer to *"how strongly is this proven, to me, at this moment?"*

![The verdict ladder — trust is graduated and the verdict carries its tier; a conforming verifier never says a bare VALID. VALID:LIGHT is the floor: exact bytes, the signing key and the claimed time frame (a key, canonical form and a signature — no infrastructure, no fees). VALID:HIGH adds that the NAME is provably bound to the key (a genesis + key-log ceremony, rotation and revocation; strength corroborated or authoritative). VALID:TOP adds that the document existed BY a real point in time (an anchor inclusion proof — Bitcoin/OTS or Rekor, opt-in; stream completeness is a separate range verdict). INVALID is a definite failure (an E-* code); INDETERMINATE means cannot decide — never conflated with forged. A tier is EARNED per verification: there is no field a producer can set to claim it.](.github/ust-tiers.svg)

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

## ●  Chains and layered shards — one state, graduated visibility

The part that makes UST more than "signed JSON": a single connected state does not have to be one document.
It can be a **chain of independently signed layers**, each a full transcript with its own key, time frame and
provenance — linked by content hashes (`based_on` + a recomputed `seed`), so the **existence, order and lineage
of every layer are publicly provable while each layer's content is disclosed only to whom it is meant for**:

![One state, graduated visibility — a single connected state can be a hash-linked chain of independently signed layers. L1 is a public observation anyone verifies. L2 is a blinded commitment: the value is fixed but hidden until reveal, while its existence is public. L3 is an encrypted shard: AEAD ciphertext plus a commitment, so only key holders read and verify it. L4 is a partner’s derived shard under another publisher’s own key — cross-party, provable lineage. Each layer links to the prior by based_on = sha256(content) plus a recomputed seed, so order and lineage are publicly provable. Every layer verifies on its own; trust composes but is never inherited; payloads stay deletable while “existed, in this order” remains provable.](.github/ust-chain.svg)

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

## ●  Glue, by design

UST is not a silver bullet, and it does not replace anything you run — not your
telemetry, not your signing, not your lineage, not your logs. Each of those tools
does its job well. What none of them defines is a **portable object of state**
that travels *between* them and stays verifiable wherever it lands. That object
is what UST standardizes. The only thing it replaces is the glue code you would
otherwise write yourself.

| you already run | it keeps doing | a transcript adds |
|---|---|---|
| JWS / DSSE | signing any payload | a standard shape for the payload itself: id, time, partitions, provenance, tiers |
| Sigstore / Rekor | keyless signing, transparency log | a Rekor receipt slots in as anchor evidence — the same document, stronger time |
| in-toto / SLSA | build policy & provenance | an SLSA statement rides in a partition; `based_on` links it to its inputs |
| IETF SCITT | registries & receipts | a UST is a ready signed-statement payload; the receipt strengthens the same doc |
| C2PA | media provenance | the machine state *around* the shot — camera, sensors, model, decision — sealed next to it |
| W3C Verifiable Credentials | who the actor is, what they may do | what the actor *observed, computed or did* at `t` — VC certifies the actor, UST fixes the act |
| OpenLineage | dataset/job/run semantics | each run event becomes a signed, portable lineage node — verifiable without the backend |
| OpenTelemetry + SIEM | mass telemetry, search, alerting | the few checkpoints you must *prove* get sealed as transcripts; the rest stays telemetry |
| CloudTrail + Object Lock | managed audit & retention | seal **at the source** — the document stays provable outside the origin cloud |
| IPFS + OpenTimestamps | content addressing, proof-of-existence | one object that carries the address, the time, the signer and the verdict together |

The glue this replaces — what a comparable assembly looks like written by hand:

```
app schema + signing envelope + custom canonicalization + key-rotation DB
  + provenance graph + timestamping + WORM store + commitment conventions
  + custom verifier + custom trust semantics
```

With UST:

```
UST transcript + key custody of your choice
  (+ optional discovery, + optional anchor, + optional storage of your choice)
```

If you need exactly one of those jobs, use that tool alone — you may not need
UST at all. UST earns its place the moment state has to cross a **boundary** —
between tools, between organizations, between clouds, or across time — and
still prove itself on the other side.

> Tools sign files, log events, timestamp hashes, record lineage.
> **A UST carries the state between them — portable, layered, verifiable on arrival.**

## ●  Build with it

Produce and verify a LIGHT transcript — a signer, a frame, one `verify` call:

```js
import { generateSigner, signObservation, nowFrame } from '@ust-protocol/web-signer';
import { verify } from 'ust-protocol';
const s = await generateSigner();                              // Ed25519, non-extractable
const { ust_id, time } = nowFrame();                           // instant capture frame
const doc = await signObservation(s, { ust_id, time, data: { capture: { kind: 'captured', value: { text: 'exact bytes' } } } });
console.log(verify(doc, { context: 'data' }).result);          // → VALID:LIGHT
```

Working on the protocol itself? `npm install && npm test` runs the conformance suite (spec == package == vectors) —
see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## ●  The `ust` CLI

![The ust CLI — one entrypoint, the whole command surface (parsed from the real binary’s help). Install with npm i -g @ust-protocol/cli. The 10 subcommands: verify <file|-> (verify a transcript (exit 0 = VALID, 1 = not; --require-anchored floors at TOP)); canon <file|-> (print canonical bytes + hash (cross-language diff)); genesis --domain <d> (run the HIGH genesis ceremony (add --publish cf for one-click serving)); rotate --domain <d> --root <enc> (APPEND a key rotation to the served log (never re-mint; old docs stay valid)); discovery <domain> (attest the §20.1 serving contract (any infra)); publish cf --domain <d> --genesis <f> (deploy the CF serving adapter for an existing genesis); mirror <domain> (publish + attest a SECOND-vendor mirror (§20.1 vendor-independence)); stream <frames…> (RANGE verdict: chain · forks · completeness (needs --checkpoint for proven)); forkchoice <docs…> (pick the CANONICAL doc among candidates for ONE ust_id (canonical = anchor-included)); witness rekor --domain <d> (log the genesis in a transparency log → automatic no-fork (#68)). Exit 0 = VALID with the tier in the verdict, 1 = not; the ceremony self-verifies its outputs, fail-closed.](.github/ust-cli.svg)

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

## ●  What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged.* It does
**not** prove the data is *correct* — a publisher can sign a wrong reading. You learn **whom to hold accountable**
and **that nothing was tampered** — a real, bounded guarantee, not an oracle of truth.

The precise semantics of every verdict — verification as a measurability test over three nested σ-algebras —
is the **formal model**: [`spec/UST-1.0-formal-model.md`](spec/UST-1.0-formal-model.md) (non-normative).

## ●  Stability of assurance tiers

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

## ●  Layout

![Repository map. spec/ holds the normative UST-1.0.md plus a measure-theoretic formal model. vectors/ holds language-neutral conformance vectors and a byte corpus — the cross-implementation arbiter. packages/ holds ust-protocol (the zero-dep reference verifier + producer), ust-cli (the ust command: verify, canon, the HIGH genesis ceremony, witness), ust-mcp (an MCP server so agents verify natively), ust-lite (a byte-identical minimal subset), ust-web-signer (WebCrypto browser signing with non-extractable keys), and ust-ots-verify / ust-rekor-verify (opt-in Bitcoin/OTS and Sigstore Rekor anchor substrates). docs/ is the client-side web verifier plus zero-dependency single-file verifiers. tools/ are the drift gates that keep spec = code = vectors = README = these panels in sync.](.github/ust-map.svg)

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

## ●  License

**Code: Apache-2.0.** **Specification text: CC BY 4.0.** Source code (`packages/**`, tooling) is licensed under
the Apache License 2.0 (`LICENSE`); the specification and documentation prose (`spec/**` and other `.md` docs)
under Creative Commons Attribution 4.0 International (`LICENSE-SPEC`). The names *UST* / *Universal State
Transcript* and the *UST-compatible* claim: see [`TRADEMARK.md`](TRADEMARK.md). How changes are made:
[`GOVERNANCE.md`](GOVERNANCE.md).

© 2026 THE LAB
