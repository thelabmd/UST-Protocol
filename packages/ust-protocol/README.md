<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the reference implementation

**Verify machine-readable state without trusting whoever handed it to you.**

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same no matter how it reached you (a cache, a
mirror, another agent, a file on disk). TLS secures the pipe; **UST secures the payload**, and the guarantee
travels *with* the data.

`ust-protocol` is the stateless reference base: canonical hashing (JCS), Ed25519 signing, three-tier
verification, privacy commitments, chains, and anchoring. Zero-dependency (`node:crypto`; a WebCrypto/`@noble`
adapter for browsers and Workers — same rules, same results).

> **Release candidate.** The wire format `ust:"1.0"` is stable across all rc's; this package pins its own rc on npm — pin exact versions. Extensively
> red-teamed; multiple external AI reviews folded in structurally; an independent human cryptographic audit is
> pending. Suitable for evaluation and integration testing. Pin exact versions.

## Install

```
npm i ust-protocol@rc
```

## Verify a document

```js
import { verify } from 'ust-protocol';

const r = verify(doc);
// { result: 'VALID:LIGHT'|'VALID:HIGH'|'VALID:TOP' | 'INVALID' | 'INDETERMINATE', tier, identity, time, publisher_claimed|publisher, content_hash, ... }
// The verdict CARRIES ITS TIER — a bare 'VALID' is never emitted. Test with isValid(r), not r.result === 'VALID'.
```

- **`VALID`** — well-formed, hashes match the data, signature checks out: the document **is** what the publisher
  committed to, unchanged.
- **`INVALID`** — a check failed (tampering, bad signature, malformed) — with an `error` code.
- **`INDETERMINATE`** — something needed for a higher tier was *unavailable* (not a failure; retry).

## Run it end to end — copy this file and it works

```js
// runnable: node this file. No network, no keys to obtain — it makes its own.
import { verify, isValid, contentHash } from 'ust-protocol';
import { generateSigner, signObservation, nowFrame } from '@ust-protocol/web-signer';

const signer = await generateSigner();                       // Ed25519, private key stays in WebCrypto
const { ust_id, time } = nowFrame();
const doc = await signObservation(signer, {
  ust_id, time,
  data: { reading: { kind: 'captured', value: { temp_c: '21.4' } } },   // string-only leaves, verbatim
});

const v = verify(doc);
console.log(v.result, isValid(v), contentHash(doc).slice(0, 20) + '…');   // VALID:LIGHT true sha256:…

doc.state.data.reading.value.temp_c = '99.9';                 // tamper with one leaf
console.log(verify(doc).result, verify(doc).error);           // INVALID E-CANON
```

Identity here is the KEY, not a name — `domain_shard` is the signer's own `key_id`, so nothing is claimed that
cannot be checked from the document alone. That is the LIGHT tier being honest about its own reach.


## Mint a trust chain and reach VALID:HIGH — also runnable

```js
// runnable: node this file. Builds a genesis, a key-log, and a document that resolves to VALID:HIGH.
import { buildGenesis, buildKeyLogEntry, buildState, verify, resolveKeys, contentHash } from 'ust-protocol';
import { generateSigner, seal } from '@ust-protocol/web-signer';

const T = { generated_at: '2026-07-30T12:00:00Z', valid_from: '2026-07-30T12:00:00Z', valid_to: '2026-07-30T12:00:00Z' };
const DOMAIN = 'example.com';
const root = await generateSigner();      // the crown — signs the genesis and the key log, nothing else
const op   = await generateSigner();      // the operational key — signs your documents

// 1. the genesis binds the NAME to the root key
const genesis = await seal(buildGenesis(
  { domain_shard: DOMAIN, ust_id: 'ust:20260730.12', key_id: root.key_id, class: 'genesis' },
  T, root.pub, 512), root);

// 2. the key log ADDS the operational key, signed by the root, chained to the genesis
const keylog = [await seal(buildKeyLogEntry(
  { domain_shard: DOMAIN, ust_id: 'ust:20260730.12', key_id: root.key_id },
  T, { op: 'add', pub: op.pub }, contentHash(genesis)), root)];

console.log(resolveKeys(genesis, keylog).active.size);   // 2 — root and operational. NOTE: a Map, not an object

// 3. a document that CLAIMS the name, signed by the operational key
const doc = await seal(buildState(
  { domain_shard: DOMAIN, ust_id: 'ust:20260730.12', key_id: op.key_id, class: 'observation' },
  T, { reading: { kind: 'captured', value: { temp_c: '21.4' } } }), op);

console.log(verify(doc, { genesis, keylog }).result);    // INDETERMINATE — no no-fork evidence yet
console.log(verify(doc, { genesis, keylog, noForkConfirmed: true, acceptConsumerOverride: true }).result);  // VALID:HIGH
```

**Why the last two lines differ, and why that is the point.** `noForkConfirmed` is the CALLER asserting there is no
rival genesis — an air-gap assertion. It does not grant itself force: the consumer must also `acceptConsumerOverride`,
because independence is the consumer's property, never the publisher's claim. Without either, a name claim the
verifier cannot confirm is `INDETERMINATE` — *unavailable*, not *false*. In production you supply real no-fork
evidence (a witness log, an anchored name-map) and the same document reaches HIGH without any override.

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged.* It does
**not** prove the data is *correct* — a publisher can sign a wrong reading. You learn **whom to hold accountable**
and **that nothing was tampered** — a real, bounded guarantee, not an oracle of truth.

## Trust tiers — same document, more trust as you bring more

| Tier | You also supply | You learn |
|------|-----------------|-----------|
| **LIGHT** | nothing (the document alone) | integrity + a *claimed* publisher (`self-asserted`) |
| **HIGH** | the publisher's genesis + key-log (+ witness) | the key is *provably bound* to the publisher's name. Strength `corroborated` (the publisher's own witness shows no rival) or `authoritative` (**independent** non-membership: an anchored name-map inclusion, or a caller air-gap assertion) — only `authoritative` surfaces the definitive `publisher` and reaches TOP |
| **TOP** | an anchor proof | the document provably existed by a point in time (a stream range is `chain-consistent` — no-deletion; full `complete` needs the signed-cadence grid) |

```js
// HIGH — resolve name authority
verify(doc, { genesis, keylog, noForkConfirmed: true, requireAuthoritative: true });

// TOP — verify a time-anchor's inclusion proof (substrate confirmation is delegated to the caller)
import { verifyAnchor } from 'ust-protocol';
verifyAnchor(content_hash, proof);
```

## Automatic HIGH — resolution + witness (the document brings its own name)

A document carries its own `domain_shard`. `resolveByDiscovery` fetches that publisher's discovery pair
(`/.well-known/ust-genesis` + `ust-keylog`) and its **witness** (`/.well-known/ust-witness`), resolves the
chain, and re-verifies with the capacity grant — so **HIGH is automatic**, not an expert dance:

```js
import { resolveByDiscovery, combineSubstrates } from 'ust-protocol';
import { substrateVerify as ots }   from '@ust-protocol/ots-verify';    // Bitcoin (opt-in)
import { substrateVerify as rekor } from '@ust-protocol/rekor-verify';  // Sigstore Rekor (opt-in)

const { verdict, resolution } = await resolveByDiscovery(doc, { context: 'data' },
  { substrateVerify: combineSubstrates([ots, rekor]) });
// verdict.result === 'VALID:HIGH', identity.strength === 'corroborated' when the publisher's witness shows one
// anchored active genesis. That is CORROBORATION, not independent no-fork: the publisher could omit a rival from
// its own list, so `authoritative` needs an INDEPENDENT anchored name-map (or an air-gap noForkConfirmed:true).
// resolution.noFork = 'served-list (corroborated)' | 'caller-asserted (authoritative)' | 'HIGH pending — …'.
```

- **corroborated ≠ authoritative** (§12.1a, formal model F.5a): a served witness proves *membership* (this
  genesis is anchored), never *non-membership* (no rival exists). The honest verdict is `corroborated`;
  `authoritative` requires independent non-membership. The witness anchor is still cross-checked against its substrate
  (Bitcoin via `@ust-protocol/ots-verify`, Rekor via `@ust-protocol/rekor-verify`) — the endpoint is only an
  index, the anchor is the independent truth. Two anchored genesis roots ⇒ `E-GENESIS` (fork).
- **the verifier embeds no blockchain.** Substrate checks are an *injection* (`combineSubstrates` routes by
  substrate; an unknown one ⇒ `INDETERMINATE`, never a faked HIGH). Zero-dep core stays portable.
- **SSRF-guarded**: `isPublicDnsShard` runs before any discovery fetch — an untrusted document cannot point
  the verifier at an internal address.
- untrusted bytes go through `verifyJson(raw)` (duplicate-key + admission checks *before* parse), never
  `JSON.parse` → `verify`.

## Create

```js
import { buildState, seal } from 'ust-protocol';

const state = buildState(
  { domain_shard: 'example.com', ust_id: 'ust:20260705.15', key_id, class: 'observation' },
  { generated_at, valid_from, valid_to },
  { reading: { kind: 'captured', value: { temp_c: '21.4' } } }   // string-only leaves, verbatim
);
const doc = seal(state, privateKey, publicKeyB64url);
```

Also: `buildAttestation` (Merkle root over constituents), `buildDerivation` (based-on + seed), `buildGenesis`,
`buildKeyLogEntry`, `buildCheckpoint`, `blindPartition` (privacy commitments). `resolveAuthority` and
`verifyStream` cover HIGH name-authority and TOP completeness.

## Design in one paragraph

Every value is a **string** (numbers stay verbatim — no float drift). Documents are **canonicalized** (JCS,
tightened) before hashing, so the same state always yields the same bytes. Hashing is **domain-separated**; the
`content_hash` is a unique descriptor of the whole document. Signatures use **strict** Ed25519 (non-canonical `S`
rejected). Verification is **fail-closed** and returns one of three honest outcomes — availability is never
confused with failure.

## Spec & conformance

- Specification and a client-side verifier: **https://github.com/thelabmd/UST-Protocol/blob/main/spec/UST-1.0.md**
- This library is validated against a suite of deterministic conformance vectors (the same vectors any
  independent implementation should pass).

## License

Apache-2.0 · © 2026 THE LAB
