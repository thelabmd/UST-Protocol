# ust-protocol

**Verify machine-readable state without trusting whoever handed it to you.**

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same no matter how it reached you (a cache, a
mirror, another agent, a file on disk). TLS secures the pipe; **UST secures the payload**, and the guarantee
travels *with* the data.

`ust-protocol` is the stateless reference base: canonical hashing (JCS), Ed25519 signing, three-tier
verification, privacy commitments, chains, and anchoring. Zero-dependency (`node:crypto`; a WebCrypto/`@noble`
adapter for browsers and Workers — same rules, same results).

> **Release candidate.** The specification is at `1.0.0-rc.6`; this package pins its own rc on npm. Extensively
> red-teamed; five external AI reviews folded in; an independent human cryptographic audit is pending. Suitable
> for evaluation and integration testing. Pin exact versions.

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

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged.* It does
**not** prove the data is *correct* — a publisher can sign a wrong reading. You learn **whom to hold accountable**
and **that nothing was tampered** — a real, bounded guarantee, not an oracle of truth.

## Trust tiers — same document, more trust as you bring more

| Tier | You also supply | You learn |
|------|-----------------|-----------|
| **LIGHT** | nothing (the document alone) | integrity + a *claimed* publisher (`self-asserted`) |
| **HIGH** | the publisher's genesis + key-log | the key is *provably bound* to the publisher's name (`authoritative`) |
| **TOP** | an anchor proof | the document provably existed by a point in time; a stream is provably complete |

```js
// HIGH — resolve name authority
verify(doc, { genesis, keylog, noForkConfirmed: true, requireAuthoritative: true });

// TOP — verify a time-anchor's inclusion proof (substrate confirmation is delegated to the caller)
import { verifyAnchor } from 'ust-protocol';
verifyAnchor(content_hash, proof);
```

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
