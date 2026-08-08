<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the LIGHT floor, standalone

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same however it reached you. TLS secures the
pipe; **UST secures the payload**, so the guarantee travels with the data instead of with the connection.

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

Publish and verify a **signed, canonical, addressable, string-only, bounded JSON state** with a **carried key** —
in a minute, with zero dependencies (WebCrypto: Ed25519 + SHA-256 — so it runs in Node, in a worker and in a
browser, unchanged). Everything that touches a hash or a signature is **async**; `canon` and `signedContent`
are pure and stay synchronous. No genesis, key-log, anchoring, checkpoints,
or the assurance lattice. **A `ust-light` document is a valid UST document**: it verifies `VALID:LIGHT` under the full
`ust-protocol` verifier, and this verifier accepts any UST document at the LIGHT floor. The canon/hash/sign
primitives are byte-identical to the reference implementation (`test.mjs` proves both directions + byte-identity).

LIGHT = **integrity + a CLAIMED key**. It does NOT resolve name authority (HIGH) or anchored time (TOP) — for those,
use the full `ust-protocol`. LIGHT identity is reported `self-asserted`.

## Install

```bash
npm i ust-light
```

## The floor, in five rules (§ = `spec/UST-1.0.md`)

1. **Shape** (§4) — `{ ust:"1.0", state:{ id, time, data, hashes }, sig }`; only reserved keys; ≥1 partition;
   partition names are not reserved.
2. **String-only + canonical** (§5/§6) — every leaf is a string; JCS with tightenings (UTF-16-sorted keys, NFC,
   unique names, no whitespace). Numbers/bools/null are unrepresentable.
3. **Per-partition hash** (§4.4) — each partition binds its publisher: `H("ust:shard", canon({domain_shard, ust_id,
   partition, value}))` (public) or `H("ust:shard", commit)` (private); `hashes` is an exact bijection with `data`.
4. **Signature** (§7) — strict Ed25519 over `canon({ust, state})`, with `key_id == H("ust:keylog", pub) ==
   state.id.key_id`. Non-canonical encodings are rejected (I4 raw-byte determinism).
5. **Addressing + bounds** (§8/§13) — `ust_id = ust:YYYYMMDD.HH[MM[SS]]` (a valid UTC frame), RFC3339-Z times,
   `valid_from ≤ valid_to`; ≤ 64 partitions, ≤ 1 MiB signed content (the anonymous floor).

## Use

```js
// runnable: node this file as-is.
import { keypair, buildState, seal, verify } from 'ust-light';

const kp = await keypair();
const doc = await seal(await buildState(
  { domain_shard: 'example.md', ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' },
  { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' },
  { reading: { kind: 'captured', value: { celsius: '21.5' } } },
), kp.privateKey, kp.pub);

await verify(doc);   // → { result: 'VALID:LIGHT', identity: 'self-asserted', content_hash, ust_id, key_id, … }
```

`npm test` cross-verifies against the full reference implementation (byte-identical, both directions).

## Boundary (honest)

`ust-light`'s verifier applies the **structural** floor (canon / hash / strict-signature / shape). The full
`ust-protocol` verifier adds semantic hardening at LIGHT (real-calendar date existence, homograph A-label guard) and
the HIGH/TOP tiers (genesis name-authority, anchored time, stream completeness, the assurance lattice). Use `ust-light`
to adopt in a minute and to independently re-check the floor; use `ust-protocol` for authority and time.
