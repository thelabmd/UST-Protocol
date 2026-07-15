<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ust-lite — the UST 1.0 LIGHT floor, standalone

Publish and verify a **signed, canonical, addressable, string-only, bounded JSON state** with a **carried key** —
in a minute, with zero dependencies (Node `crypto`: Ed25519 + SHA-256). No genesis, key-log, anchoring, checkpoints,
or the assurance lattice. **A `ust-lite` document is a valid UST document**: it verifies `VALID:LIGHT` under the full
`ust-protocol` verifier, and this verifier accepts any UST document at the LIGHT floor. The canon/hash/sign
primitives are byte-identical to the reference implementation (`test.mjs` proves both directions + byte-identity).

LIGHT = **integrity + a CLAIMED key**. It does NOT resolve name authority (HIGH) or anchored time (TOP) — for those,
use the full `ust-protocol`. LIGHT identity is reported `self-asserted`.

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
import { keypair, buildState, seal, verify } from 'ust-lite';

const kp = keypair();
const doc = seal(buildState(
  { domain_shard: 'example.md', ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' },
  { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' },
  { reading: { kind: 'captured', value: { celsius: '21.5' } } },
), kp.privateKey, kp.pub);

verify(doc);   // → { result: 'VALID:LIGHT', identity: 'self-asserted', content_hash, ust_id, key_id, … }
```

`npm test` cross-verifies against the full reference implementation (byte-identical, both directions).

## Boundary (honest)

`ust-lite`'s verifier applies the **structural** floor (canon / hash / strict-signature / shape). The full
`ust-protocol` verifier adds semantic hardening at LIGHT (real-calendar date existence, homograph A-label guard) and
the HIGH/TOP tiers (genesis name-authority, anchored time, stream completeness, the assurance lattice). Use `ust-lite`
to adopt in a minute and to independently re-check the floor; use `ust-protocol` for authority and time.
