<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# A name-bound UST (HIGH) — verify the authority yourself

The [LIGHT recipe](./ust-verify-recipe.md) proves the bytes, the key and the time frame. This one goes one tier up:
it proves the **name** `observatory.example` is bound to the signing key — `VALID:HIGH`. Two files:
[`ust-sample-HIGH.json`](./ust-sample-HIGH.json) (the observation) and
[`ust-sample-HIGH-genesis.json`](./ust-sample-HIGH-genesis.json) (the name-binding root).

## The tier ladder, one step at a time

```js
import { verify } from 'ust-protocol';                 // npm i ust-protocol
import { readFileSync } from 'node:fs';
const doc     = JSON.parse(readFileSync('ust-sample-HIGH.json', 'utf8'));
const genesis = JSON.parse(readFileSync('ust-sample-HIGH-genesis.json', 'utf8'));

// 1. the LIGHT floor — bytes + key + frame, no authority claimed
verify(doc, { context: 'data' }).result;               // → 'VALID:LIGHT'

// 2. add the genesis → the name is provably bound to the key (identity: corroborated)
const bound = verify(doc, { context: 'data', genesis });
bound.result;                                          // → 'VALID:LIGHT'  (tier not yet raised)
bound.identity.strength;                               // → 'corroborated' (name ↔ key proven)
bound.publisher_claimed;                               // → 'observatory.example'

// 3. add no-fork evidence → VALID:HIGH
//    offline, the caller air-gap-asserts "I checked out-of-band that no rival root exists":
verify(doc, { context: 'data', genesis,
              noForkConfirmed: true, acceptConsumerOverride: true }).result;   // → 'VALID:HIGH'
```

## What each step means

- **LIGHT → corroborated identity.** The genesis is itself a signed UST (`class: "genesis"`) that binds
  `observatory.example` to `key_id`. With it in hand, the verifier re-derives that the document's key belongs to
  that name — the name is no longer a *claim*, it is *resolved*. `verify` reports `identity.strength:
  'corroborated'` even while the tier stays at the LIGHT floor, because HIGH also needs the **no-fork** step.
- **HIGH needs no-fork.** HIGH says "and no *rival* genesis exists for this name." The honest, automatic way is the
  **served-surfaces path**: a publisher serves `/.well-known/ust-genesis` + `/.well-known/ust-witness`, and
  `resolveByDiscovery(doc)` fetches and cross-checks them, reaching `VALID:HIGH` with zero configuration. Offline,
  step 3 substitutes a **caller air-gap assertion** (`noForkConfirmed` + `acceptConsumerOverride`) — you take
  responsibility out-of-band. That is honest about its basis: the verdict carries `strength:
  'consumer-override'` and `independently_verified: false` — it never silently claims *independent* authority.

## Honesty

`consumer-override` (you vouched) and `authoritative` (an anchored name-map or an independent witness vouched) are
**different rungs** — only the latter names the definitive `publisher` and can reach TOP. UST never inflates the
tier: a rung is earned per verification, there is no field a producer can set to claim it. See the
[verdict ladder](https://github.com/thelabmd/UST-Protocol#what-is-a-real-truth-in-an-agent-world) in the README.

> Verify with the canonical reference — never eyeball. Fetch `ust-protocol` from npm or this repo, not from a
> sender's message.
