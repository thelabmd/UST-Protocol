<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# @ust-protocol/rekor-verify

An **opt-in witness substrate** for [UST](https://github.com/thelabmd/UST-Protocol) — Sigstore
[Rekor](https://docs.sigstore.dev/logging/overview/), a public append-only transparency log. A second
substrate next to Bitcoin ([@ust-protocol/ots-verify](https://www.npmjs.com/package/@ust-protocol/ots-verify)):
logging is **seconds** (not Bitcoin's hours) and **independent of the publisher**. Trade-off: you trust the
Rekor operator's log (its own witnesses co-sign the tree head); Bitcoin is trustless but slow. Accept BOTH.

```js
import { substrateVerify as ots } from '@ust-protocol/ots-verify';
import { substrateVerify as rekor } from '@ust-protocol/rekor-verify';
import { combineSubstrates, resolveByDiscovery } from 'ust-protocol';

const substrateVerify = combineSubstrates([ots, rekor]);   // Bitcoin OR Rekor, whichever the anchor speaks
const { verdict } = await resolveByDiscovery(doc, { context: 'data' }, { substrateVerify });
```

Zero-dependency: plain REST to Rekor + RFC 6962 inclusion-proof verification (validated against the live
log). The proof is self-contained — the Merkle math decides, the API is only a fallback fetch (claim ≠ proof).
The `ust` CLI and `@ust-protocol/mcp` auto-detect this package alongside `ots-verify`.
