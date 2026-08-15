<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the Rekor anchor verifier

```
     ▄▀▀▀▀▀▀▀▀▀▀▀▀█▄
    █ ▄▄      ▄▄    █              UST · Rekor
  ▄▄▀ ▀▀ ▄▄▄  ▀▀    █              transparency-log receipts
  ▄█▀▀ ▀█▄▀▄▄▀ ▀█▀  █    █▀▄   ▄▄
   ▀█               █▄   █▄ ██▀ █
     █               ▀▄▄  █   ▄█
     █                  ▀▀   █▀
     █▄      ▄              █▀
     ███▄    █    █       ▄█▀
   ▄▀▀  ██▄▄▄█     ▀▄▄▄▄█▀▀
   ▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀
```

**Browser: node-only.** This package does **not** run in a browser, and that is a decision rather than an omission. See `ust:browser.why` in its `package.json` for the reason, and UST-Protocol#148 for what a browser can and cannot reach without it.

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same however it reached you. TLS secures the
pipe; **UST secures the payload**, so the guarantee travels with the data instead of with the connection.

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

An **opt-in witness substrate** for [UST](https://github.com/thelabmd/UST-Protocol) — Sigstore
[Rekor](https://docs.sigstore.dev/logging/overview/), a public append-only transparency log. A second
substrate next to Bitcoin ([@ust-protocol/ots-verify](https://www.npmjs.com/package/@ust-protocol/ots-verify)):
logging is **seconds** (not Bitcoin's hours) and **independent of the publisher**. Trade-off: you trust the
Rekor operator's log (its own witnesses co-sign the tree head); Bitcoin is trustless but slow. Accept BOTH.

## Install

```bash
npm i @ust-protocol/rekor-verify
```

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
