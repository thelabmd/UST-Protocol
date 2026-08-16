# UST Protocol — the RFC 6962 inclusion CONSTRUCTION connector

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

**Browser: node-only.** This package does **not** run in a browser, and that is a decision rather than an omission. See `ust:browser.why` in its `package.json`. A page is not left without a route: the construction is a CONSUMER faculty by design, and since round 236 the core's inclusion seam admits an ASYNCHRONOUS connector through `verifyAsync()` / `resolveByDiscovery()` — which is what a browser can supply, because WebCrypto's SHA-256 is a promise. What a browser cannot do is install THIS build and have it work.

The **construction** connector for UST anchor proofs built on the RFC 6962 tree (`rfc6962-raw`).

UST anchor evidence has two independent axes, and [§11.2](../../spec/UST-1.0.md) keeps them apart on purpose:

| axis | question | who answers | bundled in the core |
|---|---|---|---|
| substrate | is this **root** committed to the outside world, and when? | `@ust-protocol/rekor-verify`, `@ust-protocol/ots-verify` | no — the core carries no log client |
| **construction** | is this **content_hash** a member of that root? | this package, for `rfc6962-raw` | `ust-merkle-tagged` only |

They are two proofs and must not be conflated: membership carries a `content_hash` to a `root` in the
**publisher's own tree**, and the substrate check then decides whether that root was committed.

## Why it is its own package

It used to live inside `@ust-protocol/rekor-verify`. That made a consumer install a transparency-log client in
order to verify a publisher who anchors in **Bitcoin** — a dependency that takes no part in the check and
misdescribes what is happening. Nothing here touches rekor: the whole file is SHA-256 and RFC 6962 arithmetic
over bytes the caller already holds. No network.

`@ust-protocol/rekor-verify` re-exports both functions, so nothing installed breaks.

## Use

```js
import { inclusionVerify } from '@ust-protocol/rfc6962-verify';
import { verifyAsync } from 'ust-protocol';

const verdict = await verifyAsync(doc, { inclusionVerify, substrateVerify });
```

`inclusionVerify` returns `null` for a proof declaring a different construction — the core's router then tries the
next connector, so it is safe to pass unconditionally. It returns a strict boolean otherwise and never throws.

**Async hosts.** In a browser SHA-256 is asynchronous, so a browser connector is a promise by construction. The
core's inclusion seam admits that through `verifyAsync()` / `resolveByDiscovery()`, which resolve the connector
before deciding; the synchronous `verify()` withholds rather than refusing. See UST-Protocol#173.

## Notes

Tree indices are unbounded naturals and are read as BigInt: `number | string | bigint` are all accepted, because a
log serving a `uint64` past 2^53 must send it as a string. A verifier that narrows the index to 32 bits is correct
only below 2^31 — that defect shipped once and is what the arithmetic here is written against.

Apache-2.0.
