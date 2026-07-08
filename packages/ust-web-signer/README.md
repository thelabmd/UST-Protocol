<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ust-web-signer

The **browser-side signer** for [UST (Universal State Transcript)](https://github.com/thelabmd/UST). It is the
one piece [`ust-protocol`](https://www.npmjs.com/package/ust-protocol) deliberately leaves out: a **private key
never enters the verifier library**. This package generates an Ed25519 key with WebCrypto, signs, and produces the
full `{ ust, state, sig }` document. Its `canon`/hash/preimage code is byte-identical to `ust-protocol`, so what
it signs verifies **VALID** there.

Runs in browsers, Web Workers / service workers, and Node ≥ 20 (global `crypto.subtle`). Zero dependencies.

```js
import { generateSigner, signObservation, nowFrame } from 'ust-web-signer';

const signer = await generateSigner();                 // Ed25519, private key NON-EXTRACTABLE (stays in WebCrypto)
const { ust_id, time } = nowFrame();                   // hour frame for addressing; time = an INSTANT (valid_from = valid_to = generated_at)
const doc = await signObservation(signer, {
  ust_id, time,
  data: { capture: { kind: 'captured', value: { text: 'the exact bytes I saw' } } },
});
// doc verifies as VALID:LIGHT under ust-protocol. doc.sig.pub is the public key; signer.key_id is the identity.
```

## LIGHT-tier honesty (read this)

At the LIGHT tier a signature proves exactly three things: **the exact bytes**, **the signing key**, and **the
claimed time**. It does **not** prove *who you are* (a human/domain name is a HIGH-tier claim) or *where the bytes
came from* (an unverifiable page URL is the signer's claim, not a proof).

So this signer, by design:

- sets `domain_shard` to the signer's own **`key_id`** — identity is the **key**, self-certifying. It never puts a
  claimed domain name into the signed state.
- signs **only** the captured value + time. Do **not** put a page URL, origin, or claimed source inside the signed
  `state` — a consumer would read the signature as proving it. Keep such context **outside** the signed document
  (e.g. a plain-text, explicitly-unverified note in the clipboard next to the UST).

Persist the identity by storing the `CryptoKey` (structured-cloneable) in **IndexedDB**; a non-extractable key
cannot be exported, which is the point.
