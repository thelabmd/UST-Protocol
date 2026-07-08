<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Make it UST — test browser extension

A minimal Manifest V3 extension that packages the **LIGHT tier** of [UST](https://github.com/thelabmd/UST) into
one gesture: **select text → right-click → "Make it UST" → a signed transcript is on your clipboard.**

It is the reference consumer of [`ust-web-signer`](../packages/ust-web-signer) (bundled in `lib/`).

## Load it (unpacked)

1. Chrome → `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `extension/` folder.
3. On first use it generates a **non-extractable** Ed25519 key (your identity, `key_id`), stored in IndexedDB and
   never exported. Click the toolbar icon to see your `key_id`.

## What ends up on your clipboard

```
Source: https://example.com/article  (claimed by sender — NOT verified)
Verified by UST (LIGHT): the exact bytes below · the signing key · the capture time. The source URL is not part of the proof.
———UST(base64)———
eyJ1c3QiOiIxLjAiLCJzdGF0ZSI6eyJpZCI6ey…
```

The lines before `———UST(base64)———` are a **plain-text, unsigned** note for humans — the page URL is the
sender's *claim*, deliberately kept **outside** the signature. The token after the delimiter is the signed
document, **base64-encoded** so its exact bytes survive any paste channel (chat / terminal / apps often normalize
whitespace + unicode inside raw JSON, which would silently break the signature — a real capture failed exactly
this way).

## Verify a copied transcript

Take the base64 after `———UST(base64)———`, decode it, and verify with the reference verifier:

```
npm i ust-protocol@rc
node -e "import('ust-protocol').then(P=>console.log(P.verify(JSON.parse(Buffer.from(process.argv[1],'base64').toString('utf8')),{context:'data'})))" '<paste the base64>'
```

Expected: `result: "VALID:LIGHT"`, `identity.strength: "self-asserted"`, `publisher_claimed` = your `key_id`
(the identity is your **key**, self-certifying — no name is claimed). Edit a byte of the text and it goes
`INVALID`.

## What this proves — and what it doesn't

- **Proves:** these exact bytes were signed by this key at this claimed time. Tamper-evident, verifiable offline.
- **Does NOT prove:** that you are a specific person or domain (that is **HIGH** tier — name authority), or that
  the page really served those bytes (an unverifiable URL; a real proof would need the site to sign, a witness, or
  a TLS-notarization layer). The extension says exactly this, in plain language, so no one over-reads a LIGHT
  capture.

*Test extension — no key backup, per-browser identity, best-effort clipboard. Not production.*
