<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Make it UST — test browser extension

A minimal Manifest V3 extension that packages the **LIGHT tier** of [UST](https://github.com/thelabmd/UST-Protocol)
into one gesture each way:

- **Sign:** select text → right-click → **"Make it UST"** → a signed transcript is on your clipboard.
- **Verify:** select a pasted UST anywhere → right-click → **"Verify UST"** → the popup opens with the verdict
  plus the **real signed content**, verified locally. (Or click the toolbar icon and paste it into the box —
  same thing.) Chrome collapses newlines in a selection; harmless — the signed bytes ride as base64 armor.

It is the reference consumer of [`@ust-protocol/web-signer`](../packages/ust-web-signer) (bundled in `lib/`, alongside the
zero-dependency verifier `ust-verify.mjs`).

## Load it (unpacked)

1. Chrome → `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `extension/` folder.
3. On first use it generates a **non-extractable** Ed25519 key (your identity, `key_id`), stored in IndexedDB and
   never exported. Click the toolbar icon to see your `key_id`.

## What ends up on your clipboard

```
UST/1.0; ref=pkg:npm/ust-protocol; web=https://verify.ustprotocol.com/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time
Source: https://example.com/article  (claimed by sender — NOT verified; not part of the proof)
———UST(base64)———
eyJ1c3QiOiIxLjAiLCJzdGF0ZSI6eyJpZCI6ey…
```

The first line is a **machine-first, self-describing header** — a parseable `key=value` line (read it like a
`Content-Type`) that a receiving agent consumes deterministically. It is a **discovery aid, not a trust root**:
`ref` is a [PURL](https://github.com/package-url/purl-spec) naming the canonical reference verifier;
`trust=resolve-by-name` says resolve it **by name, out-of-band** (never from a link a sender hands you); `web` is a
convenience browser verifier. The method is a property of the version `ust:1.0`, never a per-doc field. The `Source`
line is the sender's unverified *claim*, kept **outside** the signature. Everything after the delimiter is the
signed document, **base64-encoded** so its exact bytes survive any paste channel (chat / terminal / apps normalize
whitespace + unicode inside raw JSON and would silently break the signature — a real capture failed exactly this
way). *(For API / JSON-LD-graph surfaces, use the richer JSON-LD `UstVerify` object instead of this header.)*

## Verify a copied transcript

**In the extension (recipient side):** click the toolbar icon and paste the whole thing into **Verify a
transcript** — it decodes, verifies with the bundled zero-dependency verifier, and shows the verdict plus the
content **regenerated from the signed bytes** (the sender's preamble is never displayed as truth). Everything runs
locally. Or use the [web verifier](https://verify.ustprotocol.com/), or the reference from npm:

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
