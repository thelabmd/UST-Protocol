// SPDX-License-Identifier: Apache-2.0
// #143 — the platform's cryptographic faculty, behind ONE internal module.
//
// WHY A MODULE AND NOT AN OPTION. Selection happens at BUILD time. A security-relevant faculty must never be
// reachable from the data path: round-29 P0-02 exposed the witness clock as a public `opts.__nowMs` field and
// a caller flipped a verdict with it. Crypto is strictly worse than a clock — a supplied `verify` that always
// returns true forges everything. So this module is NOT in package.json `exports`, takes no parameters, and
// offers no setter. The browser build gets a DIFFERENT FILE, chosen by the bundler, not by the caller.
//
// WHY BYTES AND NOT `Buffer`. `Buffer` is a Node global, not an import — no bundler reports it, so a browser
// bundle builds green and dies on the first call. Measured 2026-08-08: with `node:crypto` stubbed the core
// bundled to 258 KB carrying 47 `Buffer` references. This surface therefore speaks `Uint8Array` only, and
// `Buffer` is a `Uint8Array` subclass, so Node call sites keep working while they are converted.
//
// CLOSED 2026-08-08 by round 184 — the conversion finished inside the same round; no call site was left half-converted.
//
// WHAT THE BROWSER VARIANT DOES NOT DO, and why that is a refusal rather than a gap: SHA-256 is vendored there
// (deterministic, vector-checkable, no secrets). Ed25519 and AES-GCM are NOT. A browser has them only through
// `crypto.subtle`, which is ASYNCHRONOUS, and this core is synchronous by design — the alternative was
// hand-rolling Ed25519 verification, where a subtle error accepts forged signatures. That is the one defect
// this project cannot afford, so the browser build REFUSES those operations by name instead of approximating
// them. See `_crypto.browser.mjs`.

import { createHash, sign as edSign, verify as edVerify, createPublicKey, createCipheriv, createDecipheriv } from 'node:crypto';

/** Which faculty this build carries. Read by the portability gate, never by the data path. */
export const CRYPTO_BUILD = 'node';

/** SHA-256 over raw bytes → lowercase hex. */
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const SPKI_ED25519_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/** Ed25519 verify over raw bytes. Returns a boolean; never throws for bad input. */
export function ed25519Verify(msgBytes, pubBytes, sigBytes) {
  try {
    const spki = new Uint8Array(SPKI_ED25519_PREFIX.length + pubBytes.length);
    spki.set(SPKI_ED25519_PREFIX, 0);
    spki.set(pubBytes, SPKI_ED25519_PREFIX.length);
    const key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    return edVerify(null, Buffer.from(msgBytes), key, Buffer.from(sigBytes));
  } catch {
    return false;
  }
}

/** Ed25519 sign over raw bytes with an already-constructed private key object. Signing is a Node-only path. */
export function ed25519Sign(msgBytes, privKeyObj) {
  return new Uint8Array(edSign(null, Buffer.from(msgBytes), privKeyObj));
}

/**
 * AES-256-GCM decrypt. Returns the plaintext bytes, or `null` on an auth-tag failure — a null here is a
 * COMMIT failure, not an unsupported algorithm; the caller distinguishes the two.
 */
/**
 * AES-256-GCM encrypt — the producer half of the pair above, added with `encryptPartition` (#175).
 *
 * It exists because the format had a reader and no writer: `privacy: "encrypted"` was defined in §10, decided in
 * four places by the verifier, and constructible by nothing in this tree. A fixture written by hand to fill that
 * hole would have described the verifier instead of testing it.
 *
 * The IV is an ARGUMENT, never generated here. GCM is catastrophic under nonce reuse, and §10 permits it "only
 * with a stated unique-nonce-per-key derivation" — so the derivation is stated at the one call site that knows
 * what makes it unique (the frame-bound commitment), and this leaf stays a primitive with no policy in it.
 */
export function aesGcmEncrypt(keyBytes, ivBytes, plaintextBytes) {
  const c = createCipheriv('aes-256-gcm', Buffer.from(keyBytes), Buffer.from(ivBytes));
  const body = Buffer.concat([c.update(Buffer.from(plaintextBytes)), c.final()]);
  return { body: new Uint8Array(body), tag: new Uint8Array(c.getAuthTag()) };
}

export function aesGcmDecrypt(keyBytes, ivBytes, tagBytes, bodyBytes) {
  try {
    const d = createDecipheriv('aes-256-gcm', Buffer.from(keyBytes), Buffer.from(ivBytes));
    d.setAuthTag(Buffer.from(tagBytes));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(bodyBytes)), d.final()]));
  } catch {
    return null;
  }
}

/**
 * WHICH AEADs THIS BUILD CAN RUN — a DECLARATION, read before any document is.
 *
 * The model (F.7a.2, second corollary) states why this cannot be discovered by trying: an absent primitive and an
 * unauthentic ciphertext are the SAME observation — "no plaintext" — so a verifier that learns its own limits by
 * calling into them holds one signal for two facts and must guess which. Measured 2026-08-31 before this existed:
 * a build with Ed25519 and no AES-GCM answered an honest document `INVALID E-COMMIT`, "AEAD↔commit mismatch" —
 * its own inability rendered as an accusation against the publisher, on the axis where being wrong is silently
 * dangerous rather than merely wrong. CLOSED 2026-08-31 by this declaration and `aead-faculty.test.mjs`, which
 * runs a build declaring only the MTI and asserts `INDETERMINATE(unsupported_alg)` where `E-COMMIT` used to be.
 *
 * `Impl ⊆ Reg` (§17). A build may implement FEWER algorithms than the registry names — that is what OPTIONAL
 * means — and never more: an algorithm outside the registry is the document's defect and is refused at admission.
 */
export const AEAD_IMPLEMENTED = ['AES-256-GCM', 'XChaCha20-Poly1305'];

/**
 * HChaCha20 (draft-irtf-cfrg-xchacha §2.2) WITHOUT a ChaCha20 of our own.
 *
 * XChaCha20-Poly1305 is `HChaCha20(key, nonce[0..16])` → subkey, then IETF ChaCha20-Poly1305 under that subkey.
 * Node ships `chacha20` and `chacha20-poly1305`; it does not ship HChaCha20. Hand-rolling one would put a cipher
 * we wrote into the TCB — the thing this module refuses to do for Ed25519 in the browser, for the same reason.
 *
 * It is not necessary. A ChaCha20 keystream block is `working_state + initial_state` word-wise, and the initial
 * state is fully known: the four constants, the key, and the 16-byte nonce in words 12–15 — which is exactly
 * OpenSSL's `chacha20` IV layout. So `working = keystream − initial (mod 2³²)`, and HChaCha20's output is
 * working-state words 0–3 ‖ 12–15. Arithmetic over a primitive Node already ships and has already had reviewed.
 *
 * Pinned against the CFRG draft vector in the conformance corpus, not against our own output.
 */
const CHACHA_CONSTANTS = 'expand 32-byte k';
// EXPORTED for one reason: this derivation is the only cipher arithmetic in this tree that we wrote, and it
// is pinned against the CFRG vector rather than against our own output. `chacha20-poly1305` underneath is
// Node's and carries its own review; this is the part that could be silently wrong. The module is not in
// package.json `exports`, so exporting it here reaches the test and nothing else.
export function hchacha20(keyBytes, nonce16) {
  const key = Buffer.from(keyBytes), n16 = Buffer.from(nonce16);
  const ks = createCipheriv('chacha20', key, n16).update(Buffer.alloc(64));   // one keystream block, counter 0
  const initial = new Uint32Array(16), C = Buffer.from(CHACHA_CONSTANTS, 'latin1');
  for (let i = 0; i < 4; i++) initial[i] = C.readUInt32LE(i * 4);
  for (let i = 0; i < 8; i++) initial[4 + i] = key.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) initial[12 + i] = n16.readUInt32LE(i * 4);
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeUInt32LE((ks.readUInt32LE(i * 4) - initial[i]) >>> 0, i * 4);
  for (let i = 0; i < 4; i++) out.writeUInt32LE((ks.readUInt32LE((12 + i) * 4) - initial[12 + i]) >>> 0, 16 + i * 4);
  return out;
}

/** The 24-byte nonce splits: 16 bytes derive the subkey, 8 become the IETF nonce behind four zero bytes. */
const xchachaParams = (keyBytes, nonce24) => {
  const n = Buffer.from(nonce24);
  return { subkey: hchacha20(keyBytes, n.subarray(0, 16)), iv12: Buffer.concat([Buffer.alloc(4), n.subarray(16, 24)]) };
};

export function xchachaEncrypt(keyBytes, nonceBytes, plaintextBytes) {
  const { subkey, iv12 } = xchachaParams(keyBytes, nonceBytes);
  const c = createCipheriv('chacha20-poly1305', subkey, iv12, { authTagLength: 16 });
  const body = Buffer.concat([c.update(Buffer.from(plaintextBytes)), c.final()]);
  return { body: new Uint8Array(body), tag: new Uint8Array(c.getAuthTag()) };
}

export function xchachaDecrypt(keyBytes, nonceBytes, tagBytes, bodyBytes) {
  try {
    const { subkey, iv12 } = xchachaParams(keyBytes, nonceBytes);
    const d = createDecipheriv('chacha20-poly1305', subkey, iv12, { authTagLength: 16 });
    d.setAuthTag(Buffer.from(tagBytes));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(bodyBytes)), d.final()]));
  } catch {
    return null;                                                    // authentication failure — the DOCUMENT's defect
  }
}
