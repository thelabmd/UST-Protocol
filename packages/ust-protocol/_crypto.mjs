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
// WHAT THE BROWSER VARIANT DOES NOT DO, and why that is a refusal rather than a gap: SHA-256 is vendored there
// (deterministic, vector-checkable, no secrets). Ed25519 and AES-GCM are NOT. A browser has them only through
// `crypto.subtle`, which is ASYNCHRONOUS, and this core is synchronous by design — the alternative was
// hand-rolling Ed25519 verification, where a subtle error accepts forged signatures. That is the one defect
// this project cannot afford, so the browser build REFUSES those operations by name instead of approximating
// them. See `_crypto.browser.mjs`.

import { createHash, sign as edSign, verify as edVerify, createPublicKey, createDecipheriv } from 'node:crypto';

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
export function aesGcmDecrypt(keyBytes, ivBytes, tagBytes, bodyBytes) {
  try {
    const d = createDecipheriv('aes-256-gcm', Buffer.from(keyBytes), Buffer.from(ivBytes));
    d.setAuthTag(Buffer.from(tagBytes));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(bodyBytes)), d.final()]));
  } catch {
    return null;
  }
}
