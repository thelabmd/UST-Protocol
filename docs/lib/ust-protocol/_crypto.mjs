// SPDX-License-Identifier: Apache-2.0
// #143 — the browser build's cryptographic faculty. Selected by the bundler through package.json `browser`,
// never by a caller: see `_crypto.mjs` for why a runtime switch here would be a verdict-forging hazard.
//
// WHAT IS HERE AND WHAT IS REFUSED, and the line between them is not convenience.
//
// SHA-256 is implemented. It is deterministic, takes no key, leaks nothing through timing that matters, and is
// checkable against published vectors — so writing it is ordinary work, and it is what `canon` → `contentHash`
// needs. Without it a browser cannot hash a document, which is most of what a browser wants from this core.
//
// Ed25519 verification is NOT implemented, and this is the deliberate half. A browser offers it only through
// `crypto.subtle`, which is ASYNCHRONOUS, and this core is synchronous by construction. The alternative was to
// hand-roll it — and a subtle error in Ed25519 verification does not fail loudly, it ACCEPTS FORGED
// SIGNATURES. Non-canonical S, small-order points, the RFC-8032/ZIP-215 split: each is a way to be quietly
// wrong in the one direction this project cannot be wrong in. A refusal that names itself is worth more than
// an approximation that verifies.
//
// AES-256-GCM is refused for the same reason plus one: it decrypts, so being wrong means emitting garbage as
// though it were committed plaintext.
//
// A browser consumer therefore gets canonicalisation, hashing, building and shape checking from this core, and
// performs the signature step itself with `crypto.subtle.verify` — which is async, which is honest, and which
// is exactly the tier boundary anyway: name-binding needs the network, so a browser verifier was never going
// to be synchronous end to end.

/** Which faculty this build carries. Read by the portability gate, never by the data path. */
export const CRYPTO_BUILD = 'browser';

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** SHA-256 over raw bytes → lowercase hex. FIPS 180-4; checked against published vectors in conformance. */
export function sha256Hex(bytes) {
  const msg = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const bitLen = msg.length * 8;
  const withPad = new Uint8Array(((msg.length + 9 + 63) >> 6) << 6);
  withPad.set(msg);
  withPad[msg.length] = 0x80;
  // Length is 64-bit big-endian. JS bitwise is 32-bit, so the high word is written via division, not `>>>`.
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(withPad.length - 4, bitLen >>> 0);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  let out = '';
  for (let i = 0; i < 8; i++) out += h[i].toString(16).padStart(8, '0');
  return out;
}

/**
 * A refusal that names itself MACHINE-READABLY, not one that names itself in prose.
 *
 * The refusal carried its meaning only in the message text until 2026-08-09 (#144), and prose is not a channel a
 * verifier can branch on: every layer above had to either guess from a substring or collapse the refusal into a
 * verdict — and one of them did, turning a VALID signature into `INVALID:E-SIG`.
 *
 * `code` is the channel the rest of the core already uses (`err(code, detail)`), so a refusal now travels the
 * same way every other typed failure does, and the public boundary can tell "this document is bad" from
 * "I am not able to check" without reading English.
 */
const unsupported = (detail) => {
  const e = new Error('E-UNSUPPORTED: ' + detail);
  e.code = 'E-UNSUPPORTED';                       // ⇒ INDETERMINATE(unsupported_alg) at the boundary, never INVALID
  e.detail = detail;
  return e;
};

/**
 * A refusal that names itself, not a stub that returns false.
 *
 * Returning `false` would read as "the signature did not verify" — a VERDICT about the document. This build
 * has no verdict to give: it cannot perform the check at all. Conflating "I checked and it failed" with "I
 * cannot check" is the same defect the tier vocabulary exists to prevent, so it throws.
 */
export function ed25519Verify() {
  throw unsupported('Ed25519 verification is not available in the browser build — the browser offers it only through the asynchronous crypto.subtle, and this core is synchronous. Verify the signature at the call site with crypto.subtle.verify.');
}

export function ed25519Sign() {
  throw unsupported('signing is not available in the browser build — a signing key does not belong in a page.');
}

export function aesGcmDecrypt() {
  throw unsupported('AES-256-GCM decryption is not available in the browser build — the browser offers it only through the asynchronous crypto.subtle. Encrypted partitions cannot be opened here.');
}
