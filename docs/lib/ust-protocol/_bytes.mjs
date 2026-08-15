// SPDX-License-Identifier: Apache-2.0
// #143 — byte helpers that exist on every runtime, so the core stops depending on `Buffer`.
//
// `Buffer` is a Node GLOBAL, not an import. No bundler reports it: measured 2026-08-08, with the crypto
// faculty substituted the core bundled green to 261 KB carrying 51 `Buffer` references, every one of which
// throws on the first call in a page. A build that succeeds and dies at runtime is worse than one that fails,
// because the failure has been moved from our CI to the consumer's browser.
// CLOSED 2026-08-08 by round 184 — none of those references remain, and the gate re-derives that on every run.
//
// STRICTNESS IS UNCHANGED. These are encodings, not policy: the decode→re-encode→identity discipline that
// makes `strictB64url` reject non-canonical aliases lives at the call site and still does. What changes is
// only which primitive performs the transform. `atob`/`btoa` are globals in browsers and in Node since 16.
//
// CLOSED 2026-08-08 by round 184 — the core carries no `Buffer`, and `test:browser` runs it with the global deleted, so
// the class cannot come back silently: a reintroduced global reddens the run leg by its own name.

const TE = new TextEncoder();
const TD = new TextDecoder('utf-8', { fatal: false });

/** UTF-8 encode. */
export const utf8 = (s) => TE.encode(s);

/** Byte length of the UTF-8 encoding, without materialising it twice at call sites that only need the count. */
export const utf8Len = (s) => TE.encode(s).length;

/** UTF-8 decode of raw bytes. */
export const decodeUtf8 = (b) => TD.decode(b instanceof Uint8Array ? b : new Uint8Array(b));

/** Concatenate byte arrays. */
export function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** Lowercase hex of raw bytes. */
export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Raw bytes from lowercase/uppercase hex. Returns null when the input is not exact hex pairs. */
export function fromHex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Unpadded base64url of raw bytes. */
export function toB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Raw bytes from base64url — PERMISSIVE, byte-for-byte as `Buffer.from(s, 'base64url')` was, characters
 * outside the alphabet ignored, and never null.
 *
 * The permissiveness is deliberate and is NOT an oversight being carried forward. Two reasons:
 *
 * It is not this layer's job to judge. Canonicality lives one level up, in `strictB64url`, which decodes and
 * re-encodes and demands identity (#75) — that is what stops two distinct strings from verifying alike, and
 * it keeps working only if the primitive underneath behaves the same way it always did.
 *
 * And a refusal here would not be a refusal, it would be a THROW. Returning null fed `null.length` inside
 * `keyId`, turning a malformed public key from a clean mismatch into a host exception — measured, and a
 * totality break: an export must answer hostile input with a value, never by throwing.
 *
 * A portability round changes WHERE code runs, never WHAT it decides. Tightening the decoder here would have
 * been a semantic change smuggled inside a build fix, and it would have shown up as a verdict difference.
 */
export function fromB64url(s) {
  // Node's base64url decoder also admits the STANDARD alphabet (`+`, `/`) and stray padding — measured, not
  // assumed: `Buffer.from('a+b', 'base64url')` yields two bytes, so dropping those characters would decode
  // fewer bytes than the code being replaced and change what hashes to what.
  if (typeof s !== 'string') return new Uint8Array(0);
  const clean = s.replace(/[^A-Za-z0-9+/_-]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const b64 = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  let bin;
  try { bin = atob(b64); } catch { return new Uint8Array(0); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
