// SPDX-License-Identifier: Apache-2.0
// ust-web-signer — WebCrypto Ed25519 SIGNER + producer for UST 1.0. Browser + Workers + Node (global crypto.subtle).
// The canon/hash/preimage helpers are BYTE-IDENTICAL to ust-protocol (same spec §6/§7/§4.4), so documents this
// produces verify as VALID under ust-protocol / the clean-room verifier. The PRIVATE KEY never leaves WebCrypto:
// generate it NON-EXTRACTABLE and persist the CryptoKey object (structured-cloneable) in IndexedDB.
//
// LIGHT-tier honesty (see the extension): sign ONLY what the signature guarantees — the exact bytes, the key, and
// the claimed time. Identity is the KEY, not a claimed name: `domain_shard` is set to the signer's own key_id
// (self-certifying). Do NOT put an unverifiable page URL or a claimed domain inside the signed state.

const te = (s) => new TextEncoder().encode(s);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };
const b64urlToBytes = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesToB64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// ─── §6 canon (JCS tightened): string-only leaves, NFC (names + values), sorted+unique keys. Throws E-CANON. ───
export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') throw { code: 'E-CANON', detail: 'non-string leaf' };
  if (typeof v === 'string') { if (v.normalize('NFC') !== v) throw { code: 'E-CANON', detail: 'non-NFC' }; return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const k = Object.keys(v); if (new Set(k).size !== k.length) throw { code: 'E-CANON', detail: 'dup key' };
  for (const x of k) if (x.normalize('NFC') !== x) throw { code: 'E-CANON', detail: 'non-NFC key' };
  return '{' + k.sort().map((x) => JSON.stringify(x) + ':' + canon(v[x])).join(',') + '}';
}
// ─── §7 domain-separated hash: "sha256:" + hex(SHA256(ascii(tag) || 0x00 || body)) ───
async function digest(tag, body) { return 'sha256:' + hex(await crypto.subtle.digest('SHA-256', concat(concat(te(tag), new Uint8Array([0])), body))); }
export const H = (tag, str) => digest(tag, te(str));
export const Hbytes = (tag, bytes) => digest(tag, bytes);
export const keyId = (pubB64url) => Hbytes('ust:keylog', b64urlToBytes(pubB64url));   // §12.2 over RAW pubkey bytes
export async function partitionHash({ domain_shard, ust_id, name, value, commit }) {
  if (commit !== undefined) return H('ust:shard', commit);                             // §10 private
  return H('ust:shard', canon({ domain_shard, ust_id, partition: name, value }));      // uniform preimage (name is a VALUE)
}
export const contentHash = (doc) => H('ust:state', canon({ ust: doc.ust, state: doc.state }));
export const signedContent = (doc) => canon({ ust: doc.ust, state: doc.state });

// ─── producer: assemble a State with per-partition `hashes` auto-computed (§4.4) ───
export async function buildState(id, time, data) {
  const hashes = {};
  for (const [name, part] of Object.entries(data)) {
    hashes[name] = part.commit !== undefined
      ? await partitionHash({ commit: part.commit })
      : await partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value });
  }
  return { id, time, data, hashes };
}

// ─── the SIGNER — the piece ust-protocol deliberately omits (a key never enters the verifier lib) ───
// Generate an Ed25519 keypair. `extractable:false` keeps the private key inside WebCrypto forever; the CryptoKey
// object itself is structured-cloneable, so persist it in IndexedDB to reuse the same identity across sessions.
export async function generateSigner({ extractable = false } = {}) {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, extractable, ['sign', 'verify']);
  return signerFromKeys(kp.privateKey, kp.publicKey);
}
export async function signerFromKeys(privateKey, publicKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));          // 32 raw pubkey bytes (always exportable)
  const pub = bytesToB64url(raw);
  return { privateKey, publicKey, pub, key_id: await keyId(pub) };
}

// §7 seal — sign canon({ust,state}) with the WebCrypto private key. Ed25519 signing is always canonical-S, so the
// strict verifier accepts it. Returns the full { ust, state, sig } document.
export async function seal(state, signer) {
  const input = signedContent({ ust: '1.0', state });
  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, signer.privateKey, te(input));
  const sig = bytesToB64url(new Uint8Array(sigBuf));
  return { ust: '1.0', state, sig: { alg: 'Ed25519', key_id: state.id.key_id, pub: signer.pub, sig } };
}

// ─── convenience: build + sign a LIGHT observation. Identity = the KEY (domain_shard := key_id, self-certifying);
//     no claimed name, no unverifiable URL in the signed state. `data` maps partition-name → { value } (captured). ───
export async function signObservation(signer, { ust_id, time, data }) {
  const id = { domain_shard: signer.key_id, ust_id, key_id: signer.key_id, class: 'observation' };
  const state = await buildState(id, time, data);
  return seal(state, signer);
}

// helper: current UTC hour → ust_id + a matching time window (valid_from = generated_at = now, valid_to = +1h).
export function nowFrame(date = new Date()) {
  const iso = date.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const to = new Date(date.getTime() + 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const ust_id = 'ust:' + iso.slice(0, 10).replace(/-/g, '') + '.' + iso.slice(11, 13);
  return { ust_id, time: { generated_at: iso, valid_from: iso, valid_to: to } };
}
