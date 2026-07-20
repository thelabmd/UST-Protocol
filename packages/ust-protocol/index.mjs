// SPDX-License-Identifier: Apache-2.0
// ust-protocol — reference implementation of UST 1.0 (the official STATELESS base; the public verification lib) (REV 26), LIGHT floor first.
// §16: ONE version source — the conformance runner asserts spec/package/vectors all carry the same rc.
export const VERSION = { wire: '1.0', spec: '1.0.0-rc.36', revision: 64 };   // #75 P1-09: machine-readable {wire, spec, revision} — Status line & appendix must agree
// Written FROM THE SPEC (§ references inline), NOT copied from the vector generator — so running it against
// the vectors is a cross-check between two independently-written artifacts. Zero-dependency: node:crypto
// (Ed25519 + SHA-256). Portable note: WebCrypto (SubtleCrypto Ed25519) or @noble/{ed25519,hashes} for
// browsers/Workers; same rules.
import { createHash, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey, createDecipheriv } from 'node:crypto';
import { witnessNow } from './_clock.mjs';   // rev33 R4 — the witness-budget clock is a VERIFIER-OWNED faculty in an INTERNAL module, never a caller-supplied opts field (round-29 P0-02)

// ─── §6 Canonicalization (JCS tightened) ────────────────────────────────────────────────────────────
// keys sorted by UTF-16 code unit, no whitespace, string-only leaves (reject number/bool/null), NFC,
// unique member names. Throws {code:'E-CANON'} on violation.
export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') throw err('E-CANON', 'non-string leaf');
  if (typeof v === 'string') { if (v.normalize('NFC') !== v) throw err('E-CANON', 'non-NFC string'); return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';          // §6.3 order significant
  if (typeof v === 'object') {
    const k = Object.keys(v);
    if (new Set(k).size !== k.length) throw err('E-CANON', 'duplicate key'); // §6.1
    for (const x of k) if (x.normalize('NFC') !== x) throw err('E-CANON', 'non-NFC member name'); // §6 — NAMES too, not just leaves (F6)
    return '{' + k.slice().sort().map(x => JSON.stringify(x) + ':' + canon(v[x])).join(',') + '}';
  }
  throw err('E-CANON', 'unsupported');
}

// ─── §7 Domain-separated hash: H_t(x) = "sha256:" || hex(SHA256(ascii(t) || 0x00 || x)) ──────────────
function sha(buf) { return 'sha256:' + createHash('sha256').update(buf).digest('hex'); }
export const H = (tag, strInput) => sha(Buffer.concat([Buffer.from(tag, 'ascii'), Buffer.from([0]), Buffer.from(strInput, 'utf8')])); // x = utf8 string
export const Hbytes = (tag, rawBuf) => sha(Buffer.concat([Buffer.from(tag, 'ascii'), Buffer.from([0]), rawBuf]));                     // x = raw bytes

// ─── §12.2/§17 key_id = H("ust:keylog", raw_pub_bytes) — raw = base64url-decode(pub), NOT plain SHA256(pub)
export const keyId = (pubB64url) => Hbytes('ust:keylog', Buffer.from(pubB64url, 'base64url'));

// ─── §4.4 per-partition hash — UNIFORM: EVERY partition binds its publisher (domain_shard). The partition NAME
//     is carried as a VALUE (`partition:`), never as a key, so it can never overwrite a protocol field (closes the
//     reserved-name collision). The old domain-less `computed` mode is REMOVED: its "cross-engine corroboration"
//     was forgeable (anyone copies a domain-less hash to fake agreement) — real corroboration compares two
//     publisher-BOUND values a layer up. `kind` is now descriptive metadata only and does NOT affect the hash.
export function partitionHash({ domain_shard, ust_id, name, value, commit }) {
  if (commit !== undefined) return Hbytes('ust:shard', Buffer.from(commit, 'utf8')); // §4.4 private: hash over its commit
  return H('ust:shard', canon({ domain_shard, ust_id, partition: name, value }));
}

// ─── §7 content_hash = H("ust:state", canon({ust, state})) — the unique document descriptor ─────────────
export const signedContent = (doc) => canon({ ust: doc.ust, state: doc.state });
export const contentHash = (doc) => H('ust:state', signedContent(doc));

// ─── §9.4 seed / §9.2 Merkle root ───────────────────────────────────────────────────────────────────
export const seed = (contentHashes) => H('ust:seed', canon(contentHashes));           // pinned signed order
export function merkleRoot(contentHashes) {                                            // byte-ascending sort, ust:leaf/ust:node
  let lvl = contentHashes.slice().sort().map(h => Hbytes('ust:leaf', Buffer.from(h, 'utf8')));
  while (lvl.length > 1) {
    const nx = [];
    for (let i = 0; i < lvl.length; i += 2)
      nx.push(i + 1 < lvl.length ? Hbytes('ust:node', Buffer.from(lvl[i] + lvl[i + 1], 'utf8')) : lvl[i]);
    lvl = nx;
  }
  return lvl[0];
}

// ─── §10 PRIVACY — blinded commitment (frame-bound, G23; nonce MUST be fresh & unique per commit, Z2) ────
// commit = H_shard(canon({domain_shard, ust_id, nonce, <name>: value}))  — verifier reproduces from a disclosure.
export const blindedCommit = ({ domain_shard, ust_id, name, value, nonce }) =>
  H('ust:shard', canon({ domain_shard, ust_id, nonce, partition: name, value }));   // name as VALUE, non-colliding
// producer helper: build a blinded PRIVATE partition envelope + its hashes entry (§4.4 private hash = H over commit).
export function blindPartition(name, value, { domain_shard, ust_id, nonce, kind = 'captured' }) {
  const commit = blindedCommit({ domain_shard, ust_id, name, value, nonce });
  return { partition: { kind, privacy: 'blinded', commit }, hash: partitionHash({ commit }) };
}
// §10/§17 encrypted: AEAD-decrypt to recover the committed plaintext canon({nonce,<name>:value}).
// Registry discipline (MTI): AES-256-GCM is MANDATORY-to-implement (node:crypto, zero-dep); XChaCha20-Poly1305 is
// OPTIONAL — a conforming verifier that does not implement it returns INDETERMINATE(unsupported_alg), NEVER a
// silent null/INVALID (the document may be honest; the verifier just cannot decide). 'unsupported' marks that.
function aeadDecrypt(enc, keyRawB64url) {
  if (enc.alg !== 'AES-256-GCM') return 'unsupported';                  // optional alg not implemented here (§17 MTI)
  try {
    const raw = Buffer.from(enc.ct, 'base64url'), key = Buffer.from(keyRawB64url, 'base64url');
    const iv = raw.subarray(0, 12), tag = raw.subarray(raw.length - 16), body = raw.subarray(12, raw.length - 16);
    const d = createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
    return Buffer.concat([d.update(body), d.final()]).toString('utf8'); // the committed plaintext (utf8 canon)
  } catch { return null; }                                             // auth-tag failure ⇒ null ⇒ E-COMMIT
}

// ─── crypto helpers (strict Ed25519 via node:crypto/OpenSSL) ─────────────────────────────────────────
const pubKeyObj = (b64url) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b64url, 'base64url')]), format: 'der', type: 'spki' });
export function edVerifyStrict(pubB64url, msgUtf8, sigB64url) {
  if (strictB64url(pubB64url, 32) === null || strictB64url(sigB64url, 64) === null) return false;   // round-36 P1-02 — canonical Pub32/Sig64 wire encoding IS part of "strict": Node's base64url decoder is permissive (a trailing-bit alias maps to the same bytes), so a non-canonical pub/sig would verify identically and split cross-language. Enforcing it at the crypto LEAF makes EVERY caller (incl. the provenance src_sig path) canonical-safe with no per-site guard.
  try { return edVerify(null, Buffer.from(msgUtf8, 'utf8'), pubKeyObj(pubB64url), Buffer.from(sigB64url, 'base64url')); }
  catch { return false; }
}

// ─── #75 STRICT ENCODERS — Node's permissive decoders make DISTINCT byte-strings verify identically, breaking
//     I4 raw-byte determinism + cross-language agreement. Each of these is EXACT: decode is only accepted if the
//     canonical re-encode reproduces the input byte-for-byte (P1-01/02/03).
// Strict UNPADDED base64url of EXACTLY `bytes` bytes → Buffer, or null (padding, non-alphabet char, wrong length,
// or a non-canonical trailing-bit encoding all fail: decode → re-encode → require identity).
export function strictB64url(s, bytes) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) return null;   // unpadded base64url alphabet only ('=' rejected)
  let buf; try { buf = Buffer.from(s, 'base64url'); } catch { return null; }
  if (buf.length !== bytes) return null;                                   // exact length (Ed25519 pub=32, sig=64)
  if (buf.toString('base64url') !== s) return null;                        // canonical: no non-zero trailing bits, no alias
  return buf;
}
// round-34 P0-01 — Pub32: a canonical unpadded base64url of EXACTLY 32 bytes (strictB64url already rejects a non-canonical
// trailing-bit alias, line 102). MIRRORS the kernel `strictPub`. Every AUTHORITY-bearing public field must pass this
// BEFORE keyId()/Ed25519 verify — Node's base64url decoder is permissive (a `...YKc`→`...YKd` alias maps to the same 32
// bytes), so `keyId(pub) === key_id` alone admits a non-canonical alias the kernel rejects (a public↔kernel split).
const strictPub = (p) => strictB64url(p, 32) !== null;
// A cadence is SECONDS as a canonical positive integer STRING — no fraction, no leading zero, no sign, bounded.
export function parseCadenceInt(s) {
  if (typeof s !== 'string' || !/^[1-9][0-9]*$/.test(s)) return null;      // "1.5", "030", "-1", "1e2", 30(number) all fail
  const n = Number(s);
  return (Number.isSafeInteger(n) && n > 0 && n <= BOUNDS.cadenceMax) ? n : null;
}
// round-24 P0-02 — a CANONICAL non-negative integer from a signed genesis ceremony field. Signed ceremony values
// (capacity max_partitions/max_transcript_bytes, recovery threshold) must be exact decimal STRINGS, never coerced by
// Number(...): `["4096"]`, `"0x80"`, `"1.28e2"`, `" 128 "`, `"+128"`, `"0128"` all collapse to a number under Number()
// and would manufacture authority-bearing capacity / lower a recovery takeover threshold. → a safe integer, or undefined.
const canonUint = (s) => { if (typeof s !== 'string' || !/^(0|[1-9][0-9]*)$/.test(s)) return undefined; const n = Number(s); return Number.isSafeInteger(n) && n >= 0 ? n : undefined; };
// Strict UTF-8 decode: Node's Buffer.toString('utf8') silently maps invalid bytes to U+FFFD, so 0xFF and the real
// 3-byte U+FFFD collapse to one string. fatal:true rejects invalid UTF-8 instead (P1-01). → string | null.
function strictUtf8(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes)); }
  catch { return null; }
}
// round-19 P1-01 — ONE Unicode byte-admission (§6), shared by the discovery resolver AND the byte-checker TCB, so
// authority material has ONE canonical Unicode domain (a BOM/surrogate that the byte checker rejects must not upgrade
// a document via discovery). (1) a leading UTF-8 BOM (EF BB BF) is REJECTED, not silently stripped — TextDecoder would
// alias two distinct byte-strings to one decoded object (M-BYTE injectivity). → { text } | { err:'BOM' } | { err:'UTF8' }.
export function admitUtf8(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (b.length >= 3 && b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF) return { err: 'BOM' };
  const t = strictUtf8(b);
  return t === null ? { err: 'UTF8' } : { text: t };
}
// (2) a JSON `\uD800` escape decodes to a JS string holding an UNPAIRED UTF-16 surrogate — not a Unicode SCALAR; other
// languages' canonicalizers replace/reject it, so it breaks language-neutral canon. Checked over the PARSED tree (keys +
// values), ITERATIVE (a recursive walk overflows on deep arrays before a depth guard runs — round-14 P2-01).
const hasLoneSurrogate = (s) => {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xDC00 && c <= 0xDFFF) return true;                                                   // unpaired low
    if (c >= 0xD800 && c <= 0xDBFF) { const n = s.charCodeAt(i + 1); if (!(n >= 0xDC00 && n <= 0xDFFF)) return true; i++; }   // unpaired high
  }
  return false;
};
export function anyLoneSurrogate(root) {
  const stack = [root];
  while (stack.length) {
    const v = stack.pop();
    if (typeof v === 'string') { if (hasLoneSurrogate(v)) return true; }
    else if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) stack.push(v[i]); }
    else if (v !== null && typeof v === 'object') { for (const k of Object.keys(v)) { if (hasLoneSurrogate(k)) return true; stack.push(v[k]); } }
  }
  return false;
}
// round-19 P1-02 — DEFENSIVE boundary admission (HARDENING, not a §14-domain fix). The math domain of the §14 totality
// theorem is the received document BYTES (model §I4: "a total deterministic function of `d`'s bytes"), and JSON.parse of
// bytes NEVER yields a Proxy / throwing accessor — every P1-02 repro passes an INTEGRATOR-supplied hostile object as
// opts/key-log/transport, not untrusted bytes, so this is not a reachable soundness bug. But the reference checker CLAIMS
// totality, so a caller record carrying a throwing accessor / Proxy trap maps to a STRUCTURED reject, never a host throw:
// snapshot OWN data via descriptors (getOwnPropertyDescriptor does NOT fire a getter), contained in try (a Proxy
// ownKeys/descriptor trap that throws → null). null/undefined → {} (the rev15 null-total default). → inert record | null.
function admitOpts(v) {
  if (v === undefined || v === null) return {};
  if (typeof v !== 'object') return null;
  try {
    const out = Object.create(null);                                             // round-20 P1-01 — null-proto: a JSON-native "__proto__" own key becomes plain own data, never a prototype swap
    for (const k of Reflect.ownKeys(v)) {
      if (typeof k === 'symbol') continue;                                        // string keys only (config is a string-keyed record)
      if (k === '__proto__' || k === 'prototype' || k === 'constructor') continue;   // round-20 P1-01 — never admit a key that could install inherited authority config (evidence must be an OWN admitted field of C — model ℐ_C)
      const d = Object.getOwnPropertyDescriptor(v, k);
      if (!d) continue;
      if (d.get || d.set) return null;                                            // an accessor is not an inert record field
      // rev39 R3 (round-31) — DEEP-admit each nested DATA value ONCE, closing the whole nested-untrusted-doc class at ONE
      // control: a resolver can no longer hold a live nested caller object (opts.genesis / config.checkpoint / a chain) to
      // re-read after verification. A FUNCTION is a capability (fetchImpl/substrateVerify) → preserved as-is; a
      // verifier-MINTED branded token (anchor/served/fresh/handle) → preserved by admitDeep; everything else is frozen inert.
      const val = (typeof d.value === 'function') ? d.value : admitDeep(d.value);
      if (val === ADMIT_REJECT) return null;                                      // a nested non-inert value (accessor at depth, non-plain proto, cycle) → the whole opts record is a structured reject
      Object.defineProperty(out, k, { value: val, writable: true, enumerable: true, configurable: true });   // defineProperty, never assignment through a legacy setter
    }
    return out;
  } catch { return null; }
}
// round-26 (rev24 Class C+D) — the ONE untrusted-input boundary. `admitDeep` takes a DEEP inert snapshot of a caller
// object: every value is read EXACTLY ONCE at snapshot time, so a live getter cannot return one value during signature
// verification and another during handle construction (the getter-TOCTOU that minted a genuine EvidenceHandle with
// UNSIGNED facts — round-26 P0-03). An accessor at ANY depth, a non-plain prototype, a cycle, or an over-deep graph is
// NOT an inert record → ADMIT_REJECT (the caller returns a structured malformed result, never a host throw or a
// second read). For JSON-sourced input (no getters) the snapshot is value-identical, so canon(admitDeep(x)) == canon(x)
// and no verdict changes. This is admitOpts made total + recursive; it dissolves malformed-non-null (C) and TOCTOU (D)
// at the same seam. `ADMIT_REJECT` is a module-private sentinel (never null — null is a legal admitted value).
const ADMIT_REJECT = Symbol('admit-reject');
// round-27 (canon-exactness, self-audit): admitDeep must be BYTE-TRANSPARENT to canon — for any x, `canon(admitDeep(x))`
// is the SAME bytes as `canon(x)`, and admitDeep REJECTS exactly what canon THROWS on — else the snapshot silently flips
// a verdict. canon throws on a function/symbol value, so admitDeep REJECTS it (an earlier DROP diverged). canon has NO
// depth cap (it recurses to the stack limit, bounded by the §13 transport size); so admitDeep has NONE either — an earlier
// depth-64 cap FALSE-REJECTED a valid deep `class:data` doc that canon accepts. Cycles are refused by the `seen` visited
// set; a pathological non-cyclic depth overflows the stack in BOTH canon and admitDeep and is caught as a structured reject.
export const admitDeep = (v, seen = new WeakSet()) => {   // THE input-boundary primitive — exported so its canon-transparency is TESTABLE (and a consumer can admit its own untrusted object)
  if (v === null) return null;
  const t = typeof v;
  if (t === 'function' || t === 'symbol') return ADMIT_REJECT;                         // canon throws on a function/symbol value → so do we (canon-exact); the only helper-carrying input (a keylog `prove` closure) is a BUILDER field, never passed as signed proof data
  if (t !== 'object') return v;                                                        // primitive scalar passes through
  if (HANDLE_BRAND.has(v) || VERIFIED_ANCHOR.has(v) || VERIFIED_SERVED.has(v) || VERIFIED_FRESH.has(v)) return v;   // round-27/31 — a verifier-MINTED brand (a verified handle, or an anchor/served/fresh token) is ALREADY a trusted inert snapshot: pass it through, never deep-copy off the brand (a copy loses the WeakSet identity the resolvers check). A caller cannot forge a brand, so this is sound; it lets admitOpts DEEP-admit nested data (round-31) without stripping branded tokens.
  if (seen.has(v)) return ADMIT_REJECT;                                                // cycle → refuse (total, never infinite); non-cyclic depth is unbounded, matching canon
  seen.add(v);
  try {
    if (Array.isArray(v)) {
      const out = new Array(v.length);                                                // round-28 P1-01 — PRESERVE holes + length (canon uses `.map`, which SKIPS holes); densifying to `undefined` diverged
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) continue;                                                       // a HOLE — leave it a hole (canon's `.map` skips it); do not densify
        const d = Object.getOwnPropertyDescriptor(v, i);
        if (d.get || d.set) return ADMIT_REJECT;                                       // no accessor elements (TOCTOU)
        const r = admitDeep(v[i], seen);
        if (r === ADMIT_REJECT) return ADMIT_REJECT;
        out[i] = r;
      }
      return Object.freeze(out);                                                       // non-index own props are ignored, exactly as canon's `.map` ignores them
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return ADMIT_REJECT;             // plain / null-proto ONLY (Date/Map/Set/class instances rejected — fail-closed per round-28 div2: stricter-than-canon means REJECT the whole input, never accept-and-rewrite)
    const out = Object.create(null);
    // round-28 P0-01 — the EXACT canon key domain: `Object.keys` (ENUMERABLE OWN STRING keys). This DROPS non-enumerable
    // keys and symbols (canon does too) and — critically — INCLUDES `__proto__`/`constructor`/`prototype` as OWN DATA
    // (dropping them let an attacker attach an unsigned member under those names and still get VALID — a false accept).
    // On a null-proto target these names are plain data via defineProperty; the verifier's exact-key grammar then REJECTS
    // the extra member (E-MALFORMED), never erases it. admitDeep must be NEVER LOOSER than canon.
    for (const k of Object.keys(v)) {
      const d = Object.getOwnPropertyDescriptor(v, k);
      if (d.get || d.set) return ADMIT_REJECT;                                         // a DECLARED accessor at ANY depth → not inert (round-26 TOCTOU closure)
      const r = admitDeep(v[k], seen);                                                 // rev32 R3 — read the VALUE through canon's OWN channel ([[Get]] / v[k]), NOT descriptor.value: a Proxy answering the descriptor one value and [[Get]] another must have its [[Get]] face (the one canon/contentHash read) snapshotted and verified, so a tampered get-face fails the signature instead of a signed descriptor-face passing (round-29 P0-01)
      if (r === ADMIT_REJECT) return ADMIT_REJECT;
      Object.defineProperty(out, k, { value: r, enumerable: true });                  // read-only own data (safe for __proto__ on a null-proto object)
    }
    return Object.freeze(out);
  } catch { return ADMIT_REJECT; }
  finally { seen.delete(v); }                                                          // a DAG (same object in sibling positions) is fine; only a true cycle is refused
};
// a caller-supplied array (key-log): a NATIVE array only; snapshot inside try so a Proxy length/index trap → null.
// null/undefined → [] (default). → inert array | null.
function admitArray(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return null;
  try { const out = []; const n = v.length; for (let i = 0; i < n; i++) out[i] = v[i]; return out; } catch { return null; }
}

// ─── producer: §7 seal — sign canon({ust,state}) with an Ed25519 private key ─────────────────────────
export function seal(state, privKeyObj, pubB64url) {
  // final protocol-law check (rc.12): a sealed transcript may NEVER exceed the ABS — fail closed
  // at the producer, not only at verifiers.
  {
    const sBytes = Buffer.byteLength(canon({ ust: '1.0', state }), 'utf8');
    if (sBytes > BOUNDS.sizeBytes) throw Object.assign(new Error(`E-BOUNDS: canonical transcript ${sBytes} B > ABS ${BOUNDS.sizeBytes}`), { code: 'E-BOUNDS' });
  }
  const doc = { ust: '1.0', state };
  const sig = edSign(null, Buffer.from(signedContent(doc), 'utf8'), privKeyObj).toString('base64url');
  return { ust: '1.0', state, sig: { alg: 'Ed25519', key_id: state.id.key_id, pub: pubB64url, sig } };
}

// ─── producer helpers: assemble a State with the per-partition `hashes` auto-computed (§4.4). `seal` signs it.
//     `id` = {domain_shard, ust_id, key_id[, parent_ust]}. `data` = {name: {kind,value} | {kind,privacy,commit,enc?}}.
export function buildState(id, time, data, provenance, opts) {
  // §13 capacity guard (rc.10): a producer never SILENTLY emits past its capacity. The anonymous
  // floor is 64; pass {maxPartitions} matching your genesis declaration to go higher (ABS 4096).
  const n = Object.keys(data).length;
  const cap = Math.min(Number(opts?.maxPartitions ?? BOUNDS.floorPartitions), BOUNDS.partitions);
  if (n > cap) throw Object.assign(
    new Error(`E-BOUNDS: ${n} partitions > ${cap} — declare {maxPartitions} matching your genesis max_partitions (§12.1; ABS ${BOUNDS.partitions})`),
    { code: 'E-BOUNDS' });
  const hashes = {};
  for (const [name, part] of Object.entries(data))
    hashes[name] = part.commit !== undefined ? partitionHash({ commit: part.commit })
      : partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value });
  const state = { id, time, data, hashes };
  if (provenance) state.provenance = provenance;
  // #69 E2 — the EXACT normative metric: UTF-8 bytes of the signed content canon({ust, state}). The sig is
  // NOT signed content, so no envelope pad (the old +300 over-counted → false rejects near the limit). This
  // is byte-identical to what seal()'s final ABS guard and the verifier's checkBounds measure — one metric.
  const stBytes = Buffer.byteLength(signedContent({ ust: '1.0', state }), 'utf8');
  const capB = Math.min(Number(opts?.maxTranscriptBytes ?? BOUNDS.floorSizeBytes), BOUNDS.sizeBytes);
  if (stBytes > capB) throw Object.assign(
    new Error(`E-BOUNDS: signed content ${stBytes} B > ${capB} — declare {maxTranscriptBytes} matching your genesis max_transcript_bytes (§12.1; ABS ${BOUNDS.sizeBytes})`),
    { code: 'E-BOUNDS' });
  return state;
}
export const buildAttestation = (id, time, data, constituents, prev) =>            // §9.2 constituents + Merkle root
  buildState({ ...id, class: 'attestation' }, time, data, { constituents, root: merkleRoot(constituents), ...(prev !== undefined ? { prev } : {}) });
export const buildDerivation = (id, time, data, basedOn, prev) =>                  // §9.3/§9.4 based_on + seed
  buildState({ ...id, class: 'derivation' }, time, data, { based_on: basedOn, seed: seed(basedOn.map(b => b.hash)), ...(prev !== undefined ? { prev } : {}) });
export const buildGenesis = (id, time, pub, maxPartitions, maxTranscriptBytes, cadence, checkpointAuthority, recovery) =>  // §12.1 self-signed name-binding root
  buildState({ ...id, class: 'genesis' }, time, { genesis: { kind: 'captured', value: {
    pub, role: 'name-binding-root',
    ...(maxPartitions !== undefined ? { max_partitions: String(maxPartitions) } : {}),           // §13 ladder (≠ ceiling; ABS 4096)
    ...(maxTranscriptBytes !== undefined ? { max_transcript_bytes: String(maxTranscriptBytes) } : {}), // §13 ladder (≠ ceiling; ABS 64 MiB)
    ...(cadence !== undefined ? { cadence: String(cadence) } : {}),                               // §11.3 C — SIGNED cadence (sec) → the expected grid; resolved not free-chosen (#69 C)
    // P1-04 — the genesis CARRIES its own checkpoint-authority + recovery set, so `authority_root` is RESOLVED from
    // the signed genesis, not a raw caller pin. `recovery.keys` is a {key_id: pub} map (each key_id = H(ust:keylog, pub)).
    ...(checkpointAuthority ? { checkpoint_authority: { key_id: checkpointAuthority.key_id, pub: checkpointAuthority.pub } } : {}),
    ...(recovery ? { recovery: { keys: recovery.keys, threshold: String(recovery.threshold) } } : {}),
  } } });
// P1-04 — resolve the checkpoint-authority + recovery roots FROM the signed genesis value (typed, key_id = keyId(pub)
// validated), never from a raw caller option. Returns {genesisAuthority?, recoveryKeys?, recoveryThreshold?} or null.
export function resolveCheckpointRoots(genesis) {
  // P0-2 (rc.35 audit) — roots are extracted ONLY from a VERIFIED, self-signed `class:"genesis"` document. Without this,
  // a raw unsigned object {state:{data:{genesis:{value:{checkpoint_authority}}}}} installed an ATTACKER checkpoint root
  // (authority_root:"genesis") and derived corroborated/attested freshness. Verify the doc BEFORE trusting its fields.
  const G = admitDeep(genesis); if (G === ADMIT_REJECT) return null;                   // round-27 P0-01 — snapshot ONCE: verify(G) and the .value extraction below read the SAME bytes (a getter can't return the signed authority during verify and an attacker authority on the extraction read)
  if (G?.state?.id?.class !== 'genesis' || !isValid(verify(G, { context: 'key' }))) return null;
  const gv = G?.state?.data?.genesis?.value; if (!gv) return null;
  const out = {};
  const ca = gv.checkpoint_authority;
  if (admitAuthorityKey(ca)) out.genesisAuthority = { key_id: ca.key_id, pub: ca.pub };   // round-36 — the ONE authority-key admission (exact { key_id, pub }, strict Pub32, key_id === keyId(pub))
  const rec = gv.recovery;
  if (rec && rec.keys && typeof rec.keys === 'object') {
    const keys = {}; let ok = true;
    for (const [kid, pub] of Object.entries(rec.keys)) { if (!admitAuthorityKey({ key_id: kid, pub })) ok = false; else keys[kid] = pub; }   // round-36 — each genesis recovery key is a usable { key_id === keyId(pub) } pair via the ONE primitive
    if (ok && Object.keys(keys).length) { const t = canonUint(rec.threshold); if (t !== undefined && t >= 1) { out.recoveryKeys = keys; out.recoveryThreshold = t; } }   // round-24 P0-02 — canonical decimal threshold ≥1 only; a coercible non-string (`["1"]`) no longer lowers the takeover threshold
  }
  return out;
}
// M2 (rc.35 refactor, UST-985) — the canonical genesis_epoch is DERIVED from the active genesis; the publisher can never
// choose the uniqueness namespace (epoch-split). Everything downstream reads this, never a body field.
export const genesisEpoch = (activeGenesis) => H('ust:genesis-epoch', activeGenesis);
// K2 (rc.37) — the ONE authority namespace is a function of the WHOLE verified genesis: scope_id =
// H('ust:authority-scope', contentHash(g)). Since active_genesis = contentHash(g), a single input suffices, and it
// binds domain + genesis key + checkpoint authority + recovery + capacity + cadence at once — nothing downstream can
// pick a namespace by choosing domain/epoch, because they are not in the preimage (and not transmitted). The old
// canon({domain, active_genesis, genesis_epoch}) triple was redundant (all three functions of contentHash) and
// weaker (bound 3 fields). `genesis_epoch` survives only as diagnostic metadata / the legacy wire field.
export const authorityScopeId = (activeGenesis) => H('ust:authority-scope', activeGenesis);

// ─── K3 (rc.37, UST-znh) — OPAQUE HANDLE REGISTRY. The topology rule: no public API past the first level accepts a
//     caller-NAMED `Verified*` object. A handle is a frozen value MINTED only inside this module and registered in a
//     module-private brand; downstream requires the brand, so a caller cannot construct one, serialize it, or rebuild
//     it from JSON. Four kinds: 'genesis' (VerifiedAuthorityContext), 'chain' (verified checkpoint chain +
//     PinnedCheckpointState), 'evidence' (image of VerifyEvidence_C), 'predicate-graph' (the proven atoms the
//     assembler reads). The round-2 WeakSet brand generalized to EVERY verified object — the runtime witness of
//     image-membership. `isVerifiedHandle(kind, x)` is the ONLY exported reader (a boolean; never a constructor).
const HANDLE_BRAND = new WeakSet(), HANDLE_KIND = new WeakMap();
// round-24 P0-01 — DEEP-freeze before branding. `Object.freeze` froze only the outer shell, so a caller holding a genuine
// branded handle could mutate a NESTED authority field (checkpoint_authority / recoveryKeys / authority_for_next) AFTER
// verification and have the same brand authorize attacker-signed checkpoints. The brand must prove the CONSUMED values are
// the verified values — freeze the whole tree (the isFrozen guard makes it terminating + cycle-safe).
// round-25 P0-03 — visited-set by WeakSet, NOT `Object.isFrozen`: a container that was ALREADY shallow-frozen (e.g.
// verifyEvidenceReceipt's `Object.freeze({...facts})`) must NOT stop the recursion, or its nested values stay mutable and
// a caller mutates a genuine EvidenceHandle after verification. Traverse every own value regardless; WeakSet is cycle-safe.
const deepFreeze = (o, seen = new WeakSet()) => { if (!o || typeof o !== 'object' || seen.has(o)) return o; seen.add(o); for (const k of Object.keys(o)) deepFreeze(o[k], seen); return Object.freeze(o); };
const mintHandle = (kind, obj) => { const h = deepFreeze(obj); HANDLE_BRAND.add(h); HANDLE_KIND.set(h, kind); return h; };
const isHandle = (kind, x) => x !== null && typeof x === 'object' && HANDLE_BRAND.has(x) && HANDLE_KIND.get(x) === kind;
export const isVerifiedHandle = (kind, x) => isHandle(kind, x);   // consumers may TEST provenance; they can never MINT it

// M2 — the SOLE producer of an authority SCOPE. verifyGenesis (§2.1 design record): verify the doc, then DERIVE the
// immutable scope {domain, active_genesis, genesis_epoch, scope_id}. Returns null iff the genesis does not verify as a
// self-signed class:"genesis"; otherwise the context every checkpoint/uniqueness/recovery predicate is a function of.
// K3: the returned context is a BRANDED, frozen GenesisHandle — the chain verifier requires the brand (a caller-shaped
// look-alike is rejected, closing round-3 P0-1).
export function verifiedGenesisContext(genesis) {
  const G = admitDeep(genesis); if (G === ADMIT_REJECT) return null;               // round-26 (rev24 D) — snapshot ONCE; the sig-verified genesis and the hashed/scoped genesis are the SAME bytes (no getter divergence)
  const roots = resolveCheckpointRoots(G);                                         // P0-2: verifies class:genesis + self-sig
  if (!roots) return null;
  const active_genesis = contentHash(G), domain = G.state?.id?.domain_shard;
  const genesis_epoch = genesisEpoch(active_genesis);                                // diagnostic / legacy wire only
  const scope_id = authorityScopeId(active_genesis);                                 // K2: scope binds the whole genesis
  return mintHandle('genesis', { scope_id, domain, active_genesis, genesis_epoch,
    checkpoint_authority: roots.genesisAuthority,
    ...(roots.recoveryKeys ? { recoveryKeys: roots.recoveryKeys, recoveryThreshold: roots.recoveryThreshold } : {}) });
}
export const buildKeyLogEntry = (id, time, keyOp, prev) =>                         // §12.2 add|rotate|revoke
  buildState({ ...id, class: 'key' }, time, { key_op: { kind: 'captured', value: keyOp } }, { prev });
export const buildCheckpoint = (id, time, head, frameCount, prev, interval) =>   // §11.3 M5 (interval = {from,to} for completeness, #69 C)
  buildState({ ...id, class: 'attestation' }, time, { checkpoint: { kind: 'computed', value: { head, frame_count: String(frameCount), ...(interval ? { from: interval.from, to: interval.to } : {}) } } }, { prev });
export const buildGap = (id, time, prev, reason) =>                               // §11.3 C2 — a signed gap record: this slot (id.ust_id) is HONESTLY absent
  buildState({ ...id, class: 'attestation' }, time, { gap: { kind: 'computed', value: { reason: reason || 'no-frame' } } }, { prev });
export const buildAbsence = (id, time, name, reason, extra = {}, prev) =>         // §4.4 #39 — a NEGATIVE observation: partition `name` asserts non-occurrence/unavailability (reason unreachable|no-event|unchanged); `extra` MAY carry {from,to} (the window a no-event covers) / subject
  buildState({ ...id, class: 'observation' }, time, { [name]: { kind: 'absence', value: { reason, ...extra } } }, prev ? { prev } : undefined);
export const buildCadenceEntry = (id, time, cadence, effectiveFrom, prev) =>      // §11.3 continuity — a signed cadence CHANGE (key-log pattern); resolved at a slot's time
  buildState({ ...id, class: 'cadence' }, time, { cadence_op: { kind: 'computed', value: { cadence: String(cadence), effective_from: effectiveFrom } } }, { prev });

// ─── reserved-key sets (§3/§4.2/§17) ─────────────────────────────────────────────────────────────────
const RESERVED = { transcript: ['ust','state','sig','proof'], state: ['id','time','data','hashes','provenance'],
  id: ['domain_shard','ust_id','key_id','class','parent_ust'], envelope: ['kind','value','privacy','commit','enc'],
  provenance: ['sources','constituents','based_on','root','seed','prev'], sig: ['alg','key_id','pub','sig'] };
// §17: "Reserved names MUST NOT be used as partition or source names" — the FULL registry, every level
// (the 11th audit found the old set enforced only state+id keys — a spec-impl mismatch).
const RES_PARTITION_NAMES = new Set([...RESERVED.transcript, ...RESERVED.state, ...RESERVED.id,
  ...RESERVED.envelope, ...RESERVED.provenance, ...RESERVED.sig, 'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
// §4.4 partition kinds: captured (observed), computed (derived), absence (#39 — a NORMATIVE NEGATIVE: 'source
// unreachable' / 'no-event' / 'value unchanged'). `absence` is machine-distinguishable from a captured-empty reading
// and from a not-published transcript. ABSENCE_REASONS is a RECOMMENDED (not closed) set — the value MUST carry a
// non-empty `reason`; publishers MAY use others, but a consumer branches on these three.
const KINDS = ['captured', 'computed', 'absence'], PRIVACY = ['blinded', 'encrypted'];   // §S4/D1: secret-url is a disclosure CHANNEL (§out-of-scope), not a privacy mode
const ABSENCE_REASONS = ['unreachable', 'no-event', 'unchanged'];
const AEAD_ALGS = ['AES-256-GCM', 'XChaCha20-Poly1305'], B64URL = /^[A-Za-z0-9_-]+$/;
// the verdict is tier-scoped (`VALID:LIGHT|HIGH|TOP`); this is the ONE place code should test "did it verify" —
// a bare `r.result === 'VALID'` is intentionally no longer valid (it forces callers to face the tier).
export const isValid = (r) => typeof r?.result === 'string' && r.result.slice(0, 6) === 'VALID:';
const CLASSES = ['observation','attestation','derivation','genesis','key','cadence'];
// §6 pinned RFC3339 UTC-Z with VALID RANGES — month 01-12, day 01-31, hour 00-23, min/sec 00-59.
// Rejects leap seconds (:60) and out-of-range (:99, hour 99) so two conforming verifiers ALWAYS agree (I4).
// Publishers MUST smear leap seconds to :59 (there is no representable :60).
const TS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
// §8 ust_id = ust:YYYYMMDD.HH[MM[SS]] as a VALID UTC frame — month 01-12, day 01-31, hour 00-23, min/sec 00-59 (F8).
const USTID = /^ust:\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\.([01]\d|2[0-3])(([0-5]\d)([0-5]\d)?)?$/;
// §14.5 semantic-consistency: a date must exist on the REAL calendar (Feb 31 / Apr 31 pass the range regex but are
// not dates). Round-trip through Date.UTC and require the components to survive — deterministic on every engine.
function calendarValid(y, mo, d) {
  const t = new Date(Date.UTC(+y, +mo - 1, +d));
  return t.getUTCFullYear() === +y && t.getUTCMonth() === +mo - 1 && t.getUTCDate() === +d;
}
const tsCalendarOk = (ts) => calendarValid(ts.slice(0, 4), ts.slice(5, 7), ts.slice(8, 10));
const ustIdCalendarOk = (u) => calendarValid(u.slice(4, 8), u.slice(8, 10), u.slice(10, 12));
// §4/§12 typed identity namespace: `domain_shard` is a NAME (dns) or a self-certifying KEY-ID. A key-form shard
// MUST equal `state.id.key_id` — the identity IS the signing key, and that equality is a checked obligation.
const KEYID_FORM = /^sha256:[0-9a-f]{64}$/;

// ─── §13 structural bounds — hard ceilings; exceed ⇒ E-BOUNDS ─────────────────────────────────────────
const BOUNDS = { depth: 8, array: 4096, partitions: 4096, floorPartitions: 64, breadth: 64, sizeBytes: 67108864, floorSizeBytes: 1048576, cadenceMax: 31622400,  // cadenceMax = 366 d in seconds (#75: bounded integer cadence)
  witnessEntries: 256, witnessActive: 16, anchorsPerGenesis: 8,  // round-20 P1-02 — F.9 structural fan-out budget: a body under the byte ceiling still bounds connector CALLS (≤ witnessActive × anchorsPerGenesis substrate invocations per resolution)
  forkCandidates: 64 };  // round-21 P1-02 — forkChoice candidate budget (a plain JSON array of N copies must not fan out into N verifications)
export function checkBounds(doc) {
  // #69 E3 — the normative VOLUME metric is the signed content canon({ust, state}), NOT the transport object:
  // sig/proof are bounded by transport admission (verifyJson maxInputBytes), never by the signed-content ABS.
  // Counting a large anchor proof here would falsely reject a valid signed content near 64 MiB.
  let signedBytes; try { signedBytes = Buffer.byteLength(signedContent(doc), 'utf8'); } catch { signedBytes = Buffer.byteLength(JSON.stringify(doc), 'utf8'); }
  if (signedBytes > BOUNDS.sizeBytes) return 'signed content > 64 MiB';
  if (doc.state?.data && Object.keys(doc.state.data).length > BOUNDS.partitions) return 'partitions > 4096';
  let bad = null;
  (function walk(v, d) {
    if (bad) return;
    if (d > BOUNDS.depth) { bad = 'depth > 8'; return; }
    if (Array.isArray(v)) { if (v.length > BOUNDS.array) { bad = 'array > 4096'; return; } for (const x of v) walk(x, d + 1); }
    else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], d + 1);
  })(doc.state ?? doc, 0);
  const pr = doc.state?.provenance;
  if (!bad && pr) for (const f of ['based_on', 'constituents']) if (Array.isArray(pr[f]) && pr[f].length > BOUNDS.breadth) bad = f + ' breadth > 64';
  return bad;
}

// ─── §14 Verification (LIGHT floor: steps 1,2,4,5,8 + §13 bounds). Returns the three-outcome result. ──
// opts: { requireVersion:'1.0', context:'data'|'key' } ; HIGH/TOP (steps 3,6,7) are separate, later.
// round-27 (3) — THE ONE INPUT BOUNDARY. `verify` (public) admits its untrusted `doc` ONCE at the door (a getter/accessor
// at any depth → E-MALFORMED; `admitDeep` is canon-exact so a legit doc is byte-transparent) and hands an inert snapshot to
// `verifyCore`. INTERNAL machinery that already holds an admitted/getter-free object (verifyAsync's JSON snapshot + the
// substrate-receipt identity shim, forkChoice) calls `verifyCore` directly — so the door snapshot does not re-clone inside
// the hot core and break the internal identity coupling. One place admits; the core trusts. This is the single seat.
export function verify(doc, opts = {}) {
  const D = admitDeep(doc);
  if (D === ADMIT_REJECT) return bad('E-MALFORMED', 'document is not an inert record — an accessor/getter cannot sign one payload and disclose another (round-27: the ONE input boundary)');
  const verdict = verifyCore(D, opts);
  // rev32 R3 (non-bypass output) — EMIT id(x̂): the content hash of the ADMITTED snapshot the verdict is about. A consumer
  // addresses the transcript by THIS returned id (a projection of the admitted artifact), never by re-hashing the raw input
  // `doc` — so a live/mutable/Proxy object that shows one face to `verify` and another to a later `contentHash(doc)` cannot
  // split the verdict from the identity. The verdict and the id come from the SAME single admission.
  let id; try { if (D && typeof D === 'object' && D.state !== undefined) id = contentHash(D); } catch { /* malformed → no addressable id */ }
  return id === undefined ? verdict : { ...verdict, id };
}
function verifyCore(doc, opts = {}) {
  try {
    // step 1 — structural admission (§14.1)
    if (typeof doc !== 'object' || doc === null) return bad('E-MALFORMED', 'not an object');
    if (doc.ust === undefined || doc.state === undefined || doc.sig === undefined) return bad('E-MALFORMED', 'missing ust/state/sig');
    if (doc.ust !== '1.0') return bad('E-MALFORMED', 'unknown version ' + doc.ust);   // §19 (this verifier is 1.0)
    // §4.1 top-level is EXACTLY {ust,state,sig,proof} — REJECT unknown members (fail-closed). An "ignore unknown"
    // rule would reopen the K1/F2 class: an unsigned member riding next to a VALID verdict.
    for (const k of Object.keys(doc)) if (!RESERVED.transcript.includes(k)) return bad('E-MALFORMED', 'unknown top-level member: ' + k);
    const bnd = checkBounds(doc); if (bnd) return bad('E-BOUNDS', bnd);               // §13 bounds
    const st = doc.state;
    for (const k of Object.keys(st)) if (!RESERVED.state.includes(k)) return bad('E-MALFORMED', 'reserved-key: state.' + k);
    if (!st.id || !st.time || !st.data || !st.hashes) return bad('E-MALFORMED', 'state missing id/time/data/hashes');
    for (const k of Object.keys(st.id)) if (!RESERVED.id.includes(k)) return bad('E-MALFORMED', 'reserved-key: id.' + k);
    // §I3 partition NAME non-reserved (defense-in-depth) + envelope-key + kind/privacy registry (§4.4)
    for (const name of Object.keys(st.data)) {
      if (RES_PARTITION_NAMES.has(name)) return bad('E-MALFORMED', 'reserved partition name: ' + name);
      const part = st.data[name];
      for (const k of Object.keys(part)) if (!RESERVED.envelope.includes(k)) return bad('E-MALFORMED', 'reserved-key: data.' + name + '.' + k);
      // §4.4 CLOSED per-mode schema: `kind` (captured|computed) is REQUIRED for EVERY partition — a private value
      // was still captured-or-computed; a partition with no kind is malformed, not "private enough to skip."
      if (!KINDS.includes(part.kind)) return bad('E-MALFORMED', 'unknown partition kind: ' + name + '.' + part.kind);
      // §4.4 #39 — a PUBLIC absence assertion MUST name WHY it is absent (non-empty `value.reason`), so 'source down'
      // can never be silently confused with 'source returned empty' (a captured partition with an empty value). A
      // private (blinded/encrypted) absence carries its reason inside the sealed value, so the plain check is skipped.
      if (part.kind === 'absence' && part.privacy === undefined && (typeof part.value?.reason !== 'string' || part.value.reason.length === 0))
        return bad('E-MALFORMED', 'absence partition requires a non-empty value.reason: ' + name);
      if (part.privacy !== undefined && !PRIVACY.includes(part.privacy)) return bad('E-MALFORMED', 'unknown privacy mode: ' + name + '.' + part.privacy);
      // §4.4 CLOSED envelope variants — ENFORCE the public/private XOR, not just the key allowlist (self-audit rc.35,
      // agent-found P0/P2). The per-partition hash is taken over `commit` WHENEVER present, so a PUBLIC partition that
      // also carried a `commit` would bind the hash to the commit while DISPLAYING an unrelated `value` — "what you see
      // ≠ what is signed", and two verifiers (mode-by-commit vs mode-by-privacy) disagree (I4). So: PUBLIC (no privacy)
      // MUST carry `value` and MUST NOT carry `commit`/`enc`; PRIVATE MUST carry `commit` and MUST NOT carry a plaintext `value`.
      if (part.privacy === undefined) {
        if (part.commit !== undefined || part.enc !== undefined) return bad('E-MALFORMED', 'public partition must not carry commit/enc (§4.4 public = {kind,value}): ' + name);
        if (part.value === undefined) return bad('E-MALFORMED', 'public partition requires value (§4.4): ' + name);
      } else {
        if (part.commit === undefined) return bad('E-MALFORMED', 'private partition requires commit (§4.4): ' + name);
        if (part.value !== undefined) return bad('E-MALFORMED', 'private partition must not carry a plaintext value (§4.4): ' + name);
      }
    }
    // step 2 — canonical, content_hash, bijection, per-partition hashes (§14.2, G19, §4.4)
    let S; try { S = signedContent(doc); } catch (e) { return bad('E-CANON', e.detail || 'canon'); }
    const ch = H('ust:state', S);
    const dk = Object.keys(st.data).sort(), hk = Object.keys(st.hashes).sort();
    if (dk.length !== hk.length || dk.some((k, i) => k !== hk[i])) return bad('E-MALFORMED', 'hashes⇄data not a bijection (G19)');
    for (const name of dk) {
      const part = st.data[name];
      let recomputed;
      try {
        recomputed = part.commit !== undefined
          ? partitionHash({ commit: part.commit })
          : partitionHash({ domain_shard: st.id.domain_shard, ust_id: st.id.ust_id, name, value: part.value });
      } catch (e) { return bad('E-CANON', 'partition canon: ' + name); }
      if (recomputed !== st.hashes[name]) return bad('E-CANON', 'partition hash mismatch: ' + name, { obligation: '§4.4 partition-hash', partition: name, expected: st.hashes[name], actual: recomputed });
    }
    // step 5 — well-formed shape + SEMANTIC consistency (§14.5): shape regex AND real-calendar existence AND
    // cross-field invariants — local shape alone let "Feb 31" through (audit E, M-02).
    if (!USTID.test(st.id.ust_id)) return bad('E-MALFORMED', 'ust_id shape');
    if (!ustIdCalendarOk(st.id.ust_id)) return bad('E-MALFORMED', 'ust_id date not on the calendar');
    if (!TS.test(st.time.generated_at) || !TS.test(st.time.valid_from) || !TS.test(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp not pinned RFC3339-Z');
    for (const t of [st.time.generated_at, st.time.valid_from, st.time.valid_to])
      if (!tsCalendarOk(t)) return bad('E-MALFORMED', 'timestamp date not on the calendar: ' + t);
    if (st.time.valid_from > st.time.valid_to) return bad('E-MALFORMED', 'valid_from > valid_to');
    // §4/§12 typed identity: a key-form domain_shard is SELF-CERTIFYING and MUST equal the signing key_id —
    // claiming ANOTHER key's shard is malformed (the identity IS the key; the equality is an obligation).
    const shardMode = KEYID_FORM.test(st.id.domain_shard) ? 'key' : 'name';
    if (shardMode === 'key' && st.id.domain_shard !== st.id.key_id) return bad('E-MALFORMED', 'key-form domain_shard != key_id (self-certifying identity must be the signing key)');
    // §4.3a #40 HOMOGRAPH GUARD — a name-form domain_shard MUST be an A-label: ASCII only (punycode `xn--` for IDN),
    // never raw Unicode. 'аpple.com' (Cyrillic а, U+0430) renders identically to 'apple.com' but is a DIFFERENT
    // string — a homograph genesis would impersonate a name to a human reading the verdict. Rejecting U-labels means
    // a consumer sees either plain ASCII or a visibly-distinct `xn--…`, never deceptive glyphs. (NFC alone does NOT
    // catch this: U+0430 is a single, already-NFC code point.) The floor stays light — no confusables table needed.
    if (shardMode === 'name' && /[^\x00-\x7f]/.test(st.id.domain_shard))
      return bad('E-MALFORMED', 'name-form domain_shard must be an A-label (ASCII; punycode xn-- for IDN), not raw Unicode glyphs (homograph guard)', { obligation: '§4.3a name-form A-label' });
    // §13 capacity ladder (rc.10): ≤64 = the anonymous floor, admissible for everyone (LIGHT-anywhere).
    // Above it, capacity is EARNED BY CEREMONY: a name-form shard admits up to its genesis-declared
    // max_partitions (≤ ABS 4096). A key-form identity can hold no ceremony → the floor is its law.
    // Without the capacity-bearing genesis the question cannot complete → INDETERMINATE('unavailable'),
    // never INVALID (violation unprovable) and never VALID (floor unpassable) — the honest tier ladder.
    // §13 NORMATIVE size metric (rc.12): UTF-8 bytes of the SIGNED CONTENT canon({ust,state}) — the
    // string S already computed for the hash. Transport formatting can never flip a verdict (P0-3).
    const sBytes = Buffer.byteLength(S, 'utf8');
    if (sBytes > BOUNDS.sizeBytes) return bad('E-BOUNDS', `canonical transcript ${sBytes} B > 64 MiB ABS`);
    // verifier CAPABILITY ceiling (rc.12): protocol-valid but beyond THIS verifier ⇒ honest refusal.
    if (opts.maxSupportedBytes && sBytes > Number(opts.maxSupportedBytes))
      return { result: 'INDETERMINATE', reason: 'resource_limit', detail: `canonical transcript ${sBytes} B > this verifier's capability ${opts.maxSupportedBytes} B` };
    if (dk.length > BOUNDS.floorPartitions || sBytes > BOUNDS.floorSizeBytes) {
      const over = dk.length > BOUNDS.floorPartitions
        ? `partitions ${dk.length} > ${BOUNDS.floorPartitions}` : `canonical size ${sBytes} B > 1 MiB`;
      if (shardMode === 'key') return bad('E-BOUNDS', `${over} anonymous floor (key-form identity cannot declare capacity)`);
      // Capacity is a TRUSTED GRANT (rc.12, P0-4): the caller passes opts.capacity AFTER establishing
      // authority (resolveAuthority → .capacity, or a pin/policy). A raw caller-supplied genesis no
      // longer expands anything — a self-signed genesis was a self-issued budget.
      const cap = opts.capacity ?? {};
      if (dk.length > BOUNDS.floorPartitions) {
        const granted = Number(cap.maxPartitions ?? NaN);
        if (!Number.isInteger(granted) || granted < 1 || granted > BOUNDS.partitions)
          return { result: 'INDETERMINATE', reason: 'unavailable', detail: `${over} floor — no trusted capacity grant for ${st.id.domain_shard} (resolve authority, then pass opts.capacity)` };
        if (dk.length > granted) return bad('E-BOUNDS', `partitions ${dk.length} > granted ${granted}`);
      }
      if (sBytes > BOUNDS.floorSizeBytes) {
        const grantedB = Number(cap.maxTranscriptBytes ?? NaN);
        if (!Number.isInteger(grantedB) || grantedB < 1 || grantedB > BOUNDS.sizeBytes)
          return { result: 'INDETERMINATE', reason: 'unavailable', detail: `canonical size ${sBytes} B > 1 MiB floor — no trusted capacity grant for ${st.id.domain_shard}` };
        if (sBytes > grantedB) return bad('E-BOUNDS', `canonical size ${sBytes} B > granted ${grantedB}`);
      }
    }
    if (!CLASSES.includes(st.id.class)) return bad('E-MALFORMED', 'unknown class ' + st.id.class);
    if (dk.length < 1) return bad('E-MALFORMED', 'no partition');
    const HASH = /^sha256:[0-9a-f]{64}$/;
    for (const name of dk) {                                            // §S4/F5 — private partition schema
      const part = st.data[name];
      if (part.privacy !== undefined) {
        if (!HASH.test(part.commit || '')) return bad('E-MALFORMED', 'private partition commit not sha256:hex: ' + name);
        if (part.privacy === 'encrypted') {                             // encrypted MUST carry a well-formed AEAD block
          const e = part.enc;
          if (!e || !AEAD_ALGS.includes(e.alg) || typeof e.key_id !== 'string' || !B64URL.test(e.ct || '')) return bad('E-MALFORMED', 'encrypted partition missing/invalid enc{alg,key_id,ct}: ' + name);
        }
      } else if (part.value === undefined) return bad('E-MALFORMED', 'public partition without value: ' + name);
    }
    // §S4/F4 — class ↔ provenance consistency (§14.5, MUST). A signed gap record is the ONLY attestation whose
    // constituents may be empty (class:attestation + provenance.prev; §14 step 5).
    const pr = st.provenance;
    if (st.id.class === 'observation' && (pr?.constituents !== undefined || pr?.root !== undefined)) return bad('E-MALFORMED', 'observation MUST NOT carry constituents/root');
    if (st.id.class === 'derivation' && (pr?.based_on === undefined || pr?.seed === undefined)) return bad('E-MALFORMED', 'derivation MUST carry based_on + seed');
    // §11.3 continuity — a cadence entry is the key-log pattern for the stream CADENCE: prev-chained, carrying a
    // cadence_op {cadence, effective_from}. Resolved at a slot's time, so a cadence CHANGE never invalidates old
    // data (old slots verify under the cadence in force AT THEIR time) — the "no operator change breaks history" law.
    if (st.id.class === 'cadence' && (pr?.prev === undefined || st.data?.cadence_op === undefined)) return bad('E-MALFORMED', 'cadence entry MUST carry provenance.prev + a cadence_op partition (§11.3)');
    if (st.id.class === 'attestation') {
      // #69 C2 — an empty-constituents attestation used to be a bare shape (prev + no constituents), which
      // COLLIDED a checkpoint with a gap record (same shape, different meaning). The subtype is now EXPLICIT via
      // a required, named data partition (UST idiom: the partition name IS the typed content): a `set` attestation
      // carries constituents + root; a prev-only attestation MUST be EITHER a `checkpoint` (data.checkpoint) OR a
      // `gap` (data.gap) — never neither, never both, never with a root.
      const empty = pr?.constituents === undefined || pr.constituents.length === 0;
      if (empty) {
        if (pr?.prev === undefined) return bad('E-MALFORMED', 'a no-constituents attestation MUST carry provenance.prev (checkpoint or gap, §11.3)');
        if (pr?.root !== undefined) return bad('E-MALFORMED', 'a checkpoint/gap attestation MUST NOT carry a root');
        const hasCp = st.data?.checkpoint !== undefined, hasGap = st.data?.gap !== undefined;
        if (hasCp === hasGap) return bad('E-MALFORMED', 'a prev-only attestation MUST be a checkpoint (data.checkpoint) XOR a gap (data.gap) — the §11.3 subtype, never both/neither');
      } else if (pr?.root === undefined) return bad('E-MALFORMED', 'a set attestation MUST carry constituents + root');
    }
    // W3 class-context: a data verify must not accept a key-log/genesis transcript as data
    if (opts.context === 'data' && (st.id.class === 'key' || st.id.class === 'genesis' || st.id.class === 'cadence')) return bad('E-MALFORMED', 'class ' + st.id.class + ' not valid in data context (W3)');
    // step 4 — authenticity (§14.4): closed sig schema + declared alg + key_id consistency + strict Ed25519 over S
    if (typeof doc.sig !== 'object' || doc.sig === null) return bad('E-SIG', 'sig missing');
    for (const k of Object.keys(doc.sig)) if (!RESERVED.sig.includes(k)) return bad('E-SIG', 'unknown sig member: ' + k);
    if (doc.sig.alg !== 'Ed25519') return bad('E-SIG', 'sig.alg must be Ed25519');
    if (doc.sig.key_id !== st.id.key_id) return bad('E-SIG', 'sig.key_id != state.id.key_id');
    if (doc.sig.pub === undefined) return bad('E-KEY', 'no carried pub (LIGHT)');
    // #75 P1-02 — STRICT unpadded base64url of EXACT length: Node's base64url decode ignores padding / stray chars,
    // so `sig + '='` or non-alphabet bytes verify identically. Reject anything whose canonical re-encode differs.
    if (strictB64url(doc.sig.pub, 32) === null) return bad('E-SIG', 'sig.pub is not canonical unpadded base64url of a 32-byte Ed25519 key', { obligation: '§14.4 sig encoding' });
    if (strictB64url(doc.sig.sig, 64) === null) return bad('E-SIG', 'sig.sig is not canonical unpadded base64url of a 64-byte Ed25519 signature', { obligation: '§14.4 sig encoding' });
    if (keyId(doc.sig.pub) !== st.id.key_id) return bad('E-SIG', 'key_id != H(ust:keylog, pub)', { obligation: '§4.2 key_id-binding', expected: st.id.key_id, actual: keyId(doc.sig.pub) });
    if (!edVerifyStrict(doc.sig.pub, S, doc.sig.sig)) return bad('E-SIG', 'Ed25519 verify failed', { obligation: '§14.2 whole-state-signature' });
    // #75 ROOT 1 — TWO-PHASE: verify the anchor FIRST so its PROVEN time flows INTO authority resolution below
    // (revocation / retirement / freshness / the K_n(t) window are judged against the proven upper bound, not a
    // caller-supplied or absent anchorTime — the P0-01 gap). §S3/F3: an EMBEDDED proof MUST verify (present-but-bad
    // ⇒ E-ANCHOR, never a VALID doc beside an unchecked proof); the availability STATUS is carried, never flattened.
    let timeField = { strength: 'unproven', status: 'none' };
    if (doc.proof !== undefined) {
      const a = verifyAnchorCore(ch, doc.proof, opts);   // internal: doc.proof already admitted at the verify door
      if (!a.inclusion) return bad('E-ANCHOR', a.detail || 'embedded proof does not verify');
      // §14.6 N9 — a document cannot be generated AFTER the anchor that contains it (pinned RFC3339-Z compare as instants).
      if (a.time === 'anchored' && a.anchorTime && st.time.generated_at > a.anchorTime)
        return bad('E-ANCHOR', 'generated_at after the anchor time (N9: the document postdates its own anchor)');
      timeField = { strength: a.time, status: a.status, inclusion: true, ...(a.anchorTime ? { anchorTime: a.anchorTime } : {}), ...(a.assurance ? { assurance: a.assurance } : {}) };
    }
    const provenAnchorTime = timeField.strength === 'anchored' ? timeField.anchorTime : undefined;   // the proven upper bound U (else undefined)
    // step 3 — name authority (§14.3): HIGH resolves genesis+key-log; else a PINNED key (TOFU, §3.1) if the caller
    // supplies pinnedKeys — a key NOT in the pin set is INVALID (that is what pinning means); else self-asserted.
    // round-16 P0-01 — ONLY the PROVEN anchor time feeds the K_n(t) query; a raw caller `opts.anchorTime` is NOT a
    // proven upper bound and must never become the coordinate (it made a retired-key doc VALID:HIGH with a forged/absent
    // string while the honest late U rejected it). No proof ⇒ U is undefined ⇒ a closed key lifecycle fails closed.
    let identity;
    if (opts.genesis) identity = resolveAuthority(doc, { ...opts, anchorTime: provenAnchorTime !== undefined ? provenAnchor(provenAnchorTime) : undefined });   // round-17 P0-02 — mint a proven-anchor TOKEN; a raw opts.anchorTime is dropped and can never reach K_n(t)
    else if (opts.pinnedKeys) identity = opts.pinnedKeys.includes(st.id.key_id)
      ? { strength: 'pinned', status: 'verified' }
      : { error: 'E-KEY', detail: 'key_id not in the pinned set (§3.1 TOFU)' };
    else identity = { strength: 'self-asserted', status: 'verified' };
    if (identity.error) return bad(identity.error, identity.detail);              // forked genesis / broken key-log / not pinned
    if (opts.requireAuthoritative && !(identity.strength === 'authoritative' && identity.status === 'verified'))
      return identity.status === 'unavailable'
        ? { result: 'INDETERMINATE', reason: 'unavailable', identity, detail: identity.detail }   // W1: retry, NOT failure
        : bad('E-GENESIS', 'authoritative required but ' + identity.strength + '/' + identity.status);
    // §12.2a #40 — a consumer that needs a CURRENT key-log (revocation may have propagated) sets requireFreshKeylog:
    // an `unverified` freshness (a possibly-stale cache) ⇒ INDETERMINATE (retry: re-fetch the key-log from the
    // authoritative discovery surface or supply a VERIFIED keylogHeadAnchor), NEVER a silent accept on a stale view.
    if (opts.requireFreshKeylog && identity.freshness === 'unverified')
      return { result: 'INDETERMINATE', reason: 'stale_keylog', identity, detail: 'key-log freshness unverified (possibly-stale cache); re-fetch from authoritative discovery or supply a verified keylogHeadAnchor (§12.2a)' };
    // step 8 — privacy (§14.8/§10): if the caller discloses {nonce,value}, REPRODUCE the commit; for
    // `encrypted`, AEAD-decrypt must reproduce the SAME committed plaintext (E-COMMIT on mismatch). Never brute-force.
    const disclosed = [];
    for (const name of dk) {
      const part = st.data[name];
      if (part.privacy === undefined) continue;
      const disc = opts.disclosures?.[name];
      if (!disc) continue;                                                // not authorized — commit stands, opaque
      const reproduced = blindedCommit({ domain_shard: st.id.domain_shard, ust_id: st.id.ust_id, name, value: disc.value, nonce: disc.nonce });
      if (reproduced !== part.commit) return bad('E-COMMIT', 'blinded commit mismatch: ' + name);
      if (part.privacy === 'encrypted' && part.enc && opts.decKeys?.[part.enc.key_id]) {
        const pt = aeadDecrypt(part.enc, opts.decKeys[part.enc.key_id]);  // → canon({nonce,<p>:value}) plaintext
        if (pt === 'unsupported')                                          // §17 MTI: optional alg ⇒ cannot decide, NOT invalid
          return { result: 'INDETERMINATE', reason: 'unsupported_alg', detail: 'AEAD ' + part.enc.alg + ' is OPTIONAL and not implemented by this verifier: ' + name };
        if (pt === null || pt !== canon({ nonce: disc.nonce, partition: name, value: disc.value })) return bad('E-COMMIT', 'AEAD↔commit mismatch: ' + name);
      }
      disclosed.push(name);
    }
    // step 9 — provenance (§14.9): bound source identity (§9.1, I8). A source with a verifiable `src_sig`
    // (the source's own signature over its `addr`) is AUTHENTICATED; without one it is an operator LABEL —
    // marked `unauthenticated`, and a consumer MUST NOT surface it as source attribution.
    const sources = {};
    if (st.provenance?.sources) for (const [sid, s] of Object.entries(st.provenance.sources)) {
      const key = opts.sourceKeys?.[sid];
      sources[sid] = (key && s.src_sig && edVerifyStrict(key, s.addr, s.src_sig)) ? 'authenticated' : 'unauthenticated';
    }
    // §14.9/§14a OBLIGATIONS TABLE — every commitment-bearing provenance member carries a RECOMPUTE obligation.
    // No member may be "present but unchecked" (audit E: the root was checked while the seed was not — the
    // asymmetry class this table abolishes). Shapes first, then recomputes:
    const HASHREF = /^sha256:[0-9a-f]{64}$/;
    if (pr?.constituents !== undefined) {
      if (!Array.isArray(pr.constituents) || pr.constituents.some((h) => !HASHREF.test(h))) return bad('E-MALFORMED', 'constituents must be sha256:hex content_hashes');
      if (new Set(pr.constituents).size !== pr.constituents.length) return bad('E-MALFORMED', 'duplicate hash in constituents (double-counts the Merkle root, §9.4)');
      if (pr.root !== undefined && merkleRoot(pr.constituents) !== pr.root) return bad('E-ROOT', 'attestation root mismatch', { obligation: '§9.4 attestation-root', expected: pr.root, actual: merkleRoot(pr.constituents) });
    }
    if (pr?.based_on !== undefined) {
      if (!Array.isArray(pr.based_on) || pr.based_on.some((b) => !b || !HASHREF.test(b.hash || ''))) return bad('E-MALFORMED', 'based_on entries must carry sha256:hex `hash`');
      if (new Set(pr.based_on.map((b) => b.hash)).size !== pr.based_on.length) return bad('E-MALFORMED', 'duplicate hash in based_on (citing a referent twice has no composite meaning, §9.4)');
      if (seed(pr.based_on.map((b) => b.hash)) !== pr.seed) return bad('E-SEED', 'derivation seed != H(ust:seed, canon(based_on hashes))', { obligation: '§9.4 derivation-seed', expected: pr.seed, actual: seed(pr.based_on.map((b) => b.hash)) });
    }
    if (pr?.prev !== undefined && !HASHREF.test(pr.prev)) return bad('E-MALFORMED', 'prev must be a sha256:hex content_hash');
    // §14.9 bounded referent walk (I14: depth-0 default). The RESULT always reports how deep verification went —
    // a consumer can see `referents:'unverified'` instead of assuming the chain was walked (audit E, H-04).
    let provenanceReport = { depth: 0, referents: (pr?.based_on?.length || pr?.constituents?.length) ? 'unverified' : 'none' };
    if (opts.provenanceDepth > 0 && typeof opts.resolveRef === 'function') {
      // §13 P4: a GLOBAL verified-node budget (default 256, opts.refBudget) — exhaustion fails the WHOLE
      // walk (E-BOUNDS), never a partial success, so traversal order cannot affect any verdict (I4).
      const refBudget = { left: Number(opts.refBudget) > 0 ? Math.floor(Number(opts.refBudget)) : 256 };
      const walked = walkReferents(st, opts, Math.min(opts.provenanceDepth, BOUNDS.depth), new Set([ch]), refBudget);
      if (walked.error) return bad(walked.error, walked.detail);
      provenanceReport = { depth: walked.depth, referents: walked.referents };
    }
    // §Y3: `domain_shard` is surfaced as `publisher` ONLY at `authoritative` strength; otherwise it is a
    // self-asserted/pinned LABEL — `publisher_claimed` — so a consumer that never read Y3 cannot over-attribute.
    // (Pinning authenticates the KEY, not the name.)
    // P0-2 audit — a raw `consumer-override` reaches the name-authoritative TIER only when the consumer CONSCIOUSLY
    // honors its own out-of-band assertion (opts.acceptConsumerOverride); the verdict still carries independently_verified:false.
    const nameAuthoritative = identity.strength === 'authoritative' || (identity.strength === 'consumer-override' && opts.acceptConsumerOverride && identity.status === 'verified');
    const nameField = nameAuthoritative ? { publisher: st.id.domain_shard } : { publisher_claimed: st.id.domain_shard };
    // (the anchor was verified in phase 1 above; `timeField`/`provenAnchorTime` already carry its proven time.)
    // The verdict CARRIES ITS SCOPE: `VALID:LIGHT|HIGH|TOP`, so a consumer cannot read "valid" without reading
    // valid-AT-WHAT (a bare `=== 'VALID'` no longer matches — the same forcing function as publisher_claimed).
    // tier = the highest fully-satisfied rung (monotonic, §3.1). The NAME is bound to the key at both `corroborated`
    // and `authoritative` (§12.1a F.5a) — both reach HIGH. The no-fork STRENGTH separates them: only `authoritative`
    // (independent non-membership) reaches TOP, so an anchored-but-only-corroborated name never overclaims TOP.
    const verified = identity.status === 'verified';
    const authoritative = nameAuthoritative && verified;
    // §3.1/§15 — TOP = authoritative identity + anchored time. HIGH = name-bound (corroborated or authoritative).
    // Stream COMPLETENESS is a separate RANGE verdict (verifyStream), never a single-document claim.
    // P1-03/C3 — ONE assembler: verify() maps the consumer-override π_override projection (an explicit consumer
    // axiom, applied BEFORE assembly — never a hidden boolean inside it) and hands the SEAM VERDICTS to
    // deriveAssurance; the lattice IS the machine (no second inline tier formula).
    const idVerdict = (identity.strength === 'consumer-override' && nameAuthoritative) ? { ...identity, strength: 'authoritative' } : identity;
    const report = deriveAssurance(sealPredicateGraph(provePredicates({ identity: idVerdict, anchor: doc.proof !== undefined ? { inclusion: timeField.inclusion === true, time: timeField.strength } : undefined })));   // round-25 P0-01: verify() is the ONLY seat that seals the graph — over REAL seam verdicts, never caller labels
    const assurance = report.strength;
    const tier = report.tier;
    // §3.1/F.5b DOWNGRADE RESISTANCE — the symmetric floor to requireAuthoritative. A consumer requiring TOP
    // MUST reject anything the evidence proves below TOP, NEVER silently accept a lower tier (stripping the anchor
    // can only LOWER the tier, W1: it cannot forge upward). The rejection NAMES the missing coordinate: a
    // non-authoritative identity fails the name axis first (E-GENESIS / INDETERMINATE-on-unavailable, as
    // requireAuthoritative); an authoritative doc with NO proof attached is a structural downgrade (E-ANCHOR); a
    // proof that is PRESENT + inclusion-valid but whose substrate is unreachable / not-yet-buried is retryable,
    // not a forgery (INDETERMINATE). (A malformed / non-reaching proof already returned E-ANCHOR above, ln 410.)
    if (opts.requireAnchored && tier !== 'TOP') {
      if (!authoritative)
        return identity.status === 'unavailable'
          ? { result: 'INDETERMINATE', reason: 'unavailable', identity, detail: identity.detail }
          : bad('E-GENESIS', 'anchored (TOP) required but identity is ' + identity.strength + '/' + identity.status);
      if (doc.proof === undefined)
        return bad('E-ANCHOR', 'anchored (TOP) required but no anchor proof is attached (downgrade rejected)');
      return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'anchored (TOP) required; proof present but substrate is ' + timeField.status + '/' + timeField.strength + ' — retry' };
    }
    return { result: 'VALID:' + tier, tier, assurance, identity: { ...identity, mode: shardMode }, disclosed, sources, ...nameField,
      ...(identity.noFork ? { no_fork: identity.noFork } : {}),
      ust_id: st.id.ust_id, class: st.id.class, content_hash: ch, time: timeField, provenance: provenanceReport,
      completeness: 'not_evaluated' };
  } catch (e) {
    return bad(e.code || 'E-MALFORMED', e.detail || String(e));         // fail-closed (§14/I10)
  }
}

// ─── §14.9 bounded referent walk (I14): resolve each based_on/constituents hash via the caller's resolver,
//     verify each referent (context:'data'), recurse to `depth`, visited-set ⇒ E-CYCLE, bounds ⇒ E-BOUNDS.
//     A hash the resolver cannot supply leaves referents:'partial' (availability ≠ failure); a resolved referent
//     that verifies INVALID is a REAL failure. Returns {depth, referents} or {error, detail}.
function walkReferents(st, opts, depth, visited, budget) {
  const refs = [...(st.provenance?.constituents ?? []), ...(st.provenance?.based_on ?? []).map((b) => b.hash)];
  if (!refs.length) return { depth: 0, referents: 'none' };
  let sawUnresolved = false, reached = 1;
  for (const h of refs) {
    if (visited.has(h)) return { error: 'E-CYCLE', detail: 'referent cycle at ' + h };
    if (visited.size > BOUNDS.array) return { error: 'E-BOUNDS', detail: 'referent walk exceeds bounds (§13)' };
    const rawRef = opts.resolveRef(h);
    if (!rawRef) { sawUnresolved = true; continue; }
    // rev35 R3 (round-30 P0-02) — ADMIT the resolved referent ONCE and verify + RECURSE over that SAME frozen snapshot.
    // Previously verify(refDoc) ran, then the walk recursed through the RAW refDoc.state — a stateful Proxy from resolveRef
    // showed the signed face to verify and a provenance-stripped face to the walk, so a missing nested referent was falsely
    // reported 'verified'. R3: the provenance report is a projection over the admitted snapshot, never a live re-read.
    const refDoc = admitDeep(rawRef);
    if (refDoc === ADMIT_REJECT) { sawUnresolved = true; continue; }     // a non-inert referent is unresolved (availability ≠ failure), never a host throw
    if (--budget.left < 0) return { error: 'E-BOUNDS', detail: 'referent walk exceeds the verified-node budget (§13 P4 — default 256, opts.refBudget)' };
    const rv = verify(refDoc, { ...opts, provenanceDepth: 0 });          // verify the ADMITTED referent (one level)
    if (!isValid(rv)) return { error: rv.error || 'E-SIG', detail: 'referent ' + h + ' invalid: ' + (rv.detail || rv.error) };
    if (rv.content_hash !== h) return { error: 'E-MALFORMED', detail: 'resolver returned a different document for ' + h };
    if (depth > 1) {
      const sub = walkReferents(refDoc.state, opts, depth - 1, new Set([...visited, h]), budget);   // recurse over the ADMITTED snapshot, not raw
      if (sub.error) return sub;
      if (sub.referents === 'partial') sawUnresolved = true;
      reached = Math.max(reached, 1 + sub.depth);
    }
  }
  return { depth: reached, referents: sawUnresolved ? 'partial' : 'verified' };
}

// a REAL RFC3339-Z calendar instant (not just the regex shape — 9999-99-99T99:99:99Z matches the shape but is not a
// time); module-level so resolveKeys, resolveAuthority and resolveByDiscovery share ONE definition (round-15 P1-01).
const isRealRfc3339Z = (x) => { if (typeof x !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(x)) return false; const t = Date.parse(x); return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + 'Z' === x; };
// round-18 P0-02 — the ONE closed substrate-receipt decoder (F.5.0/C3/I4): an "anchored" determination requires a
// verified status from the seam with a real anchored instant — `final` a STRICT Boolean true AND `time` a real
// RFC3339-Z. Every substrate decision (verifyAnchor AND the witness genesisAnchored path) routes through it, so a
// truthy-non-Boolean ({final:"yes"}) or a timeless/typeless receipt ({final:true,time:{}}) can never mint F_t anywhere.
// round-19 P0-02 — the substrate seam is a CLOSED TYPED verdict (F.5.0/C3: "a bare label or a caller boolean earns
// nothing"; "a look-alike … earns nothing"). Decode to an INERT record from OWN PRIMITIVE DATA only: an accessor,
// an inherited field, or a non-plain object earns nothing — Object.create({final:true,time}) has empty own-data and
// must NOT mint anchored. `assurance` (#71 trust-model basis) is the ONE optional own-string; UNKNOWN extra fields are
// ignored, NOT rejected (rejecting them would drop a legitimate `assurance`). → inert {final,time,assurance?} | null.
const decodeSubstrate = (sub) => {
  if (sub === null || typeof sub !== 'object') return null;
  const proto = Object.getPrototypeOf(sub);
  if (proto !== Object.prototype && proto !== null) return null;                 // plain / null-proto ONLY — no class instances, Promises, or prototype look-alikes
  const fd = Object.getOwnPropertyDescriptor(sub, 'final');
  if (!fd || !('value' in fd) || fd.value !== true) return null;                 // OWN data `final === true` (an accessor has no `value`; an inherited field has no own descriptor)
  const td = Object.getOwnPropertyDescriptor(sub, 'time');
  if (!td || !('value' in td) || !isRealRfc3339Z(td.value)) return null;         // OWN data real RFC3339-Z instant
  const out = Object.create(null); out.final = true; out.time = td.value;
  const ad = Object.getOwnPropertyDescriptor(sub, 'assurance');                  // optional #71 basis — OWN string only
  if (ad && ('value' in ad) && typeof ad.value === 'string') out.assurance = ad.value;
  return out;
};
const substrateFinal = (sub) => decodeSubstrate(sub) !== null;
// §12.2 — the SHARED key-log walk (genesis self-signed root + prev-chained entries each signed by a CURRENT
// valid key). Returns { validKeys: Map<key_id,pub>, revoked: Map } or { error, detail }. Used by BOTH
// resolveAuthority (name authority) AND resolveCadence — a cadence-log entry MUST be signed by an AUTHORIZED
// key (not any LIGHT doc with the same domain_shard), the P0 the cadence-log missed.
export function resolveKeys(genesis, keylog = []) {
  if (!genesis || typeof genesis !== 'object') return { error: 'E-GENESIS', detail: 'no genesis' };
  // rev35 R3 (round-30 P0-01) — ADMIT the genesis ONCE at THIS door and operate ONLY on the frozen snapshot. Previously the
  // reducer called verify(genesis) but then RE-READ the raw genesis (genesis.state, contentHash(genesis), genesis.sig) — a
  // stateful Proxy showed the SIGNED face to verify and a DIFFERENT face to the reducer, so it emitted keys for a genesis
  // verify never vouched for. R3: every emitted quantity is a projection over the admitted x̂, nothing re-reads raw x.
  { const G = admitDeep(genesis); if (G === ADMIT_REJECT) return { error: 'E-GENESIS', detail: 'genesis is not an inert record (round-30 R3 — the reducer verifies and reads ONE admitted snapshot, never a live re-read)' }; genesis = G; }
  keylog = admitArray(keylog);                                                    // round-19 P1-02 — a native array snapshot; a Proxy length/index trap is contained → structured reject, never a host throw
  if (keylog === null) return { error: 'E-MALFORMED', detail: 'key-log must be a native array (round-17 P1-02 / round-19 P1-02 — the reducer is TOTAL: a hostile accessor/Proxy is a structured reject, never a host throw)' };
  const gv = verify(genesis);                                                     // genesis is the ADMITTED snapshot (frozen inert) — verify re-admits it idempotently; every read below is of this snapshot
  if (!isValid(gv)) return { error: 'E-GENESIS', detail: 'genesis invalid: ' + gv.error };
  if (genesis.state.id.class !== 'genesis') return { error: 'E-GENESIS', detail: 'not class:genesis' };
  if (genesis.sig.key_id !== genesis.state.id.key_id) return { error: 'E-GENESIS', detail: 'genesis not self-signed' };
  if (keylog.length > 256) return { error: 'E-BOUNDS', detail: 'key-log > 256 (§13)' };
  let prevHash = contentHash(genesis);
  const gKid = genesis.state.id.key_id, gPub = genesis.sig.pub, gDomain = genesis.state.id.domain_shard;
  let prevTime = genesis.state.time.generated_at;                                   // round-16 P1-02: the key-log timeline must be NONDECREASING along the prev-chain, else intervals are unordered/inverted and the K_n(t) shortcuts over intervals[0]/last are unjustified (M-KEY-INTERVAL)
  // §12.2 #75 ROOT 2 — the key-log is a TEMPORAL STATE MACHINE (reducer), not a growing set. Two sets that used to
  // be ONE (the bug behind P0-02): `all` = every key ever authorized (key_id→pub) for DOCUMENT BINDING (a retired
  // key's earlier doc still binds, then X1 judges it by time — continuity); `active` = the keys that may sign the
  // NEXT log/cadence entry (SHRINKS on revoke/rotate). `revoked` carries the §12.2 X1 end-record for every key that
  // left active (reason retired|compromised). `history` records per-key lifecycle for the K_n(t) temporal query.
  const all = new Map([[gKid, gPub]]);
  const active = new Map([[gKid, gPub]]);
  const revoked = new Map();                                                      // key_id → {reason, compromised_since?, at}
  const compromised = new Set();                                                  // MONOTONIC (round-14 P0-01): compromise is TERMINAL — a compromised key is never re-authorized, and its status can never be downgraded (compromised → retired) by a later revoke
  const history = new Map([[gKid, { pub: gPub, intervals: [{ from: genesis.state.time.generated_at, to: null, end: null }] }]]);  // round-15 P0-02: ORDERED authorization intervals (two-sided K_n(t), F.5e). A key's lifetime is a SET of active windows; re-add opens a NEW interval, so add→retire→re-add→retire keeps the retired GAP unauthorized. Scalar first/last collapsed disjoint windows into one → a doc in the gap escaped both bounds.
  const OP_FIELDS = Object.assign(Object.create(null), { add: ['op', 'pub', 'new_key_id'], rotate: ['op', 'pub', 'new_key_id'], revoke: ['op', 'pub', 'reason', 'compromised_since'] });   // null-proto (UST-Protocol round-13 P2-01): OP_FIELDS["toString"] must be undefined, not an inherited function
  const derive = (i, pub, label) => {                                            // strict pub + derived key_id
    if (strictB64url(pub, 32) === null) return { error: { error: 'E-KEY', detail: 'entry ' + i + ' ' + label + ' pub not a 32-byte base64url key' } };
    return { kid: keyId(pub) };
  };
  for (const [i, e] of keylog.entries()) {                                        // §12.2 walk: prev-chained, signed by a CURRENTLY-ACTIVE key
    const ev = verify(e, { context: 'key' });
    if (!isValid(ev)) return { error: 'E-KEY', detail: 'key-log entry ' + i + ' invalid: ' + ev.error };
    if (e.state.id.class !== 'key') return { error: 'E-KEY', detail: 'entry ' + i + ' not class:key' };
    if (e.state.id.domain_shard !== gDomain) return { error: 'E-KEY', detail: 'entry ' + i + ' domain_shard ≠ genesis domain (round-15 P0-03: the single-domain key-log invariant lives IN the reducer, not only in the NameBound caller — the reducer is a TCB unit and must be sound in isolation, since resolveAuthority consumes it directly)' };
    if (e.state.provenance?.prev !== prevHash) return { error: 'E-PREV', detail: 'entry ' + i + ' prev not chained' };
    // round-16 P1-02 — the key-log timeline is NONDECREASING: a later prev-chain entry cannot claim an EARLIER
    // generated_at, else the emitted intervals invert ({from > to}) and the ordered-window precondition breaks.
    if (e.state.time.generated_at < prevTime) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' generated_at precedes an earlier key-log entry (non-monotone timeline — intervals would be unordered, M-KEY-INTERVAL)' };
    prevTime = e.state.time.generated_at;
    // #75 P0-02a/b — the signer MUST be ACTIVE at this point, not merely ever-seen: a revoked or rotated-out key
    // can no longer authorize a later entry.
    const sKid = keyId(e.sig.pub);
    if (active.get(sKid) !== e.sig.pub) return { error: 'E-KEY', detail: 'entry ' + i + ' not signed by a currently-active key (revoked / rotated-out / never-authorized)' };
    const op = e.state?.data?.key_op?.value;
    // #75 P0-02d/e + P1-07 — CLOSED exact schema per op: an unknown op or a stray field is an ERROR, never a no-op.
    if (typeof op !== 'object' || op === null || typeof op.op !== 'string' || !Object.hasOwn(OP_FIELDS, op.op)) return { error: 'E-KEY', detail: 'entry ' + i + ' unknown or missing key_op.op (add|rotate|revoke)' };
    for (const k of Object.keys(op)) if (!OP_FIELDS[op.op].includes(k)) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' stray field in ' + op.op + ': ' + k };
    if (op.op === 'add' || op.op === 'rotate') {
      const d = derive(i, op.pub, op.op); if (d.error) return d.error;
      if (op.new_key_id !== undefined && op.new_key_id !== d.kid) return { error: 'E-KEY', detail: 'entry ' + i + ' new_key_id != H(ust:keylog, pub)' };
      if (compromised.has(d.kid)) return { error: 'E-KEY', detail: 'entry ' + i + ' cannot re-authorize a COMPROMISED key (terminal, round-14 P0-01)' };
      all.set(d.kid, op.pub); active.set(d.kid, op.pub);
      { const h = history.get(d.kid), t = e.state.time.generated_at;                // round-15 P0-02: re-add after retirement OPENS A NEW interval (never reuses the old authorized_at)
        if (!h) history.set(d.kid, { pub: op.pub, intervals: [{ from: t, to: null, end: null }] });
        else if (h.intervals[h.intervals.length - 1].to !== null) h.intervals.push({ from: t, to: null, end: null }); }
      // #75 spec §12.2 "each rotation is authorized by the key it supersedes": on rotate the SIGNER is superseded —
      // it leaves active (cannot sign later entries) and is recorded retired (its EARLIER docs stay valid, X1).
      if (op.op === 'rotate' && sKid !== d.kid) {
        active.delete(sKid);
        revoked.set(sKid, { reason: 'retired', at: e.state.time.generated_at });
        const h = history.get(sKid); if (h) { const iv = h.intervals[h.intervals.length - 1]; if (iv.to === null) { iv.to = e.state.time.generated_at; iv.end = 'retired'; } }   // round-15 P0-02: close the current active interval
      }
    } else {  // revoke
      const d = derive(i, op.pub, 'revoke'); if (d.error) return d.error;
      if (!all.has(d.kid)) return { error: 'E-KEY', detail: 'entry ' + i + ' revoke of a never-authorized key' };
      if (op.reason !== 'retired' && op.reason !== 'compromised') return { error: 'E-MALFORMED', detail: 'entry ' + i + ' revoke reason MUST be "retired" | "compromised"' };
      if (op.reason === 'compromised') {
        if (!isRealRfc3339Z(op.compromised_since)) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' compromised requires a REAL RFC3339-Z compromised_since (round-15 P1-01: shape ≠ time — 9999-99-99T99:99:99Z passes a regex but is not a calendar instant; the string-compare U ≥ C then always failed, silently downgrading E-KEY to suspect)' };
      } else if (op.compromised_since !== undefined) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' retired MUST NOT carry compromised_since' };
      if (compromised.has(d.kid)) return { error: 'E-KEY', detail: 'entry ' + i + ' COMPROMISED is terminal — cannot re-revoke or downgrade (round-14 P0-01)' };
      active.delete(d.kid);
      if (op.reason === 'compromised') compromised.add(d.kid);                     // monotonic — never cleared
      revoked.set(d.kid, { reason: op.reason, compromised_since: op.compromised_since, at: e.state.time.generated_at });
      const h = history.get(d.kid); if (h) { const iv = h.intervals[h.intervals.length - 1]; if (iv.to === null) { iv.to = e.state.time.generated_at; iv.end = op.reason; } }   // round-15 P0-02: close the current active interval with the end reason
    }
    prevHash = contentHash(e);
  }
  return { validKeys: all, active, revoked, history, head: prevHash };            // validKeys = the all-ever BINDING map; head (§12.2a) = last entry content_hash (genesis if empty)
}

// ─── §12 HIGH name-authority resolution. STATELESS: the caller (ustate/engine) supplies the genesis +
//     key-log transcripts (retrieval is the stateful layer's job) and asserts no-fork from the witness (W1).
// ─── §12.1a / P0-2 (audit) — NAME NO-FORK EVIDENCE. `authoritative` name-authority is EARNED, never self-declared:
//     it requires a TYPED, domain-separated no-fork claim signed by a witness the CONSUMER trusts (resolved against
//     `trustRoots`: issuer_id → pub | {pub[, trust_domain]}), bound to this domain + active genesis. The witness
//     CANNOT grant itself a trust domain — it is NOT in the signed claim; the consumer owns the issuer→domain map
//     (self-declared `trust_domain`/`issuer_id` inside a claim is rejected). A raw `noForkConfirmed` boolean is NOT
//     evidence: it is a distinct `consumer-override` (independently_verified:false), never silently `authoritative`
//     (the removed overclaim class — the same as `mapInclusion:true`). Independent-map `authoritative` stays #42.
export function noForkClaim({ domain_shard, active_genesis, map_checkpoint, map_sequence }) {   // round-35 — no `valid_as_of`: a signer cannot self-declare TIME in a signed authority claim (assurance-never-self-declared; time comes from an external anchor, not the witness)
  return { purpose: 'ust:name-no-fork', domain_shard, active_genesis,
    ...(map_checkpoint !== undefined ? { map_checkpoint } : {}),
    ...(map_sequence !== undefined ? { map_sequence } : {}) };
}
export function buildNoForkEvidence(fields, privKeyObj, issuerPubB64url) {
  const claim = noForkClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
// Verify an envelope { claim, issuer_id, sig } against the target domain + active genesis and consumer trustRoots.
// Independence is CONSUMER-OWNED: the issuer must be accepted in trustRoots; any trust_domain INSIDE the claim is
// rejected (that would be self-declared independence, P0-2). Returns { ok, witness_id, trust_domain, detail }.
export function verifyNoForkEvidence(evidence, config) {
  const c = admitOpts(config); if (c === null) return { ok: false, detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 — total for null/hostile config
  const { domain_shard, active_genesis, trustRoots = {} } = c;
  { const E = admitDeep(evidence); if (E === ADMIT_REJECT) return { ok: false, detail: 'evidence is not an inert record (round-27 — the witness claim is read once; no getter re-read after canon)' }; evidence = E; }   // round-27 — snapshot the primary signed input, uniform with the authority-graph boundary
  if (!evidence || typeof evidence !== 'object') return { ok: false, detail: 'no evidence' };
  const { claim, issuer_id, sig } = evidence || {};
  if (!closedNoForkWitness(evidence)) return { ok: false, detail: 'no-fork witness is not a closed typed ADT (round-35 P0-03 — exact { claim, issuer_id, sig } + admitSigner (issuer_id === sig.key_id === keyId(pub), exact Ed25519 wrapper, Pub32/Sig64) + exact typed no-fork claim; a signed authority witness now in the closed-ADT sweep)' };
  if (claim.domain_shard !== domain_shard) return { ok: false, detail: 'claim domain_shard mismatch' };
  if (claim.active_genesis !== active_genesis) return { ok: false, detail: 'claim not bound to this active genesis' };
  const root = trustRoots[issuer_id];
  if (!root) return { ok: false, detail: 'issuer not in consumer trustRoots' };
  const rootPub = typeof root === 'string' ? root : root.pub;
  if (rootPub !== sig.pub) return { ok: false, detail: 'issuer pub not the configured trust root' };   // signer identity (issuer_id===sig.key_id===keyId(pub)) already bound by closedNoForkWitness → admitSigner
  let msg; try { msg = canon(claim); } catch { return { ok: false, detail: 'claim not canonicalizable (round-25 P1-02 — a malformed non-null claim returns structured, never a thrown E-CANON)' }; }   // the leaf canon boundary is inside the result algebra (mirrors verifyCheckpointUniqueness)
  if (!edVerifyStrict(sig.pub, msg, sig.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true, witness_id: issuer_id, ...(typeof root === 'object' && root.trust_domain ? { trust_domain: root.trust_domain } : {}) };
}

// ─── #76 Phase A — CONNECTOR EVIDENCE ALGEBRA. A connector returns VERIFIED FACTS only, never an assurance label —
//     the CORE derives the class. Two algebra ops the checkpoint/authority layers consume: `compareEvidenceOrder`
//     (temporal order is a PROOF RELATION, not a comparison of RFC3339 fields) and `quorumTrustDomains` (quorum counts
//     DISTINCT CONSUMER-resolved trust domains, never connectors/URLs/mirrors, never a self-declared `trust_domain`).
//     M3 (rc.36): `verifiedEvidence()` builds the RAW facts shape only — its output is NOT VerifiedEvidence and no
//     strong rung accepts it (the rc.35 round-2 forge). Provenance-bearing evidence = buildEvidenceReceipt (a signed
//     connector receipt) verified through verifyEvidenceReceipt against consumer-admitted connectors.
export function verifiedEvidence({ proof_kind, subject, source_id, facts = {}, verifier_id, verifier_version }) {
  if (!proof_kind || !subject || !source_id) throw Object.assign(new Error('E-EVIDENCE: proof_kind, subject, source_id required'), { code: 'E-EVIDENCE' });
  for (const k of ['assurance', 'strength', 'trust_domain', 'independent'])            // facts-only: no self-declared class/independence
    if (k in facts) throw Object.assign(new Error(`E-EVIDENCE: a connector must not self-declare '${k}' (facts only; the core derives it)`), { code: 'E-EVIDENCE' });
  return { proof_kind, subject, source_id, facts, ...(verifier_id ? { verifier_id } : {}), ...(verifier_version ? { verifier_version } : {}) };
}
// The CORE derives the assurance CLASS from the proof_kind — never the connector. `transparency-log` inclusion+
// consistency is NOT non-membership; only a keyed-uniqueness/map proof-kind yields non-membership. Unknown ⇒ opaque.
export function evidenceClass(proof_kind) {
  switch (proof_kind) {
    case 'pow-header-chain':  return 'external-commitment+order+time';
    case 'transparency-log':  return 'append-only-inclusion+consistency';   // NOT non-membership
    case 'authenticated-map': return 'keyed-membership+non-membership';
    case 'content-addressed': return 'content-equality+availability';
    case 'rfc3161-tsa':       return 'trusted-timestamp';
    default:                  return 'opaque';                               // ⇒ INDETERMINATE(unsupported) upstream
  }
}
// UST-0ol Phase 2 — evidence CAPABILITY as a SET (P2-02: capabilities are not a scalar rank). A predicate is
// satisfiable ONLY by an admissible capability; strong derivation checks this before trusting a piece of evidence,
// so a connector can never exceed its declared power (content-addressed is not temporal; unknown ⇒ no capability).
const EVIDENCE_CAPS = deepFreeze(Object.assign(Object.create(null), {   // round-25 P0-04 — DEEP-frozen registry (null-proto per round-12 P0-01): no in-process mutation of the capability vocabulary
  'pow-header-chain':  ['order', 'time'],
  'transparency-log':  ['inclusion', 'consistency', 'order'],
  'authenticated-map': ['membership', 'non-membership'],
  'content-addressed': ['content-equality', 'availability'],
  'rfc3161-tsa':       ['time'],
}));
export const evidenceCaps = (proof_kind) => Object.freeze((Object.hasOwn(EVIDENCE_CAPS, proof_kind) ? EVIDENCE_CAPS[proof_kind] : []).slice());   // round-24 P1-03 — a FROZEN COPY: a caller can never mutate the internal capability array to make check_C history-dependent

// ─── M3 (UST-6vj C2) — THE EVIDENCE SEAM. Provenance is a THEOREM, not an assumption: a strong rung consumes
//     evidence only from image(VerifyEvidence_C) — either a proof the core verifies inline (terminality / map /
//     attestation verifiers = the DirectCryptographicProof arm of RawEvidence) or a SIGNED CONNECTOR RECEIPT admitted
//     by CONSUMER config (this block). A caller-minted look-alike (rc.35 round-2 verifiedEvidence-forge) is not in
//     the image, carries no capability, and lifts no rung. trust_domain flows from the CONSUMER config, never the
//     receipt; the receipt carries FACTS only — a capability/assurance/independence/threshold field is rejected.
const BANNED_EVIDENCE_FACTS = ['assurance', 'strength', 'trust_domain', 'independent', 'capability', 'attested', 'threshold'];
const RFC3339Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export function evidenceReceiptClaim({ domain_shard, active_genesis, genesis_epoch, subject, proof_kind, facts = {}, payload_digest, issued_at }) {
  if (typeof domain_shard !== 'string' || !domain_shard || !isHashStr(active_genesis)) throw Object.assign(new Error('E-EVIDENCE: domain_shard/active_genesis required'), { code: 'E-EVIDENCE' });
  if (typeof subject !== 'string' || !subject || typeof proof_kind !== 'string' || !proof_kind) throw Object.assign(new Error('E-EVIDENCE: subject and proof_kind required'), { code: 'E-EVIDENCE' });
  if (!facts || typeof facts !== 'object' || Array.isArray(facts)) throw Object.assign(new Error('E-EVIDENCE: facts must be an object'), { code: 'E-EVIDENCE' });
  for (const k of BANNED_EVIDENCE_FACTS)                                             // facts-only, extended ban (design §2.2)
    if (k in facts) throw Object.assign(new Error(`E-EVIDENCE: a receipt must not carry '${k}' (facts only; capability/class is core-derived, trust_domain is consumer config)`), { code: 'E-EVIDENCE' });
  if (typeof issued_at !== 'string' || !RFC3339Z.test(issued_at)) throw Object.assign(new Error('E-EVIDENCE: issued_at must be RFC3339 Z (a SIGNED claim, never proven time)'), { code: 'E-EVIDENCE' });
  return { version: '1', purpose: 'ust:evidence-receipt', domain_shard, active_genesis,
    genesis_epoch: genesis_epoch ?? genesisEpoch(active_genesis),                    // canonical by construction (M2); verify re-checks
    subject, proof_kind, facts, ...(payload_digest !== undefined ? { payload_digest } : {}), issued_at };
}
export function buildEvidenceReceipt(fields, privKeyObj, issuerPubB64url) {
  const claim = evidenceReceiptClaim(fields);
  const sig = edSign(null, Buffer.from(canon({ purpose: 'ust:evidence-receipt-signature', claim }), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export const evidenceReceiptId = (r) => H('ust:evidence-receipt', canon({ claim: r.claim, sig: r.sig }));
// K3: a VerifiedEvidence value is a branded 'evidence' handle (the M3 witness that VerifyEvidence_C produced it) —
// portability = the signed receipt, safety = the brand.
// VerifyEvidence_C — the ONLY producer of VerifiedEvidence. Seven checks IN ORDER (M3.2): bounds/shape → signature →
// round-33 P0-01 — the public receipt admission must apply the SAME CLOSED TYPED ADT the reference KERNEL's
// `closedReceipt` does (reference-checker.mjs: decodeRec + RECEIPT_CLAIM + SIG_ENV + FACTS_SCHEMA), so a receipt that is
// KERNEL-INVALID — an extra envelope/claim/facts key, a shape-valid-but-impossible `issued_at`, an unregistered
// `proof_kind`, or wrong per-kind facts — can NEVER mint a branded VerifiedEvidence handle (the divergence GPT proved in
// round-33: consumer-side order typing cannot repair a capability handle minted from a kernel-invalid receipt). These
// schemas MIRROR the kernel field-for-field (isRealRfc3339Z = pRFC, decSeq = decodeSeq); the two independent derivations
// AGREE (conformance cross-check). `decodeExact` is the kernel `decodeRec`: own-key membership only, exact keys, typed leaves.
const _evId = (x) => typeof x === 'string' && x.length > 0, _evSeq = (x) => decSeq(x) !== null;
const decodeExact = (o, schema) => {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
  for (const k of Object.keys(o)) if (!Object.hasOwn(schema, k)) return false;               // no key the schema does not OWN (round-12 P0-01 prototype-name close)
  for (const k of Object.keys(schema)) { const s = schema[k]; if (!Object.hasOwn(o, k)) { if (!s.opt) return false; continue; } if (!s.t(o[k])) return false; }
  return true;
};
const _evHash = (x) => isHashStr(x);   // arrow-wrapped: isHashStr is declared later in the module (resolved at call time, not load time — no TDZ)
const EV_SIG_SCHEMA = { alg: { t: (x) => x === 'Ed25519' }, key_id: { t: _evHash }, pub: { t: (x) => strictB64url(x, 32) !== null }, sig: { t: (x) => strictB64url(x, 64) !== null } };
const EV_CLAIM_SCHEMA = { version: { t: (x) => x === '1' }, purpose: { t: (x) => x === 'ust:evidence-receipt' }, domain_shard: { t: _evId }, active_genesis: { t: _evHash }, genesis_epoch: { t: _evHash }, subject: { t: _evId }, proof_kind: { t: _evId }, facts: { t: (x) => x !== null && typeof x === 'object' && !Array.isArray(x) }, issued_at: { t: (x) => isRealRfc3339Z(x) }, payload_digest: { t: _evHash, opt: true } };
const EV_FACTS_SCHEMA = Object.freeze(Object.assign(Object.create(null), {   // null-proto (round-12 P0-01) — keyed by an attacker-influenced proof_kind; exact facts per registered kind, mirrors the kernel FACTS_SCHEMA
  'pow-header-chain':  { substrate: { t: _evId }, position: { t: _evSeq } },
  'transparency-log':  { log_id: { t: _evId }, index: { t: _evSeq } },
  'rfc3161-tsa':       { clock_id: { t: _evId }, not_before: { t: isRealRfc3339Z }, not_after: { t: isRealRfc3339Z } },
  'authenticated-map': {},
  'content-addressed': {},
}));
const isKnownEvidenceKind = (k) => Object.hasOwn(EV_FACTS_SCHEMA, k);   // the CLOSED registry of admissible proof_kinds (own-key, not prototype-name)
// round-34 P0-01..04 — the PUBLIC authority verifiers must apply the SAME CLOSED TYPED ADT the kernel does to every
// SIGNED witness (checkpoint / epoch-transition / uniqueness / recovery) BEFORE minting a branded handle or an authority
// capability — else a witness the kernel rejects (an extra signed field, a shape-valid-impossible value, an unclosed sig
// wrapper, a non-canonical Pub32) mints a public brand (the round-33 receipt class, swept across ALL witness types).
// These schemas MIRROR the kernel SIG_ENV / CHECKPOINT_BODY / TRANSITION_CLAIM / VOTE_CLAIM field-for-field (decodeExact
// = the kernel decodeRec); the two independent derivations AGREE (conformance cross-check).
const _evRec = (schema) => (x) => decodeExact(x, schema);                 // a nested EXACT typed record — mirrors the kernel rec()
const _evObj = { t: (x) => x !== null && typeof x === 'object' && !Array.isArray(x) };
const AUTH_SIG_SCHEMA = { alg: { t: (x) => x === 'Ed25519' }, key_id: { t: _evHash }, pub: { t: strictPub }, sig: { t: (x) => strictB64url(x, 64) !== null } };   // mirrors SIG_ENV
// round-35 P0-01/02/03 — THE ONE authority signer-admission primitive (the audit choke-point). EVERY signed authority
// witness admits its signer HERE before grouping / identity / verdict / mint: an EXACT Ed25519 sig wrapper + the
// redundant identity fields bound to ONE value (expectedKeyId === sig.key_id === keyId(pub)) + canonical Pub32/Sig64.
// A foreign sig.key_id, an alg:RSA, an extra wrapper field, or a non-canonical pub/sig admits NOTHING. Returns the pub.
const admitSigner = (sig, expectedKeyId) => (decodeExact(sig, AUTH_SIG_SCHEMA) && typeof expectedKeyId === 'string' && expectedKeyId === sig.key_id && keyId(sig.pub) === sig.key_id) ? sig.pub : null;
// round-36 P1-01 — the ONE nested-authority-key admission: a { key_id, pub } authority record is usable ONLY if it is an
// EXACT pair, `pub` is canonical Pub32, and the identity RELATION `key_id === keyId(pub)` holds. Typing the two fields
// INDEPENDENTLY (rev44) admitted an internally-contradictory pair (key_id of A, pub of B) as a recovered authority.
// Every { key_id, pub } authority pair — recovery replacement, transition destination, checkpoint rotation, genesis
// authority, pinned prior — routes through this so a contradictory pair mints nothing.
const AUTH_KEY_SCHEMA = { key_id: { t: _evHash }, pub: { t: strictPub } };
const admitAuthorityKey = (a) => decodeExact(a, AUTH_KEY_SCHEMA) && keyId(a.pub) === a.key_id;
// round-37 P0-01 — the ONE Merkle co-path admission: `siblings` is an array of the EXPECTED length whose EVERY element is
// a canonical sha256 hash. Node preimages are then built from admitted hash STRINGS, never a generic `+` coercion — a
// `[]` sibling coerced to '' forged a root under a non-protocol grammar, and a null-proto object threw a host TypeError.
// Both Merkle verifiers (key-log terminality + SMT map) route through it, matching the kernel's typed hash arrays (pHashArr).
const admitHashPath = (siblings, expectedLen) => (Array.isArray(siblings) && siblings.length === expectedLen && siblings.every(isHashStr)) ? siblings : null;
const KEYLOG_COMMIT_SCHEMA = { root: { t: _evHash }, length: { t: _evSeq }, head: { t: _evHash } };
const CHK_AUTHORITY_SCHEMA = { current_key_id: { t: _evHash }, next_key_id: { t: _evHash, opt: true }, next_pub: { t: strictPub, opt: true }, effective_sequence: { t: _evSeq, opt: true } };
const CHECKPOINT_BODY_SCHEMA = { version: { t: (x) => x === '1' }, purpose: { t: (x) => x === 'ust:authority-checkpoint' }, domain_shard: { t: _evId }, genesis_epoch: { t: _evHash }, sequence: { t: _evSeq }, active_genesis: { t: _evHash }, checkpoint_authority: { t: _evRec(CHK_AUTHORITY_SCHEMA) }, keylog: { t: _evRec(KEYLOG_COMMIT_SCHEMA) }, previous_checkpoint: { t: _evHash, opt: true }, previous_epoch_final_checkpoint: { t: _evHash, opt: true } };
const TRANSITION_CLAIM_SCHEMA = { purpose: { t: (x) => x === 'ust:genesis-epoch-transition' }, domain_shard: { t: _evId }, from_genesis_epoch: { t: _evHash }, from_final_checkpoint: { t: _evHash }, from_sequence: { t: _evSeq }, to_active_genesis: { t: _evHash }, to_initial_sequence: { t: _evSeq }, to_genesis_epoch: { t: _evHash }, to_checkpoint_authority: { t: admitAuthorityKey } };   // round-36 P1-01 — the destination authority is a usable { key_id === keyId(pub) } pair, not two independent strings
const VOTE_CLAIM_SCHEMA = { purpose: { t: (x) => x === 'ust:checkpoint-uniqueness-attestation' }, domain_shard: { t: _evId }, genesis_epoch: { t: _evHash }, sequence: { t: _evSeq }, checkpoint: { t: _evHash } };
const RECOVERY_CLAIM_SCHEMA = { purpose: { t: (x) => x === 'ust:checkpoint-authority-recovery' }, domain_shard: { t: _evId }, genesis_epoch: { t: _evHash }, last_accepted_checkpoint: { t: _evHash }, effective_sequence: { t: _evSeq }, replacement_authority: { t: admitAuthorityKey } };   // round-36 P1-01 — the replacement authority is a usable { key_id === keyId(pub) } pair, not two independent strings; round-35 tuple (no human `reason`)
const NOFORK_CLAIM_SCHEMA = { purpose: { t: (x) => x === 'ust:name-no-fork' }, domain_shard: { t: _evId }, active_genesis: { t: _evHash }, map_checkpoint: { t: _evHash, opt: true }, map_sequence: { t: _evSeq, opt: true } };   // round-35 — no self-declared time (valid_as_of removed): a signer-declared instant is not part of the signed authority claim
// closed-witness decoders — exact envelope + the ONE admitSigner signer-admission + exact+typed body/claim. Every witness
// that carries its own issuer_id binds the signer HERE (round-35 P0-01/02/03); checkpoint/transition bind against the
// resolved authority key at the verifier (no envelope issuer_id).
const closedCheckpointWitness = (cw) => decodeExact(cw, { body: _evObj, sig: _evObj }) && decodeExact(cw.sig, AUTH_SIG_SCHEMA) && decodeExact(cw.body, CHECKPOINT_BODY_SCHEMA);   // exactly { body, sig } (round-34 P0-02: no unsigned extra field can shift the checkpoint id)
const closedTransitionWitness = (cm) => decodeExact(cm, { claim: _evObj, sig: _evObj, issuer_id: { t: _evHash, opt: true } }) && decodeExact(cm.sig, AUTH_SIG_SCHEMA) && (cm.issuer_id === undefined || cm.issuer_id === cm.sig.key_id) && decodeExact(cm.claim, TRANSITION_CLAIM_SCHEMA);
const closedVoteWitness = (vw) => decodeExact(vw, { claim: _evObj, issuer_id: { t: _evHash }, sig: _evObj }) && admitSigner(vw.sig, vw.issuer_id) !== null && decodeExact(vw.claim, VOTE_CLAIM_SCHEMA);   // issuer_id REQUIRED + bound to sig.key_id === keyId(pub) (round-35 P0-01)
const closedRecoveryWitness = (rw) => decodeExact(rw, { claim: _evObj, issuer_id: { t: _evHash }, sig: _evObj }) && admitSigner(rw.sig, rw.issuer_id) !== null && decodeExact(rw.claim, RECOVERY_CLAIM_SCHEMA);   // round-35 P0-02
const closedNoForkWitness = (nw) => decodeExact(nw, { claim: _evObj, issuer_id: { t: _evHash }, sig: _evObj }) && admitSigner(nw.sig, nw.issuer_id) !== null && decodeExact(nw.claim, NOFORK_CLAIM_SCHEMA);   // round-35 P0-03 — no-fork is a signed authority witness, now in the closed-ADT sweep
// subject binding → scope binding → admission (consumer connectors) → role (allowed_proof_kinds, B4) → total.
// Tamper/malformation ⇒ INVALID(E-EVIDENCE); not-admitted-for-THIS-consumer/scope/subject ⇒ INDETERMINATE
// (evidence_unverified) — absence of admission is not proof of fraud, but it earns nothing (fail-closed).
export function verifyEvidenceReceipt(receipt, config) {
  const c = admitOpts(config); if (c === null) return { result: 'INVALID', error: 'E-EVIDENCE', detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 — total for null/hostile config
  const { subject, scope = {}, connectors = {} } = c;
  const R = admitDeep(receipt); if (R === ADMIT_REJECT) return { result: 'INVALID', error: 'E-EVIDENCE', detail: 'receipt is not an inert record — an accessor/getter input cannot mint an EvidenceHandle (round-26 P0-03: canon/verify/id/handle all read ONE snapshot)' };   // round-26 P0-03 — snapshot ONCE; no getter-TOCTOU between verify and handle construction
  try {
    const c = R?.claim, s = R?.sig;
    const bad = (detail) => ({ result: 'INVALID', error: 'E-EVIDENCE', detail });
    const unv = (detail) => ({ result: 'INDETERMINATE', reason: 'evidence_unverified', detail });
    // round-33 P0-01/02 — the CLOSED typed ADT over the ADMITTED snapshot R (NEVER the raw `receipt`), mirroring the
    // kernel closedReceipt: exact envelope { claim, issuer_id, sig }, typed sig wrapper, exact+typed claim (real-calendar
    // issued_at), registered proof_kind, exact per-kind facts. A receipt the kernel would reject can no longer mint a handle.
    if (!decodeExact(R, { claim: { t: (x) => x !== null && typeof x === 'object' && !Array.isArray(x) }, issuer_id: { t: isHashStr }, sig: { t: (x) => x !== null && typeof x === 'object' && !Array.isArray(x) } })) return bad('receipt envelope not closed (exactly { claim, issuer_id, sig })');
    if (!decodeExact(s, EV_SIG_SCHEMA)) return bad('receipt sig wrapper not typed (exactly { alg:Ed25519, key_id, pub, sig })');
    if (!decodeExact(c, EV_CLAIM_SCHEMA)) return bad('receipt claim not typed (exact keys + real-calendar issued_at — round-33 P0-01: 9999-99-99T99:99:99Z is shape-valid, not a real instant)');
    if (!isKnownEvidenceKind(c.proof_kind)) return bad(`proof_kind '${c.proof_kind}' is not a registered kind`);
    if (!decodeExact(c.facts, EV_FACTS_SCHEMA[c.proof_kind])) return bad(`receipt facts not typed for proof_kind '${c.proof_kind}' (round-33 P0-01: exact per-kind facts, no extra field)`);
    if (c.genesis_epoch !== genesisEpoch(c.active_genesis)) return bad('genesis_epoch ≠ canonical H("ust:genesis-epoch", active_genesis) (M2)');
    if (admitSigner(s, R.issuer_id) === null) return bad('signer not admitted — issuer_id === sig.key_id === keyId(pub) over an exact Ed25519 wrapper (round-35 admitSigner; issuer_id read from the admitted snapshot R)');
    if (!edVerifyStrict(s.pub, canon({ purpose: 'ust:evidence-receipt-signature', claim: c }), s.sig)) return bad('Ed25519 verify failed');
    if (subject !== undefined && c.subject !== subject) return unv('receipt subject is not the required subject (binding, M3.2/3)');
    if (c.domain_shard !== scope.domain_shard || c.active_genesis !== scope.active_genesis || c.genesis_epoch !== scope.genesis_epoch) return unv('receipt scope ≠ the authority scope (binding, M3.2/4)');
    const conn = connectors?.[s.key_id];
    if (!conn || conn.pub !== s.pub) return unv('issuer is not a consumer-admitted connector (admission, M3.2/5)');
    if (!Array.isArray(conn.allowed_proof_kinds) || !conn.allowed_proof_kinds.includes(c.proof_kind)) return unv(`connector is not admitted for proof_kind '${c.proof_kind}' (role, M3.2/6 — B4)`);
    const evidence = mintHandle('evidence', { evidence_id: evidenceReceiptId(R),
      authority_scope_id: authorityScopeId(scope.active_genesis),                     // K2: scope = H(tag, contentHash(g))
      subject_id: c.subject, proof_kind: c.proof_kind, verified_facts: Object.freeze({ ...c.facts }), issuer_id: s.key_id,
      ...(conn.trust_domain !== undefined ? { trust_domain: conn.trust_domain } : {}), basis: 'admitted-connector-receipt' });
    return { result: 'VALID', evidence };
  } catch (e) { return { result: 'INVALID', error: 'E-EVIDENCE', detail: 'receipt verification threw: ' + (e?.message || e) }; }   // M3.2/7 — total
}
// Freshness-side admission: a pre-verified token re-checks only its BINDING (scope + subject, never the crypto);
// a raw {claim, sig} receipt goes through the full seam; anything else is the forge and earns nothing.
function admitFreshnessEvidence(x, subject, scope, trust) {
  if (isHandle('evidence', x))
    return x.authority_scope_id === authorityScopeId(scope.active_genesis) && x.subject_id === subject
      ? { evidence: x } : { detail: 'core-verified evidence is bound to a different scope/subject' };
  if (x && typeof x === 'object' && x.claim && x.sig) { const r = verifyEvidenceReceipt(x, { subject, scope, connectors: trust?.connectors }); return r.evidence ? { evidence: r.evidence } : { detail: r.detail }; }
  return { detail: 'caller-supplied evidence is neither a signed connector receipt nor core-verified (M3 — a minted look-alike earns nothing)' };
}
const temporalOrderCapable = (ev) => { const c = evidenceCaps(ev?.proof_kind); return c.includes('order') || c.includes('time'); };
// round-32 P0-01 (M3 evidence-seam soundness / R2 processing-purity) — THE public evidence-order path
// (deriveCheckpointFreshness → compareEvidenceOrder) must apply the SAME closed typed decode the reference KERNEL's
// `orderSemantic` does (ORDER_COORD/FACTS_SCHEMA in reference-checker.mjs), so the two INDEPENDENT derivations agree.
// A connector's `facts` are untyped strings; the order coordinate is read ONLY from the proof_kind's authorised fields
// and is proof-kind-NAMESPACED — a transparency-log's log-index is never comparable to a pow chain's block-height, a
// rfc3161-tsa interval is a SAME-CLOCK pair of REAL calendar instants with not_before ≤ not_after (isRealRfc3339Z, the
// one real-calendar validator, = the kernel's pRFC). Cross-kind, non-calendar, inverted, cross-clock, or half-open
// inputs decode to NOTHING ⇒ no `proven-after` (the corroborated-freshness forge). Total, fail-closed, never throws.
const decSeq = (s) => (typeof s === 'string' && /^(0|[1-9]\d*)$/.test(s)) ? s : null;      // CanonicalSeq — mirrors reference-checker decodeSeq/pSeq
function decodeOrderFacts(proof_kind, facts) {
  if (!facts || typeof facts !== 'object' || Array.isArray(facts)) return null;
  const pid = (s) => (typeof s === 'string' && s.length > 0) ? s : null;                    // a non-empty identifier — mirrors the kernel's pId
  switch (proof_kind) {                                                                     // the CLOSED admissible-kind set = ORDER_COORD keys (no free substrate)
    case 'pow-header-chain': { const sub = pid(facts.substrate), pos = decSeq(facts.position);   // Position(substrate, position)
      return (sub && pos) ? { order: { ns: 'pow-header-chain ' + sub, pos } } : null; }
    case 'transparency-log': { const log = pid(facts.log_id), idx = decSeq(facts.index);        // Position(log_id, index) — the field is `index`, NOT `log_index`/`substrate`
      return (log && idx) ? { order: { ns: 'transparency-log ' + log, pos: idx } } : null; }
    case 'rfc3161-tsa': { const clk = pid(facts.clock_id);                                       // Interval(clock_id, not_before ≤ not_after)
      if (!clk || !isRealRfc3339Z(facts.not_before) || !isRealRfc3339Z(facts.not_after) || facts.not_before > facts.not_after) return null;   // clock_id + BOTH real-calendar bounds, well-formed
      return { interval: { id: 'rfc3161-tsa ' + clk, nb: facts.not_before, na: facts.not_after } }; }
    default: return null;                                                                       // authenticated-map / content-addressed (no order coord) + unknown ⇒ nothing
  }
}
// compareEvidenceOrder(a, b): is `a` PROVEN to be after `b`? Routed through the ONE closed decoder — positions in the
// SAME proof-kind order-namespace are a total order; else a SAME-CLOCK real-calendar interval relation (`a.not_before ≥
// b.not_after` proves after, `b.not_before ≥ a.not_after` proves not-after). Cross-kind, cross-namespace, cross-clock,
// or two-bounds-unrelated inputs prove nothing ⇒ `unproven`.
export function compareEvidenceOrder(a, b) {
  const da = decodeOrderFacts(a?.proof_kind, a?.verified_facts ?? a?.facts ?? (a && typeof a === 'object' ? a : {}));   // M3: VerifiedEvidence carries proof_kind + verified_facts
  const db = decodeOrderFacts(b?.proof_kind, b?.verified_facts ?? b?.facts ?? (b && typeof b === 'object' ? b : {}));
  if (!da || !db) return 'unproven';
  if (da.order && db.order && da.order.ns === db.order.ns)                                 // same kind + same substrate/log ⇒ one total order
    return BigInt(da.order.pos) > BigInt(db.order.pos) ? 'proven-after' : 'not-after';
  if (da.interval && db.interval && da.interval.id === db.interval.id) {                   // same clock ⇒ comparable (cross-clock proves nothing — kernel P0-03)
    if (da.interval.nb >= db.interval.na) return 'proven-after';
    if (db.interval.nb >= da.interval.na) return 'not-after';
  }
  return 'unproven';                                                                       // two upper bounds, cross-namespace, or undecodable
}
// quorumTrustDomains(list, { domains, threshold }): count DISTINCT CONSUMER-resolved trust domains. `domains` maps a
// verified source_id → trustDomain (consumer config). Sources absent from `domains` are NOT admitted; a `trust_domain`
// carried on the evidence itself is ignored. Multiple sources in one domain count once.
export function quorumTrustDomains(list, config) {
  const c = admitOpts(config); if (c === null) return { count: 0, domains: [], met: false, detail: 'config must be an inert record (round-23 P1-02)' };   // round-23 P1-02 — total boundary
  const { domains = {}, threshold } = c;
  const seen = new Set();
  for (const e of Array.isArray(list) ? list : []) {
    const sid = e?.source_id ?? e?.facts?.source_id;
    const dom = sid !== undefined ? domains[sid] : undefined;                          // consumer-resolved ONLY
    if (typeof dom === 'string' && dom.length && !hasLoneSurrogate(dom)) seen.add(dom.normalize('NFC'));   // round-23 P0-01 + round-24 P0-03 — a non-empty Unicode-SCALAR NFC string only (a lone surrogate is outside the §6 domain and would fake an independent domain)
  }
  const arr = [...seen].sort();                                                        // round-23 P1-01 — canonical order
  // M5 ValidThreshold — uniform across EVERY quorum surface (the rc.35 round-2 sibling of P0-4: threshold ≤ 0 here
  // made `met: true` from an EMPTY evidence list). A non-positive/non-integer threshold never satisfies a quorum.
  if (threshold !== undefined && (!Number.isInteger(threshold) || threshold < 1))
    return { count: arr.length, domains: arr, met: false, detail: 'threshold must be a positive integer (got ' + threshold + ')' };
  return { count: arr.length, domains: arr, ...(threshold !== undefined ? { met: arr.length >= threshold } : {}) };
}

// ─── UST-0ol Phase 1 — the TRUST BOUNDARY (I_C). A map root is admissible ONLY if the CONSUMER independently holds
//     it (trust.mapRoots — anchored/pinned out-of-band); it is NEVER taken from the same bundle as the proof. Absence
//     of admission ⇒ no strong rung (fail-safe). This is the separation of trust-configuration from evidence.
const mapRootAdmitted = (trust, root) => Array.isArray(trust?.mapRoots) && trust.mapRoots.includes(root);
// P0-1 (rc.35 audit) — a module-private capability set. Only resolveByDiscovery (which actually ran witnessNoFork)
// mints a servedNoFork object into it; a transcript caller cannot add to it, so a plain look-alike object earns nothing.
const VERIFIED_SERVED = new WeakSet();
// round-16 P0-02 — the SAME unforgeable-token discipline for key-log freshness. `fresh` is EARNED by an authenticated
// fetch (F.5d), never a raw caller timestamp (a bare string, even 9999-99-99…, minted `fresh` and bypassed
// requireFreshKeylog). Only resolveByDiscovery, which actually fetched /.well-known/ust-keylog, mints an observation
// token into this set, bound to (domain, active_genesis, observed_at). A raw string/object is a caller assertion.
const VERIFIED_FRESH = new WeakSet();
// round-17 P0-02 — the SAME unforgeable-token discipline for the K_n(t) upper bound U. resolveAuthority is stateless and
// cannot itself verify an anchor (that needs the async substrate), so U is an input — and a RAW caller string is a
// forgeable coordinate (F.5e/Reach_C: no coordinate from a bare caller label; the MCP resolver tool exposed exactly this).
// Only the verified anchor seam (verify/verifyAsync) mints a proven-U token into this set; a raw string yields NO U ⇒
// a closed key lifecycle fails closed. `provenAnchor` is module-private so a caller cannot forge it.
const VERIFIED_ANCHOR = new WeakSet();
const provenAnchor = (t) => { const tok = { anchorTime: t }; VERIFIED_ANCHOR.add(tok); return tok; };
export function resolveAuthority(doc, opts = {}) {
  { const D = admitDeep(doc); if (D === ADMIT_REJECT) return { error: 'E-MALFORMED', detail: 'document is not an inert record (round-28 totality — a hostile getter cannot throw a host exception at this door)' }; doc = D; }   // round-28 P1-02 — admit at the door; totality
  if (!doc || typeof doc !== 'object' || !doc.state?.id?.domain_shard || !doc.sig?.pub) return { error: 'E-MALFORMED', detail: 'document must be a UST object with state.id and sig (round-17 P1-02 totality)' };
  const O = admitOpts(opts);   // round-19 P1-02 — inert snapshot of the caller record; a throwing accessor/Proxy trap → null → structured reject (not a host throw)
  if (O === null) return { error: 'E-MALFORMED', detail: 'opts must be an inert record (round-19 P1-02 totality — a hostile accessor/Proxy is a structured reject)' };
  let { genesis, keylog = [], noForkConfirmed = false, noForkEvidence, nameMap, trustRoots, corroborated = false, servedNoFork, anchorTime, keylogFreshAsOf, keylogHeadAnchor, substrateVerify, trust } = O;   // round-18 P1-01 — destructure from the admitted record so a null/hostile opts is a structured reject/default, not a host throw
  // rev38 R3 (round-31 P0-01) — admitOpts is SHALLOW (it preserves function capabilities); a NESTED untrusted DATA object in
  // opts stays a live caller object. resolveAuthority verifies `genesis` via resolveKeys (which admits its OWN snapshot) but
  // then RE-READS the raw nested genesis for contentHash + max_partitions — a two-face Proxy served the signed face to
  // resolveKeys and an unsigned face carrying elevated capacity to the outer reads. Every nested untrusted DATA object a
  // resolver verifies must be DEEP-admitted ONCE and read only from the frozen snapshot (R3 across the WHOLE input graph).
  if (genesis != null) { const G = admitDeep(genesis); if (G === ADMIT_REJECT) return { error: 'E-GENESIS', detail: 'genesis is not an inert record (round-31 R3 — a nested untrusted object is admitted once and read only from the snapshot)' }; genesis = G; }
  // round-17 P0-02 — U comes ONLY from a proven-anchor token (verify/verifyAsync mint it); a raw string never reaches K_n(t).
  const U = (anchorTime && typeof anchorTime === 'object' && VERIFIED_ANCHOR.has(anchorTime) && isRealRfc3339Z(anchorTime.anchorTime)) ? anchorTime.anchorTime : undefined;
  if (!genesis) return { strength: 'self-asserted', status: 'verified' };         // LIGHT — nothing to resolve
  if (genesis.state?.id?.domain_shard !== doc.state.id.domain_shard) return { error: 'E-GENESIS', detail: 'genesis domain mismatch' };
  const rk = resolveKeys(genesis, keylog);
  if (rk.error) return { error: rk.error, detail: rk.detail };
  const { validKeys, revoked, history } = rk;
  // §12.2a KEY-LOG FRESHNESS — "this key is still valid" is an authenticated NON-MEMBERSHIP claim: a CACHED key-log
  // proves only "revoke ∉ my view", never "revoke does not exist".
  // UST-0ol Phase 3 (P0-03) — the legacy `keylogHeadAnchor → attested` shortcut is DELETED. An anchored key-log HEAD
  // proves membership AT its anchor time, NOT that it is the LATEST head at the document's time: a revoke that
  // FOLLOWS the anchored prefix is invisible to it. Strong key-log freshness (corroborated/attested) is reachable
  // ONLY through the one checkpoint derivation (deriveCheckpointFreshness): authorization + strict terminality +
  // proven-after ordering + independent uniqueness. resolveAuthority reports at most `fresh` (single-view): a
  // round-16 P0-02 / F.5d — `fresh` is EARNED from an authenticated fetch, NEVER a raw caller string (that self-declared
  // the FreshnessStrength axis and bypassed requireFreshKeylog). Only a token minted by resolveByDiscovery into
  // VERIFIED_FRESH — bound to THIS domain + active genesis and observed no earlier than the proven U — lifts it; a bare
  // string/object is a caller assertion that stays `unverified` (⇒ requireFreshKeylog still floors to INDETERMINATE).
  let freshness = 'unverified';
  if (keylogFreshAsOf && typeof keylogFreshAsOf === 'object' && VERIFIED_FRESH.has(keylogFreshAsOf)
      && keylogFreshAsOf.domain === doc.state.id.domain_shard && keylogFreshAsOf.active_genesis === contentHash(genesis)
      && isRealRfc3339Z(keylogFreshAsOf.observed_at) && (!U || keylogFreshAsOf.observed_at >= U)) freshness = 'fresh';
  // rc.12: surface the ceremony-declared CAPACITY so callers can pass it as opts.capacity to verify()
  // once authority is established — the grant flows FROM resolution, never from a raw genesis.
  const gvCap = genesis.state?.data?.genesis?.value ?? {};
  const capacity = {   // round-24 P0-02 — canonical decimal strings only; a coercible `["4096"]` grants NO elevated capacity (falls to the floor)
    ...(canonUint(gvCap.max_partitions) !== undefined ? { maxPartitions: canonUint(gvCap.max_partitions) } : {}),
    ...(canonUint(gvCap.max_transcript_bytes) !== undefined ? { maxTranscriptBytes: canonUint(gvCap.max_transcript_bytes) } : {}),
  };
  // authority is granted ONLY if the doc's key_id maps to the doc's ACTUAL signing pub (binding, not membership).
  if (validKeys.get(doc.state.id.key_id) !== doc.sig.pub)
    return { strength: 'self-asserted', status: 'verified', detail: 'doc key not bound in this key-log' };
  // §12.2/#75 ROOT 1 — K_n(t) is a TWO-SIDED window over ORDERED authorization intervals (round-15 P0-02). A document is
  // key-active iff its proven anchor U lands INSIDE some active interval [from, to]; U before the FIRST authorization ⇒
  // premature; U in a retired GAP between intervals (add→retire→re-add→retire) ⇒ expired. Only decidable WITH a proven U.
  const hk = history.get(doc.state.id.key_id);                                     // U (the proven anchor upper bound) is resolved from the token at the top of resolveAuthority
  if (U && hk && U < hk.intervals[0].from)
    return { strength: 'self-asserted', status: 'premature', detail: 'document anchored before its signing key was authorized (K_n(t) lower bound §12.2)' };
  // §12.2 X1 — the UPPER bound, decided against the proven anchor U. Compromise is terminal; retirement leaves a GAP.
  // Per-interval "active until": the revoke transition R (v.to) ends the authorization window — F.5e: a key leaves the
  // active process at R, and the compromise estimate C can only SHORTEN/taint the window, never LENGTHEN it past R
  // (round-16 P1-01: rev12 used C alone, so a future C let a doc long after R still count as in-window). So the
  // compromised upper bound is min(R, C); a retired/open interval uses its own close time. A doc must land inside SOME
  // window; a doc in a retired GAP between intervals (add→retire→re-add→…) ⇒ expired.
  const rev = revoked.get(doc.state.id.key_id);
  const minStr = (a, b) => (a === null ? b : b === null ? a : a < b ? a : b);
  const inWindow = (U && hk) ? hk.intervals.some((v) => { const upper = v.end === 'compromised' ? minStr(v.to, rev.compromised_since) : v.to; return U >= v.from && (upper === null || U <= upper); }) : false;
  // round-16 P0-01 — a key that has LEFT the active set (its LAST interval is closed: retired/revoked, not re-added)
  // cannot be authorized WITHOUT a proven U: window membership is undecidable, so it must fail closed rather than fall
  // through to authoritative. (An OPEN last interval = currently active; that path is unaffected.)
  const lastClosed = !!(hk && hk.intervals[hk.intervals.length - 1].to !== null);
  let suspect = false;
  if (rev) {
    if (rev.reason === 'compromised') {
      if (!U) return { strength: 'self-asserted', status: 'revoked-untrusted', detail: 'compromised key + UNANCHORED doc → untrusted (X1)' };
      if (U >= rev.compromised_since) return { error: 'E-KEY', detail: 'signature not provably before compromise (U ≥ compromised_since, X1)' };
      if (!inWindow) return { strength: 'self-asserted', status: 'expired', detail: 'provably pre-compromise but signed outside every active window — retired GAP or past the revoke transition (K_n(t) two-sided §12.2)' };
      suspect = true;                                                             // provably pre-compromise AND within an active window, but C is a publisher estimate
    } else if (rev.reason === 'retired') {
      if (!U && lastClosed) return { strength: 'self-asserted', status: 'expired', detail: 'retired key currently out of the active set + UNANCHORED — cannot prove the signature predates retirement (K_n(t) needs a proven U, round-16 P0-01)' };
      if (U && !inWindow) return { strength: 'self-asserted', status: 'expired', detail: 'signed outside the key active interval — retired GAP / after retirement (K_n(t) two-sided §12.2 X1)' };
    }
  }
  // §12.1a / formal model F.5a — the name is now KEY-BOUND (K_n: doc key ∈ resolved set). The no-fork STRENGTH
  // is a function of the BASIS of the non-membership evidence, and honesty forbids collapsing them:
  //   · INDEPENDENT non-membership — an anchored verifiable-map inclusion (prefix-uniqueness ⇒ ¬∃rival) OR an
  //     out-of-band caller assertion (air-gap) — ⇒ `authoritative`; the map/caller does not rely on the publisher.
  //   · the publisher's OWN served witness list shows no rival ⇒ `corroborated` — a real, bounded fact (membership
  //     of A in the published set), but NOT independent non-membership (the publisher can omit a rival, F.5a).
  //   · no no-fork evidence at all ⇒ DENIED (status unavailable → the name-authority tier is not reached, W1).
  const st2 = suspect ? 'suspect' : 'verified';
  // #69 A2 P1 / P0-2 audit — `authoritative` requires INDEPENDENT non-membership, EARNED not self-declared:
  //   · a verified NAME NO-FORK EVIDENCE — a typed claim signed by a witness the CONSUMER trusts (trustRoots),
  //     bound to this domain + active genesis ⇒ `authoritative`, independently_verified, basis accepted-external-witness.
  //   · the independent name-map VERIFIER (#42) ⇒ `authoritative` once a real VerifiedMapReceipt is checked (future).
  //   · a raw `noForkConfirmed` boolean is NOT evidence — the caller vouches out-of-band (air-gap). It is a distinct
  //     `consumer-override` (independently_verified:false), NEVER silently `authoritative` (the removed overclaim,
  //     same class as `mapInclusion:true`). A consumer consciously honoring its own override sets acceptConsumerOverride
  //     at verify(); the verdict stays transparent. Present-but-invalid evidence never upgrades (fail-safe).
  if (nameMap && mapRootAdmitted(trust, nameMap.mapRoot)) {                          // #42 — name-map inclusion, root CONSUMER-ADMITTED (Phase 1); a self-supplied root never reaches here
    const nm = verifyActiveGenesisUniqueness(nameMap.proof, { domain_shard: doc.state.id.domain_shard, active_genesis: contentHash(genesis), mapRoot: nameMap.mapRoot });
    if (nm.authoritative) return { strength: 'authoritative', noFork: 'map-inclusion', independently_verified: true,
      basis: 'authenticated-map-uniqueness', map_root: nm.map_root, map_root_admitted: true, status: st2, capacity, freshness };
  }
  if (noForkEvidence !== undefined) {
    const ev = verifyNoForkEvidence(noForkEvidence, { domain_shard: doc.state.id.domain_shard, active_genesis: contentHash(genesis), trustRoots: trustRoots || {} });
    if (ev.ok) return { strength: 'authoritative', noFork: 'accepted-external-witness', independently_verified: true,
      basis: 'accepted-external-witness', witness_id: ev.witness_id, ...(ev.trust_domain ? { trust_domain: ev.trust_domain } : {}), status: st2, capacity, freshness };
  }
  // VERIFIED served-list no-fork ⇒ corroborated (HIGH, honest: membership in the published set, NOT independent
  // non-membership, F.5a). P0-1 (rc.35 audit) — the trust is an UNFORGEABLE internal token: only resolveByDiscovery
  // (which actually ran witnessNoFork: network fetch + anchor cross-check) can mint a servedNoFork into VERIFIED_SERVED.
  // A transcript caller's plain object {confirmed:true, active_genesis:<public hash>} is NOT in the set — the binding
  // hash it holds is public, so without the token it earns nothing beyond a caller assertion.
  if (servedNoFork?.confirmed === true && VERIFIED_SERVED.has(servedNoFork) && servedNoFork.active_genesis === contentHash(genesis))
    return { strength: 'corroborated', noFork: 'served-list', status: st2, capacity, freshness };
  // a bare `corroborated`/`noForkConfirmed` boolean OR an unminted `servedNoFork` is a CALLER ASSERTION, not a verified
  // predicate (a STATELESS verifier cannot fetch a served list). Like noForkConfirmed it is consumer-override, NEVER a
  // silent corroborated (self-audit rc.35 — same class as the removed `corroborated:true`/`mapInclusion:true`).
  if (noForkConfirmed || corroborated || servedNoFork) return { strength: 'consumer-override', noFork: 'caller-asserted', independently_verified: false, status: st2, capacity, freshness,
    ...(noForkEvidence !== undefined ? { detail: 'noForkEvidence rejected → consumer-override only (not independently verified)' } : {}) };
  return { strength: 'corroborated', noFork: 'unconfirmed', status: 'unavailable', capacity, freshness,
    detail: 'no independent no-fork evidence; a served witness only corroborates (§12.1a F.5a) → authority pending, retry' };
}

// ─── TOP §11.2 anchor-proof: recompute the Merkle inclusion path content_hash→root (RFC 6962, domain-sep
//     ust:leaf/ust:node). The SUBSTRATE check (e.g. bitcoin-ots) is DELEGATED to opts.substrateVerify (needs
//     external Bitcoin access — the caller/ustate's job). Returns { inclusion, time, status, anchorTime? }.
// round-28 P1-02 — public DOOR admits the proof once (a hostile getter → structured E-ANCHOR, never a host throw); the
// internal verifyCore calls verifyAnchorCore over the ALREADY-admitted doc.proof, so the substrate-receipt identity shim
// (`a === capA`) is not broken by a re-clone. Same public-door/internal-core split as verify.
export function verifyAnchor(contentHash, proof, opts = {}) {
  if (typeof contentHash !== 'string') return { inclusion: false, error: 'E-ANCHOR', detail: 'contentHash must be a string (round-29 P1-01 totality — a hostile object at arg 0 cannot throw at this door)' };
  const Pf = admitDeep(proof);
  if (Pf === ADMIT_REJECT) return { inclusion: false, error: 'E-ANCHOR', detail: 'proof is not an inert record (round-28 totality — a hostile getter cannot throw at this door)' };
  return verifyAnchorCore(contentHash, Pf, opts);
}
function verifyAnchorCore(contentHash, proof, opts = {}) {
  opts = opts || {};                                             // round-18 P1-01 — a default param only catches `undefined`; coerce `null` too (total boundary)
  // fail-closed on a malformed proof: validate shape BEFORE recomputing (no TypeError, no dir!=L ⇒ R fallthrough).
  const HASH = /^sha256:[0-9a-f]{64}$/;
  if (!proof || typeof proof !== 'object' || !Array.isArray(proof.path) || !HASH.test(proof.root || ''))
    return { inclusion: false, time: 'unproven', status: 'verified', error: 'E-ANCHOR', detail: 'malformed anchor proof' };
  for (const s of proof.path) if (!s || (s.dir !== 'L' && s.dir !== 'R') || !HASH.test(s.hash || ''))
    return { inclusion: false, time: 'unproven', status: 'verified', error: 'E-ANCHOR', detail: 'malformed path entry (dir must be "L"|"R", hash sha256:hex)' };
  let node = Hbytes('ust:leaf', Buffer.from(contentHash, 'utf8'));
  for (const s of proof.path) node = Hbytes('ust:node', Buffer.from(s.dir === 'L' ? s.hash + node : node + s.hash, 'utf8'));
  const inclusion = node === proof.root;
  if (!inclusion) return { inclusion: false, time: 'unproven', status: 'verified', detail: 'inclusion path does not reach root' };
  if (!opts.substrateVerify) return { inclusion: true, time: 'unproven', status: 'unavailable', detail: 'inclusion OK; substrate not verified (caller job)' };
  const sub = opts.substrateVerify(proof.anchor, proof.root);          // → { final, time }
  // #69 E1 — the official substrate plugins are ASYNC; a sync verify() cannot await one. Detect the thenable
  // and say so HONESTLY (not a silent 'unproven') — the caller must use verifyAsync / resolveByDiscovery,
  // which pre-resolve the substrate. Fail-safe either way: a Promise is never mistaken for a final anchor.
  if (sub && typeof sub.then === 'function') return { inclusion: true, time: 'unproven', status: 'unavailable', detail: 'substrate check is ASYNC — use verifyAsync() or resolveByDiscovery() (they await it), not sync verify()' };
  if (!sub) return { inclusion: true, time: 'unproven', status: 'unavailable', detail: 'substrate unreachable' };
  // round-17 P1-01 — the substrate result is a CLOSED, TYPED leaf (F.5.0/C3/I4): `final` must be a strict Boolean and
  // a final anchor MUST carry a REAL RFC3339-Z instant. A truthy non-Boolean ("yes") or a non-string/empty time
  // ({}) can no longer mint TimeStrength=anchored (and can no longer coerce past the N9 generated_at ≤ anchor check).
  const dec = decodeSubstrate(sub);   // round-19 P0-02 — read the anchored instant + assurance from the INERT decoded record, never the live seam object
  if (!dec) return { inclusion: true, time: 'unproven', status: 'unavailable', detail: 'substrate not a typed FINAL receipt (final must be an OWN Boolean true AND carry an OWN real RFC3339-Z instant on a plain record; a prototype/accessor look-alike earns nothing) — no F_t (round-17 P1-01 / round-18 P0-02 / round-19 P0-02)' };
  // #71 — carry the substrate's ASSURANCE basis so TOP names its trust model honestly (an OTS plugin that
  // corroborates via independent explorers reports `explorer-corroborated`; an operator real-node/SPV plugin
  // would report `bitcoin-node`). TOP is earned either way; assurance says HOW, never inflating the tier.
  return { inclusion: true, time: 'anchored', status: 'verified', anchorTime: dec.time, ...(dec.assurance ? { assurance: dec.assurance } : {}) };
}

// #69 E1 — the ONE async entry: verify() is deliberately sync (portable, no await in the hot path), but the
// official substrate plugins are async. verifyAsync pre-resolves a doc.proof's substrate ONCE (await), then
// runs the sync verifier with the resolved receipt as a sync shim — so TOP is reachable with async plugins
// through a single contract, and verify() never has to become async. Everything else is identical to verify().
export async function verifyAsync(doc, opts = {}) {
  opts = admitOpts(opts);                                        // round-19 P1-02 — inert snapshot; a throwing accessor/Proxy trap → null → structured reject (not a host throw)
  if (opts === null) return { result: 'E-MALFORMED', tier: 'NONE', detail: 'opts must be an inert record (round-19 P1-02 totality)' };
  const D = admitDeep(doc);                                      // round-27 (3) — admit ONCE at this public door; below runs verifyCore over the inert snapshot (a getter can't split the substrate await from the sync verify)
  if (D === ADMIT_REJECT) return { result: 'E-MALFORMED', tier: 'NONE', detail: 'document is not an inert record (round-27: the ONE input boundary)' };
  doc = D;
  if (!doc?.proof || !opts.substrateVerify || opts.offline) return verifyCore(doc, opts);
  // round-17 P0-01 — verify an IMMUTABLE SNAPSHOT. The live object could be swapped between the await and the sync
  // verify (TOCTOU): the substrate receipt is obtained for root A, then a mutated document B with root B reuses it and
  // gets VALID:TOP for evidence that was never its own (I4/F.5c: TimeStrength=anchored must be evidence for content_hash(d)).
  // Snapshot before the await; the sync shim ALSO binds the receipt to the captured (anchor, root), so a different root
  // can never claim it.
  let snap; try { snap = JSON.parse(JSON.stringify(doc)); } catch { return verifyCore(doc, opts); }
  const capA = snap.proof?.anchor, capR = snap.proof?.root;
  let receipt; try { receipt = await opts.substrateVerify(capA, capR); } catch { receipt = null; }
  return verifyCore(snap, { ...opts, substrateVerify: (a, r) => (a === capA && r === capR ? receipt : null) });   // verifyCore (NOT verify): no re-clone, so the receipt-identity binding `a === capA` holds across the door
}

// §3.1/F.5c FORK-CHOICE — canonical = anchor-included. One `ust_id` may have several candidate documents with
// DISTINCT content_hashes (the honest dual-writer race — main + failover both seal the slot — or an adversary
// offering two states). The CANONICAL document is the one whose content_hash is in the authority's anchored hour
// root; a consumer holding more than one resolves DETERMINISTICALLY from the chain, not from local arrival order
// (Proposition F.5c). Async because "anchor-included" means substrate-final, which verifyAsync awaits. Fail-safe:
// with no substrateVerify NO candidate is anchored ⇒ INDETERMINATE, never a guessed winner. Returns ONE verdict.
export async function forkChoice(candidates, opts = {}) {
  opts = admitOpts(opts);                                              // round-20 P2-01 — forkChoice missed admitOpts in rev16; a hostile opts Proxy threw at `{...opts}`. Now the same inert admission as the other boundaries.
  if (opts === null) return { result: 'E-MALFORMED', detail: 'opts must be an inert record (round-20 P2-01 totality)' };
  if (!Array.isArray(candidates) || candidates.length === 0)
    return { result: 'E-MALFORMED', detail: 'forkChoice needs a non-empty array of candidate documents' };
  if (candidates.length > BOUNDS.forkCandidates)                      // round-21 P1-02 — F.9 fan-out: refuse an over-budget candidate count BEFORE snapshotting/verifying (never truncate a fork-choice input)
    return { result: 'INDETERMINATE', reason: 'resource_limit', detail: `forkChoice got ${candidates.length} candidates > ${BOUNDS.forkCandidates} (§F.9 fan-out — refused, never truncated; round-21 P1-02)` };
  // round-19 P0-01 — SNAPSHOT every candidate to an inert clone BEFORE ANY read, INCLUDING the ust_id grouping below.
  // rev15 still (a) read `c.state.id.ust_id` off the LIVE object to group, and (b) fell back to the live object (`d=c`)
  // when JSON cloning threw — so a one-shot throwing toJSON, or a ust_id accessor that lies once, let the classified/
  // returned value diverge from the verified snapshot. A snapshot failure is now a structured E-MALFORMED, NEVER a
  // live-object fallback: the value grouped, verified, and returned as canonical is the SAME frozen bytes
  // (F.5c: canonical(ust_id) = the unique dᵢ whose content_hash ∈ leaves — a mutable original re-read mid-await breaks it).
  const snaps = [];
  for (const c of candidates) {
    let d; try { d = JSON.parse(JSON.stringify(c)); } catch { return { result: 'E-MALFORMED', detail: 'forkChoice candidate is not an inert JSON snapshot (throwing toJSON / hostile accessor) — no live-object fallback (round-19 P0-01)' }; }
    if (d === null || typeof d !== 'object') return { result: 'E-MALFORMED', detail: 'forkChoice candidate did not snapshot to a JSON object (round-19 P0-01)' };
    snaps.push(d);
  }
  const ids = new Set(snaps.map((d) => d?.state?.id?.ust_id));         // group from the SNAPSHOT, never the live object
  if (ids.size !== 1 || ids.has(undefined))                            // fork-choice is PER-SLOT — a mixed batch is a caller bug, not a fork
    return { result: 'E-MALFORMED', detail: 'forkChoice candidates must all share one ust_id (fork-choice is per-slot)' };
  const ust_id = [...ids][0];
  // verify each at its NATURAL tier (strip the floors — forkChoice does its own tier logic). A candidate is
  // ANCHOR-INCLUDED iff it VERIFIES and its content_hash sits in a substrate-final anchored root (time 'anchored').
  const vopts = { ...opts, requireAnchored: false, requireAuthoritative: false };
  // the object returned as canonical MUST be the exact snapshot dᵢ whose content_hash is in F_t (F.5c) — verify the
  // SAME frozen dᵢ that is grouped and returned, so classification, content_hash, and returned value cannot diverge.
  // round-21 P1-02 — the candidate BUDGET above bounds the fan-out; there is NO dedupe. rev18 dedup'd by content_hash,
  // which was LOSSY (round-22 self-catch): content_hash covers the STATE, not the `proof`, so two candidates with one
  // state but different anchor proofs collapsed — dropping a VALID proof behind an invalid one and HIDING an
  // equivocation (the same lossy-projection class the witness fix closed). Verify EVERY snapshot; the budget caps the work.
  const verds = await Promise.all(snaps.map(async (d) => ({ doc: d, v: await verifyAsync(d, vopts) })));
  const anchored = [], losers = [], invalid = [], unauthenticated = [];
  for (const { doc, v } of verds) {
    if (!/^VALID:/.test(v.result || '')) { invalid.push({ result: v.result, detail: v.detail }); continue; }
    // #75 P0-03a — the authority is the RESOLVED one (key ∈ K_A via genesis+key-log), NEVER the unverified LIGHT
    // `domain_shard` claim. A candidate whose key is NOT bound to its claimed authority (self-asserted / pinned)
    // is an IMPOSTER for that name and can NEVER be canonical under it — the math: content_hash commits the
    // CLAIMED domain, authority resolution proves the claim (ROOT 1+2). No manifest needed to close this.
    const bound = v.identity && (v.identity.strength === 'authoritative' || v.identity.strength === 'corroborated');
    if (!bound) { unauthenticated.push({ content_hash: v.content_hash, claimed: doc?.state?.id?.domain_shard, anchored: v.time?.strength === 'anchored' }); continue; }
    const rec = { doc, content_hash: v.content_hash, authority: doc.state.id.domain_shard, tier: v.tier };   // domain_shard now VERIFIED-bound (resolveAuthority checked genesis.domain == doc.domain)
    (v.time?.strength === 'anchored' ? anchored : losers).push(rec);   // anchored = in the chain; else a valid non-anchored candidate
  }
  if (anchored.length === 0)                                           // no BOUND candidate in Fₜ yet — undecidable, wait or resolve at HIGH
    return { result: 'INDETERMINATE', ust_id, reason: 'no authoritative anchor-included candidate', detail: 'no candidate is BOTH bound to its claimed authority (key ∈ key-log) AND in a substrate-final anchored root', losers: losers.length, invalid: invalid.length, ...(unauthenticated.length ? { unauthenticated } : {}) };
  // group anchored by AUTHORITY (domain_shard). A single authority with ≥2 DISTINCT anchored content_hashes for
  // one ust_id is EQUIVOCATION — it signed a root containing both = a non-repudiable, punishable fault (E-PREV).
  const byAuth = new Map();
  for (const a of anchored) { if (!byAuth.has(a.authority)) byAuth.set(a.authority, new Set()); byAuth.get(a.authority).add(a.content_hash); }
  for (const [authority, hashes] of byAuth) if (hashes.size >= 2)
    return { result: 'E-PREV', ust_id, authority, detail: `operator equivocation: authority ${authority} anchored ${hashes.size} distinct content_hashes for one ust_id`, content_hashes: [...hashes].sort() };   // sorted — set-determined, not arrival-order
  if (byAuth.size > 1)                                                 // distinct NAMES sharing a ust_id string — not a fork; canonicity is per-authority
    return { result: 'MULTI_AUTHORITY', ust_id, detail: 'distinct authorities anchored the same ust_id string — not a fork (canonicity is per-authority)', canonicals: anchored.map((a) => ({ authority: a.authority, content_hash: a.content_hash })).sort((x, y) => (x.authority + x.content_hash < y.authority + y.content_hash ? -1 : 1)) };
  // round-22 P1-01 — the returned canonical must be a function of the candidate SET, not arrival order (F.5c: "two
  // consumers with the same candidate set … emit the SAME canonical"). All `anchored` here share ONE content_hash (byAuth
  // passed), but they may be equal-state / different-valid-proof variants; pick the one with the smallest canonical
  // serialization so `forkChoice([A,B])` and `forkChoice([B,A])` return the identical document.
  // round-23 P1-03 — the ordering key must be TOTAL over the admitted candidate domain: canon(doc) can THROW on outer
  // proof extras (a valid TOP doc whose proof carries numeric diagnostics), which left winner=anchored[0] (arrival order).
  // JSON.stringify over the inert snapshot never throws and is a total order, so min is set-determined for EVERY candidate.
  const jkey = (d) => { try { return JSON.stringify(d); } catch { return ''; } };
  let winner = anchored[0], winnerKey = jkey(winner.doc);
  for (const a of anchored) { const k = jkey(a.doc); if (k < winnerKey) { winner = a; winnerKey = k; } }
  // round-22 P1-01 + round-23 P1-04 — the WHOLE return is a function of the candidate SET; every diagnostic array is
  // sorted by its FULL record (a total tie-break), because content_hash alone leaves equal-hash records in arrival order.
  const bj = (x, y) => { const a = jkey(x), b = jkey(y); return a < b ? -1 : a > b ? 1 : 0; };
  return { result: 'CANONICAL', ust_id, authority: winner.authority, content_hash: winner.content_hash, tier: winner.tier, canonical: winner.doc,
    losers: losers.map((l) => ({ content_hash: l.content_hash, tier: l.tier, reason: 'valid but not anchor-included for this slot (out-raced or unanchored)' })).sort(bj),
    ...(unauthenticated.length ? { unauthenticated: unauthenticated.slice().sort(bj) } : {}),   // key-unbound impostors under a claimed name — recorded, never canonical
    ...(invalid.length ? { invalid: invalid.slice().sort(bj) } : {}) };
}

// ─── #44 AGENT-SAFETY: throw-on-non-VALID. `isValid(r)` returns a bool an agent can IGNORE (catch the error,
// use the data anyway — the exact laziness the audit named). `verifyOrThrow` puts verification in the CONTROL
// FLOW: a non-VALID verdict THROWS, so the language forces the agent to handle it — it cannot silently continue.
// The thrown error CARRIES the full structured verdict (`.verdict`) for branching. The distinction matters:
// UstInvalid = a real integrity failure (forged/tampered/broken chain); UstIndeterminate = "cannot decide yet"
// (substrate unreachable, unsupported alg) — an agent must treat these DIFFERENTLY (reject vs retry), so they are
// distinct classes, not one. The soft path (read the verdict as data) stays available: just call `verify` directly.
export class UstInvalid extends Error {
  constructor(verdict) { super('UST verification failed: ' + (verdict?.error || 'INVALID') + (verdict?.detail ? ' — ' + verdict.detail : '')); this.name = 'UstInvalid'; this.verdict = verdict; this.code = verdict?.error; }
}
export class UstIndeterminate extends Error {
  constructor(verdict) { super('UST verification indeterminate: ' + (verdict?.reason || 'unknown') + (verdict?.detail ? ' — ' + verdict.detail : '')); this.name = 'UstIndeterminate'; this.verdict = verdict; this.reason = verdict?.reason; }
}
// Assert a verdict is VALID (any tier) or THROW the typed error. Works on the result of verify OR verifyAsync —
// so an async/TOP caller does `assertValid(await verifyAsync(doc, opts))`. Returns the verdict for chaining.
export function assertValid(verdict) {
  if (/^VALID:/.test(verdict?.result || '')) return verdict;
  if (verdict?.result === 'INDETERMINATE') throw new UstIndeterminate(verdict);
  throw new UstInvalid(verdict || { error: 'E-MALFORMED', detail: 'no verdict' });
}
// The SYNC one-call agent entrypoint: verify + assert in the control flow. For anchored/async substrates use
// `assertValid(await verifyAsync(doc, opts))`.
export function verifyOrThrow(doc, opts = {}) { return assertValid(verify(doc, opts)); }

// ─── #69 C — the EXPECTED GRID. `ust_id` IS the time coordinate, so the slots a cadence implies over an
// interval are COMPUTED, not stored: parse `ust:YYYYMMDD.HH[MM[SS]]` ↔ UTC epoch, step by the cadence. The
// grid's precision follows the cadence (a multiple of 3600 → hour, of 60 → minute, else second).
function ustToEpoch(ustId) {
  const m = /^ust:(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})?(\d{2})?$/.exec(ustId || '');
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +(m[5] || 0), +(m[6] || 0)) / 1000 : null;
}
function epochToUst(epoch, prec) {
  const d = new Date(epoch * 1000), p = (n) => String(n).padStart(2, '0');
  let s = `ust:${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}.${p(d.getUTCHours())}`;
  if (prec !== 'hour') s += p(d.getUTCMinutes());
  if (prec === 'second') s += p(d.getUTCSeconds());
  return s;
}
export function ustGrid(from, to, cadenceSec) {
  const e0 = ustToEpoch(from), e1 = ustToEpoch(to);
  if (e0 === null || e1 === null || !(cadenceSec > 0) || e1 < e0) return null;
  const prec = cadenceSec % 3600 === 0 ? 'hour' : cadenceSec % 60 === 0 ? 'minute' : 'second';
  const grid = [];
  for (let e = e0; e <= e1; e += cadenceSec) { grid.push(epochToUst(e, prec)); if (grid.length > 200000) return null; }  // bound (§13 discipline)
  return grid;
}

// §11.3 continuity — resolve the cadence IN FORCE at a slot time from the genesis value + a cadence-log (the
// key-log pattern applied to cadence: a signed, prev-chained sequence of changes). Old data verifies under the
// cadence signed for ITS time, so an operator changing cadence NEVER retroactively invalidates history. Each
// entry is a normal transcript, verified by §14; the log is genesis-rooted and prev-chained. → {cadence}|{error}.
export function resolveCadence(genesis, cadenceLog = [], atTime, opts) {
  { const G = admitDeep(genesis); if (G === ADMIT_REJECT) return { error: 'E-MALFORMED', detail: 'genesis is not an inert record (round-28 totality)' }; genesis = G; const C = admitDeep(cadenceLog); if (C === ADMIT_REJECT) return { error: 'E-MALFORMED', detail: 'cadenceLog is not an inert record (round-28 totality)' }; cadenceLog = C; }   // round-28 P1-02 — admit at the door
  const _o = admitOpts(opts); if (_o === null) return { error: 'E-MALFORMED', detail: 'opts is not an inert record (round-29 P1-01 totality — a hostile 4th arg cannot throw at this door)' };   // round-26/29 — admit the opts at the door (a hostile Proxy 4th arg → structured, never a host throw)
  const { keylog } = _o;
  if (cadenceLog !== undefined && cadenceLog !== null && !Array.isArray(cadenceLog)) return { error: 'E-MALFORMED', detail: 'cadenceLog must be an array' };
  cadenceLog = Array.isArray(cadenceLog) ? cadenceLog : [];
  // #75 P1-03 — cadence is a canonical positive-integer STRING of seconds ("1.5" / "030" / 1e2 rejected).
  const gCad = genesis?.state?.data?.genesis?.value?.cadence;
  if (gCad !== undefined && parseCadenceInt(gCad) === null) return { error: 'E-MALFORMED', detail: 'genesis cadence not a canonical positive integer of seconds (§11.3)' };
  let cadence = gCad !== undefined ? parseCadenceInt(gCad) : null;                 // the genesis value is authorized by construction (self-signed)
  if (!Array.isArray(cadenceLog) || !cadenceLog.length) return { cadence };
  if (cadenceLog.length > 256) return { error: 'E-BOUNDS', detail: 'cadence-log > 256 (§13)' };
  // #71-followup P0 — a cadence CHANGE is an OPERATOR AUTHORITY parameter, not "any LIGHT doc with the same
  // domain_shard". Resolve the authorized key set ONCE (genesis + key-log) and reject an entry signed OUTSIDE
  // it. Without the key-log only the genesis key can authorize a change (fail-closed, not fail-open).
  const rk = resolveKeys(genesis, Array.isArray(keylog) ? keylog : []);
  if (rk.error) return { error: rk.error, detail: 'cadence authority: ' + rk.detail };
  // #75 P0-02c — a cadence entry MUST be signed by a currently-ACTIVE key (not merely ever-seen): a retired or
  // rotated-out or revoked key can no longer move the grid. `active` already excludes all of them (state machine).
  const active = new Set(rk.active.values());
  const atE = ustToEpoch(atTime);
  let prev = contentHash(genesis), lastEff = null;
  for (const [i, e] of cadenceLog.entries()) {
    const ev = verify(e, { context: 'key' });
    if (!isValid(ev)) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' invalid: ' + (ev.error || ev.result) };
    if (e.state.id.class !== 'cadence') return { error: 'E-MALFORMED', detail: 'cadence-log entry ' + i + ' not class:cadence' };
    if (e.state.id.domain_shard !== genesis.state.id.domain_shard) return { error: 'E-AUTHORITY', detail: 'cadence entry ' + i + ' domain mismatch' };
    if (e.state.provenance?.prev !== prev) return { error: 'E-PREV', detail: 'cadence entry ' + i + ' not chained' };
    if (!active.has(e.sig.pub)) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' NOT signed by a currently-active key (retired/revoked/unauthorized, §12.2)' };
    const op = e.state.data.cadence_op.value;
    const effE = ustToEpoch(op.effective_from);
    if (effE === null) return { error: 'E-MALFORMED', detail: 'cadence entry ' + i + ' bad effective_from' };
    if (lastEff !== null && effE < lastEff) return { error: 'E-PREV', detail: 'cadence effective_from not monotonic (entry ' + i + ')' };
    if (parseCadenceInt(op.cadence) === null) return { error: 'E-MALFORMED', detail: 'cadence entry ' + i + ' cadence not a canonical positive integer of seconds' };
    if (atE !== null && effE <= atE) cadence = parseCadenceInt(op.cadence);        // latest change in force at atTime wins
    lastEff = effE; prev = contentHash(e);
  }
  return { cadence };
}

// ─── #76/#77 AUTHORITY CHECKPOINT — the latest-head authority object (distinct from the STREAM `buildCheckpoint`).
//     THREE LAYERS (a signer cannot sign its own signature): unsigned CheckpointBody → preimage
//     canon({purpose:"ust:authority-checkpoint-signature", body}) → signed {body, sig}, with
//     authorityCheckpointId = H("ust:authority-checkpoint", canon({body, sig})). External evidence (anchors, map
//     proofs) is NEVER inside the id. Authority is carried IN-BAND and NON-CIRCULARLY: genesis authorizes C₀'s
//     signer; each Cₙ₋₁ authorizes the signer of Cₙ (its `checkpoint_authority.next_*`, effective at seq n); a
//     checkpoint NEVER authorizes its own signer. The expected signer is resolved from PRIOR state BEFORE the
//     signature is trusted; the carried `current_key_id` is diagnostic and MUST equal that resolved signer.
export function buildAuthorityCheckpoint({ domain_shard, genesis_epoch, sequence, previous_checkpoint = null, previous_epoch_final_checkpoint, active_genesis, current_key_id, next_key_id, next_pub, effective_sequence, keylog }) {
  const ca = { current_key_id,
    ...(next_key_id !== undefined ? { next_key_id } : {}),
    ...(next_pub !== undefined ? { next_pub } : {}),
    ...(effective_sequence !== undefined ? { effective_sequence } : {}) };
  return { version: '1', purpose: 'ust:authority-checkpoint', domain_shard, genesis_epoch, sequence: String(sequence),
    ...(previous_checkpoint !== undefined && previous_checkpoint !== null ? { previous_checkpoint } : {}),   // C₀ is genesis-rooted: no prior
    ...(previous_epoch_final_checkpoint !== undefined ? { previous_epoch_final_checkpoint } : {}),           // epoch-B initial: binds epoch-A final
    active_genesis, checkpoint_authority: ca, keylog };
}
export function sealAuthorityCheckpoint(body, privKeyObj, pubB64url) {
  const sig = edSign(null, Buffer.from(canon({ purpose: 'ust:authority-checkpoint-signature', body }), 'utf8'), privKeyObj).toString('base64url');
  return { body, sig: { alg: 'Ed25519', key_id: keyId(pubB64url), pub: pubB64url, sig } };
}
export const authorityCheckpointId = (cp) => H('ust:authority-checkpoint', canon({ body: cp.body, sig: cp.sig }));   // ONLY body+sig — external evidence excluded
const isSeq = (s) => typeof s === 'string' && /^(0|[1-9]\d*)$/.test(s);                                              // canonical decimal, no leading zeroes
function authorityCheckpointSigOk(cp, expectedKeyId, expectedPub) {
  const s = cp?.sig, spub = admitSigner(s, expectedKeyId);   // round-35 — the ONE signer admission: key_id === expectedKeyId === keyId(pub), exact Ed25519 wrapper, Pub32/Sig64
  if (spub === null || spub !== expectedPub) return { ok: false, detail: 'signer is not the authorized checkpoint authority (round-35 admitSigner)' };
  if (!edVerifyStrict(spub, canon({ purpose: 'ust:authority-checkpoint-signature', body: cp.body }), s.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true };
}
// Verify a chain of authority checkpoints. Root the FIRST element's signer in the genesis-authorized checkpoint key
// (`genesisAuthority = {key_id, pub}`, the reference profile's dedicated key) OR a pinned prior checkpoint
// (`pinnedPrior = {checkpoint_id, authority:{key_id, pub}, sequence}`). No root ⇒ INDETERMINATE(authority_unresolved).
// ─── #76 §1.7 CHECKPOINT RECOVERY — a genesis-authorized N-of-M multisig that re-authorizes the checkpoint authority
//     after key loss WITHOUT bypassing checkpoint validation. Role-separated from data/checkpoint keys; the recovery
//     set is genesis-fixed (immutable within the epoch). A DORMANT emergency mechanism, NOT a normal rotation: it
//     authorizes ONLY the next checkpoint's replacement key, bound to (domain, epoch, last_accepted_checkpoint, seq).
export function checkpointRecoveryClaim({ domain_shard, genesis_epoch, last_accepted_checkpoint, replacement_key_id, replacement_pub, effective_sequence }) {   // round-35 P1-01 — the NORMATIVE recovery tuple; a human `reason` is NOT part of the signed authority claim (portability divergence removed)
  return { purpose: 'ust:checkpoint-authority-recovery', domain_shard, genesis_epoch, last_accepted_checkpoint,
    replacement_authority: { key_id: replacement_key_id, pub: replacement_pub }, effective_sequence: String(effective_sequence) };
}
export function buildRecoveryStatement(fields, privKeyObj, issuerPubB64url) {
  const claim = checkpointRecoveryClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export function verifyCheckpointRecovery(statements, config) {
  const c = admitOpts(config); if (c === null) return { recovered: false, detail: 'config must be an inert record (round-23 P1-02 totality)' };   // round-23 P1-02 — total: admit config BEFORE destructure
  const { domain_shard, genesis_epoch, last_accepted_checkpoint, effective_sequence, recoveryKeys = {}, threshold = 2 } = c;
  const S = admitDeep(statements); if (S === ADMIT_REJECT) return { recovered: false, detail: 'recovery statements are not an inert record (round-27 P0-03 — a getter on replacement_authority cannot re-sign the quorum after canonicalization)' };   // round-27 P0-03 — snapshot ONCE; the quorum payload is a frozen copy of the exact canonical claim whose signature was checked
  statements = S;
  if (!Array.isArray(statements) || statements.length === 0) return { recovered: false, detail: 'no recovery statements' };
  // M5 instance — the recovery quorum is the SAME algebra (admit → group → count → adjudicate): voter = the
  // genesis-authorized recovery signer, ValidThreshold bounded by |recoveryKeys| (a closed voter set), >1 winning
  // replacement = CONFLICT never first-wins (P0-05), and a malformed leaf admits nothing instead of throwing
  // (the rc.35 round-2 recovery-DoS: canon(claim) threw through the whole verification).
  const r = quorumAdjudicate(statements, { threshold, maxVoters: Object.keys(recoveryKeys).length, admit: (s) => {
    if (!closedRecoveryWitness(s)) return null;                                         // round-34 P0-04 — CLOSED envelope { claim, issuer_id, sig } + typed sig wrapper (Ed25519, strict Pub32, Sig64) + exact typed recovery claim (purpose, replacement_authority strict Pub32), mirroring the kernel; an open/untyped statement mints nothing
    const { claim, issuer_id, sig } = s;
    if (claim.domain_shard !== domain_shard || claim.genesis_epoch !== genesis_epoch || claim.last_accepted_checkpoint !== last_accepted_checkpoint) return null;   // scope binding (shape/purpose already typed)
    if (claim.effective_sequence !== String(effective_sequence)) return null;           // authorizes ONLY the next checkpoint (effective_sequence already a CanonicalSeq)
    const ra = claim.replacement_authority, cc = canon(claim);                          // ra key_id/pub already typed + strict Pub32 by the closed decode
    const pub = recoveryKeys[issuer_id];
    if (!pub || pub !== sig.pub) return null;                                           // genesis-authorized recovery signer pub (signer identity already bound by closedRecoveryWitness → admitSigner)
    if (!edVerifyStrict(sig.pub, cc, sig.sig)) return null;                             // sig bytes already Sig64-typed by the closed decode
    return { key: cc, voter: issuer_id, payload: ra };
  } });
  if (r.outcome === 'conflict') return { recovered: false, conflict: true, detail: 'recovery equivocation: ' + r.count + ' conflicting replacements each reached threshold' };
  if (r.outcome === 'invalid-threshold') return { recovered: false, detail: 'invalid recovery threshold ' + threshold + ' (must be 1..' + Object.keys(recoveryKeys).length + ')' };
  return r.outcome === 'accepted'
    ? { recovered: true, replacement_authority: r.payload, threshold: String(threshold), signers: r.voters }
    : { recovered: false, detail: 'recovery quorum not met (no claim reached ' + threshold + ' distinct signers)' };
}

// ─── #76 (audit-8) GENESIS-EPOCH TRANSITION — a new genesis epoch must NOT silently reset the authority chain. The
//     A→B transition is a typed statement SIGNED BY EPOCH A's checkpoint authority, binding A's final checkpoint and
//     naming epoch B's initial checkpoint authority + initial sequence. Epoch B's C₀ then binds that final checkpoint.
export function epochTransitionClaim({ domain_shard, from_genesis_epoch, from_final_checkpoint, from_sequence, to_active_genesis, to_genesis_epoch, to_key_id, to_pub, to_initial_sequence = '0' }) {
  // M4.4 — a transition hands authority to a VERIFIED new genesis, not a free epoch label: it binds
  // to_active_genesis, and to_genesis_epoch is CANONICAL to it (derived when omitted; verify re-checks).
  const toEpoch = to_genesis_epoch ?? (isHashStr(to_active_genesis) ? genesisEpoch(to_active_genesis) : undefined);
  return { purpose: 'ust:genesis-epoch-transition', domain_shard, from_genesis_epoch, from_final_checkpoint,
    ...(from_sequence !== undefined ? { from_sequence: String(from_sequence) } : {}),   // M-ERA: bind the epoch-A FINAL sequence (the reference checker requires it; UST-Protocol round-11 P1-01)
    ...(to_active_genesis !== undefined ? { to_active_genesis } : {}),                 // absence is caught at verify (M4.4), kept out of canon
    ...(toEpoch !== undefined ? { to_genesis_epoch: toEpoch } : {}),
    to_checkpoint_authority: { key_id: to_key_id, pub: to_pub }, to_initial_sequence: String(to_initial_sequence) };
}
export function buildEpochTransition(fields, privKeyObj, issuerPubB64url) {
  const claim = epochTransitionClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export function verifyEpochTransition(statement, config) {
  const c = admitOpts(config); if (c === null) return { ok: false, detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 — total for null/hostile config
  const { domain_shard, from_genesis_epoch, from_final_checkpoint, from_sequence, fromAuthority } = c;
  const St = admitDeep(statement); if (St === ADMIT_REJECT) return { ok: false, detail: 'transition statement is not an inert record (round-27 — the returned to_active_genesis/to_checkpoint_authority must equal the SIGNED bytes, no getter re-read)' };   // round-27 — snapshot: the return re-reads claim.* after canon-verify; a getter could sign one destination and hand back another
  const { claim, sig } = St || {};
  if (!fromAuthority) return { ok: false, detail: 'no from-authority' };
  if (!closedTransitionWitness(St)) return { ok: false, detail: 'transition witness not typed (round-34 P0-04 — CLOSED envelope { claim, sig, issuer_id? } + Ed25519 sig wrapper + strict Pub32 + exact typed transition claim, mirroring the kernel closedTransition; an extra field / alg:RSA / non-canonical pub mints nothing)' };
  if (claim.domain_shard !== domain_shard || claim.from_genesis_epoch !== from_genesis_epoch || claim.from_final_checkpoint !== from_final_checkpoint) return { ok: false, detail: 'transition not bound to this (domain, from-epoch, from-final-checkpoint)' };
  // round-24 P1-02 — the signed `from_sequence` MUST equal epoch A's verified FINAL sequence (the reference checker
  // requires it; the public verifier skipped the coordinate). Require it present + canonical; when the caller supplies the
  // verified prior sequence, require equality — a transition cannot claim it bridges from a sequence epoch A never reached.
  // round-25 P1-01 — ONE CanonicalSeq decoder (isSeq: canonical decimal string, no leading zero, no `String([...])`
  // coercion) at EVERY signed sequence coordinate. The signed from_sequence must be canonical, AND the caller MUST
  // supply the verified prior-chain FINAL sequence as a canonical coordinate: an omitted comparison coordinate can no
  // longer yield ok:true trusting an attacker's signed from_sequence (a full transition-verification API is not partial).
  if (!isSeq(claim.from_sequence)) return { ok: false, detail: 'transition from_sequence missing or non-canonical (round-24 P1-02)' };
  if (!isSeq(from_sequence)) return { ok: false, detail: 'epoch transition requires the verified prior-chain FINAL sequence as a canonical from_sequence coordinate (round-25 P1-01 — no partial verification)' };
  if (from_sequence !== claim.from_sequence) return { ok: false, detail: `transition from_sequence ${claim.from_sequence} ≠ epoch A final sequence ${from_sequence} (round-24 P1-02)` };
  if (!isSeq(claim.to_initial_sequence)) return { ok: false, detail: 'transition to_initial_sequence non-canonical (round-25 P1-01 — a coercible `["0"]` no longer seeds the next epoch)' };
  // M4.4 — the destination is a VERIFIED genesis, never a free epoch label: the transition MUST bind
  // to_active_genesis, and to_genesis_epoch MUST be canonical to it (the M2 hygiene, uniform).
  if (!isHashStr(claim.to_active_genesis) || claim.to_genesis_epoch !== genesisEpoch(claim.to_active_genesis)) return { ok: false, detail: 'transition does not bind a verified destination genesis (to_active_genesis missing or to_genesis_epoch non-canonical, M4.4)' };
  const ta = claim.to_checkpoint_authority;
  if (!admitAuthorityKey(ta)) return { ok: false, detail: 'to_checkpoint_authority not a usable { key_id === keyId(pub) } pair (round-36 admitAuthorityKey; also bound by the closed transition claim schema)' };
  const tpub = admitSigner(sig, fromAuthority.key_id);   // round-35 — key_id === fromAuthority.key_id === keyId(pub), exact Ed25519 wrapper
  if (tpub === null || tpub !== fromAuthority.pub) return { ok: false, detail: 'transition not signed by epoch A checkpoint authority (round-35 admitSigner)' };
  if (!edVerifyStrict(tpub, canon(claim), sig.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true, to_active_genesis: claim.to_active_genesis, to_genesis_epoch: claim.to_genesis_epoch, to_checkpoint_authority: ta, to_initial_sequence: claim.to_initial_sequence };
}

const CP_BODY_KEYS = new Set(['version', 'purpose', 'domain_shard', 'genesis_epoch', 'sequence', 'previous_checkpoint', 'previous_epoch_final_checkpoint', 'active_genesis', 'checkpoint_authority', 'keylog']);
const CP_CA_KEYS = new Set(['current_key_id', 'next_key_id', 'next_pub', 'effective_sequence']);
const isHashStr = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
export function verifyAuthorityCheckpointChain(chain, config) {
  // round-27 P0-01/P0-02 — snapshot the COMPLETE (chain, config) authority graph ONCE, DEEP. rev24 put admitDeep on the
  // evidence/genesis-context entries but NOT here, so the chain verifier held live `cp.body` / raw `genesis` / `recoveries`
  // references and re-read them AFTER signature verification — a getter signed a no-rotation body then minted an attacker
  // rotation (P0-02), and a raw genesis TOCTOU installed an unsigned authority (P0-01). No live caller reference survives.
  // admitDeep PASSES BRANDED HANDLES THROUGH (context / a chain-handle pinnedPrior stay branded); raw fields are deep-copied.
  if (config != null && typeof config !== 'object') return { error: 'E-MALFORMED', detail: 'config must be an inert record (round-24 P1-01 totality)' };
  const cfg = config == null ? {} : admitDeep(config); if (cfg === ADMIT_REJECT) return { error: 'E-MALFORMED', detail: 'config is not an inert record — an accessor/getter in the authority config cannot re-read after verification (round-27)' };
  const C = admitDeep(chain); if (C === ADMIT_REJECT) return { error: 'E-MALFORMED', detail: 'chain is not an inert record — a getter on a checkpoint body cannot sign one body and mint another (round-27 P0-02)' };
  chain = C;
  let { genesis, context, genesisAuthority, pinnedPrior, recoveries, recoveryKeys, recoveryThreshold, epochTransitions, keylogEntries } = cfg;   // let — the body may re-resolve some fields (e.g. recovery)
  if (!Array.isArray(chain) || chain.length === 0) return { error: 'E-MALFORMED', detail: 'empty checkpoint chain' };
  // M4.2 (C4 bounds-before-work) — the optional full prefix-extension witness is the key-log ENTRY vector itself,
  // capped by the §13 resolution ceiling BEFORE any Merkle work.
  if (keylogEntries !== undefined && (!Array.isArray(keylogEntries) || keylogEntries.length > 256 || keylogEntries.some((e) => !isHashStr(e))))
    return { result: 'INVALID', error: 'E-BOUNDS', detail: 'keylogEntries must be ≤ 256 sha256 entry hashes (§13 key-log ceiling)' };
  // P1-04 — prefer roots RESOLVED from the signed genesis; a raw genesisAuthority is a consumer PIN, reported as such.
  // C1 (M2) — a VerifiedAuthorityContext (the verifiedGenesisContext seam output) is the PREFERRED downstream root:
  // scope + authority + recovery keys all come from ONE verified derivation, never re-read from raw genesis fields.
  let authority_root = 'consumer-pin', ctxGenesis = null;
  // K3 — the context root MUST be a BRANDED GenesisHandle (minted only by verifiedGenesisContext). A caller-shaped
  // {scope_id, checkpoint_authority} object is NOT a handle, so it is ignored → round-3 P0-1 (forged verified-context)
  // is closed at the type level, not by comparing extra fields. A non-handle object passed as `context` is rejected.
  if (context !== undefined) {
    if (!isHandle('genesis', context)) return { result: 'INVALID', error: 'E-AUTHORITY', detail: 'context is not a verified GenesisHandle (K3 — a caller-shaped context cannot root a chain; use verifiedGenesisContext)' };
    // round-26 P0-01/P0-02 (rev25, model M2 L642 "never raw fields" + F.5l "recovery immutable within the epoch") — a
    // branded context is the SOLE authority root: EVERY scope/authority/recovery parameter is a function of contentHash(g)
    // via the ONE derivation. A raw authority-root field ALONGSIDE the context is a mixed configuration that substitutes
    // the root the context fixes — a foreign `pinnedPrior` seized the chain scope/authority (P0-01) and raw recovery was
    // INJECTED when the context carried none (P0-02), both while still reporting authority_root:"verified-context". Reject
    // the whole raw family; recovery comes ONLY from the context. (The raw family stays live WITHOUT a context — consumer-pin.)
    if (pinnedPrior !== undefined || genesis !== undefined || genesisAuthority !== undefined || recoveryKeys !== undefined || recoveryThreshold !== undefined)
      return { result: 'INVALID', error: 'E-AUTHORITY', detail: 'a verified GenesisHandle context is the SOLE authority root — no raw pinnedPrior / genesis / genesisAuthority / recoveryKeys / recoveryThreshold may accompany it (round-26 P0-01/P0-02: never raw fields, M2/F.5l)' };
    genesisAuthority = context.checkpoint_authority; ctxGenesis = context.active_genesis; authority_root = 'verified-context';
    if (context.recoveryKeys) { recoveryKeys = context.recoveryKeys; recoveryThreshold = context.recoveryThreshold; }   // recovery is FIXED by the genesis, never a call argument
  } else if (genesis) { const gr = resolveCheckpointRoots(genesis); if (gr?.genesisAuthority) { genesisAuthority = gr.genesisAuthority; authority_root = 'genesis'; } if (gr?.recoveryKeys && recoveryKeys === undefined) { recoveryKeys = gr.recoveryKeys; recoveryThreshold = recoveryThreshold ?? gr.recoveryThreshold; } }
  if (!genesisAuthority && !pinnedPrior) return { result: 'INDETERMINATE', reason: 'authority_unresolved', detail: 'no genesis-rooted or pinned-prior checkpoint authority to resolve the first signer' };
  // K5 (round-3 P0-2) — a mid-chain cold start roots ONLY in a full PinnedCheckpointState (a SCOPED snapshot), never a
  // bare {id, authority, sequence}. Admissible as a branded CheckpointChainHandle (produced by a prior verification) OR
  // a complete consumer-supplied snapshot; either way it carries scope_id + keylog, so the continuation is scope-bound
  // and append-only holds from the pin. A scope-free pin used to let a continuation jump into a new domain/genesis.
  let prev = null;
  if (pinnedPrior !== undefined) {
    const pp = pinnedPrior, a = pp?.authority_for_next;
    const full = isHandle('chain', pp) || (pp && typeof pp === 'object'
      && isHashStr(pp.scope_id) && isHashStr(pp.checkpoint_id) && isSeq(pp.sequence)
      && admitAuthorityKey(a)   // round-36 — the ONE authority-key admission on a raw pinnedPrior authority (exact { key_id, pub }, strict Pub32, key_id === keyId(pub))
      && isSeq(pp.keylog_size) && isHashStr(pp.keylog_root) && isHashStr(pp.keylog_head));
    if (!full) return { result: 'INVALID', error: 'E-AUTHORITY', detail: 'pinnedPrior must be a branded CheckpointChainHandle or a full PinnedCheckpointState {scope_id, checkpoint_id, sequence, authority_for_next, keylog_size, keylog_root, keylog_head} — a scope-free pin is rejected (round-3 P0-2)' };
    prev = { id: pp.checkpoint_id, authority: a, sequence: pp.sequence, pinScope: pp.scope_id,
      body: { keylog: { length: pp.keylog_size, root: pp.keylog_root, head: pp.keylog_head } } };   // synthetic prior — carries keylog for append-only; no domain/epoch (scope check binds them)
  }
  for (let i = 0; i < chain.length; i++) {
    const cp = chain[i], b = cp?.body;
    if (!b || b.purpose !== 'ust:authority-checkpoint') return { result: 'INVALID', error: 'E-MALFORMED', detail: 'not an authority-checkpoint body' };
    if (!isSeq(b.sequence)) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'sequence is not a canonical decimal string' };
    // P1-01 — enforce the FIXED CheckpointBody grammar BEFORE trusting a (validly-signed) body: version + exact-key
    // allowlists (body / checkpoint_authority / keylog) + keylog field shapes. A correct signature over junk is junk.
    if (b.version !== '1') return { result: 'INVALID', error: 'E-MALFORMED', detail: 'checkpoint version must be "1"' };
    if (Object.keys(b).some((k) => !CP_BODY_KEYS.has(k))) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'unknown checkpoint body field' };
    const ca0 = b.checkpoint_authority;
    if (!ca0 || typeof ca0 !== 'object' || Object.keys(ca0).some((k) => !CP_CA_KEYS.has(k))) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'malformed or unknown checkpoint_authority field' };
    const kl0 = b.keylog;
    if (!kl0 || typeof kl0 !== 'object' || Object.keys(kl0).some((k) => !['root', 'length', 'head'].includes(k)) || !isHashStr(kl0.root) || !isSeq(kl0.length) || !isHashStr(kl0.head)) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'malformed keylog {root,length,head}' };
    if (!closedCheckpointWitness(cp)) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'checkpoint witness is not a closed typed ADT (round-34 P0-02/P0-01 — exactly { body, sig }, typed sig wrapper with strict Pub32, exact typed body, mirroring the kernel closedCheckpoint; an unsigned extra sig field must not shift the checkpoint id, a non-canonical Pub32 must not sign)' };   // BEFORE authorityCheckpointId / sig verify
    // M2 (rc.36 refactor) — genesis_epoch is CANONICAL: it MUST equal H("ust:genesis-epoch", active_genesis). The publisher
    // cannot pick the uniqueness namespace: two rival C₀ with the same active_genesis but different epoch (epoch-split)
    // used to key to DIFFERENT map slots and both attest; now a non-canonical epoch is malformed, so rivals collide in ONE slot.
    if (!isHashStr(b.active_genesis) || b.genesis_epoch !== genesisEpoch(b.active_genesis))
      return { result: 'INVALID', error: 'E-MALFORMED', detail: 'genesis_epoch ≠ canonical H("ust:genesis-epoch", active_genesis) — publisher-chosen namespace rejected (M2, epoch-split)' };
    // 1) resolve the EXPECTED signer from PRIOR state (genesis / pinned / previous checkpoint) — before trusting cp
    let expected;
    if (prev === null) {
      // P0-3 (rc.35 audit) — a genesis/authority-rooted START is C₀: sequence "0", NO previous-checkpoint fields, and
      // (when the genesis doc is known) active_genesis == contentHash(genesis). Else a RETIRED genesis key could present
      // an arbitrary nonzero singleton with no previous_checkpoint and RE-ROOT the chain, bypassing every rotation. A
      // start from a later point needs pinnedPrior (carrying the prior sequence + authority), never the raw root.
      if (b.sequence !== '0' || b.previous_checkpoint !== undefined || b.previous_epoch_final_checkpoint !== undefined)
        return { result: 'INVALID', error: 'E-SEQ', detail: 'a genesis/authority-rooted first checkpoint must be sequence "0" with no previous_checkpoint (re-root rejected)' };
      if (authority_root === 'genesis' && b.active_genesis !== contentHash(genesis))
        return { result: 'INVALID', error: 'E-GENESIS', detail: 'C₀ active_genesis ≠ contentHash(genesis) — checkpoint not bound to its rooting genesis' };
      if (authority_root === 'verified-context' && b.active_genesis !== ctxGenesis)
        return { result: 'INVALID', error: 'E-GENESIS', detail: 'C₀ active_genesis ≠ the verified context active_genesis — checkpoint not bound to its rooting scope (C1/M2)' };
      expected = { key_id: genesisAuthority.key_id, pub: genesisAuthority.pub };       // C₀ rooted in the genesis-authorized key
    } else if (prev.body && prev.body.genesis_epoch !== undefined && b.genesis_epoch !== prev.body.genesis_epoch) {   // a scope-pin has no genesis_epoch — its continuation is a normal step bound by scope, not an epoch transition
      // GENESIS-EPOCH TRANSITION — a new epoch must NOT silently reset: it needs an authenticated A→B transition
      // signed by epoch A's authority (prev.authority), binding A's final checkpoint (prev.id). Same domain.
      if (b.domain_shard !== prev.body.domain_shard) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'domain_shard changes within the chain' };
      const et = epochTransitions && epochTransitions[b.genesis_epoch] ? verifyEpochTransition(epochTransitions[b.genesis_epoch], { domain_shard: b.domain_shard, from_genesis_epoch: prev.body.genesis_epoch, from_final_checkpoint: prev.id, from_sequence: prev.body.sequence, fromAuthority: prev.authority }) : { ok: false };   // round-24 P1-02 — pass epoch A's verified FINAL sequence so the transition's signed from_sequence is checked
      if (!et.ok || et.to_genesis_epoch !== b.genesis_epoch) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'genesis_epoch changes without an authenticated epoch transition (no silent reset)' };
      // M4.4 — the epoch-initial checkpoint must LIVE IN the genesis the transition bound: a transition to genesis B
      // cannot seed a chain for genesis B'. With M2 canonical epochs on BOTH sides this equality is derivable
      // (epoch match ⇒ genesis match); the explicit check is the hash-collision belt, kept for defense-in-depth.
      if (b.active_genesis !== et.to_active_genesis) return { result: 'INVALID', error: 'E-GENESIS', detail: 'epoch-initial active_genesis ≠ the transition to_active_genesis (M4.4 — the destination genesis is bound, not a label)' };
      if (b.previous_epoch_final_checkpoint !== prev.id) return { result: 'INVALID', error: 'E-PREV', detail: 'epoch-initial checkpoint does not bind the prior-epoch final checkpoint' };
      if (b.sequence !== et.to_initial_sequence) return { result: 'INVALID', error: 'E-SEQ', detail: 'epoch-initial sequence ≠ the transition to_initial_sequence' };   // round-25 P1-01: both canonical (isSeq), no String() coercion
      expected = { key_id: et.to_checkpoint_authority.key_id, pub: et.to_checkpoint_authority.pub };
    } else {
      const pca = prev.body ? prev.body.checkpoint_authority : null;                    // the authority Cₙ₋₁ committed for THIS sequence, else unchanged
      expected = (pca && pca.next_key_id !== undefined && pca.effective_sequence === b.sequence) ? { key_id: pca.next_key_id, pub: pca.next_pub } : prev.authority;
      if (b.previous_checkpoint !== prev.id) return { result: 'INVALID', error: 'E-PREV', detail: 'previous_checkpoint ≠ id of the prior accepted checkpoint' };
      if (b.sequence !== String(BigInt(prev.sequence) + 1n)) return { result: 'INVALID', error: 'E-SEQ', detail: 'sequence is not prev+1' };
      // K5 — a scope-pinned continuation MUST live in the pin's scope (round-3 P0-2): scope(g) = H(tag, active_genesis)
      // binds the whole genesis, so this is stronger than a domain match and covers the pin's missing domain/epoch.
      if (prev.pinScope !== undefined && authorityScopeId(b.active_genesis) !== prev.pinScope)
        return { result: 'INVALID', error: 'E-GENESIS', detail: 'pinned-continuation active_genesis is not in the pinned scope (round-3 P0-2 — a scope-free jump is rejected)' };
      if (prev.body?.domain_shard !== undefined && b.domain_shard !== prev.body.domain_shard) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'domain_shard changes within the chain' };
      // M4.2 ChainConsistent — the key log is APPEND-ONLY ACROSS same-epoch checkpoints (closes keylog-rewind). Length
      // monotone + equal-length-identical are UNCONDITIONAL; a GROWTH edge REQUIRES the prefix-extension witness
      // (keylogEntries) — without it append-only across the growth is unproven (round-3 P0-3), so the chain is
      // INDETERMINATE, never VALID. Length alone does not prove [A]→[X,Y] is an append.
      if (prev.body) {
        const Lp = BigInt(prev.body.keylog.length), Ln = BigInt(b.keylog.length);
        if (Ln < Lp) return { result: 'INVALID', error: 'E-COMMIT', detail: 'keylog length ' + Ln + ' < prior checkpoint ' + Lp + ' — a signed key-log rewind (append-only violated, M4.2)' };
        if (Ln === Lp && (b.keylog.root !== prev.body.keylog.root || b.keylog.head !== prev.body.keylog.head))
          return { result: 'INVALID', error: 'E-COMMIT', detail: 'equal-length keylog with a different root/head — a same-length history rewrite (M4.2)' };
        if (Ln > Lp && keylogEntries === undefined)
          return { result: 'INDETERMINATE', reason: 'chain_consistency_unproven', detail: 'a growth edge (keylog ' + Lp + '→' + Ln + ') requires a prefix-extension witness (keylogEntries); append-only across the growth cannot be proven from length alone (round-3 P0-3)' };
      }
    }
    // M4.2 prefix-extension witness — when the consumer supplies the key-log ENTRY vector (it already holds it for
    // resolveKeys), EVERY checkpoint's committed keylog must be the commitment over a PREFIX of that ONE vector; all
    // prefixes of one vector are mutually consistent, so this proves ChainConsistent for the whole chain.
    if (keylogEntries !== undefined) {
      const L = Number(BigInt(b.keylog.length));
      if (L > keylogEntries.length) return { result: 'INVALID', error: 'E-COMMIT', detail: 'checkpoint commits a keylog of length ' + L + ' but only ' + keylogEntries.length + ' entries were supplied (M4.2)' };
      const kc = buildKeylogCommitment(keylogEntries.slice(0, L));
      if (kc.root !== b.keylog.root || kc.head !== b.keylog.head)
        return { result: 'INVALID', error: 'E-COMMIT', detail: 'checkpoint keylog is not the commitment over a prefix of the supplied key-log entries (M4.2 prefix-extension)' };
    }
    if (!expected || !expected.key_id || !expected.pub) return { result: 'INDETERMINATE', reason: 'authority_unresolved', detail: 'cannot resolve the expected signer for sequence ' + b.sequence };
    // 2) the signer must be the RESOLVED authority — OR, after key loss, a genesis-recovery-threshold REPLACEMENT for
    //    this exact sequence (bound to the prior checkpoint). Recovery re-authorizes the signer; it does NOT bypass any
    //    later checkpoint check. Both candidates are resolved from PRIOR state before cp's signature is trusted.
    const candidates = [expected];
    let recoveredWith = null;
    if (recoveries && prev && recoveries[b.sequence]) {
      const rec = verifyCheckpointRecovery(recoveries[b.sequence], { domain_shard: b.domain_shard, genesis_epoch: b.genesis_epoch, last_accepted_checkpoint: prev.id, effective_sequence: b.sequence, recoveryKeys: recoveryKeys || {}, threshold: recoveryThreshold });
      if (rec.recovered) { recoveredWith = rec.replacement_authority; candidates.push(recoveredWith); }
    }
    const matched = candidates.find((c) => c && c.key_id && c.pub && authorityCheckpointSigOk(cp, c.key_id, c.pub).ok);
    if (!matched) return { result: 'INVALID', error: 'E-AUTHORITY', detail: 'checkpoint not signed by the authorized' + (recoveredWith ? ' (or recovery-replacement)' : '') + ' checkpoint authority' };
    // 3) the carried current_key_id is diagnostic — it must EQUAL the matched signer, never resolve it
    if (b.checkpoint_authority?.current_key_id !== matched.key_id) return { result: 'INVALID', error: 'E-AUTHORITY', detail: 'carried current_key_id ≠ the authorized signer' };
    // 4) rotation exactness — all-or-none; keyId(next_pub)==next_key_id; effective_sequence == seq+1 (no arbitrary future activation)
    const ca = b.checkpoint_authority || {};
    const rot = [ca.next_key_id, ca.next_pub, ca.effective_sequence].filter((x) => x !== undefined).length;
    if (rot !== 0 && rot !== 3) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'checkpoint_authority rotation fields must be all-present or all-absent' };
    if (rot === 3) {
      if (!admitAuthorityKey({ key_id: ca.next_key_id, pub: ca.next_pub })) return { result: 'INVALID', error: 'E-KEY', detail: 'rotation next authority not a usable { key_id === keyId(pub) } pair' };   // round-36 — the ONE authority-key admission
      if (ca.effective_sequence !== String(BigInt(b.sequence) + 1n)) return { result: 'INVALID', error: 'E-SEQ', detail: 'effective_sequence ≠ sequence+1' };
    }
    prev = { id: authorityCheckpointId(cp), authority: matched, sequence: b.sequence, body: b };
  }
  const lb = chain[chain.length - 1].body, lca = lb.checkpoint_authority || {};
  const activeAuthority = (lca.next_key_id !== undefined) ? { key_id: lca.next_key_id, pub: lca.next_pub, effective_sequence: lca.effective_sequence } : prev.authority;
  // K3 — a VALID chain also mints a branded CheckpointChainHandle carrying the full PinnedCheckpointState (§5 of the
  // calculus): the ONLY admissible mid-chain cold-start root besides a genesis (K5 requires the brand, closing the
  // scope-free-pin round-3 P0-2). `pin` is a scoped snapshot, never a bare key.
  const pin = mintHandle('chain', { scope_id: authorityScopeId(lb.active_genesis), checkpoint_id: prev.id, sequence: lb.sequence,
    authority_for_next: activeAuthority, keylog_size: lb.keylog?.length, keylog_root: lb.keylog?.root, keylog_head: lb.keylog?.head });
  return { result: 'VALID', head: prev.id, length: String(chain.length), sequence: lb.sequence, active_genesis: lb.active_genesis, keylog: lb.keylog, activeAuthority, authority_root, pin };
}

// ─── #76 Phase C — CHECKPOINT UNIQUENESS (independent anti-equivocation). `attested` needs a `¬∃ rival at
//     (domain, genesis_epoch, sequence)` proof the PUBLISHER does not control: an `accepted-witness-quorum` (≥
//     threshold DISTINCT consumer-resolved trust domains signing the BYTE-IDENTICAL typed uniqueness claim) — or the
//     `authenticated-map-uniqueness` map path (#42). Independence is CONSUMER-owned (issuer→domain), never
//     self-declared; a bare-observation co-sign is corroboration, not uniqueness (wrong purpose ⇒ not admitted).
export function checkpointUniquenessClaim({ domain_shard, genesis_epoch, sequence, checkpoint }) {   // round-34 P0-03 — EXACTLY the kernel VOTE_CLAIM: no as_of (a signer can't self-declare time) / observed_map_root; builder == public verifier == kernel
  return { purpose: 'ust:checkpoint-uniqueness-attestation', domain_shard, genesis_epoch, sequence: String(sequence), checkpoint };
}
export function buildUniquenessAttestation(fields, privKeyObj, issuerPubB64url) {
  const claim = checkpointUniquenessClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
// ─── M5 (UST-6vj) — ONE QUORUM ALGEBRA: admit (authenticate FIRST, total) → group by canon(claim) AFTER admission →
//     count DISTINCT consumer-resolved voters per group → adjudicate. Uniqueness attestations and recovery statements
//     are INSTANCES of this core, so the guarantees hold once for both: an unauthenticated element can never poison
//     the group reference (the rc.35 round-2 quorum-poison: `ref` was locked to the FIRST binding claim BEFORE its
//     signature was checked, so a garbage-signed variant suppressed the honest quorum); the winner is independent of
//     iteration order; >1 winning group is CONFLICT/equivocation, never first-wins; malformed input admits nothing
//     and throws nothing (total). ValidThreshold: integer, 1 ≤ t (≤ |voters| where the voter set is closed).
function quorumAdjudicate(items, { threshold, maxVoters, admit }) {
  if (!Number.isInteger(threshold) || threshold < 1 || (maxVoters !== undefined && threshold > maxVoters))
    return { outcome: 'invalid-threshold', detail: 'threshold must be an integer in 1..' + (maxVoters ?? '∞') + ' (got ' + threshold + ')' };
  const groups = new Map();                                                             // canon(claim) → { voters:Set, tags:Set, payload }
  for (const it of Array.isArray(items) ? items : []) {
    let a; try { a = admit(it); } catch { a = null; }                                   // total: a malformed element admits nothing, never throws
    if (!a) continue;
    let g = groups.get(a.key); if (!g) { g = { voters: new Set(), tags: new Set(), payload: a.payload }; groups.set(a.key, g); }
    g.voters.add(a.voter); if (a.tag !== undefined) g.tags.add(a.tag);
  }
  const winners = [...groups.values()].filter((g) => g.voters.size >= threshold);
  if (winners.length === 0) return { outcome: 'quorum_not_met', detail: 'no claim reached ' + threshold + ' distinct voters (groups: ' + groups.size + ')' };
  if (winners.length > 1) return { outcome: 'conflict', detail: 'equivocation: ' + winners.length + ' conflicting claims each reached threshold', count: winners.length };
  const w = winners[0];
  return { outcome: 'accepted', voters: [...w.voters].sort(), tags: [...w.tags].sort(), payload: w.payload };   // round-23 P1-01 — canonical order: the M5 result is set-determined, not iteration-order (uniqueness + recovery both inherit this)
}
export function verifyCheckpointUniqueness(attestations, config) {
  const c = admitOpts(config); if (c === null) return { attested: false, detail: 'config must be an inert record (round-23 P1-02 totality)' };   // round-23 P1-02 — total: admit config BEFORE destructure (a null/hostile config is a structured result, never a host throw)
  { const A = admitDeep(attestations); if (A === ADMIT_REJECT) return { attested: false, detail: 'attestations are not an inert record (round-27 — quorum reads each claim once)' }; attestations = A; }   // round-27 — snapshot the signed inputs, uniform boundary
  const { domain_shard, genesis_epoch, sequence, checkpoint, trustRoots = {}, domains = {}, threshold = 2 } = c;
  if (!Array.isArray(attestations) || attestations.length === 0) return { attested: false, detail: 'no attestations' };
  // M5 instance — voter = the CONSUMER-resolved trust domain (many issuers in one domain count once); admission =
  // typed purpose + no self-declared independence + binding + consumer-accepted issuer + strict signature, all
  // BEFORE any grouping. P0-4: threshold ≥ 1 (0 distinct ≥ 0 earned attested from an empty set).
  const r = quorumAdjudicate(attestations, { threshold, admit: (a) => {
    if (!closedVoteWitness(a)) return null;                                             // round-34 P0-03 — CLOSED envelope { claim, issuer_id?, sig } + Ed25519 sig wrapper (strict Pub32, Sig64) + exact VOTE_CLAIM (purpose + no as_of / trust_domain / issuer_id in the claim, no extra field), mirroring the kernel; the official builder emits exactly this claim
    const { claim, issuer_id, sig } = a;
    if (claim.domain_shard !== domain_shard || claim.genesis_epoch !== genesis_epoch || claim.sequence !== String(sequence) || claim.checkpoint !== checkpoint) return null;   // scope binding (sequence already a CanonicalSeq by the closed decode)
    const cc = canon(claim);                                                            // may throw on a malformed leaf → the core skips it (total)
    const root = trustRoots[issuer_id]; const pub = typeof root === 'string' ? root : root?.pub;
    if (!pub || pub !== sig.pub) return null;                                           // consumer-accepted issuer pub (signer identity issuer_id===sig.key_id===keyId(pub) already bound by closedVoteWitness → admitSigner)
    if (!edVerifyStrict(sig.pub, cc, sig.sig)) return null;                             // sig bytes already Sig64-typed by the closed decode
    const dom = domains[issuer_id]; if (typeof dom !== 'string' || !dom.length || hasLoneSurrogate(dom)) return null;   // round-23 P0-01 + round-24 P0-03 — a NON-EMPTY Unicode-SCALAR NFC string only (object/array/number/null, or a lone UTF-16 surrogate outside §6, is NOT an admitted domain and would fake an independent quorum)
    return { key: cc, voter: dom.normalize('NFC'), tag: issuer_id };
  } });
  if (r.outcome === 'conflict') return { attested: false, conflict: true, detail: r.detail };   // two rival uniqueness claims each with quorum = equivocation, never first-wins
  return r.outcome === 'accepted'
    ? { attested: true, basis: 'accepted-witness-quorum', threshold: String(threshold), accepted_witnesses: r.tags, trust_domains: r.voters }
    : { attested: false, detail: r.outcome === 'invalid-threshold' ? r.detail : 'quorum not met: no byte-identical claim reached ' + threshold + ' distinct trust domains' };
}

// ─── #76/#42 AUTHENTICATED-MAP UNIQUENESS — the INDEPENDENT (non-publisher) non-membership coordinate, via a sparse
//     Merkle tree keyed by H(typed-key): the key's position is a deterministic function of the key, so an inclusion
//     proof for a key returning a value IS the non-membership proof for every rival value at that key (prefix/position
//     uniqueness). Two TYPED, domain-separated key/value spaces (NEVER a generic flag): checkpoint-map (attested
//     freshness) and name-map (authoritative identity). The consumer trusts the (anchored, independent) map root.
const SMT_DEPTH = 256;
const smtDefaults = (() => { const d = new Array(SMT_DEPTH + 1); d[SMT_DEPTH] = H('ust:smt-empty', ''); for (let i = SMT_DEPTH - 1; i >= 0; i--) d[i] = H('ust:smt-node', d[i + 1] + '|' + d[i + 1]); return d; })();
const smtHex = (kh) => kh.replace(/^sha256:/, '');
const smtBit = (hex, i) => (parseInt(hex[i >> 2], 16) >> (3 - (i & 3))) & 1;                 // MSB-first bit i of the 256-bit key hash
const smtLeaf = (kh, vh) => H('ust:smt-leaf', kh + '|' + vh);
function smtRoot(depth, entries) {                                                          // entries: [{hex, kh, vh}]
  if (entries.length === 0) return smtDefaults[depth];
  if (depth === SMT_DEPTH) return smtLeaf(entries[0].kh, entries[0].vh);
  const L = entries.filter((e) => smtBit(e.hex, depth) === 0), R = entries.filter((e) => smtBit(e.hex, depth) === 1);
  return H('ust:smt-node', smtRoot(depth + 1, L) + '|' + smtRoot(depth + 1, R));
}
// Build a verifiable map from typed leaves; returns the root and a prover (inclusion co-path, top→bottom).
export function buildVerifiableMap(leaves) {
  const seen = new Set();                                                             // P1-05: an authenticated dictionary is ONE value per key — reject duplicates (root would be input-order dependent otherwise)
  for (const l of leaves) { if (seen.has(l.key)) throw Object.assign(new Error('E-MALFORMED: duplicate typed key in verifiable map (one value per key)'), { code: 'E-MALFORMED' }); seen.add(l.key); }
  const entries = leaves.map((l) => ({ hex: smtHex(l.key), kh: l.key, vh: l.value }));
  const root = smtRoot(0, entries);
  const prove = (key) => { const hex = smtHex(key); const sib = []; let ents = entries;
    for (let d = 0; d < SMT_DEPTH; d++) { const goR = smtBit(hex, d) === 1;
      const L = ents.filter((e) => smtBit(e.hex, d) === 0), R = ents.filter((e) => smtBit(e.hex, d) === 1);
      sib.push(smtRoot(d + 1, goR ? L : R)); ents = goR ? R : L; }
    return { siblings: sib }; };
  return { root, prove };
}
// verify inclusion (value present) or non-membership (value=null) of key under root, using the co-path
function smtVerify(root, key, value, proof) {
  const sibs = admitHashPath(proof?.siblings, SMT_DEPTH); if (sibs === null) return false;   // round-37 P0-01 — every SMT co-path element is a canonical sha256 hash (no `+` coercion grammar, no host throw on a null-proto object)
  const hex = smtHex(key);
  let node = value === null ? smtDefaults[SMT_DEPTH] : smtLeaf(key, value);
  for (let d = SMT_DEPTH - 1; d >= 0; d--) node = smtBit(hex, d) === 0 ? H('ust:smt-node', node + '|' + sibs[d]) : H('ust:smt-node', sibs[d] + '|' + node);
  return node === root;
}
// TYPED, domain-separated key/value spaces — one map may serve both predicates with NO collision (a checkpoint proof
// is not a name proof). Exported so operators/verifiers build leaves without recomputing the hashing.
export const checkpointMapLeaf = ({ domain_shard, genesis_epoch, sequence, checkpoint }) => ({ key: H('ust:checkpoint-map-key', canon({ domain_shard, genesis_epoch, sequence: String(sequence) })), value: H('ust:checkpoint-map-value', canon({ checkpoint })) });
export const nameMapLeaf = ({ domain_shard, active_genesis }) => ({ key: H('ust:name-map-key', canon({ domain_shard })), value: H('ust:name-map-value', canon({ active_genesis })) });
// TWO distinct TYPED predicates over the SAME map infra — never a generic `verifyMapInclusion(flag)`:
export function verifyCheckpointMapUniqueness(proof, config) {
  const c = admitOpts(config); if (c === null) return { attested: false, detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 — total for null/hostile config
  { const Pf = admitDeep(proof); if (Pf === ADMIT_REJECT) return { attested: false, detail: 'proof is not an inert record (round-27)' }; proof = Pf; }   // round-27 — snapshot
  const { domain_shard, genesis_epoch, sequence, checkpoint, mapRoot } = c;
  if (typeof domain_shard !== 'string' || typeof genesis_epoch !== 'string' || typeof checkpoint !== 'string' || typeof mapRoot !== 'string' || !isSeq(sequence)) return { attested: false, detail: 'missing/invalid uniqueness fields (round-24 P1-01 + round-25 P1-01: sequence must be a CanonicalSeq) — canon over undefined/coercible would throw or ambiguate the leaf' };   // guard the leaf inputs so a null/empty/non-canonical config returns structured, never a thrown E-CANON or a coerced `["0"]` leaf
  const { key, value } = checkpointMapLeaf({ domain_shard, genesis_epoch, sequence, checkpoint });
  if (smtVerify(mapRoot, key, value, proof)) return { attested: true, basis: 'authenticated-map-uniqueness', map_root: mapRoot };
  if (smtVerify(mapRoot, key, null, proof)) return { attested: false, absent: true, detail: 'no checkpoint bound at (domain, genesis_epoch, sequence) under mapRoot (proven non-membership)' };
  return { attested: false, detail: 'checkpoint not the unique value at (domain, genesis_epoch, sequence) under mapRoot (a rival value is bound)' };
}
export function verifyActiveGenesisUniqueness(proof, config) {
  const c = admitOpts(config); if (c === null) return { authoritative: false, detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 — total for null/hostile config
  { const Pf = admitDeep(proof); if (Pf === ADMIT_REJECT) return { authoritative: false, detail: 'proof is not an inert record (round-27)' }; proof = Pf; }   // round-27 — snapshot
  const { domain_shard, active_genesis, mapRoot } = c;
  if (typeof domain_shard !== 'string' || typeof active_genesis !== 'string' || typeof mapRoot !== 'string') return { authoritative: false, detail: 'missing/invalid uniqueness fields (round-24 P1-01) — canon over undefined would throw' };   // round-24 P1-01 — guard the leaf inputs (null/empty config → structured, never a thrown E-CANON)
  const { key, value } = nameMapLeaf({ domain_shard, active_genesis });
  if (smtVerify(mapRoot, key, value, proof)) return { authoritative: true, basis: 'authenticated-map-uniqueness', map_root: mapRoot };
  if (smtVerify(mapRoot, key, null, proof)) return { authoritative: false, absent: true, detail: 'domain has no active_genesis binding under mapRoot (proven non-membership)' };
  return { authoritative: false, detail: 'active_genesis not the unique value for domain under mapRoot (a rival value is bound)' };
}

// ─── #77 STRICT KEY-LOG TERMINALITY — head is the LAST entry of a length-L log: inclusion of the entry at position
//     L-1 AND non-membership at position L (no successor). A positioned SMT (F.5k) keyed by index — strictly stronger
//     than the earlier `head ∈ root` membership (which a hidden successor could satisfy). keylog.root = this SMT root.
// UST-0ol Phase 4 (P0-02) — a positioned SMT keyed by HASHED index cannot prove "nothing follows the head": absence
// at index L says nothing about L+1, L+2 (a hidden entry at a non-adjacent index passed as terminal). Replaced by a
// SIZE-BOUND ordered VECTOR COMMITMENT: root = H("ust:keylog-commit", {length, merkle_root}) over an ordered Merkle
// of EXACTLY L leaves (padded to a power of two with a domain-separated empty leaf). Terminality = head is the leaf
// at index L-1 AND every RIGHT sibling on its path is the empty-subtree default ⇒ NOTHING exists beyond the head.
const KL_EMPTY = H('ust:keylog-empty', '');
export const keylogLeaf = (entryHash) => H('ust:keylog-leaf', canon({ h: entryHash }));
const klNode = (l, r) => H('ust:keylog-node', l + '|' + r);
const klEmptyDefault = (d) => { let e = KL_EMPTY; for (let i = 0; i < d; i++) e = klNode(e, e); return e; };
export function buildKeylogCommitment(entryHashes) {
  const L = entryHashes.length;
  let width = 1; while (width < L) width <<= 1;
  const layers = [entryHashes.map(keylogLeaf)]; while (layers[0].length < width) layers[0].push(KL_EMPTY);
  while (layers[layers.length - 1].length > 1) {
    const cur = layers[layers.length - 1], nxt = [];
    for (let j = 0; j < cur.length; j += 2) nxt.push(klNode(cur[j], cur[j + 1]));
    layers.push(nxt);
  }
  const merkle_root = layers[layers.length - 1][0];
  const prove = (index) => { const sib = []; for (let d = 0, i = index; d < layers.length - 1; d++, i >>= 1) sib.push(layers[d][i ^ 1]); return { index: String(index), siblings: sib }; };
  return { root: H('ust:keylog-commit', canon({ length: String(L), merkle_root })), length: String(L), head: entryHashes[L - 1], merkle_root, headProof: prove(L - 1), prove };
}
export function verifyKeylogTerminality(head_, proof = {}) {
  const h = admitOpts(head_); if (h === null) return { terminal: false, detail: 'malformed key-log head record (round-24 P1-01 totality)' };   // round-24 P1-01 — the FIRST arg is destructured; total for null/hostile
  const { root, length, head } = h;
  if (!isSeq(length)) return { terminal: false, detail: 'length is not a canonical decimal string (round-26 B — a coercible `["1"]`/non-canonical length no longer decodes via BigInt())' };   // round-26 B — CanonicalSeq before BigInt: BigInt(["1"]) === 1n would coerce an array
  const L = BigInt(length);
  if (L < 1n) return { terminal: false, detail: 'empty key-log' };
  const p0 = admitDeep(proof); const p = (p0 !== ADMIT_REJECT && p0 && typeof p0 === 'object') ? p0 : {};   // round-25 P1-02 null-total + round-27 snapshot: a getter on the Merkle proof (index/siblings) is read once, never re-read after the depth/root check
  const hp = p.headProof || p;
  if (!hp || !Array.isArray(hp.siblings) || !isSeq(hp.index) || BigInt(hp.index) !== L - 1n) return { terminal: false, detail: 'head proof missing or index ≠ length-1 (round-26 B — the Merkle index is a CanonicalSeq, no String([...]) coercion)' };
  // P0-5 (rc.35 audit) — the proof depth MUST be EXACTLY ceil(log2(width)), width = next-pow2(L). An UNDER-DEPTH proof
  // (fewer siblings than the tree has levels) recomputes the root over a SMALLER tree; with an attacker-chosen `root`
  // it FORGES terminality for a key-log that actually has successors — re-opening the P0-02 false-terminality class.
  let width = 1n, depth = 0n; while (width < L) { width <<= 1n; depth++; }
  const sibs = admitHashPath(hp.siblings, Number(depth)); if (sibs === null) return { terminal: false, detail: 'proof depth/co-path invalid: siblings must be a length-' + depth + ' co-path of canonical sha256 hashes (round-37 P0-01 — under/over-depth or a non-hash element earns nothing; no coercion grammar)' };
  let node = keylogLeaf(head), i = L - 1n;
  for (let d = 0; d < sibs.length; d++) {
    const sib = sibs[d], weAreLeft = (i & 1n) === 0n;                                   // LEFT child ⇒ sibling is to the RIGHT (higher indices) ⇒ MUST be an empty subtree
    if (weAreLeft && sib !== klEmptyDefault(d)) return { terminal: false, detail: 'a later key-log entry exists beyond the head (right subtree at level ' + d + ' is not empty)' };
    node = weAreLeft ? klNode(node, sib) : klNode(sib, node);                           // combine using the INDEX-derived side, not a proof field
    i >>= 1n;
  }
  if (i !== 0n) return { terminal: false, detail: 'index not fully consumed by the proof (head index outside the tree)' };
  return H('ust:keylog-commit', canon({ length: String(L), merkle_root: node })) === root ? { terminal: true } : { terminal: false, detail: 'commitment root mismatch (length/merkle not bound in root)' };
}

// ─── #76 Phase B — publisher-checkpoint CORROBORATED freshness. Compose the AUTHORIZED chain (F.5h) with the key-log
//     head's membership in the committed root + a VERIFIED external commitment ordered AFTER the target document
//     (F.5g `compareEvidenceOrder`, never a timestamp compare). This CLOSES the P0-05 stale-prefix overclaim by
//     earning `corroborated`, NEVER `attested`: a single publisher cannot prove split-view absence — independent
//     anti-equivocation is Phase C/#42. (Strict last-index terminality is the #77 refinement; here `head ∈ root`.)
// STABILITY (rc.37 UST-znh K1 — the ship-gate freeze). LIGHT/HIGH are STABLE. This checkpoint-freshness subsystem is
// EXPERIMENTAL until the kernel gates (one closed API + mandatory append-only consistency proof + scope-bound pinning
// + shared node/web core + boundary fuzzing + independent clean-run/audit). Its top rung `attested` fell in all three
// audit rounds via its SUPPORTING layer, so the STABLE verifier does not EMIT it: attested requires the caller to
// consciously opt into the experimental extension (`opts.allowExperimentalAttested === true`); without it the verdict
// is capped at `corroborated` and carries `attested_withheld:'experimental-gate'`. Nothing else changes — this is a
// contract-honesty gate, not a logic change; the closed kernel (UST-znh) replaces this whole function.
export const STABILITY = Object.freeze({ light: 'stable', high: 'stable', corroborated: 'experimental-usable', attested: 'experimental-extension' });
export function deriveCheckpointFreshness(chain, config) {
  const c = admitOpts(config); if (c === null) return { result: 'INVALID', detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 (self-audit) — the parallel freshness surface, total for null/hostile config
  // rev38 R3 (round-31 P0-03) — admit the CHAIN ONCE here: verifyAuthorityCheckpointChain admits its OWN snapshot, but this
  // assembler then RE-READ the raw `chain[last].body` for scope/sequence/active-genesis — a two-face Proxy served the signed
  // chain to the verifier and an unsigned body (sequence "999", fake active genesis) to the assembly. Verify + read the SAME frozen chain.
  { const Ch = admitDeep(chain); if (Ch === ADMIT_REJECT) return { result: 'INVALID', detail: 'checkpoint chain is not an inert record (round-31 R3 — the chain is admitted once and read only from the snapshot)' }; chain = Ch; }
  const { genesis, context, genesisAuthority, pinnedPrior, keylogEntries, target, commitment, terminality, uniqueness, trust, allowExperimentalAttested = false } = c;
  const chn = verifyAuthorityCheckpointChain(chain, { genesis, context, genesisAuthority, pinnedPrior, keylogEntries });   // K5: forward the prefix witness so a growth chain can reach corroborated (round-3 P0-3)
  if (chn.result !== 'VALID') return chn.result === 'INDETERMINATE' ? chn
    : { result: 'INVALID', error: chn.error, detail: 'checkpoint chain not authorized: ' + (chn.detail || chn.error), keylog_freshness: 'unverified' };
  const b = chain[chain.length - 1].body, headId = chn.head;
  if (target) {                                                                         // bind to the target's authority epoch + domain
    if (target.active_genesis !== undefined && b.active_genesis !== target.active_genesis) return { result: 'INVALID', error: 'E-GENESIS', detail: 'checkpoint active_genesis ≠ target', keylog_freshness: 'unverified' };
    if (target.domain_shard !== undefined && b.domain_shard !== target.domain_shard) return { result: 'INVALID', error: 'E-GENESIS', detail: 'checkpoint domain ≠ target', keylog_freshness: 'unverified' };
  }
  const term = verifyKeylogTerminality({ root: b.keylog?.root, length: b.keylog?.length, head: b.keylog?.head }, terminality || {});  // head = LAST entry (position L-1) AND no successor at L
  if (!term.terminal) return { result: 'INDETERMINATE', reason: 'terminality_unproven', detail: term.detail || 'key-log head terminality not proven', keylog_freshness: 'unverified' };
  if (!commitment) return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'no external-commitment evidence supplied for the checkpoint id', keylog_freshness: 'unverified' };
  if (!target || !target.anchor) return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'no target anchor evidence to order against', keylog_freshness: 'unverified' };
  if (typeof target.subject !== 'string' || !target.subject) return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'no target.subject id to bind the anchor evidence to', keylog_freshness: 'unverified' };
  // M3 — evidence enters ONLY through the seam: a signed receipt of a consumer-admitted connector (or a pre-verified
  // token), scope-bound to THIS chain's authority scope and subject-bound to the checkpoint id / target subject.
  // A caller-minted facts object (the rc.35 round-2 forge) is not in image(VerifyEvidence_C) and earns nothing.
  const scope = { domain_shard: b.domain_shard, active_genesis: b.active_genesis, genesis_epoch: b.genesis_epoch };
  const cAdm = admitFreshnessEvidence(commitment, headId, scope, trust);
  if (!cAdm.evidence) return { result: 'INDETERMINATE', reason: 'evidence_unverified', detail: 'commitment: ' + cAdm.detail, keylog_freshness: 'unverified' };
  const aAdm = admitFreshnessEvidence(target.anchor, target.subject, scope, trust);
  if (!aAdm.evidence) return { result: 'INDETERMINATE', reason: 'evidence_unverified', detail: 'anchor: ' + aAdm.detail, keylog_freshness: 'unverified' };
  if (!temporalOrderCapable(cAdm.evidence) || !temporalOrderCapable(aAdm.evidence))    // Phase 2: proof_kind must ESTABLISH temporal order (content-addressed / map / opaque cannot)
    return { result: 'INDETERMINATE', reason: 'order_unproven', detail: 'commitment/anchor evidence class does not establish temporal order (capability check: ' + evidenceClass(cAdm.evidence.proof_kind) + ')', keylog_freshness: 'unverified' };
  const ord = compareEvidenceOrder(cAdm.evidence, aAdm.evidence);                       // F.5g proof relation, NOT a timestamp compare
  if (ord !== 'proven-after') return { result: 'INDETERMINATE', reason: 'order_unproven', detail: 'checkpoint commitment not proven-after the target (' + ord + ')', keylog_freshness: 'unverified' };
  // corroborated holds. Phase C — an INDEPENDENT anti-equivocation proof over THIS checkpoint upgrades to `attested`.
  // Uniqueness on an UNAUTHORIZED/UNBOUND checkpoint never reaches here (the corroborated conjunction above already
  // failed) ⇒ `attested ⇒ corroborated ∧ independent-uniqueness`; uniqueness alone never earns `attested`.
  if (uniqueness) {
    let uq = null;                                                                       // two INDEPENDENT bases for the SAME predicate
    if (uniqueness.map && mapRootAdmitted(trust, uniqueness.map.mapRoot)) uq = verifyCheckpointMapUniqueness(uniqueness.map.proof, { domain_shard: b.domain_shard, genesis_epoch: b.genesis_epoch, sequence: b.sequence, checkpoint: headId, mapRoot: uniqueness.map.mapRoot });   // Phase 1: map root must be consumer-admitted (trust.mapRoots)
    if ((!uq || !uq.attested) && uniqueness.attestations) uq = verifyCheckpointUniqueness(uniqueness.attestations, { domain_shard: b.domain_shard, genesis_epoch: b.genesis_epoch, sequence: b.sequence, checkpoint: headId, trustRoots: uniqueness.trustRoots, domains: uniqueness.domains, threshold: uniqueness.threshold });
    if (uq && uq.attested) {
      // K1 ship-gate: the STABLE verifier does not emit `attested`. Without the explicit experimental opt-in the
      // proof still HOLDS (uniqueness verified) but the reported rung is capped at `corroborated`, with the withheld
      // rung named — an honest downgrade, never a silent one.
      if (!allowExperimentalAttested) return { result: 'VALID', keylog_freshness: 'corroborated', basis: uq.basis, anti_equivocation: 'attested',
        attested_withheld: 'experimental-gate', stability: 'experimental-extension',
        ...(uq.map_root ? { map_root: uq.map_root } : {}), head: headId, sequence: b.sequence, active_genesis: b.active_genesis };
      return { result: 'VALID', keylog_freshness: 'attested', basis: uq.basis, anti_equivocation: 'attested', stability: 'experimental-extension',
        ...(uq.threshold ? { threshold: uq.threshold, accepted_witnesses: uq.accepted_witnesses, trust_domains: uq.trust_domains } : {}),
        ...(uq.map_root ? { map_root: uq.map_root } : {}), head: headId, sequence: b.sequence, active_genesis: b.active_genesis };
    }
  }
  return { result: 'VALID', keylog_freshness: 'corroborated', basis: 'publisher-checkpoint', anti_equivocation: 'unverified',  // ceiling without independent uniqueness
    head: headId, sequence: b.sequence, active_genesis: b.active_genesis };
}

// ─── K4/Closed-Proof-Kernel (rc.37, UST-yoe) — THE ONE PUBLIC AUTHORITY ENTRYPOINT is now PROVER ∘ check_C: the
//     producer stack is DEMOTED to an untrusted prover that only PROPOSES a proof term; the reference checker
//     (packages/ust-protocol/reference-checker.mjs) is the SOLE acceptance oracle for any strong verdict. Trust comes
//     ONLY from config, never inputs (round-4 P0-02); D1 returns base + anti-equivocation basis, never a scalar
//     `attested`. Differential fuzz (rnd/fuzz-differential.mjs) proved check_C is strictly stricter than the old
//     producer path on exactly the round-4 residual holes. `verifyAuthorityBundle` + `buildAuthorityProof` are
//     RE-EXPORTED from the checker module (call-time cyclic import is safe — the checker uses index's leaf primitives
//     only inside function bodies).
export { verifyAuthorityBundle, buildAuthorityProof, checkAuthorityProof, checkAuthorityProofBytes, RULE_CONTRACTS, REFERENCE_CHECKER_RULES, REFERENCE_CHECKER_VERSION } from './reference-checker.mjs';

// ─── #78 ASSURANCE PRODUCT-LATTICE (formal-model F.5.0, CODE realization — the math must pass through code +
//     vectors + guard before it ships). The linear tier LIGHT ⊆ HIGH ⊆ TOP is ONE policy projection of a PRODUCT of
//     FOUR orthogonal, independently-strengthening STRENGTH axes — identity and freshness strengthen SEPARATELY
//     (F.5 gap 1/3, product-incomparability M1.4). Each axis is a finite CHAIN (a rank); AssuranceState is their
//     product under the componentwise (partial) order — a LATTICE of 2·4·4·2 = 64 states: meet = per-axis min,
//     join = per-axis max. `projectTier` reads ONLY identity+time (the classic tier); freshness rides alongside.
//     M1.1 (rc.36): EvidenceBasis is NOT a strength axis — a capability set is a Boolean lattice (P(Caps), ⊆), not a
//     4-chain; the rc.35 five-axis product (256) was self-contradictory ("a SET" yet "every axis is a total order").
//     STRENGTH (what is proven, per coordinate) is separate from SUPPORT (which capabilities the admitted evidence
//     supplies — EVIDENCE_CAPS_UNIVERSE below); support DERIVES strength, it is not a fifth coordinate.
export const ASSURANCE_AXES = deepFreeze({   // round-25 P0-04 — DEEP-frozen: mutating a nested axis array (e.g. reordering `identity`) would change projectTier's ranks and the exported REGISTRY alias → history-dependent TCB
  integrity: ['invalid', 'valid'],                                            // the §14 floor (canon/hash/sig) — the Integrity axis
  identity:  ['self-asserted', 'pinned', 'corroborated', 'authoritative'],    // A_id: name-binding + active-genesis uniqueness (§12.1a)
  freshness: ['unverified', 'fresh', 'corroborated', 'attested'],             // A_fresh: terminality + order + checkpoint uniqueness (§12.2a / §12.3.5)
  time:      ['unproven', 'anchored'],                                        // Fₜ: the anchor filtration (§11.2)
});
// M1.1 — the capability-support UNIVERSE (single-sourced from EVIDENCE_CAPS): |Caps| = 8, support ∈ (P(Caps), ⊆).
// A predicate is discharged only by an admissible capability (B4); no composition step manufactures one (B3).
export const EVIDENCE_CAPS_UNIVERSE = Object.freeze([...new Set(Object.values(EVIDENCE_CAPS).flat())].sort());
const AXES = Object.keys(ASSURANCE_AXES);
export const axisRank = (axis, v) => ASSURANCE_AXES[axis].indexOf(v);          // -1 ⇒ not a value of this axis
const axisLE = (axis, a, b) => { const ra = axisRank(axis, a), rb = axisRank(axis, b); return ra >= 0 && rb >= 0 && ra <= rb; };
// AssuranceState = a full 5-tuple; every axis present with an in-range value, else E-ASSURANCE (fail-closed).
export function assuranceState(s = {}) {
  const out = {};
  for (const ax of AXES) { if (axisRank(ax, s[ax]) < 0) throw Object.assign(new Error(`E-ASSURANCE: axis '${ax}' missing or out of range`), { code: 'E-ASSURANCE' }); out[ax] = s[ax]; }
  return out;
}
// The product order (F.5 gap 1): a ≤ b iff a ≤ b on EVERY axis — a PARTIAL order (identity & freshness independent,
// so most pairs are incomparable). meet/join make it a LATTICE.
export const assuranceLE = (a, b) => { const A = assuranceState(a), B = assuranceState(b); return AXES.every((ax) => axisLE(ax, A[ax], B[ax])); };   // round-37 P1-01 — ADMIT both operands into the full in-range product before comparing (an out-of-domain axis → E-ASSURANCE, never a silent rank -1)
const axisMin = (axis, a, b) => (axisRank(axis, a) <= axisRank(axis, b) ? a : b);
const axisMax = (axis, a, b) => (axisRank(axis, a) >= axisRank(axis, b) ? a : b);
export const meetAssurance = (a, b) => { const A = assuranceState(a), B = assuranceState(b); return Object.fromEntries(AXES.map((ax) => [ax, axisMin(ax, A[ax], B[ax])])); };   // round-37 P1-01 — ADMIT both operands (no lattice op repairs a malformed operand into an earned state)
export const joinAssurance = (a, b) => { const A = assuranceState(a), B = assuranceState(b); return Object.fromEntries(AXES.map((ax) => [ax, axisMax(ax, A[ax], B[ax])])); };   // round-37 P1-01 — ADMIT both operands: a join with an out-of-domain axis throws E-ASSURANCE, never synthesizes a valid TOP
// PolicyProjection (F.5 gap 1 / F.5b): the classic tier reads ONLY identity+time. TOP = authoritative name ∧ anchored
// time; HIGH = name-bound (identity ≥ corroborated); LIGHT = the integrity floor; below the floor there is NO tier.
// This is the CANONICAL projection; the inline §14 verify tier is conformance-pinned to agree with it (no 2nd truth).
export function projectTier(state) {
  const s = assuranceState(state);
  if (!axisLE('integrity', 'valid', s.integrity)) return 'NONE';              // integrity floor unmet ⇒ INVALID upstream
  if (s.identity === 'authoritative' && s.time === 'anchored') return 'TOP';
  if (axisLE('identity', 'corroborated', s.identity)) return 'HIGH';          // corroborated ≤ identity ⇒ name-bound
  return 'LIGHT';
}
export const TIER_RANK = { NONE: -1, LIGHT: 0, HIGH: 1, TOP: 2 };
// capAssurance (F.5 gap 2 — the CAPPED term ℐ_C): the reported state is the MEET of what is PROVEN and the ceiling
// ADMISSIBLE under the consumer config C (a per-axis max: no accepted trust domains ⇒ freshness caps below
// `attested`; no pinned/accepted roots ⇒ identity caps at `self-asserted`). Assurance is EARNED by proof and CAPPED
// by trust — never self-declared; an unspecified ceiling axis imposes no cap (tops out).
export function capAssurance(state, ceiling) {
  const s = assuranceState(state);
  if (!ceiling) return s;
  const cap = assuranceState(Object.fromEntries(AXES.map((ax) => [ax, ceiling[ax] ?? ASSURANCE_AXES[ax][ASSURANCE_AXES[ax].length - 1]])));
  return meetAssurance(s, cap);
}

// ─── C3 (UST-6vj, M1.2) — THE ONE ASSURANCE ASSEMBLER. Pure, deterministic, total: strength coordinates are DERIVED
//     from SEAM VERDICTS (the resolveAuthority / deriveCheckpointFreshness / verifyAnchor result objects) by fixed
//     rules — never from caller labels or booleans; capability SUPPORT is the union of capabilities of evidence that
//     is actually in image(VerifyEvidence_C) (the WeakSet witness) — a minted look-alike contributes nothing (B3: no
//     step manufactures a capability). Runs strictly AFTER the §14 integrity floor: an INVALID document never reaches
//     assembly, so integrity is 'valid' by position, not by parameter (Reach_C: the verifier only emits tuples whose
//     coordinates were each earned by a predicate; the confinement property is pinned in conformance, Phase V).
// C3/K3 — provePredicates maps SEAM VERDICTS (resolveAuthority / deriveCheckpointFreshness / verifyAnchor results,
// plus image('evidence') handles) to the proven-atom strength coordinates and mints a branded PREDICATE-GRAPH handle.
// It is the ONLY producer of that handle. The seam verdicts it reads are produced by the verifiers, never by a caller
// label. (K4/K7: the kernel calls this over verdicts it derived from RAW inputs; a caller cannot reach it with fakes.)
// K7 (rc.37, calculus §7) — the HORN inference layer. provePredicates extracts the proven ATOMS from seam verdicts
// (never caller labels), then a fixed rule set derives the rungs as a least-closure; the trace records each derived
// predicate with its premises, so every strong verdict is explainable. `deriveAssurance` projects the closure. The
// coordinate values are unchanged — the win is that assurance is a DERIVATION over admitted atoms, not a passed value.
const HORN_RULES = [
  { concl: 'IdentityAuthoritative', premises: ['name-bound', 'active-genesis-unique'] },
  { concl: 'FreshnessCorroborated', premises: ['checkpoint-authorized', 'scope-bound', 'keylog-append-only', 'snapshot-terminal', 'checkpoint-committed', 'checkpoint-after-target'] },
  { concl: 'FreshnessAttested', premises: ['FreshnessCorroborated', 'checkpoint-unique'] },
  { concl: 'TierTOP', premises: ['integrity-valid', 'IdentityAuthoritative', 'time-anchored'] },
  { concl: 'TierHIGH', premises: ['integrity-valid', 'name-bound'] },
  { concl: 'TierLIGHT', premises: ['integrity-valid'] },
];
const hornClosure = (atomSet) => {                                                    // least fixed point over HORN_RULES
  const closed = new Set(atomSet), trace = [];
  let grew = true;
  while (grew) { grew = false; for (const r of HORN_RULES) if (!closed.has(r.concl) && r.premises.every((p) => closed.has(p))) { closed.add(r.concl); trace.push({ rule: r.concl, premises: r.premises.slice() }); grew = true; } }
  return { closed, trace };
};
export function provePredicates(seams = {}) {
  const { identity, freshness, anchor, evidence = [] } = (seams && typeof seams === 'object') ? seams : {};   // round-25 P1-02 — null-total: `provePredicates(null)` no longer throws on destructuring (a malformed non-null arg floors to LIGHT)
  const verified = identity?.status === 'verified';                                  // 'suspect' (pre-compromise window) never name-binds — mirrors §14 exactly
  const idStr = !verified ? 'self-asserted'
    : identity.strength === 'authoritative' ? 'authoritative'
    : identity.strength === 'corroborated' ? 'corroborated'
    : identity.strength === 'pinned' ? 'pinned' : 'self-asserted';
  const frStr = (freshness?.result === 'VALID' && (freshness.keylog_freshness === 'corroborated' || freshness.keylog_freshness === 'attested')) ? freshness.keylog_freshness
    : identity?.freshness === 'fresh' ? 'fresh' : 'unverified';                       // fresh = the single-view §12.2a rung carried by the identity resolution
  const tmStr = anchor?.inclusion === true && anchor?.time === 'anchored' ? 'anchored' : 'unproven';
  const support = [...new Set((Array.isArray(evidence) ? evidence : [])
    .filter((e) => isHandle('evidence', e))                                          // K3: capability only from image(VerifyEvidence_C) (B3)
    .flatMap((e) => evidenceCaps(e.proof_kind)))].sort();
  // K7 — the proven ATOMS the seams established (the coordinate strengths are read from these). The Horn closure
  // derives the composite rungs + a premise trace; a coordinate never lifts without its atom (no-upward-forge).
  const atomSet = ['integrity-valid'];
  if (idStr === 'authoritative') atomSet.push('name-bound', 'active-genesis-unique');
  else if (idStr === 'corroborated') atomSet.push('name-bound');                          // corroborated ≥ the HIGH threshold ⇒ name-bound (TierHIGH)
  else if (idStr === 'pinned') atomSet.push('key-pinned');                                // round-32 P2-01 — pinned < corroborated ⇒ NOT name-bound; the Horn trace must not derive TierHIGH where projectTier returns LIGHT (key-pinned lifts no Tier rule)
  if (frStr === 'corroborated' || frStr === 'attested') atomSet.push('checkpoint-authorized', 'scope-bound', 'keylog-append-only', 'snapshot-terminal', 'checkpoint-committed', 'checkpoint-after-target');
  if (frStr === 'attested') atomSet.push('checkpoint-unique');
  if (tmStr === 'anchored') atomSet.push('time-anchored');
  const { trace } = hornClosure(atomSet);
  // round-25 P0-01 — provePredicates is the PURE seam→atom MAPPER and returns an UNBRANDED graph. It does NOT mint the
  // predicate-graph brand: minting from caller-shaped labels was a public forgery oracle (deriveAssurance blessed it → TOP
  // with zero verified evidence). The brand is minted ONLY by sealPredicateGraph, called ONLY inside verify() (the TCB),
  // which passes REAL seam verdicts. A consumer can still inspect this projection, but deriveAssurance rejects an
  // unbranded graph — so caller labels earn no authoritative verdict. (isHandle('predicate-graph', provePredicates(x)) === false.)
  return Object.freeze({ atoms: Object.freeze({ integrity: 'valid', identity: idStr, freshness: frStr, time: tmStr }),
    support: Object.freeze(support), provenAtoms: Object.freeze(atomSet.slice()), derivation: Object.freeze(trace.map((t) => Object.freeze({ ...t, premises: Object.freeze(t.premises) }))) });
}
// MODULE-PRIVATE (never exported — not in package `exports`, so no consumer path reaches it): the sole minter of the
// predicate-graph brand. Only verify() calls it, and only over seam verdicts produced by the real verification seams.
const sealPredicateGraph = (graph) => mintHandle('predicate-graph', graph);
// The assembler. Takes ONLY a branded PredicateGraph (K3 — a caller-shaped {identity:'authoritative'} is NOT a graph,
// so no coordinate lifts: round-3 P0-4 closed at the type level). Emits the frozen assurance report + the K7 trace.
export function deriveAssurance(graph) {
  if (!isHandle('predicate-graph', graph)) return Object.freeze({ error: 'E-ASSURANCE', detail: 'deriveAssurance requires a verified PredicateGraph handle (K3 — build it with provePredicates over seam verdicts; a caller-shaped object earns nothing)' });
  const strength = Object.freeze(assuranceState({ integrity: 'valid', ...graph.atoms }));
  return Object.freeze({ strength, support: graph.support, tier: projectTier(strength), derivation: graph.derivation, provenAtoms: graph.provenAtoms });
}

// ─── #oy8 CANONICAL REGISTRY — the SINGLE SOURCE OF TRUTH for the protocol's machine-checkable STRING SETS. The spec's
//     registry blocks (§15/§17) are GENERATED from this (tools/gen-spec-registry.mjs), and tools/spec-code-sync.mjs
//     asserts the code's ACTUAL literal usage (H/Hbytes domains, `purpose:` strings, thrown `E-` codes) equals these
//     sets — so spec prose, this registry, and code usage cannot silently diverge (the spec↔code drift seam). Enums
//     that already exist as code (ASSURANCE_AXES, TIER_RANK) are REFERENCED, never re-declared.
export const REGISTRY = deepFreeze({   // round-25 P0-04 — DEEP-frozen: the canonical string sets are TCB truth; no in-process mutation
  // hash domain tags (§7/§17) — the tag passed to H()/Hbytes(). MEASURED against actual usage by spec-code-sync.
  hashDomains: ['ust:state', 'ust:shard', 'ust:seed', 'ust:keylog', 'ust:leaf', 'ust:node',
    'ust:authority-checkpoint', 'ust:checkpoint-map-key', 'ust:checkpoint-map-value', 'ust:name-map-key', 'ust:name-map-value',
    'ust:keylog-empty', 'ust:keylog-leaf', 'ust:keylog-node', 'ust:keylog-commit', 'ust:smt-empty', 'ust:smt-node', 'ust:smt-leaf',
    'ust:genesis-epoch', 'ust:authority-scope', 'ust:evidence-receipt'],
  // signed `canon` preimage purposes (§12.1a/§12.3) — domain-separated, never interchangeable.
  purposes: ['ust:name-no-fork', 'ust:authority-checkpoint', 'ust:authority-checkpoint-signature',
    'ust:checkpoint-authority-recovery', 'ust:genesis-epoch-transition', 'ust:checkpoint-uniqueness-attestation',
    'ust:evidence-receipt', 'ust:evidence-receipt-signature'],
  // INVALID error codes (§15) — every code the verifier/API can emit. Ordered as §15 lists them.
  errorCodes: ['E-MALFORMED', 'E-CANON', 'E-BOUNDS', 'E-CYCLE', 'E-SIG', 'E-KEY', 'E-GENESIS', 'E-ANCHOR',
    'E-COMMIT', 'E-ROOT', 'E-SEED', 'E-PREV', 'E-AUTHORITY', 'E-SEQ', 'E-EVIDENCE', 'E-ASSURANCE'],
  // INDETERMINATE reasons — the §14 document-verifier's CLOSED set, and the §12.3.6 authority-checkpoint set (distinct).
  indeterminateReasons: { document: ['unavailable', 'unsupported_alg', 'resource_limit', 'stale_keylog'],
    checkpoint: ['authority_unresolved', 'terminality_unproven', 'order_unproven', 'evidence_unverified', 'chain_consistency_unproven'] },
  tiers: Object.keys(TIER_RANK),                                    // NONE/LIGHT/HIGH/TOP — single-sourced from TIER_RANK
  assuranceAxes: ASSURANCE_AXES,                                    // single-sourced from the #78 lattice (§F.5.0)
  evidenceOrder: ['proven-after', 'not-after', 'unproven'],        // compareEvidenceOrder returns (§12.3.5)
  verifiedEvidenceFields: { required: ['proof_kind', 'subject', 'source_id', 'facts'], optional: ['verifier_id', 'verifier_version'] },
  // M3 — the SIGNED connector-receipt claim (§12.3.5): facts only; a capability/assurance/independence field is E-EVIDENCE.
  evidenceReceiptClaimFields: { required: ['version', 'purpose', 'domain_shard', 'active_genesis', 'genesis_epoch', 'subject', 'proof_kind', 'facts', 'issued_at'], optional: ['payload_digest'] },
});

// ─── TOP §11.3 completeness: a sequenced stream is prev-chained; first frame's prev = genesis content_hash
//     (M4); per-frame validity is verified too (X2 — completeness ≠ validity); duplicate ust_id / shared prev
//     = a fork ⇒ E-PREV (Y1). A covering checkpoint (M5) proves 'chain-consistent' (no-deletion); the open tail
//     is 'provisional'. 'complete' (no-omission, needs the signed-cadence grid, F.4) is a future rung (#69 C).
export function verifyStream(frames, config) {
  const c = admitOpts(config); if (c === null) return { complete: 'none', detail: 'config must be an inert record (round-24 P1-01 totality)' };   // round-24 P1-01 (self-audit) — the parallel stream surface, total for null/hostile config
  { const Fr = admitDeep(frames); if (Fr === ADMIT_REJECT) return { complete: 'none', detail: 'frames are not an inert record (round-27)' }; frames = Fr; }   // round-27 — snapshot
  let { genesis, keylog, checkpoint, cadenceLog, requirePerFrameValid = true } = c;
  // rev38 R3 (round-31 P0-02) — admitOpts is SHALLOW: the NESTED `genesis` and `checkpoint` in config stay live caller objects.
  // verifyStream calls verify(checkpoint) but then re-reads the raw checkpoint's class/head/count (and reads raw genesis for
  // prevHash) — a two-face Proxy served the signed face to verify and an unsigned face to the reads. Admit both nested docs once.
  if (genesis != null) { const G = admitDeep(genesis); if (G === ADMIT_REJECT) return { complete: 'none', detail: 'genesis is not an inert record (round-31 R3 — nested config docs are admitted once)' }; genesis = G; }
  if (checkpoint != null) { const C = admitDeep(checkpoint); if (C === ADMIT_REJECT) return { complete: 'none', detail: 'checkpoint is not an inert record (round-31 R3 — nested config docs are admitted once)' }; checkpoint = C; }
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  const authority = frames[0]?.state?.id?.domain_shard;                // §11.3: a stream belongs to ONE authority
  if (typeof authority !== 'string') return { complete: 'none', detail: 'malformed first frame — no stream authority (round-24 self-audit totality)' };   // round-24 (self-audit) — a malformed frame is a structured result, never a host throw
  let prevHash = genesis ? contentHash(genesis) : null;
  // #75 P0-03b — when a genesis is supplied, EACH frame's key MUST be BOUND to that authority's key-log (key ∈
  // K_A), not merely claim the `domain_shard`. Otherwise an impostor's frames (key ∉ K_A), prev-chained to the
  // victim genesis hash, read as a `complete` stream under the victim's name. Math: the LIGHT `domain_shard` is a
  // CLAIM; binding (ROOT 1+2) is the proof. No manifest needed — the authority is the resolved key set.
  let boundKeys = null;
  if (genesis) {
    if (genesis.state?.id?.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'genesis domain_shard != stream authority (' + authority + ')' };
    const rk = resolveKeys(genesis, Array.isArray(keylog) ? keylog : []);
    if (rk.error) return { error: rk.error, detail: 'stream authority: ' + rk.detail };
    boundKeys = rk.validKeys;
  }
  const seenUstId = new Set(), seenPrev = new Set();
  let lastE = null;
  for (const [i, f] of frames.entries()) {
    if (requirePerFrameValid) { const v = verify(f, { context: 'data' }); if (!isValid(v)) return { error: 'E-SIG', detail: 'frame ' + i + ' invalid: ' + v.error }; } // X2
    if (f.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' domain_shard != stream authority (' + authority + ') — mixed-authority stream' };
    if (boundKeys && boundKeys.get(f.state.id.key_id) !== f.sig.pub) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' key not bound to the authority key-log — impersonation (key ∉ K_A, §12.2)' };
    if (seenUstId.has(f.state.id.ust_id)) return { error: 'E-PREV', detail: 'duplicate ust_id (fork, Y1): ' + f.state.id.ust_id };
    seenUstId.add(f.state.id.ust_id);
    // #69 C P0 — the prev-chain must ALSO be CHRONOLOGICAL: `ust_id` strictly increasing in chain order. Else a
    // publisher could permute slots in TIME while keeping the chain valid and the grid-set covered (a real
    // reordering, hidden). `ust_id` is the time coordinate; compare by epoch.
    const fe = ustToEpoch(f.state.id.ust_id);
    if (i > 0 && fe !== null && lastE !== null && fe <= lastE) return { error: 'E-PREV', detail: 'frame ' + i + ' ust_id ' + f.state.id.ust_id + ' not chronologically after its predecessor — reordered stream (§11.3)' };
    lastE = fe;
    const p = f.state.provenance?.prev;
    if (i === 0) { if (genesis && p !== prevHash) return { error: 'E-PREV', detail: 'first frame prev != genesis content_hash (M4)' }; }
    else if (p !== prevHash) return { error: 'E-PREV', detail: 'frame ' + i + ' prev dangling (broken chain)' };
    if (p && seenPrev.has(p)) return { error: 'E-PREV', detail: 'two frames share a prev (fork, Y1)' };
    if (p) seenPrev.add(p);
    prevHash = contentHash(f);
  }
  // M5 — a COVERING checkpoint over a genesis-BOUND origin closes the interval. Without a genesis the origin is
  // unbound → 'provisional'. #69 C / F.4 — even WITH the checkpoint, the chain + count prove NO-DELETION over the
  // SHOWN chain, NOT no-omission: a never-emitted slot leaves a self-consistent chain with a hole (link t+1→t-1).
  // So the honest ceiling here is 'chain-consistent'; 'complete' (no-omission) is decidable only against the
  // EXPECTED GRID, which needs the operator's SIGNED CADENCE in ℐ — §11.3's next mechanism, not asserted yet.
  if (checkpoint) {
    if (!genesis) return { complete: 'provisional', head: prevHash, reason: 'origin-unbound: no genesis, cannot bound completeness (TOP needs a HIGH origin)' };
    const cv = verify(checkpoint, { context: 'data' });
    if (!isValid(cv) || checkpoint.state.id.class !== 'attestation') return { error: 'E-PREV', detail: 'invalid checkpoint' };
    if (checkpoint.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'checkpoint not from the stream authority (' + authority + ') — TOP completeness cannot cross authority' };
    if (boundKeys && boundKeys.get(checkpoint.state.id.key_id) !== checkpoint.sig.pub) return { error: 'E-AUTHORITY', detail: 'checkpoint key not bound to the authority key-log (impersonation, §12.2)' };
    const a = checkpoint.state.data.checkpoint?.value;
    // NOTE (honest scope) — with a genesis, `frame_count === frames.length` + `first frame.prev === genesis`
    // means this verifies the ORIGIN-TO-CHECKPOINT PREFIX (the interval's `from` MUST be the stream's first
    // frame), not an arbitrary middle `[from,to]`. A true middle-range verdict needs a PREVIOUS checkpoint and a
    // cumulative-count DELTA (currentCount − previousCount === frames.length) — a tracked follow-up, not silently
    // assumed here. The `complete`/`chain-consistent` verdict below is over this prefix.
    if (!a || a.head !== prevHash || !isSeq(a.frame_count) || a.frame_count !== String(frames.length))   // round-26 B — the signed frame_count is a CanonicalSeq; a coercible `["N"]` no longer matches via String()
      return { error: 'E-PREV', detail: 'checkpoint contradicts observed set (M5)' };
    // #69 C — no-deletion is proven. no-OMISSION needs the EXPECTED GRID: the operator's SIGNED cadence
    // (genesis value + cadence-log, RESOLVED at the interval — never a free per-checkpoint choice) AND the
    // checkpoint's interval bounds, then every slot must be a frame OR a signed gap record (§11.3 C2).
    if (a.from !== undefined && a.to !== undefined) {
      // P0 — the checkpoint's interval MUST FAITHFULLY BOUND the observed set: first==from, last==to (so
      // head==hash(frame at to)), and NO frame outside [from,to]. Else the checkpoint does not cover THIS range.
      const fromE = ustToEpoch(a.from), toE = ustToEpoch(a.to);
      if (frames[0].state.id.ust_id !== a.from) return { error: 'E-PREV', detail: 'first frame != checkpoint `from` (' + a.from + ')' };
      if (frames[frames.length - 1].state.id.ust_id !== a.to) return { error: 'E-PREV', detail: 'last frame != checkpoint `to` (' + a.to + ')' };
      for (const f of frames) { const e = ustToEpoch(f.state.id.ust_id); if (e === null || fromE === null || toE === null || e < fromE || e > toE) return { error: 'E-PREV', detail: 'frame ' + f.state.id.ust_id + ' outside the checkpoint interval [' + a.from + ',' + a.to + ']' }; }
      // continuity — resolve the cadence at BOTH ends; a change inside the interval means the grid is not uniform,
      // so the interval must be SPLIT at the boundary (old data stays complete under its own cadence). Never invalidate.
      const cF = resolveCadence(genesis, cadenceLog, a.from, { keylog }), cT = resolveCadence(genesis, cadenceLog, a.to, { keylog });
      if (cF.error) return { error: cF.error, detail: 'cadence: ' + cF.detail };
      if (cT.error) return { error: cT.error, detail: 'cadence: ' + cT.detail };
      if (cF.cadence !== cT.cadence) return { complete: 'chain-consistent', head: prevHash, interval: { from: a.from, to: a.to }, detail: 'interval crosses a cadence change — split it at the boundary; each side is `complete` under its own cadence (continuity)' };
      const grid = cF.cadence > 0 ? ustGrid(a.from, a.to, cF.cadence) : null;
      if (grid) {
        const gridSet = new Set(grid);
        const covered = new Set();
        for (const f of frames) {
          const c = f.state.id.class;
          const slotBearing = c === 'observation' || c === 'derivation' || (c === 'attestation' && f.state.data?.gap !== undefined);
          if (!slotBearing) continue;
          // #75 P0-04 — grid EQUALITY, not just coverage: EVERY frame must sit ON the grid. An off-grid frame
          // (e.g. 00:15 under a 30s cadence) is an extra commitment inside a declared slot region → commitment
          // grinding. Coverage alone (every grid slot filled) let it through; equality rejects it.
          if (!gridSet.has(f.state.id.ust_id)) return { error: 'E-PREV', detail: 'off-grid frame ' + f.state.id.ust_id + ' is not a slot of the signed cadence grid (§11.3 — grid equality, no commitment grinding)' };
          covered.add(f.state.id.ust_id);
        }
        const hole = grid.find((g) => !covered.has(g));
        if (hole) return { complete: 'chain-consistent', head: prevHash, interval: { from: a.from, to: a.to }, hole, detail: 'grid slot ' + hole + ' has no frame and no signed gap — chain intact, not complete (§11.3 C)' };
        // grid EQUALITY holds: every frame ∈ grid (above) ∧ every grid slot covered (here) ∧ no dup ust_id (Y1) ⇒ bijection.
        return { complete: 'complete', head: prevHash, interval: { from: a.from, to: a.to }, cadence: String(cF.cadence), grid_slots: String(grid.length) };
      }
    }
    // windowed checkpoint but no signed cadence (grid null) OR a checkpoint with no interval bounds. When the interval
    // WAS validated (a.from/a.to present — first==from, last==to, no frame outside) return it so a no-event claim over
    // it is completeness-backed; no-deletion over [from,to] is proven even without the grid (that only adds no-omission).
    return { complete: 'chain-consistent', head: prevHash, ...(a.from !== undefined && a.to !== undefined ? { interval: { from: a.from, to: a.to } } : {}) };
  }
  return { complete: 'provisional', head: prevHash };                  // no checkpoint → open tail (P5)
}

// §11.3 #39 — a NO-EVENT claim (a `kind:'absence'`/`reason:'no-event'` partition over a ust_id window) is only as
// strong as the stream's COMPLETENESS *and* OBSERVATIONAL coverage over that window. Verdicts:
//   'completeness-backed' — window ⊆ a `complete` interval AND every covered slot was POSITIVELY observed (no blind slot);
//   'observation-gap'     — complete + covered, but the publisher was UNREACHABLE at a covered slot, so a hidden event is
//                           NOT impossible there — the no-event breaks at that slot (self-audit rc.35 #2, agent-found);
//   'observation-unchecked' — complete + covered, but `frames` not supplied, so observational coverage cannot be checked;
//   'no-deletion-only'    — a `chain-consistent` interval: no EMITTED frame deleted, but an OMITTED slot could hide it;
//   'publisher-asserted' — no covering verified interval; 'not-applicable' — no window.
// PRECONDITION the CALLER MUST also enforce (NOT checked here): the stream OBSERVES the claim's SUBJECT — a `complete`
// stream about partition X does not, on its own, deny an event about Y (agent-found). Pass `frames` (the same array
// verifyStream verified) to check observational coverage; without it the strongest verdict is withheld.
export function noEventBacking(claimWindow, streamResult, frames) {
  { const W = admitDeep(claimWindow), S = admitDeep(streamResult), F = admitDeep(frames); if (W === ADMIT_REJECT || S === ADMIT_REJECT || F === ADMIT_REJECT) return 'not-applicable'; claimWindow = W; streamResult = S; frames = F; }   // round-28 P1-02 — admit at the door; a hostile getter → the safe floor, never a host throw
  if (!claimWindow || claimWindow.from === undefined || claimWindow.to === undefined) return 'not-applicable';
  if (streamResult?.complete !== 'chain-consistent' && streamResult?.complete !== 'complete') return 'publisher-asserted';
  const iv = streamResult.interval;   // the range verifyStream ITSELF validated (first==from,last==to,no frame outside) — not a caller checkpoint, so unspoofable
  if (!iv || iv.from === undefined || iv.to === undefined) return 'publisher-asserted';
  const w0 = ustToEpoch(claimWindow.from), w1 = ustToEpoch(claimWindow.to), i0 = ustToEpoch(iv.from), i1 = ustToEpoch(iv.to);
  if ([w0, w1, i0, i1].some((x) => x === null) || !(i0 <= w0 && i1 >= w1)) return 'publisher-asserted';   // the verified interval must CONTAIN the window
  if (streamResult.complete !== 'complete') return 'no-deletion-only';   // chain-consistent: no-deletion only, an omitted slot could still hide the event
  if (!Array.isArray(frames)) return 'observation-unchecked';            // complete, but no frames to confirm the publisher actually observed each slot
  // OBSERVATIONAL coverage + SUBJECT binding (rc.35 audit P2 — GPT + agent). Every covered slot must POSITIVELY observe
  // the claim's subject: a captured/computed partition, OR an absence that OBSERVED non-occurrence (reason `no-event` /
  // `unchanged`). ANY OTHER absence (`unreachable`, `source-timeout`, … — reason-AGNOSTIC, since the recommended set is
  // open) is BLIND — the publisher saw nothing, a hidden event is not impossible. And when `claimWindow.subject` is set,
  // the observation must be OF that subject: a `complete` stream about partition X does not, alone, deny an event about Y.
  const POSITIVE = new Set(['no-event', 'unchanged']);
  const observedSubject = (f, subj) => Object.entries(f?.state?.data || {}).some(([name, p]) => (subj === undefined || name === subj) && p && (p.kind === 'captured' || p.kind === 'computed' || (p.kind === 'absence' && POSITIVE.has(p.value?.reason))));
  const gap = frames.some((f) => { const e = ustToEpoch(f?.state?.id?.ust_id); return e !== null && e >= w0 && e <= w1 && !observedSubject(f, claimWindow.subject); });
  return gap ? 'observation-gap' : 'completeness-backed';                // a blind slot OR one that never observed the subject breaks the no-event guarantee
}

// ─── §S6/F7 — the CONFORMANCE boundary is raw bytes. `verify(JSON.parse(x))` can't satisfy §6 because JSON.parse
//     silently collapses duplicate keys. `verifyJson` scans the raw bytes for duplicate member names BEFORE
//     constructing the object, then verifies. Untrusted transcripts from the network/storage MUST enter here.
export function verifyJson(rawBytes, opts = {}) {
  opts = admitOpts(opts); if (opts === null) return bad('E-MALFORMED', 'opts must be an inert record (round-26 C — a null/hostile opts no longer throws on `opts.maxInputBytes`)');   // round-26 (rev24 C) — totality: opts=null reached `Number(opts.maxInputBytes)` and threw
  // §13 TRANSPORT ADMISSION (rc.12) — distinct from the document verdict. Byte length is read
  // from the buffer BEFORE any decode/materialization (P0-2); an over-budget input is REFUSED as
  // INDETERMINATE('resource_limit') — verification never started, so it is never called INVALID.
  // The default input budget equals the protocol ABS; raw whitespace/base64 padding never flips a
  // verdict because the NORMATIVE size is measured on the canonical signed content inside verify.
  const isStr = typeof rawBytes === 'string';
  // round-25 P1-02 — TYPED input admission BEFORE any measurement: verifyJson accepts a UTF-8 string or a byte container
  // (ArrayBuffer / TypedArray / Buffer). A plain object or other non-binary reached `Buffer.from(rawBytes)` and threw a
  // host TypeError (ERR_INVALID_ARG_TYPE) instead of a structured verdict — I4 totality demands a structured result.
  if (!isStr && !(rawBytes instanceof ArrayBuffer || ArrayBuffer.isView(rawBytes)))
    return bad('E-MALFORMED', 'raw input must be a UTF-8 string or a byte buffer (ArrayBuffer/TypedArray/Buffer) — a non-binary argument returns structured, never a host TypeError (round-25 P1-02)');
  const byteLen = isStr ? Buffer.byteLength(rawBytes, 'utf8') : (rawBytes.byteLength ?? Buffer.from(rawBytes).length);
  const inputBudget = Number(opts.maxInputBytes ?? BOUNDS.sizeBytes);
  if (byteLen > inputBudget)
    return { result: 'INDETERMINATE', reason: 'resource_limit', detail: `raw input ${byteLen} B > input budget ${inputBudget} B — transport admission refused, verification not started` };
  // #75 P1-01 — STRICT UTF-8 on the raw path: Buffer.toString('utf8') maps invalid bytes to U+FFFD, so 0xFF and
  // the real 3-byte U+FFFD collapse to ONE string ⇒ distinct byte-strings, one verdict (breaks I4). fatal reject.
  let raw;
  if (isStr) { raw = rawBytes; if (raw.charCodeAt(0) === 0xFEFF) return bad('E-CANON', 'raw input has a leading U+FEFF BOM — rejected (round-19 P1-01)', { obligation: '§6 canonical UTF-8' }); }   // round-19 P1-01 — a pre-decoded string with a leading BOM (same domain as the byte checker's E-BOM)
  else { const a = admitUtf8(rawBytes); if (a.err === 'BOM') return bad('E-CANON', 'raw input has a leading UTF-8 BOM (EF BB BF) — rejected, not stripped (round-19 P1-01)', { obligation: '§6 canonical UTF-8' }); if (a.err) return bad('E-CANON', 'raw input is not valid UTF-8 (invalid byte sequence)', { obligation: '§6 canonical UTF-8' }); raw = a.text; }
  const dup = scanDuplicateKeys(raw);
  if (dup) return bad('E-CANON', dup);
  let obj; try { obj = JSON.parse(raw); } catch { return bad('E-MALFORMED', 'not valid JSON'); }
  if (anyLoneSurrogate(obj)) return bad('E-CANON', 'unpaired UTF-16 surrogate in a parsed string/key — not a Unicode scalar (round-19 P1-01; §6 canonical domain == byte checker)', { obligation: '§6 canonical UTF-8' });   // round-19 P1-01 — same lone-surrogate reject as the byte checker's E-SURROGATE
  return verify(obj, opts);
}

// ─── DISCOVERY-DRIVEN RESOLUTION (rc.13) — the SINGLE resolver every surface (web/cli/mcp) calls, so the
// "fetch the publisher's own genesis+keylog and re-verify with the grant" flow exists in ONE place, not
// three copies that drift. A verifier that resolves BY NAME must first decide the name is safe to reach:
// the domain_shard comes from an UNTRUSTED document, so an SSRF guard runs BEFORE any network call.

// SSRF guard: a discovery target MUST be a public DNS name. Rejects IPs (v4/v6), localhost, non-public
// TLDs/suffixes, ports, userinfo, and anything that is not label.label…public-tld. This is the boundary
// between "resolve by name" and "let an attacker's document point my verifier at an internal address".
export function isPublicDnsShard(shard) {
  if (typeof shard !== 'string' || !shard || shard.length > 253) return false;
  if (/[:/@\s]/.test(shard)) return false;                                  // no port/path/userinfo/space
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(shard)) return false;                  // IPv4
  if (/^[0-9a-f]*:[0-9a-f:]*$/i.test(shard)) return false;                  // IPv6-ish
  const lower = shard.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.local') ||
      lower.endsWith('.internal') || lower.endsWith('.home.arpa') || lower.endsWith('.onion')) return false;
  const labels = lower.split('.');
  if (labels.length < 2) return false;                                      // must have a TLD
  if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return false;  // RFC1123 labels
  if (!/^[a-z]{2,}$/.test(labels[labels.length - 1])) return false;         // alphabetic public TLD
  return true;
}

// Resolve a document's authority by fetching its OWN §20.1 discovery pair, then re-verify with the grant.
// Returns { verdict, resolution } — verdict is what a caller should surface; resolution carries publisher /
// capacity / noFork status / source (or an error/skip). Honest by construction: without an explicit
// noForkConfirmed the name stays provisional (never silently authoritative). `offline` forbids the network.
// fetchImpl injected for tests. This function performs the ONLY network egress in the verify path.
// Witness auto-query (§12.1 M2, #68) — fetch the publisher's genesis-log and turn no-fork from a manual
// assertion into EVIDENCE. Every listed genesis's anchor is CROSS-CHECKED against its substrate (Bitcoin
// via opts.substrateVerify — the endpoint is only an index, the anchor is the independent truth). The
// honesty ladder is §12.1 exactly: one anchored active genesis (== the one we resolved) ⇒ confirmed;
// ≥2 anchored active ⇒ fork; unreachable / unanchored ⇒ pending (W1 — never a forged HIGH, never silence).
// A genesis is "anchored" iff AT LEAST ONE of its anchors verifies: inclusion (sync Merkle) AND substrate
// finality (async — Bitcoin/Rekor, so it MUST be awaited; the earlier sync path silently dropped every
// real async plugin). `anchors[]` (several substrates) is the norm; a single `anchor` is accepted too.
// round-21 — anchored iff ANY of the given (already unioned + budget-checked) proofs both includes and is substrate-final.
// The witness caller does the grouping/union/budget so this is a pure per-root check. `proofs` is the FULL evidence set
// for one content_hash (P0-01/P0-02: no first-wins, no anchor/anchors shadow, no truncation upstream).
// round-23 P1-05 — a connector must SETTLE within a bound: a never-resolving promise cannot block the verifier forever
// (I4 totality / F.9). Race each plugin call against a deadline; a timeout is that plugin's unavailability, and the timer
// is unref'd + cleared so it neither keeps the process alive nor leaks. Matches the discovery fetch AbortSignal.timeout.
const SUBSTRATE_DEADLINE_MS = 10000, WITNESS_OP_DEADLINE_MS = 30000;   // round-24 P1-04 — per-leaf AND a whole-operation budget
const withDeadline = (p, ms = SUBSTRATE_DEADLINE_MS) => { let t; const to = new Promise((_, rej) => { t = setTimeout(() => rej(new Error('substrate plugin deadline exceeded')), ms); }); return Promise.race([Promise.resolve(p).finally(() => clearTimeout(t)), to]); };
// round-24 P1-04 — a whole-operation deadline, not merely per-leaf: a legal witness (≤16 roots × ≤8 proofs) could burn
// 16×8×10s ≈ 21 min of SEQUENTIAL per-leaf timeouts. `opDeadline` bounds the whole resolution; before each connector call
// the remaining budget also caps that leaf. Exhaustion returns the string 'resource_limit' (the caller maps it to F.9).
async function anchoredByProofs(content_hash, proofs, substrateVerify, opDeadline) {
  for (const proof of proofs) {
    if (opDeadline && witnessNow() >= opDeadline) return 'resource_limit';
    const incl = verifyAnchorCore(content_hash, proof);   // internal (witness log is JSON-parsed, getter-free); inclusion only
    if (!incl.inclusion || !substrateVerify) continue;
    const leafMs = opDeadline ? Math.max(1, Math.min(SUBSTRATE_DEADLINE_MS, opDeadline - witnessNow())) : SUBSTRATE_DEADLINE_MS;
    let sub; try { sub = await withDeadline(substrateVerify(proof.anchor, proof.root, { deadline: opDeadline }), leafMs); } catch { if (opDeadline && witnessNow() >= opDeadline) return 'resource_limit'; continue; }   // round-21 P1-01 / round-23 P1-05 — a connector throw OR a hang is UNAVAILABLE evidence; round-27 P1-01 — but a timeout that EXHAUSTED the whole-op budget is resource_limit, not a mere unavailable leaf
    if (opDeadline && witnessNow() >= opDeadline) return 'resource_limit';   // round-27 P1-01 — the budget can expire DURING the await (incl. the final leaf); check after every awaited leaf, not only before
    if (substrateFinal(sub)) return true;               // round-18 P0-02 — same closed decoder as verifyAnchor (a bare truthy `final` no longer confirms the witness genesis)
  }
  return false;
}

// round-17 P1-03 — a BYTE CEILING for authority discovery (F.9/§13). A §13 key-log is ≤256 entries and genesis/witness
// are small, so a 2 MiB cap bounds every discovery body. Reject a declared oversize BEFORE accumulating; when the body
// is a real stream, read with a hard cap and abort past it (no full accumulation); for a mocked response, cap after read.
const DISCOVERY_MAX_BYTES = 1 << 21;                              // 2 MiB — a single genesis/witness doc
const KEYLOG_MAX_BYTES = 1 << 23;                                // 8 MiB — a ≤256-entry key-log of ordinary small key docs (round-18 P0-03: rev14's 2 MiB was below a valid K≤256 log). This is a RESOURCE BUDGET, not the K bound: a genuinely huge valid log honestly hits INDETERMINATE(resource_limit), never keylog=[].
// round-18 P1-02 — authority-discovery bytes are STRICT UTF-8: an invalid sequence is REJECTED (via the existing
// module strictUtf8 fatal decoder → null), never replacement-decoded to U+FFFD (I4/M-BYTE: an FF byte and a genuine
// U+FFFD string must not collapse to one transcript — that is a cross-implementation split at the authority byte boundary).
const strictUtf8OrThrow = (buf) => { const a = admitUtf8(buf); if (a.err === 'BOM') throw new Error('discovery body has a leading UTF-8 BOM (EF BB BF) — rejected, not stripped (round-19 P1-01; §6 canonical Unicode domain == byte checker)'); if (a.err) throw new Error('discovery body is not valid UTF-8 (invalid byte sequence) — §6 canonical UTF-8'); return a.text; };
const readBounded = async (r, cap = DISCOVERY_MAX_BYTES) => {
  const cl = Number(r.headers?.get?.('content-length'));
  if (Number.isFinite(cl) && cl > cap) throw new Error(`discovery body ${cl} B exceeds the ${cap} B ceiling (§13)`);
  if (r.body && typeof r.body.getReader === 'function') {
    const reader = r.body.getReader(); let total = 0; const chunks = [];
    for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length; if (total > cap) { try { await reader.cancel(); } catch { /* already closed */ } throw new Error(`discovery body exceeds the ${cap} B ceiling (§13)`); } chunks.push(value); }
    return strictUtf8OrThrow(Buffer.concat(chunks));
  }
  if (typeof r.arrayBuffer === 'function') {                      // real fetch without a stream: strict-decode the raw bytes (never Response.text()'s replacement decode)
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.byteLength > cap) throw new Error(`discovery body ${buf.byteLength} B exceeds the ${cap} B ceiling (§13)`);
    return strictUtf8OrThrow(buf);
  }
  const body = await r.text();                                   // test-mock path: text() returns an already-decoded JS string (no raw bytes to mis-decode)
  if (Buffer.byteLength(body, 'utf8') > cap) throw new Error(`discovery body exceeds the ${cap} B ceiling (§13)`);
  return body;
};
export async function witnessNoFork(shard, genesisHash, opts) {
  // rev34 R1 (round-29 P1-01 / div1) — witnessNoFork is CONSUMER SURFACE: it is exported, takes an untrusted endpoint body,
  // and its verdict gates whether resolveByDiscovery mints a served-list basis. So it must be TOTAL on EVERY argument — a
  // hostile shard/genesisHash/opts yields a STRUCTURED result, never a host throw. Admit the opts at the door (admitOpts
  // preserves the fetchImpl/substrateVerify capabilities, rejects a hostile Proxy → null); a non-string shard/hash is not
  // a witnessable target.
  const o = admitOpts(opts);
  if (o === null || typeof shard !== 'string' || typeof genesisHash !== 'string')
    return { status: 'indeterminate', reason: 'unavailable', detail: 'witnessNoFork requires a string shard + genesisHash and an inert opts record (round-29 P1-01 totality)' };
  const { fetchImpl = fetch, substrateVerify, maxWitnessOpMs } = o;
  let log;
  try {
    const r = await fetchImpl(`https://${shard}/.well-known/ust-witness`, { signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const raw = await readBounded(r);
    // round-20 P0-01 — the witness is AUTHORITY input like genesis and the key-log, so it crosses the SAME raw-byte
    // duplicate-member boundary BEFORE JSON.parse. A duplicate `genesis_log` (or member) collapses under JS last-wins
    // parsing, and a fork-bearing occurrence can be hidden behind an innocent one → false `corroborated`. Fail closed.
    if (scanDuplicateKeys(raw)) throw new Error('witness log fails the raw-byte duplicate-member check (§6) — a duplicate member can hide a fork under last-wins parsing (round-20 P0-01)');
    log = JSON.parse(raw);
  } catch (e) { return { status: 'unreachable', detail: 'witness endpoint unreachable: ' + (e && e.message || e) }; }
  if (anyLoneSurrogate(log)) return { status: 'unreachable', detail: 'witness log has an unpaired UTF-16 surrogate — outside the §6 canonical Unicode domain (round-19 P1-01)' };   // round-19 P1-01 — same Unicode domain as genesis/key-log/byte checker
  if (!log || log.domain_shard !== shard || !Array.isArray(log.genesis_log)) return { status: 'unreachable', detail: 'witness log malformed' };
  // round-21 P0-01/P0-02 — the served list is a MEASURABLE input (F.5a corroborated: "the served witness list shows
  // exactly one active anchored binding"), NOT a lossy projection of it. rev17 dedup'd first-wins and slice()'d anchors
  // — both DISCARD rival evidence and then mint HIGH, which the model forbids: "authority is denied, never forged", and a
  // resource cap must LOWER decisibility, never RAISE assurance. So: (1) GROUP entries by content_hash and UNION their
  // anchor evidence (`anchors[]` + `anchor`) — no first-wins, no anchor/anchors shadow; (2) a structural over-budget is a
  // REFUSAL (INDETERMINATE resource_limit), NEVER a truncation that could delete the one rival proof.
  const OVER = (detail) => ({ status: 'indeterminate', reason: 'resource_limit', detail });   // round-21 P2-01 — machine-readable, not 'unreachable'
  if (log.genesis_log.length > BOUNDS.witnessEntries) return OVER(`witness genesis_log has ${log.genesis_log.length} entries > ${BOUNDS.witnessEntries} (§F.9 — structural fan-out refused, never truncated; round-21 P0-02)`);
  // round-22 P0-01 — GROUP the full equivalence class by content_hash BEFORE any status projection. rev18/rev19 filtered
  // `superseded_by` FIRST, so an active record + a superseded record for the SAME rival hash let the superseded record's
  // valid anchor be dropped → false corroborated. Now: group ALL entries; record BOTH observed statuses; SET-union proofs
  // (round-22 P2-01 — dedupe byte-identical proofs by canon, so duplicate serialization can't consume the structural cap).
  const byHash = new Map();   // content_hash → { active, superseded, proofs: Map<canon, proof> }
  for (const g of log.genesis_log) {
    if (!g || typeof g !== 'object' || !/^sha256:[0-9a-f]{64}$/.test(g.content_hash || '')) continue;
    let e = byHash.get(g.content_hash);
    if (!e) { e = { active: false, superseded: false, proofs: new Map() }; byHash.set(g.content_hash, e); }
    if (g.superseded_by) e.superseded = true; else e.active = true;                                      // record BOTH — a hash seen active AND superseded is a contradiction
    for (const p of [...(Array.isArray(g.anchors) ? g.anchors : []), ...(g.anchor ? [g.anchor] : [])]) { let k; try { k = canon(p); } catch { k = JSON.stringify(p); } if (!e.proofs.has(k)) e.proofs.set(k, p); }
  }
  // round-22 P0-01 — reconcile status AFTER grouping: a content_hash listed BOTH active and superseded is a contradictory
  // witness (a rival cannot be quietly 'superseded' on one record to erase its anchor from the active count) → fail closed.
  const active = [];
  for (const [content_hash, e] of byHash) {
    if (e.active && e.superseded) return { status: 'unreachable', detail: `witness lists ${content_hash.slice(0, 20)}… as BOTH active and superseded — contradictory, fail closed (round-22 P0-01)` };
    if (e.active) active.push({ content_hash, proofs: [...e.proofs.values()] });   // purely-superseded roots are not active
  }
  if (active.length > BOUNDS.witnessActive) return OVER(`witness has ${active.length} distinct active roots > ${BOUNDS.witnessActive} (§F.9 — refused, never truncated; round-21 P0-02)`);
  for (const a of active) if (a.proofs.length > BOUNDS.anchorsPerGenesis) return OVER(`active genesis ${a.content_hash.slice(0, 20)}… carries ${a.proofs.length} UNIQUE anchors > ${BOUNDS.anchorsPerGenesis} (§F.9 — refused, never truncated; round-21 P0-02)`);
  const anchoredActive = [];
  // round-25 Div2 (F.9 — ρ_v belongs to the VERIFIER): the reference 30 s is a DEFAULT ceiling, never a universal
  // protocol constant. A consumer with a tighter deadline caps the operation → effective budget = min(reference, consumer).
  // round-27 P2-01 — typed policy admission: ONLY an ABSENT budget selects the reference default. A SUPPLIED value that
  // is not a finite positive integer (0, -1, NaN, Infinity, fractional, non-number) is a malformed policy → refuse, never
  // silently expand to the 30 s default (which let 0/-1/NaN/Infinity all admit a 20 ms connector and return 'confirmed').
  if (maxWitnessOpMs !== undefined && !(Number.isInteger(maxWitnessOpMs) && maxWitnessOpMs > 0))
    return OVER(`maxWitnessOpMs must be a finite positive integer of milliseconds (got ${typeof maxWitnessOpMs === 'number' ? maxWitnessOpMs : typeof maxWitnessOpMs}); an invalid verifier budget is refused, never expanded to the reference default (round-27 P2-01)`);
  const opBudget = maxWitnessOpMs === undefined ? WITNESS_OP_DEADLINE_MS : Math.min(WITNESS_OP_DEADLINE_MS, maxWitnessOpMs);
  const opDeadline = witnessNow() + opBudget;   // round-24 P1-04 — bound the WHOLE witness resolution, not just each leaf
  for (const a of active) {
    const r = await anchoredByProofs(a.content_hash, a.proofs, substrateVerify, opDeadline);
    if (r === 'resource_limit') return OVER(`witness anchor verification exceeded the ${opBudget} ms whole-operation budget (§F.9 — a legal fan-out cannot monopolize a verification; the verifier's ρ_v is min(reference ${WITNESS_OP_DEADLINE_MS} ms, consumer deadline); round-24 P1-04 / round-25 Div2)`);
    if (r) anchoredActive.push({ content_hash: a.content_hash });
  }
  if (anchoredActive.length >= 2) return { status: 'fork', detail: `${anchoredActive.length} anchored active genesis roots for ${shard} — a rival name-binding root exists` };
  if (anchoredActive.length === 1) {
    if (anchoredActive[0].content_hash !== genesisHash) return { status: 'fork', detail: `the anchored active genesis (${anchoredActive[0].content_hash.slice(0, 20)}…) differs from the one served at /.well-known/ust-genesis` };
    return { status: 'confirmed', detail: 'a single anchored active genesis, cross-checked against its substrate — no rival root' };
  }
  return { status: 'pending', detail: active.length ? 'genesis present in the witness log but no anchor is final yet (substrate) — no-fork not yet evidence' : 'no active genesis in the witness log' };
}

// Multi-substrate router (#68): a verifier may understand SEVERAL anchor substrates (Bitcoin-OTS, Rekor,
// …) via injected plugins. Each plugin returns null for an anchor whose `substrate` it does not handle;
// combineSubstrates tries them in order and returns the first non-null verdict. This is how a heterogeneous
// witness world stays coherent — not one substrate, but one QUESTION ("is this root committed & final?")
// answered by whichever plugin speaks that substrate. §17 registry is the shared vocabulary.
export function combineSubstrates(verifiers) {
  const list = (Array.isArray(verifiers) ? verifiers : [verifiers]).filter(Boolean);
  return async (anchor, root, ctx) => {
    // round-22 P1-02 + round-23 P1-05 — ISOLATE each plugin AND bound it: a throwing, unreachable, OR never-settling
    // connector must not shadow a later independent one that CAN verify this substrate. A rejection/timeout from one
    // plugin is that plugin's unavailability, not the seam's. round-27 P1-01 — STOP starting new plugins once the whole-op
    // deadline has passed (was: the loop kept firing plugins after the caller returned — detached work). A plugin may
    // also honor the AbortSignal to cancel its own in-flight work.
    const ac = typeof AbortController === 'function' ? new AbortController() : null;
    for (const v of list) {
      if (ctx?.deadline && witnessNow() >= ctx.deadline) { ac?.abort(); return null; }   // budget spent → no new plugin, cancel any signal-honoring work (rev36 — the deadline is on the witnessNow() monotonic scale, NOT Date.now())
      let r; try { r = await withDeadline(v(anchor, root, { deadline: ctx?.deadline, signal: ac?.signal })); } catch { continue; }
      if (r != null) return r;
    }
    return null;   // no plugin claimed this substrate → verifyAnchor reports 'unavailable' (honest, not INVALID)
  };
}

export async function resolveByDiscovery(doc, opts = {}, transport = {}) {
  opts = admitOpts(opts); const T = admitOpts(transport);   // round-19 P1-02 — inert snapshots; a throwing accessor/Proxy trap on opts OR transport → null → structured reject (not a host throw)
  if (opts === null || T === null) return { verdict: { result: 'E-MALFORMED', tier: 'NONE', detail: 'opts and transport must be inert records (round-19 P1-02 totality)' }, resolution: null };
  const D = admitDeep(doc);   // round-27 (3, self-audit) — admit the doc ONCE at THIS door: the discovery `shard` (the fetch URL) and the verify verdict must read the SAME bytes, else a getter fetches one domain's genesis/witness while the verdict is over another.
  if (D === ADMIT_REJECT) return { verdict: { result: 'E-MALFORMED', tier: 'NONE', detail: 'document is not an inert record (round-27: the ONE input boundary)' }, resolution: null };
  doc = D;
  const { fetchImpl = fetch, substrateVerify } = T;
  const base = verify(doc, opts);
  const shard = doc?.state?.id?.domain_shard || '';
  const worth = !opts.offline && !opts.genesis &&
    (base.result === 'VALID:LIGHT' || (base.result === 'INDETERMINATE' && base.reason === 'unavailable'));
  if (!worth) return { verdict: base, resolution: null };
  if (!isPublicDnsShard(shard)) return { verdict: base, resolution: { skipped: 'domain_shard is not a public DNS name — discovery refused (SSRF guard)' } };
  let genesis, keylog = [], genesisHash, gRaw, kRaw;
  try {
    const get = async (p, cap) => { const r = await fetchImpl(`https://${shard}${p}`, { signal: AbortSignal.timeout(10000), redirect: 'error' }); if (!r.ok) { const e = new Error(`HTTP ${r.status} at ${p}`); e.httpStatus = r.status; throw e; } return readBounded(r, cap); };   // round-17 P1-03 — bounded read (byte ceiling before accumulate/scan/parse)
    gRaw = await get('/.well-known/ust-genesis');
    try { kRaw = await get('/.well-known/ust-keylog', KEYLOG_MAX_BYTES); }
    catch (e) {
      // round-18 P0-03 — an ABSENT key-log (404/410) is genuinely not served (fail-safe: only genesis-key docs stay
      // authoritative). A PRESENT-but-UNREADABLE one (oversize / transport error) must NEVER become keylog=[] — that
      // erases a real retirement and false-accepts a post-retirement doc. It is INDETERMINATE(resource_limit), F.9.
      if (e.httpStatus !== 404 && e.httpStatus !== 410)
        return { verdict: base, resolution: { status: 'INDETERMINATE', reason: /ceiling|§13/.test(e.message || '') ? 'resource_limit' : 'unavailable', error: 'key-log present but unreadable (' + (e.message || e) + ') — authority NOT computed (round-18 P0-03; never substituted with an empty log)' } };
    }
  } catch (e) { return { verdict: base, resolution: { error: 'discovery fetch failed: ' + (e && e.message || e) } }; }
  // #69 Theme D — genesis AND key-log are AUTHORITY input; both MUST cross the SAME raw-byte boundary as any
  // untrusted transcript (I4). JSON.parse silently collapses duplicate members, so the genesis goes through
  // verifyJson and the key-log's raw bytes go through the SAME scanner (scanDuplicateKeys, which descends into
  // every entry) BEFORE parse. A dup-key authority surface is E-CANON — never a silent downgrade to LIGHT.
  const gv = verifyJson(gRaw, {});
  if (!isValid(gv)) return { verdict: base, resolution: { error: 'published genesis does not VERIFY: ' + (gv.error || gv.result) } };
  genesis = JSON.parse(gRaw); genesisHash = contentHash(genesis);
  if (kRaw !== undefined) {
    const kdup = scanDuplicateKeys(kRaw);
    if (kdup) return { verdict: base, resolution: { error: 'E-CANON: published key-log fails the raw-byte check (' + kdup + ')' } };
    let k; try { k = JSON.parse(kRaw); } catch { return { verdict: base, resolution: { error: 'E-MALFORMED: published key-log is not valid JSON' } }; }
    if (anyLoneSurrogate(k)) return { verdict: base, resolution: { error: 'E-CANON: published key-log has an unpaired UTF-16 surrogate — outside the §6 canonical Unicode domain (round-19 P1-01)' } };   // round-19 P1-01 — same Unicode domain as the byte checker + genesis
    if (!Array.isArray(k)) return { verdict: base, resolution: { error: 'E-MALFORMED: published key-log is not a JSON array' } };
    keylog = k;
  }

  // no-fork EVIDENCE (default): query the witness UNLESS the caller air-gap-asserts it or forbids the network.
  // #69 B / F.5a — the publisher's OWN served witness list is CORROBORATION, not independent non-membership: a
  // confirmed served list ⇒ `corroborated` (HIGH, honest), NOT `authoritative`. Only a caller air-gap assertion
  // (out-of-band responsibility) or a future anchored map-inclusion reaches `authoritative`. A fork ⇒ E-GENESIS.
  // P0-2 — a caller-supplied no-fork basis (verified `noForkEvidence`, or the raw `noForkConfirmed` override) skips the
  // witness auto-query; otherwise the served genesis-log is queried and only ever CORROBORATES (never independent).
  let witnessConfirmed = false, noFork = 'unconfirmed', witnessReason;
  const callerNoFork = opts.noForkEvidence !== undefined || opts.noForkConfirmed;
  if (!callerNoFork && !opts.offline) {
    const w = await witnessNoFork(shard, genesisHash, { fetchImpl, substrateVerify, maxWitnessOpMs: opts.maxWitnessOpMs });   // round-26 P1-03 (rev27 E) — thread the verifier's ρ_v.time policy through the PUBLIC entry; the leaf-only budget was unreachable (F.9); round-31 — also the injectable budget clock (resource-limit only)
    if (w.status === 'fork') return { verdict: bad('E-GENESIS', w.detail), resolution: { publisher: shard, fork: true, detail: w.detail } };
    witnessConfirmed = w.status === 'confirmed';
    if (w.reason) witnessReason = w.reason;   // round-21 P2-01 — preserve the machine-readable witness reason (resource_limit) through the resolution, not just a 'HIGH pending' string
    noFork = witnessConfirmed ? 'served-list (corroborated)' : 'HIGH pending — ' + w.detail;
  }
  // VERIFIED served-list evidence (bound to THIS genesis) — the ONLY way the stateless core earns `corroborated`; a
  // bare boolean would be a mere assertion (self-audit rc.35). Present only when witnessNoFork actually confirmed.
  let servedNoFork; if (witnessConfirmed) { servedNoFork = { confirmed: true, active_genesis: genesisHash }; VERIFIED_SERVED.add(servedNoFork); }   // P0-1: mint the trusted token ONLY after witnessNoFork confirmed
  // round-16 P0-02 — key-log freshness is EARNED here: we JUST fetched /.well-known/ust-keylog for THIS domain+genesis,
  // so mint an unforgeable observation token (observed_at = the fetch instant). A raw caller string can never do this.
  let keylogFreshAsOf; if (kRaw !== undefined) { keylogFreshAsOf = { observed_at: new Date().toISOString().slice(0, 19) + 'Z', domain: shard, active_genesis: genesisHash }; VERIFIED_FRESH.add(keylogFreshAsOf); }
  const authOpts = { genesis, keylog, noForkConfirmed: opts.noForkConfirmed, noForkEvidence: opts.noForkEvidence, trustRoots: opts.trustRoots, servedNoFork, keylogFreshAsOf };
  const auth = resolveAuthority(doc, authOpts);
  if (auth.error) return { verdict: base, resolution: { error: auth.error + (auth.detail ? ' — ' + auth.detail : '') } };
  if (callerNoFork) noFork = auth.independently_verified ? 'accepted-external-witness (authoritative)' : 'caller-asserted (consumer-override)';
  const verdict = await verifyAsync(doc, { ...opts, genesis, keylog, noForkConfirmed: opts.noForkConfirmed, servedNoFork, keylogFreshAsOf, capacity: auth.capacity, substrateVerify });   // #69 E1 — await the doc's own anchor substrate (TOP); carry the EARNED freshness token (round-16 P0-02) into the final verdict
  return { verdict, resolution: { publisher: auth.publisher ?? shard, strength: auth.strength, capacity: auth.capacity, noFork, ...(witnessReason ? { witness_reason: witnessReason } : {}), source: `https://${shard}/.well-known/ (§20.1 discovery + §12.1a witness)` } };
}

// minimal duplicate-key-detecting JSON scanner (zero-dep). Returns an error string or null. Keys are parsed
// (via JSON.parse of the token) so `a` and `a` collide as the SAME member name.
function scanDuplicateKeys(s) {
  let i = 0; const n = s.length;
  const ws = () => { while (i < n && ' \t\n\r'.includes(s[i])) i++; };
  const str = () => { const a = i; i++; while (i < n) { if (s[i] === '\\') i += 2; else if (s[i] === '"') { i++; return JSON.parse(s.slice(a, i)); } else i++; } throw 'unterminated string'; };
  function value() {
    ws(); const c = s[i];
    if (c === '{') {
      i++; const keys = new Set(); ws();
      if (s[i] === '}') { i++; return; }
      for (;;) { ws(); if (s[i] !== '"') throw 'expected key'; const k = str(); if (keys.has(k)) throw 'duplicate member name: ' + k; keys.add(k); ws(); if (s[i] !== ':') throw 'expected colon'; i++; value(); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === '}') { i++; return; } throw 'bad object'; }
    } else if (c === '[') {
      i++; ws(); if (s[i] === ']') { i++; return; }
      for (;;) { value(); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === ']') { i++; return; } throw 'bad array'; }
    } else if (c === '"') { str(); }
    else { while (i < n && !',}] \t\n\r'.includes(s[i])) i++; }        // number / true / false / null
  }
  try { value(); ws(); return i >= n ? null : 'trailing bytes'; } catch (e) { return typeof e === 'string' ? e : 'malformed JSON'; }
}

function err(code, detail) { const e = new Error(code); e.code = code; e.detail = detail; return e; }
// §14 INVALID constructor. `fields` (optional) carries MACHINE-STRUCTURED context so a program branches WITHOUT
// parsing `detail` (audit #44 §2 — verification fatigue): `obligation` names the exact broken spec rule, and a
// recompute mismatch adds `expected`/`actual` (and `partition` where it applies). `error`+`detail` stay for humans.
function bad(code, detail, fields) { return { result: 'INVALID', error: code, detail, ...(fields || null) }; }
