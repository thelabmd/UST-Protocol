// SPDX-License-Identifier: Apache-2.0
// ust-protocol — reference implementation of UST 1.0 (the official STATELESS base; the public verification lib) (REV 26), LIGHT floor first.
// §16: ONE version source — the conformance runner asserts spec/package/vectors all carry the same rc.
export const VERSION = { wire: '1.0', spec: '1.0.0-rc.30', revision: 41 };   // #75 P1-09: machine-readable {wire, spec, revision} — Status line & appendix must agree
// Written FROM THE SPEC (§ references inline), NOT copied from the vector generator — so running it against
// the vectors is a cross-check between two independently-written artifacts. Zero-dependency: node:crypto
// (Ed25519 + SHA-256). Portable note: WebCrypto (SubtleCrypto Ed25519) or @noble/{ed25519,hashes} for
// browsers/Workers; same rules.
import { createHash, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey, createDecipheriv } from 'node:crypto';

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
// A cadence is SECONDS as a canonical positive integer STRING — no fraction, no leading zero, no sign, bounded.
export function parseCadenceInt(s) {
  if (typeof s !== 'string' || !/^[1-9][0-9]*$/.test(s)) return null;      // "1.5", "030", "-1", "1e2", 30(number) all fail
  const n = Number(s);
  return (Number.isSafeInteger(n) && n > 0 && n <= BOUNDS.cadenceMax) ? n : null;
}
// Strict UTF-8 decode: Node's Buffer.toString('utf8') silently maps invalid bytes to U+FFFD, so 0xFF and the real
// 3-byte U+FFFD collapse to one string. fatal:true rejects invalid UTF-8 instead (P1-01). → string | null.
function strictUtf8(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes)); }
  catch { return null; }
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
export const buildGenesis = (id, time, pub, maxPartitions, maxTranscriptBytes, cadence) =>  // §12.1 self-signed name-binding root
  buildState({ ...id, class: 'genesis' }, time, { genesis: { kind: 'captured', value: {
    pub, role: 'name-binding-root',
    ...(maxPartitions !== undefined ? { max_partitions: String(maxPartitions) } : {}),           // §13 ladder (≠ ceiling; ABS 4096)
    ...(maxTranscriptBytes !== undefined ? { max_transcript_bytes: String(maxTranscriptBytes) } : {}), // §13 ladder (≠ ceiling; ABS 64 MiB)
    ...(cadence !== undefined ? { cadence: String(cadence) } : {}),                               // §11.3 C — SIGNED cadence (sec) → the expected grid; resolved not free-chosen (#69 C)
  } } });
export const buildKeyLogEntry = (id, time, keyOp, prev) =>                         // §12.2 add|rotate|revoke
  buildState({ ...id, class: 'key' }, time, { key_op: { kind: 'captured', value: keyOp } }, { prev });
export const buildCheckpoint = (id, time, head, frameCount, prev, interval) =>   // §11.3 M5 (interval = {from,to} for completeness, #69 C)
  buildState({ ...id, class: 'attestation' }, time, { checkpoint: { kind: 'computed', value: { head, frame_count: String(frameCount), ...(interval ? { from: interval.from, to: interval.to } : {}) } } }, { prev });
export const buildGap = (id, time, prev, reason) =>                               // §11.3 C2 — a signed gap record: this slot (id.ust_id) is HONESTLY absent
  buildState({ ...id, class: 'attestation' }, time, { gap: { kind: 'computed', value: { reason: reason || 'no-frame' } } }, { prev });
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
const KINDS = ['captured', 'computed'], PRIVACY = ['blinded', 'encrypted'];   // §S4/D1: secret-url is a disclosure CHANNEL (§out-of-scope), not a privacy mode
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
const BOUNDS = { depth: 8, array: 4096, partitions: 4096, floorPartitions: 64, breadth: 64, sizeBytes: 67108864, floorSizeBytes: 1048576, cadenceMax: 31622400 };  // cadenceMax = 366 d in seconds (#75: bounded integer cadence)
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
export function verify(doc, opts = {}) {
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
      if (part.privacy !== undefined && !PRIVACY.includes(part.privacy)) return bad('E-MALFORMED', 'unknown privacy mode: ' + name + '.' + part.privacy);
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
    // step 3 — name authority (§14.3): HIGH resolves genesis+key-log; else a PINNED key (TOFU, §3.1) if the caller
    // supplies pinnedKeys — a key NOT in the pin set is INVALID (that is what pinning means); else self-asserted.
    let identity;
    if (opts.genesis) identity = resolveAuthority(doc, opts);
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
    const nameField = identity.strength === 'authoritative' ? { publisher: st.id.domain_shard } : { publisher_claimed: st.id.domain_shard };
    // §S3/F3 — an EMBEDDED proof MUST verify. present-but-bad ⇒ E-ANCHOR (never a VALID doc next to an unchecked
    // "present" proof). The anchor's availability STATUS is carried through, never flattened (audit E, M-05).
    let timeField = { strength: 'unproven', status: 'none' };
    if (doc.proof !== undefined) {
      const a = verifyAnchor(ch, doc.proof, opts);
      if (!a.inclusion) return bad('E-ANCHOR', a.detail || 'embedded proof does not verify');
      // §14.6 N9 — real time is the anchor: a document cannot be generated AFTER the anchor that contains it.
      // Pinned RFC3339-Z strings compare lexicographically as instants.
      if (a.time === 'anchored' && a.anchorTime && st.time.generated_at > a.anchorTime)
        return bad('E-ANCHOR', 'generated_at after the anchor time (N9: the document postdates its own anchor)');
      timeField = { strength: a.time, status: a.status, inclusion: true, ...(a.anchorTime ? { anchorTime: a.anchorTime } : {}), ...(a.assurance ? { assurance: a.assurance } : {}) };
    }
    // The verdict CARRIES ITS SCOPE: `VALID:LIGHT|HIGH|TOP`, so a consumer cannot read "valid" without reading
    // valid-AT-WHAT (a bare `=== 'VALID'` no longer matches — the same forcing function as publisher_claimed).
    // tier = the highest fully-satisfied rung (monotonic, §3.1). The NAME is bound to the key at both `corroborated`
    // and `authoritative` (§12.1a F.5a) — both reach HIGH. The no-fork STRENGTH separates them: only `authoritative`
    // (independent non-membership) reaches TOP, so an anchored-but-only-corroborated name never overclaims TOP.
    const verified = identity.status === 'verified';
    const authoritative = identity.strength === 'authoritative' && verified;
    const nameBound = verified && (identity.strength === 'authoritative' || identity.strength === 'corroborated');
    // §3.1/§15 — TOP = authoritative identity + anchored time. HIGH = name-bound (corroborated or authoritative).
    // Stream COMPLETENESS is a separate RANGE verdict (verifyStream), never a single-document claim.
    const tier = authoritative && timeField.strength === 'anchored' ? 'TOP' : nameBound ? 'HIGH' : 'LIGHT';
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
    return { result: 'VALID:' + tier, tier, identity: { ...identity, mode: shardMode }, disclosed, sources, ...nameField,
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
    const refDoc = opts.resolveRef(h);
    if (!refDoc) { sawUnresolved = true; continue; }
    if (--budget.left < 0) return { error: 'E-BOUNDS', detail: 'referent walk exceeds the verified-node budget (§13 P4 — default 256, opts.refBudget)' };
    const rv = verify(refDoc, { ...opts, provenanceDepth: 0 });          // verify the referent itself (one level)
    if (!isValid(rv)) return { error: rv.error || 'E-SIG', detail: 'referent ' + h + ' invalid: ' + (rv.detail || rv.error) };
    if (rv.content_hash !== h) return { error: 'E-MALFORMED', detail: 'resolver returned a different document for ' + h };
    if (depth > 1) {
      const sub = walkReferents(refDoc.state, opts, depth - 1, new Set([...visited, h]), budget);
      if (sub.error) return sub;
      if (sub.referents === 'partial') sawUnresolved = true;
      reached = Math.max(reached, 1 + sub.depth);
    }
  }
  return { depth: reached, referents: sawUnresolved ? 'partial' : 'verified' };
}

// §12.2 — the SHARED key-log walk (genesis self-signed root + prev-chained entries each signed by a CURRENT
// valid key). Returns { validKeys: Map<key_id,pub>, revoked: Map } or { error, detail }. Used by BOTH
// resolveAuthority (name authority) AND resolveCadence — a cadence-log entry MUST be signed by an AUTHORIZED
// key (not any LIGHT doc with the same domain_shard), the P0 the cadence-log missed.
export function resolveKeys(genesis, keylog = []) {
  if (!genesis) return { error: 'E-GENESIS', detail: 'no genesis' };
  const gv = verify(genesis);                                                     // genesis is itself a UST transcript
  if (!isValid(gv)) return { error: 'E-GENESIS', detail: 'genesis invalid: ' + gv.error };
  if (genesis.state.id.class !== 'genesis') return { error: 'E-GENESIS', detail: 'not class:genesis' };
  if (genesis.sig.key_id !== genesis.state.id.key_id) return { error: 'E-GENESIS', detail: 'genesis not self-signed' };
  if (keylog.length > 256) return { error: 'E-BOUNDS', detail: 'key-log > 256 (§13)' };
  let prevHash = contentHash(genesis);
  const gKid = genesis.state.id.key_id, gPub = genesis.sig.pub;
  // §12.2 #75 ROOT 2 — the key-log is a TEMPORAL STATE MACHINE (reducer), not a growing set. Two sets that used to
  // be ONE (the bug behind P0-02): `all` = every key ever authorized (key_id→pub) for DOCUMENT BINDING (a retired
  // key's earlier doc still binds, then X1 judges it by time — continuity); `active` = the keys that may sign the
  // NEXT log/cadence entry (SHRINKS on revoke/rotate). `revoked` carries the §12.2 X1 end-record for every key that
  // left active (reason retired|compromised). `history` records per-key lifecycle for the K_n(t) temporal query.
  const all = new Map([[gKid, gPub]]);
  const active = new Map([[gKid, gPub]]);
  const revoked = new Map();                                                      // key_id → {reason, compromised_since?, at}
  const history = new Map([[gKid, { pub: gPub, from: 0, retired_at: null, revoked_at: null }]]);
  const OP_FIELDS = { add: ['op', 'pub', 'new_key_id'], rotate: ['op', 'pub', 'new_key_id'], revoke: ['op', 'pub', 'reason', 'compromised_since'] };
  const derive = (i, pub, label) => {                                            // strict pub + derived key_id
    if (strictB64url(pub, 32) === null) return { error: { error: 'E-KEY', detail: 'entry ' + i + ' ' + label + ' pub not a 32-byte base64url key' } };
    return { kid: keyId(pub) };
  };
  for (const [i, e] of keylog.entries()) {                                        // §12.2 walk: prev-chained, signed by a CURRENTLY-ACTIVE key
    const ev = verify(e, { context: 'key' });
    if (!isValid(ev)) return { error: 'E-KEY', detail: 'key-log entry ' + i + ' invalid: ' + ev.error };
    if (e.state.id.class !== 'key') return { error: 'E-KEY', detail: 'entry ' + i + ' not class:key' };
    if (e.state.provenance?.prev !== prevHash) return { error: 'E-PREV', detail: 'entry ' + i + ' prev not chained' };
    // #75 P0-02a/b — the signer MUST be ACTIVE at this point, not merely ever-seen: a revoked or rotated-out key
    // can no longer authorize a later entry.
    const sKid = keyId(e.sig.pub);
    if (active.get(sKid) !== e.sig.pub) return { error: 'E-KEY', detail: 'entry ' + i + ' not signed by a currently-active key (revoked / rotated-out / never-authorized)' };
    const op = e.state?.data?.key_op?.value;
    // #75 P0-02d/e + P1-07 — CLOSED exact schema per op: an unknown op or a stray field is an ERROR, never a no-op.
    if (typeof op !== 'object' || op === null || !OP_FIELDS[op.op]) return { error: 'E-KEY', detail: 'entry ' + i + ' unknown or missing key_op.op (add|rotate|revoke)' };
    for (const k of Object.keys(op)) if (!OP_FIELDS[op.op].includes(k)) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' stray field in ' + op.op + ': ' + k };
    if (op.op === 'add' || op.op === 'rotate') {
      const d = derive(i, op.pub, op.op); if (d.error) return d.error;
      if (op.new_key_id !== undefined && op.new_key_id !== d.kid) return { error: 'E-KEY', detail: 'entry ' + i + ' new_key_id != H(ust:keylog, pub)' };
      if (revoked.get(d.kid)?.reason === 'compromised') return { error: 'E-KEY', detail: 'entry ' + i + ' cannot re-authorize a COMPROMISED key' };
      all.set(d.kid, op.pub); active.set(d.kid, op.pub);
      if (!history.has(d.kid)) history.set(d.kid, { pub: op.pub, from: i + 1, retired_at: null, revoked_at: null });
      // #75 spec §12.2 "each rotation is authorized by the key it supersedes": on rotate the SIGNER is superseded —
      // it leaves active (cannot sign later entries) and is recorded retired (its EARLIER docs stay valid, X1).
      if (op.op === 'rotate' && sKid !== d.kid) {
        active.delete(sKid);
        revoked.set(sKid, { reason: 'retired', at: e.state.time.generated_at });
        const h = history.get(sKid); if (h) h.retired_at = e.state.time.generated_at;
      }
    } else {  // revoke
      const d = derive(i, op.pub, 'revoke'); if (d.error) return d.error;
      if (!all.has(d.kid)) return { error: 'E-KEY', detail: 'entry ' + i + ' revoke of a never-authorized key' };
      if (op.reason !== 'retired' && op.reason !== 'compromised') return { error: 'E-MALFORMED', detail: 'entry ' + i + ' revoke reason MUST be "retired" | "compromised"' };
      if (op.reason === 'compromised') {
        if (typeof op.compromised_since !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(op.compromised_since)) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' compromised requires strict RFC3339-Z compromised_since (§12.2)' };
      } else if (op.compromised_since !== undefined) return { error: 'E-MALFORMED', detail: 'entry ' + i + ' retired MUST NOT carry compromised_since' };
      active.delete(d.kid);
      revoked.set(d.kid, { reason: op.reason, compromised_since: op.compromised_since, at: e.state.time.generated_at });
      const h = history.get(d.kid); if (h) h.revoked_at = e.state.time.generated_at;
    }
    prevHash = contentHash(e);
  }
  return { validKeys: all, active, revoked, history, head: prevHash };            // validKeys = the all-ever BINDING map; head (§12.2a) = last entry content_hash (genesis if empty)
}

// ─── §12 HIGH name-authority resolution. STATELESS: the caller (ustate/engine) supplies the genesis +
//     key-log transcripts (retrieval is the stateful layer's job) and asserts no-fork from the witness (W1).
export function resolveAuthority(doc, { genesis, keylog = [], noForkConfirmed = false, corroborated = false, anchorTime, keylogFreshAsOf, keylogHeadAnchor, substrateVerify } = {}) {
  if (!genesis) return { strength: 'self-asserted', status: 'verified' };         // LIGHT — nothing to resolve
  if (genesis.state?.id?.domain_shard !== doc.state.id.domain_shard) return { error: 'E-GENESIS', detail: 'genesis domain mismatch' };
  const rk = resolveKeys(genesis, keylog);
  if (rk.error) return { error: rk.error, detail: rk.detail };
  const { validKeys, revoked } = rk;
  // §12.2a #40 KEY-LOG FRESHNESS (rc.28 audit fix) — "this key is still valid" is an authenticated NON-MEMBERSHIP
  // claim (no MORE RECENT revoking entry exists), the same class as no-fork (F.5a): a CACHED key-log proves only
  // "revoke ∉ my view", never "revoke does not exist". Freshness is EARNED, and — the audit catch — a raw
  // self-computed head hash proves NOTHING (the consumer trivially derives it from its own stale log; that was an
  // overclaim, the same class as the removed `mapInclusion:true`). So `attested` requires a VERIFIED anchor proof
  // for the head: `keylogHeadAnchor` (an inclusion proof) checked against the substrate — inclusion + final proves
  // the head IS the whole log at that anchor (independent non-membership). A `keylogFreshAsOf` timestamp from an
  // AUTHORITATIVE fetch ≥ the doc anchor ⇒ `fresh` (caller-basis, like air-gap no-fork). Else `unverified` — NOT
  // invalid (the cache is not "wrong"), but the consumer is TOLD its view may be stale (F.5b).
  let freshness = 'unverified';
  if (keylogHeadAnchor && typeof substrateVerify === 'function') {
    const ha = verifyAnchor(rk.head, keylogHeadAnchor, { substrateVerify });     // VERIFIED: head ∈ a substrate-final anchored root
    if (ha.inclusion && ha.time === 'anchored') freshness = 'attested';
  }
  if (freshness === 'unverified' && keylogFreshAsOf && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(keylogFreshAsOf) && (!anchorTime || keylogFreshAsOf >= anchorTime)) freshness = 'fresh';
  // rc.12: surface the ceremony-declared CAPACITY so callers can pass it as opts.capacity to verify()
  // once authority is established — the grant flows FROM resolution, never from a raw genesis.
  const gvCap = genesis.state?.data?.genesis?.value ?? {};
  const capacity = {
    ...(gvCap.max_partitions !== undefined ? { maxPartitions: Number(gvCap.max_partitions) } : {}),
    ...(gvCap.max_transcript_bytes !== undefined ? { maxTranscriptBytes: Number(gvCap.max_transcript_bytes) } : {}),
  };
  // authority is granted ONLY if the doc's key_id maps to the doc's ACTUAL signing pub (binding, not membership).
  if (validKeys.get(doc.state.id.key_id) !== doc.sig.pub)
    return { strength: 'self-asserted', status: 'verified', detail: 'doc key not bound in this key-log' };
  // §12.2 X1 — revocation window, decided against the anchor UPPER BOUND (U = anchorTime, from §11.2).
  const rev = revoked.get(doc.state.id.key_id);
  let suspect = false;
  if (rev) {
    const U = anchorTime;                                                         // proven "not later than"
    if (rev.reason === 'compromised') {
      if (!U) return { strength: 'self-asserted', status: 'revoked-untrusted', detail: 'compromised key + UNANCHORED doc → untrusted (X1)' };
      if (U >= rev.compromised_since) return { error: 'E-KEY', detail: 'signature not provably before compromise (U ≥ compromised_since, X1)' };
      suspect = true;                                                             // provably pre-compromise, but C is a publisher estimate
    } else if (rev.reason === 'retired' && U && U > rev.at)
      return { strength: 'self-asserted', status: 'expired', detail: 'signed after hygienic retirement (X1)' };
  }
  // §12.1a / formal model F.5a — the name is now KEY-BOUND (K_n: doc key ∈ resolved set). The no-fork STRENGTH
  // is a function of the BASIS of the non-membership evidence, and honesty forbids collapsing them:
  //   · INDEPENDENT non-membership — an anchored verifiable-map inclusion (prefix-uniqueness ⇒ ¬∃rival) OR an
  //     out-of-band caller assertion (air-gap) — ⇒ `authoritative`; the map/caller does not rely on the publisher.
  //   · the publisher's OWN served witness list shows no rival ⇒ `corroborated` — a real, bounded fact (membership
  //     of A in the published set), but NOT independent non-membership (the publisher can omit a rival, F.5a).
  //   · no no-fork evidence at all ⇒ DENIED (status unavailable → the name-authority tier is not reached, W1).
  const st2 = suspect ? 'suspect' : 'verified';
  // #69 A2 P1 — `authoritative` requires INDEPENDENT non-membership. Until the name-map VERIFIER exists (#42),
  // the ONLY authoritative path is an out-of-band caller assertion (noForkConfirmed = the caller takes
  // responsibility, reported `caller-asserted`). There is deliberately NO `mapInclusion:true` boolean — a raw
  // flag that is not a verified proof would be exactly the overclaim we removed. The map path returns here as
  // `authoritative` only once a real VerifiedMapReceipt is checked (future revision).
  if (noForkConfirmed) return { strength: 'authoritative', noFork: 'caller-asserted', status: st2, capacity, freshness };
  if (corroborated) return { strength: 'corroborated', noFork: 'served-list', status: st2, capacity, freshness };
  return { strength: 'corroborated', noFork: 'unconfirmed', status: 'unavailable', capacity, freshness,
    detail: 'no independent no-fork evidence; a served witness only corroborates (§12.1a F.5a) → authority pending, retry' };
}

// ─── TOP §11.2 anchor-proof: recompute the Merkle inclusion path content_hash→root (RFC 6962, domain-sep
//     ust:leaf/ust:node). The SUBSTRATE check (e.g. bitcoin-ots) is DELEGATED to opts.substrateVerify (needs
//     external Bitcoin access — the caller/ustate's job). Returns { inclusion, time, status, anchorTime? }.
export function verifyAnchor(contentHash, proof, opts = {}) {
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
  if (!sub.final) return { inclusion: true, time: 'unproven', status: 'verified', detail: 'substrate not final (e.g. <6 conf)' };
  // #71 — carry the substrate's ASSURANCE basis so TOP names its trust model honestly (an OTS plugin that
  // corroborates via independent explorers reports `explorer-corroborated`; an operator real-node/SPV plugin
  // would report `bitcoin-node`). TOP is earned either way; assurance says HOW, never inflating the tier.
  return { inclusion: true, time: 'anchored', status: 'verified', anchorTime: sub.time, ...(sub.assurance ? { assurance: sub.assurance } : {}) };
}

// #69 E1 — the ONE async entry: verify() is deliberately sync (portable, no await in the hot path), but the
// official substrate plugins are async. verifyAsync pre-resolves a doc.proof's substrate ONCE (await), then
// runs the sync verifier with the resolved receipt as a sync shim — so TOP is reachable with async plugins
// through a single contract, and verify() never has to become async. Everything else is identical to verify().
export async function verifyAsync(doc, opts = {}) {
  if (!doc?.proof || !opts.substrateVerify || opts.offline) return verify(doc, opts);
  let receipt; try { receipt = await opts.substrateVerify(doc.proof.anchor, doc.proof.root); } catch { receipt = null; }
  return verify(doc, { ...opts, substrateVerify: () => receipt });   // receipt (or null) → sync verifyAnchor path
}

// §3.1/F.5c FORK-CHOICE — canonical = anchor-included. One `ust_id` may have several candidate documents with
// DISTINCT content_hashes (the honest dual-writer race — main + failover both seal the slot — or an adversary
// offering two states). The CANONICAL document is the one whose content_hash is in the authority's anchored hour
// root; a consumer holding more than one resolves DETERMINISTICALLY from the chain, not from local arrival order
// (Proposition F.5c). Async because "anchor-included" means substrate-final, which verifyAsync awaits. Fail-safe:
// with no substrateVerify NO candidate is anchored ⇒ INDETERMINATE, never a guessed winner. Returns ONE verdict.
export async function forkChoice(candidates, opts = {}) {
  if (!Array.isArray(candidates) || candidates.length === 0)
    return { result: 'E-MALFORMED', detail: 'forkChoice needs a non-empty array of candidate documents' };
  const ids = new Set(candidates.map((c) => c?.state?.id?.ust_id));
  if (ids.size !== 1 || ids.has(undefined))                            // fork-choice is PER-SLOT — a mixed batch is a caller bug, not a fork
    return { result: 'E-MALFORMED', detail: 'forkChoice candidates must all share one ust_id (fork-choice is per-slot)' };
  const ust_id = [...ids][0];
  // verify each at its NATURAL tier (strip the floors — forkChoice does its own tier logic). A candidate is
  // ANCHOR-INCLUDED iff it VERIFIES and its content_hash sits in a substrate-final anchored root (time 'anchored').
  const vopts = { ...opts, requireAnchored: false, requireAuthoritative: false };
  const verds = await Promise.all(candidates.map(async (d) => ({ doc: d, v: await verifyAsync(d, vopts) })));
  const anchored = [], losers = [], invalid = [];
  for (const { doc, v } of verds) {
    if (!/^VALID:/.test(v.result || '')) { invalid.push({ result: v.result, detail: v.detail }); continue; }
    const rec = { doc, content_hash: v.content_hash, authority: doc?.state?.id?.domain_shard, tier: v.tier };
    (v.time?.strength === 'anchored' ? anchored : losers).push(rec);   // anchored = in the chain; else a valid non-anchored candidate
  }
  if (anchored.length === 0)                                           // nothing in Fₜ yet — undecidable at TOP, wait or resolve at HIGH
    return { result: 'INDETERMINATE', ust_id, reason: 'no anchor-included candidate', detail: 'no candidate is in a substrate-final anchored root yet — wait for the hour anchor or resolve at HIGH', losers: losers.length, invalid: invalid.length };
  // group anchored by AUTHORITY (domain_shard). A single authority with ≥2 DISTINCT anchored content_hashes for
  // one ust_id is EQUIVOCATION — it signed a root containing both = a non-repudiable, punishable fault (E-PREV).
  const byAuth = new Map();
  for (const a of anchored) { if (!byAuth.has(a.authority)) byAuth.set(a.authority, new Set()); byAuth.get(a.authority).add(a.content_hash); }
  for (const [authority, hashes] of byAuth) if (hashes.size >= 2)
    return { result: 'E-PREV', ust_id, authority, detail: `operator equivocation: authority ${authority} anchored ${hashes.size} distinct content_hashes for one ust_id`, content_hashes: [...hashes] };
  if (byAuth.size > 1)                                                 // distinct NAMES sharing a ust_id string — not a fork; canonicity is per-authority
    return { result: 'MULTI_AUTHORITY', ust_id, detail: 'distinct authorities anchored the same ust_id string — not a fork (canonicity is per-authority)', canonicals: anchored.map((a) => ({ authority: a.authority, content_hash: a.content_hash })) };
  const winner = anchored[0];                                         // one authority, one distinct anchored content_hash → THE canonical
  return { result: 'CANONICAL', ust_id, authority: winner.authority, content_hash: winner.content_hash, tier: winner.tier, canonical: winner.doc,
    losers: losers.map((l) => ({ content_hash: l.content_hash, tier: l.tier, reason: 'valid but not anchor-included for this slot (out-raced or unanchored)' })),
    ...(invalid.length ? { invalid } : {}) };
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
export function resolveCadence(genesis, cadenceLog = [], atTime, { keylog } = {}) {
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

// ─── TOP §11.3 completeness: a sequenced stream is prev-chained; first frame's prev = genesis content_hash
//     (M4); per-frame validity is verified too (X2 — completeness ≠ validity); duplicate ust_id / shared prev
//     = a fork ⇒ E-PREV (Y1). A covering checkpoint (M5) proves 'chain-consistent' (no-deletion); the open tail
//     is 'provisional'. 'complete' (no-omission, needs the signed-cadence grid, F.4) is a future rung (#69 C).
export function verifyStream(frames, { genesis, keylog, checkpoint, cadenceLog, requirePerFrameValid = true } = {}) {
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  let prevHash = genesis ? contentHash(genesis) : null;
  const authority = frames[0].state.id.domain_shard;                   // §11.3: a stream belongs to ONE authority
  const seenUstId = new Set(), seenPrev = new Set();
  let lastE = null;
  for (const [i, f] of frames.entries()) {
    if (requirePerFrameValid) { const v = verify(f, { context: 'data' }); if (!isValid(v)) return { error: 'E-SIG', detail: 'frame ' + i + ' invalid: ' + v.error }; } // X2
    if (f.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' domain_shard != stream authority (' + authority + ') — mixed-authority stream' };
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
    const a = checkpoint.state.data.checkpoint?.value;
    // NOTE (honest scope) — with a genesis, `frame_count === frames.length` + `first frame.prev === genesis`
    // means this verifies the ORIGIN-TO-CHECKPOINT PREFIX (the interval's `from` MUST be the stream's first
    // frame), not an arbitrary middle `[from,to]`. A true middle-range verdict needs a PREVIOUS checkpoint and a
    // cumulative-count DELTA (currentCount − previousCount === frames.length) — a tracked follow-up, not silently
    // assumed here. The `complete`/`chain-consistent` verdict below is over this prefix.
    if (!a || a.head !== prevHash || String(a.frame_count) !== String(frames.length))
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
      if (cF.cadence !== cT.cadence) return { complete: 'chain-consistent', head: prevHash, detail: 'interval crosses a cadence change — split it at the boundary; each side is `complete` under its own cadence (continuity)' };
      const grid = cF.cadence > 0 ? ustGrid(a.from, a.to, cF.cadence) : null;
      if (grid) {
        const covered = new Set();
        for (const f of frames) {
          const c = f.state.id.class;
          if (c === 'observation' || c === 'derivation' || (c === 'attestation' && f.state.data?.gap !== undefined)) covered.add(f.state.id.ust_id);
        }
        const hole = grid.find((g) => !covered.has(g));
        if (hole) return { complete: 'chain-consistent', head: prevHash, hole, detail: 'grid slot ' + hole + ' has no frame and no signed gap — chain intact, not complete (§11.3 C)' };
        return { complete: 'complete', head: prevHash, cadence: String(cF.cadence), grid_slots: String(grid.length) };
      }
    }
    return { complete: 'chain-consistent', head: prevHash };           // no signed cadence + interval → no-deletion ceiling
  }
  return { complete: 'provisional', head: prevHash };                  // no checkpoint → open tail (P5)
}

// ─── §S6/F7 — the CONFORMANCE boundary is raw bytes. `verify(JSON.parse(x))` can't satisfy §6 because JSON.parse
//     silently collapses duplicate keys. `verifyJson` scans the raw bytes for duplicate member names BEFORE
//     constructing the object, then verifies. Untrusted transcripts from the network/storage MUST enter here.
export function verifyJson(rawBytes, opts = {}) {
  // §13 TRANSPORT ADMISSION (rc.12) — distinct from the document verdict. Byte length is read
  // from the buffer BEFORE any decode/materialization (P0-2); an over-budget input is REFUSED as
  // INDETERMINATE('resource_limit') — verification never started, so it is never called INVALID.
  // The default input budget equals the protocol ABS; raw whitespace/base64 padding never flips a
  // verdict because the NORMATIVE size is measured on the canonical signed content inside verify.
  const isStr = typeof rawBytes === 'string';
  const byteLen = isStr ? Buffer.byteLength(rawBytes, 'utf8') : (rawBytes.byteLength ?? Buffer.from(rawBytes).length);
  const inputBudget = Number(opts.maxInputBytes ?? BOUNDS.sizeBytes);
  if (byteLen > inputBudget)
    return { result: 'INDETERMINATE', reason: 'resource_limit', detail: `raw input ${byteLen} B > input budget ${inputBudget} B — transport admission refused, verification not started` };
  // #75 P1-01 — STRICT UTF-8 on the raw path: Buffer.toString('utf8') maps invalid bytes to U+FFFD, so 0xFF and
  // the real 3-byte U+FFFD collapse to ONE string ⇒ distinct byte-strings, one verdict (breaks I4). fatal reject.
  let raw;
  if (isStr) raw = rawBytes;
  else { raw = strictUtf8(rawBytes); if (raw === null) return bad('E-CANON', 'raw input is not valid UTF-8 (invalid byte sequence)', { obligation: '§6 canonical UTF-8' }); }
  const dup = scanDuplicateKeys(raw);
  if (dup) return bad('E-CANON', dup);
  let obj; try { obj = JSON.parse(raw); } catch { return bad('E-MALFORMED', 'not valid JSON'); }
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
async function genesisAnchored(g, substrateVerify) {
  const proofs = Array.isArray(g.anchors) ? g.anchors : (g.anchor ? [g.anchor] : []);
  for (const proof of proofs) {
    const incl = verifyAnchor(g.content_hash, proof);   // inclusion only (no substrateVerify → sync)
    if (!incl.inclusion || !substrateVerify) continue;
    const sub = await substrateVerify(proof.anchor, proof.root);
    if (sub && sub.final) return true;                  // one independent substrate confirming is enough
  }
  return false;
}

export async function witnessNoFork(shard, genesisHash, { fetchImpl = fetch, substrateVerify } = {}) {
  let log;
  try {
    const r = await fetchImpl(`https://${shard}/.well-known/ust-witness`, { signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    log = JSON.parse(await r.text());
  } catch (e) { return { status: 'unreachable', detail: 'witness endpoint unreachable: ' + (e && e.message || e) }; }
  if (!log || log.domain_shard !== shard || !Array.isArray(log.genesis_log)) return { status: 'unreachable', detail: 'witness log malformed' };
  const active = log.genesis_log.filter((g) => g && !g.superseded_by && /^sha256:[0-9a-f]{64}$/.test(g.content_hash || ''));
  const anchoredActive = [];
  for (const g of active) if (await genesisAnchored(g, substrateVerify)) anchoredActive.push(g);
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
  return async (anchor, root) => {
    for (const v of list) { const r = await v(anchor, root); if (r != null) return r; }
    return null;   // no plugin claimed this substrate → verifyAnchor reports 'unavailable' (honest, not INVALID)
  };
}

export async function resolveByDiscovery(doc, opts = {}, { fetchImpl = fetch, substrateVerify } = {}) {
  const base = verify(doc, opts);
  const shard = doc?.state?.id?.domain_shard || '';
  const worth = !opts.offline && !opts.genesis &&
    (base.result === 'VALID:LIGHT' || (base.result === 'INDETERMINATE' && base.reason === 'unavailable'));
  if (!worth) return { verdict: base, resolution: null };
  if (!isPublicDnsShard(shard)) return { verdict: base, resolution: { skipped: 'domain_shard is not a public DNS name — discovery refused (SSRF guard)' } };
  let genesis, keylog = [], genesisHash, gRaw, kRaw;
  try {
    const get = async (p) => { const r = await fetchImpl(`https://${shard}${p}`, { signal: AbortSignal.timeout(10000), redirect: 'error' }); if (!r.ok) throw new Error(`HTTP ${r.status} at ${p}`); return r.text(); };
    gRaw = await get('/.well-known/ust-genesis');
    try { kRaw = await get('/.well-known/ust-keylog'); } catch { /* key-log not served — resolution may fail on key membership */ }
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
    if (!Array.isArray(k)) return { verdict: base, resolution: { error: 'E-MALFORMED: published key-log is not a JSON array' } };
    keylog = k;
  }

  // no-fork EVIDENCE (default): query the witness UNLESS the caller air-gap-asserts it or forbids the network.
  // #69 B / F.5a — the publisher's OWN served witness list is CORROBORATION, not independent non-membership: a
  // confirmed served list ⇒ `corroborated` (HIGH, honest), NOT `authoritative`. Only a caller air-gap assertion
  // (out-of-band responsibility) or a future anchored map-inclusion reaches `authoritative`. A fork ⇒ E-GENESIS.
  let witnessConfirmed = false, noFork = opts.noForkConfirmed ? 'caller-asserted (authoritative)' : 'unconfirmed';
  if (!opts.noForkConfirmed && !opts.offline) {
    const w = await witnessNoFork(shard, genesisHash, { fetchImpl, substrateVerify });
    if (w.status === 'fork') return { verdict: bad('E-GENESIS', w.detail), resolution: { publisher: shard, fork: true, detail: w.detail } };
    witnessConfirmed = w.status === 'confirmed';
    noFork = witnessConfirmed ? 'served-list (corroborated)' : 'HIGH pending — ' + w.detail;
  }
  const authOpts = { genesis, keylog, noForkConfirmed: opts.noForkConfirmed, corroborated: witnessConfirmed };
  const auth = resolveAuthority(doc, authOpts);
  if (auth.error) return { verdict: base, resolution: { error: auth.error + (auth.detail ? ' — ' + auth.detail : '') } };
  const verdict = await verifyAsync(doc, { ...opts, genesis, keylog, noForkConfirmed: opts.noForkConfirmed, corroborated: witnessConfirmed, capacity: auth.capacity, substrateVerify });   // #69 E1 — await the doc's own anchor substrate (TOP)
  return { verdict, resolution: { publisher: auth.publisher ?? shard, strength: auth.strength, capacity: auth.capacity, noFork, source: `https://${shard}/.well-known/ (§20.1 discovery + §12.1a witness)` } };
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
