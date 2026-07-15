// SPDX-License-Identifier: Apache-2.0
// ust-protocol — reference implementation of UST 1.0 (the official STATELESS base; the public verification lib) (REV 26), LIGHT floor first.
// §16: ONE version source — the conformance runner asserts spec/package/vectors all carry the same rc.
export const VERSION = { wire: '1.0', spec: '1.0.0-rc.35', revision: 49 };   // #75 P1-09: machine-readable {wire, spec, revision} — Status line & appendix must agree
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
  if (genesis?.state?.id?.class !== 'genesis' || !isValid(verify(genesis, { context: 'key' }))) return null;
  const gv = genesis?.state?.data?.genesis?.value; if (!gv) return null;
  const out = {};
  const ca = gv.checkpoint_authority;
  if (ca && ca.key_id && ca.pub && keyId(ca.pub) === ca.key_id) out.genesisAuthority = { key_id: ca.key_id, pub: ca.pub };
  const rec = gv.recovery;
  if (rec && rec.keys && typeof rec.keys === 'object') {
    const keys = {}; let ok = true;
    for (const [kid, pub] of Object.entries(rec.keys)) { if (typeof pub !== 'string' || keyId(pub) !== kid) ok = false; else keys[kid] = pub; }
    if (ok && Object.keys(keys).length) { out.recoveryKeys = keys; out.recoveryThreshold = Number(rec.threshold); }
  }
  return out;
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
      const a = verifyAnchor(ch, doc.proof, opts);
      if (!a.inclusion) return bad('E-ANCHOR', a.detail || 'embedded proof does not verify');
      // §14.6 N9 — a document cannot be generated AFTER the anchor that contains it (pinned RFC3339-Z compare as instants).
      if (a.time === 'anchored' && a.anchorTime && st.time.generated_at > a.anchorTime)
        return bad('E-ANCHOR', 'generated_at after the anchor time (N9: the document postdates its own anchor)');
      timeField = { strength: a.time, status: a.status, inclusion: true, ...(a.anchorTime ? { anchorTime: a.anchorTime } : {}), ...(a.assurance ? { assurance: a.assurance } : {}) };
    }
    const provenAnchorTime = timeField.strength === 'anchored' ? timeField.anchorTime : undefined;   // the proven upper bound U (else undefined)
    // step 3 — name authority (§14.3): HIGH resolves genesis+key-log; else a PINNED key (TOFU, §3.1) if the caller
    // supplies pinnedKeys — a key NOT in the pin set is INVALID (that is what pinning means); else self-asserted.
    // The PROVEN anchor time wins over any caller-supplied anchorTime (a caller cannot undercut it to evade X1).
    let identity;
    if (opts.genesis) identity = resolveAuthority(doc, { ...opts, anchorTime: provenAnchorTime ?? opts.anchorTime });
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
    const nameBound = verified && (nameAuthoritative || identity.strength === 'corroborated');
    // §3.1/§15 — TOP = authoritative identity + anchored time. HIGH = name-bound (corroborated or authoritative).
    // Stream COMPLETENESS is a separate RANGE verdict (verifyStream), never a single-document claim.
    // P1-03 — the tier is the SINGLE-SOURCE projection of the live AssuranceState (§F.5.0), not a second inline
    // formula: verify() builds ONE state from its resolved strengths and projects it once, so the lattice IS the machine.
    const assurance = assuranceState({ integrity: 'valid',
      identity: authoritative ? 'authoritative' : nameBound ? 'corroborated' : (identity.strength === 'pinned' ? 'pinned' : 'self-asserted'),
      freshness: identity.freshness || 'unverified',
      time: timeField.strength === 'anchored' ? 'anchored' : 'unproven',
      evidence: 'opaque' });
    const tier = projectTier(assurance);
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
  const history = new Map([[gKid, { pub: gPub, from: 0, authorized_at: genesis.state.time.generated_at, retired_at: null, revoked_at: null }]]);  // authorized_at = K_n(t) lower bound (F.5e)
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
      if (!history.has(d.kid)) history.set(d.kid, { pub: op.pub, from: i + 1, authorized_at: e.state.time.generated_at, retired_at: null, revoked_at: null });
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
// ─── §12.1a / P0-2 (audit) — NAME NO-FORK EVIDENCE. `authoritative` name-authority is EARNED, never self-declared:
//     it requires a TYPED, domain-separated no-fork claim signed by a witness the CONSUMER trusts (resolved against
//     `trustRoots`: issuer_id → pub | {pub[, trust_domain]}), bound to this domain + active genesis. The witness
//     CANNOT grant itself a trust domain — it is NOT in the signed claim; the consumer owns the issuer→domain map
//     (self-declared `trust_domain`/`issuer_id` inside a claim is rejected). A raw `noForkConfirmed` boolean is NOT
//     evidence: it is a distinct `consumer-override` (independently_verified:false), never silently `authoritative`
//     (the removed overclaim class — the same as `mapInclusion:true`). Independent-map `authoritative` stays #42.
export function noForkClaim({ domain_shard, active_genesis, map_checkpoint, map_sequence, valid_as_of }) {
  return { purpose: 'ust:name-no-fork', domain_shard, active_genesis,
    ...(map_checkpoint !== undefined ? { map_checkpoint } : {}),
    ...(map_sequence !== undefined ? { map_sequence } : {}),
    ...(valid_as_of !== undefined ? { valid_as_of } : {}) };
}
export function buildNoForkEvidence(fields, privKeyObj, issuerPubB64url) {
  const claim = noForkClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
// Verify an envelope { claim, issuer_id, sig } against the target domain + active genesis and consumer trustRoots.
// Independence is CONSUMER-OWNED: the issuer must be accepted in trustRoots; any trust_domain INSIDE the claim is
// rejected (that would be self-declared independence, P0-2). Returns { ok, witness_id, trust_domain, detail }.
export function verifyNoForkEvidence(evidence, { domain_shard, active_genesis, trustRoots = {} } = {}) {
  if (!evidence || typeof evidence !== 'object') return { ok: false, detail: 'no evidence' };
  const { claim, issuer_id, sig } = evidence;
  if (!claim || typeof claim !== 'object' || !issuer_id || !sig || !sig.sig || !sig.pub) return { ok: false, detail: 'malformed envelope' };
  if (claim.purpose !== 'ust:name-no-fork') return { ok: false, detail: 'wrong claim purpose' };
  if ('trust_domain' in claim || 'issuer_id' in claim) return { ok: false, detail: 'self-declared trust_domain/issuer inside claim (P0-2)' };
  if (claim.domain_shard !== domain_shard) return { ok: false, detail: 'claim domain_shard mismatch' };
  if (claim.active_genesis !== active_genesis) return { ok: false, detail: 'claim not bound to this active genesis' };
  const root = trustRoots[issuer_id];
  if (!root) return { ok: false, detail: 'issuer not in consumer trustRoots' };
  const rootPub = typeof root === 'string' ? root : root.pub;
  if (rootPub !== sig.pub || keyId(sig.pub) !== issuer_id) return { ok: false, detail: 'issuer_id/pub not the configured trust root' };
  if (strictB64url(sig.sig, 64) === null) return { ok: false, detail: 'sig not canonical b64url of a 64-byte Ed25519 signature' };
  if (!edVerifyStrict(sig.pub, canon(claim), sig.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true, witness_id: issuer_id, ...(typeof root === 'object' && root.trust_domain ? { trust_domain: root.trust_domain } : {}) };
}

// ─── #76 Phase A — CONNECTOR EVIDENCE ALGEBRA. A connector returns VERIFIED FACTS only (`VerifiedEvidence`), never
//     an assurance label — the CORE derives the class. Two algebra ops the checkpoint/authority layers consume:
//     `compareEvidenceOrder` (temporal order is a PROOF RELATION, not a comparison of RFC3339 fields) and
//     `quorumTrustDomains` (quorum counts DISTINCT CONSUMER-resolved trust domains, never connectors/URLs/mirrors and
//     never a self-declared `trust_domain`, P0-2). Faithful to "assurance is earned, capped by C, strengthened by quorum".
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
const EVIDENCE_CAPS = {
  'pow-header-chain':  ['order', 'time'],
  'transparency-log':  ['inclusion', 'consistency', 'order'],
  'authenticated-map': ['membership', 'non-membership'],
  'content-addressed': ['content-equality', 'availability'],
  'rfc3161-tsa':       ['time'],
};
export const evidenceCaps = (proof_kind) => EVIDENCE_CAPS[proof_kind] || [];
const temporalOrderCapable = (ev) => { const c = evidenceCaps(ev?.proof_kind); return c.includes('order') || c.includes('time'); };
// compareEvidenceOrder(a, b): is `a` PROVEN to be after `b`? Same-substrate position (block height / log index) is a
// total order; else an interval relation `a.not_before ≥ b.not_after` proves after, `b.not_before ≥ a.not_after`
// proves not-after. Two `not_after` upper bounds ALONE (or cross-substrate positions) prove nothing ⇒ `unproven`.
export function compareEvidenceOrder(a, b) {
  const fa = a?.facts ?? a ?? {}, fb = b?.facts ?? b ?? {};
  const decint = (s) => typeof s === 'string' && /^(0|[1-9]\d*)$/.test(s);            // P1-02: canonical unsigned decimal — total/fail-closed, never BigInt(NaN)
  if (fa.substrate && fb.substrate && fa.substrate === fb.substrate && decint(fa.position) && decint(fb.position))
    return BigInt(fa.position) > BigInt(fb.position) ? 'proven-after' : 'not-after';   // one total order ⇒ decidable
  const iso = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s);
  if (iso(fa.not_before) && iso(fb.not_after) && fa.not_before >= fb.not_after) return 'proven-after';
  if (iso(fb.not_before) && iso(fa.not_after) && fb.not_before >= fa.not_after) return 'not-after';
  return 'unproven';                                                                   // two upper bounds, or cross-substrate
}
// quorumTrustDomains(list, { domains, threshold }): count DISTINCT CONSUMER-resolved trust domains. `domains` maps a
// verified source_id → trustDomain (consumer config). Sources absent from `domains` are NOT admitted; a `trust_domain`
// carried on the evidence itself is ignored. Multiple sources in one domain count once.
export function quorumTrustDomains(list, { domains = {}, threshold } = {}) {
  const seen = new Set();
  for (const e of Array.isArray(list) ? list : []) {
    const sid = e?.source_id ?? e?.facts?.source_id;
    const dom = sid !== undefined ? domains[sid] : undefined;                          // consumer-resolved ONLY
    if (dom !== undefined) seen.add(dom);
  }
  const arr = [...seen];
  return { count: arr.length, domains: arr, ...(threshold !== undefined ? { met: arr.length >= threshold } : {}) };
}

// ─── UST-0ol Phase 1 — the TRUST BOUNDARY (I_C). A map root is admissible ONLY if the CONSUMER independently holds
//     it (trust.mapRoots — anchored/pinned out-of-band); it is NEVER taken from the same bundle as the proof. Absence
//     of admission ⇒ no strong rung (fail-safe). This is the separation of trust-configuration from evidence.
const mapRootAdmitted = (trust, root) => Array.isArray(trust?.mapRoots) && trust.mapRoots.includes(root);
// P0-1 (rc.35 audit) — a module-private capability set. Only resolveByDiscovery (which actually ran witnessNoFork)
// mints a servedNoFork object into it; a transcript caller cannot add to it, so a plain look-alike object earns nothing.
const VERIFIED_SERVED = new WeakSet();
export function resolveAuthority(doc, { genesis, keylog = [], noForkConfirmed = false, noForkEvidence, nameMap, trustRoots, corroborated = false, servedNoFork, anchorTime, keylogFreshAsOf, keylogHeadAnchor, substrateVerify, trust } = {}) {
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
  // `keylogFreshAsOf` from an AUTHORITATIVE fetch ≥ the doc anchor ⇒ `fresh`; else `unverified` — TOLD, never forged.
  let freshness = 'unverified';
  if (keylogFreshAsOf && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(keylogFreshAsOf) && (!anchorTime || keylogFreshAsOf >= anchorTime)) freshness = 'fresh';
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
  // §12.2/#75 ROOT 1 — K_n(t) LOWER bound: a document cannot be PROVEN-anchored BEFORE its signing key was
  // authorized. With a proven upper bound U < the key's authorized_at, the key did not exist yet ⇒ premature
  // (self-asserted, not authoritative). Only decidable WITH a proven anchor time (else no U to compare).
  const hk = history.get(doc.state.id.key_id);
  if (anchorTime && hk?.authorized_at && anchorTime < hk.authorized_at)
    return { strength: 'self-asserted', status: 'premature', detail: 'document anchored before its signing key was authorized (K_n(t) lower bound §12.2)' };
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
    return { result: 'E-PREV', ust_id, authority, detail: `operator equivocation: authority ${authority} anchored ${hashes.size} distinct content_hashes for one ust_id`, content_hashes: [...hashes] };
  if (byAuth.size > 1)                                                 // distinct NAMES sharing a ust_id string — not a fork; canonicity is per-authority
    return { result: 'MULTI_AUTHORITY', ust_id, detail: 'distinct authorities anchored the same ust_id string — not a fork (canonicity is per-authority)', canonicals: anchored.map((a) => ({ authority: a.authority, content_hash: a.content_hash })) };
  const winner = anchored[0];                                         // one authority, one distinct anchored content_hash → THE canonical
  return { result: 'CANONICAL', ust_id, authority: winner.authority, content_hash: winner.content_hash, tier: winner.tier, canonical: winner.doc,
    losers: losers.map((l) => ({ content_hash: l.content_hash, tier: l.tier, reason: 'valid but not anchor-included for this slot (out-raced or unanchored)' })),
    ...(unauthenticated.length ? { unauthenticated } : {}),           // key-unbound impostors under a claimed name — recorded, never canonical
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
  const s = cp?.sig; if (!s || s.alg !== 'Ed25519' || !s.pub || !s.sig) return { ok: false, detail: 'malformed sig' };
  if (s.key_id !== expectedKeyId || s.pub !== expectedPub) return { ok: false, detail: 'signer is not the authorized checkpoint authority' };
  if (keyId(s.pub) !== s.key_id) return { ok: false, detail: 'sig.key_id ≠ keyId(pub)' };
  if (strictB64url(s.sig, 64) === null) return { ok: false, detail: 'sig not canonical b64url of a 64-byte Ed25519 signature' };
  if (!edVerifyStrict(s.pub, canon({ purpose: 'ust:authority-checkpoint-signature', body: cp.body }), s.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true };
}
// Verify a chain of authority checkpoints. Root the FIRST element's signer in the genesis-authorized checkpoint key
// (`genesisAuthority = {key_id, pub}`, the reference profile's dedicated key) OR a pinned prior checkpoint
// (`pinnedPrior = {checkpoint_id, authority:{key_id, pub}, sequence}`). No root ⇒ INDETERMINATE(authority_unresolved).
// ─── #76 §1.7 CHECKPOINT RECOVERY — a genesis-authorized N-of-M multisig that re-authorizes the checkpoint authority
//     after key loss WITHOUT bypassing checkpoint validation. Role-separated from data/checkpoint keys; the recovery
//     set is genesis-fixed (immutable within the epoch). A DORMANT emergency mechanism, NOT a normal rotation: it
//     authorizes ONLY the next checkpoint's replacement key, bound to (domain, epoch, last_accepted_checkpoint, seq).
export function checkpointRecoveryClaim({ domain_shard, genesis_epoch, last_accepted_checkpoint, replacement_key_id, replacement_pub, reason, effective_sequence }) {
  return { purpose: 'ust:checkpoint-authority-recovery', domain_shard, genesis_epoch, last_accepted_checkpoint,
    replacement_authority: { key_id: replacement_key_id, pub: replacement_pub }, reason, effective_sequence: String(effective_sequence) };
}
export function buildRecoveryStatement(fields, privKeyObj, issuerPubB64url) {
  const claim = checkpointRecoveryClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export function verifyCheckpointRecovery(statements, { domain_shard, genesis_epoch, last_accepted_checkpoint, effective_sequence, recoveryKeys = {}, threshold = 2 } = {}) {
  if (!Array.isArray(statements) || statements.length === 0) return { recovered: false, detail: 'no recovery statements' };
  const nKeys = Object.keys(recoveryKeys).length;
  if (!(Number.isInteger(threshold) && threshold >= 1 && threshold <= nKeys))          // P0-05: 1 ≤ threshold ≤ |recoveryKeys| (threshold=0 is not authorization)
    return { recovered: false, detail: 'invalid recovery threshold ' + threshold + ' (must be 1..' + nKeys + ')' };
  // UST-0ol Phase 4 — GROUP distinct valid signers by the canonical claim they signed; NEVER lock onto the first
  // claim seen. Threshold authorization does NOT provide anti-equivocation: with one Byzantine signer, two conflicting
  // replacements can each reach threshold. If more than ONE distinct replacement reaches threshold ⇒ CONFLICT (reject,
  // order-independent). A single equivocating recovery must not silently pick a winner by array position (P0-05).
  const byClaim = new Map();                                                            // canon(claim) → { replacement, signers:Set }
  for (const s of statements) {
    const { claim, issuer_id, sig } = s || {};
    if (!claim || !issuer_id || !sig || !sig.sig || !sig.pub) continue;
    if (claim.purpose !== 'ust:checkpoint-authority-recovery') continue;
    if (claim.domain_shard !== domain_shard || claim.genesis_epoch !== genesis_epoch || claim.last_accepted_checkpoint !== last_accepted_checkpoint) continue;
    if (String(claim.effective_sequence) !== String(effective_sequence)) continue;      // authorizes ONLY the next checkpoint
    const ra = claim.replacement_authority;
    if (!ra || !ra.key_id || !ra.pub || keyId(ra.pub) !== ra.key_id) continue;          // replacement well-formed (key_id = keyId(pub))
    const cc = canon(claim);
    const pub = recoveryKeys[issuer_id];
    if (!pub || pub !== sig.pub || keyId(sig.pub) !== issuer_id) continue;              // genesis-authorized recovery signer only
    if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, cc, sig.sig)) continue;
    let g = byClaim.get(cc); if (!g) { g = { replacement: ra, signers: new Set() }; byClaim.set(cc, g); }
    g.signers.add(issuer_id);                                                           // one signer counts once per claim
  }
  const reached = [...byClaim.values()].filter((g) => g.signers.size >= threshold);
  if (reached.length === 0) return { recovered: false, detail: 'recovery quorum not met (no claim reached ' + threshold + ' distinct signers)' };
  if (reached.length > 1) return { recovered: false, conflict: true, detail: 'recovery equivocation: ' + reached.length + ' conflicting replacements each reached threshold' };
  return { recovered: true, replacement_authority: reached[0].replacement, threshold: String(threshold), signers: [...reached[0].signers] };
}

// ─── #76 (audit-8) GENESIS-EPOCH TRANSITION — a new genesis epoch must NOT silently reset the authority chain. The
//     A→B transition is a typed statement SIGNED BY EPOCH A's checkpoint authority, binding A's final checkpoint and
//     naming epoch B's initial checkpoint authority + initial sequence. Epoch B's C₀ then binds that final checkpoint.
export function epochTransitionClaim({ domain_shard, from_genesis_epoch, from_final_checkpoint, to_genesis_epoch, to_key_id, to_pub, to_initial_sequence = '0' }) {
  return { purpose: 'ust:genesis-epoch-transition', domain_shard, from_genesis_epoch, from_final_checkpoint, to_genesis_epoch,
    to_checkpoint_authority: { key_id: to_key_id, pub: to_pub }, to_initial_sequence: String(to_initial_sequence) };
}
export function buildEpochTransition(fields, privKeyObj, issuerPubB64url) {
  const claim = epochTransitionClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export function verifyEpochTransition(statement, { domain_shard, from_genesis_epoch, from_final_checkpoint, fromAuthority } = {}) {
  const { claim, sig } = statement || {};
  if (!claim || !sig || !sig.sig || !sig.pub || !fromAuthority) return { ok: false, detail: 'malformed transition or no from-authority' };
  if (claim.purpose !== 'ust:genesis-epoch-transition') return { ok: false, detail: 'wrong purpose' };
  if (claim.domain_shard !== domain_shard || claim.from_genesis_epoch !== from_genesis_epoch || claim.from_final_checkpoint !== from_final_checkpoint) return { ok: false, detail: 'transition not bound to this (domain, from-epoch, from-final-checkpoint)' };
  const ta = claim.to_checkpoint_authority;
  if (!ta || !ta.key_id || !ta.pub || keyId(ta.pub) !== ta.key_id) return { ok: false, detail: 'to_checkpoint_authority malformed' };
  if (sig.key_id !== fromAuthority.key_id || sig.pub !== fromAuthority.pub || keyId(sig.pub) !== sig.key_id) return { ok: false, detail: 'transition not signed by epoch A checkpoint authority' };
  if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, canon(claim), sig.sig)) return { ok: false, detail: 'Ed25519 verify failed' };
  return { ok: true, to_genesis_epoch: claim.to_genesis_epoch, to_checkpoint_authority: ta, to_initial_sequence: claim.to_initial_sequence };
}

const CP_BODY_KEYS = new Set(['version', 'purpose', 'domain_shard', 'genesis_epoch', 'sequence', 'previous_checkpoint', 'previous_epoch_final_checkpoint', 'active_genesis', 'checkpoint_authority', 'keylog']);
const CP_CA_KEYS = new Set(['current_key_id', 'next_key_id', 'next_pub', 'effective_sequence']);
const isHashStr = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
export function verifyAuthorityCheckpointChain(chain, { genesis, genesisAuthority, pinnedPrior, recoveries, recoveryKeys, recoveryThreshold, epochTransitions } = {}) {
  if (!Array.isArray(chain) || chain.length === 0) return { error: 'E-MALFORMED', detail: 'empty checkpoint chain' };
  // P1-04 — prefer roots RESOLVED from the signed genesis; a raw genesisAuthority is a consumer PIN, reported as such.
  let authority_root = 'consumer-pin';
  if (genesis) { const gr = resolveCheckpointRoots(genesis); if (gr?.genesisAuthority) { genesisAuthority = gr.genesisAuthority; authority_root = 'genesis'; } if (gr?.recoveryKeys && recoveryKeys === undefined) { recoveryKeys = gr.recoveryKeys; recoveryThreshold = recoveryThreshold ?? gr.recoveryThreshold; } }
  if (!genesisAuthority && !pinnedPrior) return { result: 'INDETERMINATE', reason: 'authority_unresolved', detail: 'no genesis-rooted or pinned-prior checkpoint authority to resolve the first signer' };
  let prev = pinnedPrior ? { id: pinnedPrior.checkpoint_id, authority: pinnedPrior.authority, sequence: pinnedPrior.sequence, body: null } : null;
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
      expected = { key_id: genesisAuthority.key_id, pub: genesisAuthority.pub };       // C₀ rooted in the genesis-authorized key
    } else if (prev.body && b.genesis_epoch !== prev.body.genesis_epoch) {
      // GENESIS-EPOCH TRANSITION — a new epoch must NOT silently reset: it needs an authenticated A→B transition
      // signed by epoch A's authority (prev.authority), binding A's final checkpoint (prev.id). Same domain.
      if (b.domain_shard !== prev.body.domain_shard) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'domain_shard changes within the chain' };
      const et = epochTransitions && epochTransitions[b.genesis_epoch] ? verifyEpochTransition(epochTransitions[b.genesis_epoch], { domain_shard: b.domain_shard, from_genesis_epoch: prev.body.genesis_epoch, from_final_checkpoint: prev.id, fromAuthority: prev.authority }) : { ok: false };
      if (!et.ok || et.to_genesis_epoch !== b.genesis_epoch) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'genesis_epoch changes without an authenticated epoch transition (no silent reset)' };
      if (b.previous_epoch_final_checkpoint !== prev.id) return { result: 'INVALID', error: 'E-PREV', detail: 'epoch-initial checkpoint does not bind the prior-epoch final checkpoint' };
      if (b.sequence !== String(et.to_initial_sequence)) return { result: 'INVALID', error: 'E-SEQ', detail: 'epoch-initial sequence ≠ the transition to_initial_sequence' };
      expected = { key_id: et.to_checkpoint_authority.key_id, pub: et.to_checkpoint_authority.pub };
    } else {
      const pca = prev.body ? prev.body.checkpoint_authority : null;                    // the authority Cₙ₋₁ committed for THIS sequence, else unchanged
      expected = (pca && pca.next_key_id !== undefined && pca.effective_sequence === b.sequence) ? { key_id: pca.next_key_id, pub: pca.next_pub } : prev.authority;
      if (b.previous_checkpoint !== prev.id) return { result: 'INVALID', error: 'E-PREV', detail: 'previous_checkpoint ≠ id of the prior accepted checkpoint' };
      if (b.sequence !== String(BigInt(prev.sequence) + 1n)) return { result: 'INVALID', error: 'E-SEQ', detail: 'sequence is not prev+1' };
      if (b.domain_shard !== prev.body?.domain_shard && prev.body) return { result: 'INVALID', error: 'E-MALFORMED', detail: 'domain_shard changes within the chain' };
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
      if (keyId(ca.next_pub) !== ca.next_key_id) return { result: 'INVALID', error: 'E-KEY', detail: 'keyId(next_pub) ≠ next_key_id' };
      if (ca.effective_sequence !== String(BigInt(b.sequence) + 1n)) return { result: 'INVALID', error: 'E-SEQ', detail: 'effective_sequence ≠ sequence+1' };
    }
    prev = { id: authorityCheckpointId(cp), authority: matched, sequence: b.sequence, body: b };
  }
  const lb = chain[chain.length - 1].body, lca = lb.checkpoint_authority || {};
  const activeAuthority = (lca.next_key_id !== undefined) ? { key_id: lca.next_key_id, pub: lca.next_pub, effective_sequence: lca.effective_sequence } : prev.authority;
  return { result: 'VALID', head: prev.id, length: String(chain.length), sequence: lb.sequence, active_genesis: lb.active_genesis, keylog: lb.keylog, activeAuthority, authority_root };
}

// ─── #76 Phase C — CHECKPOINT UNIQUENESS (independent anti-equivocation). `attested` needs a `¬∃ rival at
//     (domain, genesis_epoch, sequence)` proof the PUBLISHER does not control: an `accepted-witness-quorum` (≥
//     threshold DISTINCT consumer-resolved trust domains signing the BYTE-IDENTICAL typed uniqueness claim) — or the
//     `authenticated-map-uniqueness` map path (#42). Independence is CONSUMER-owned (issuer→domain), never
//     self-declared; a bare-observation co-sign is corroboration, not uniqueness (wrong purpose ⇒ not admitted).
export function checkpointUniquenessClaim({ domain_shard, genesis_epoch, sequence, checkpoint, observed_map_root, as_of }) {
  return { purpose: 'ust:checkpoint-uniqueness-attestation', domain_shard, genesis_epoch, sequence: String(sequence), checkpoint,
    ...(observed_map_root !== undefined ? { observed_map_root } : {}), ...(as_of !== undefined ? { as_of } : {}) };
}
export function buildUniquenessAttestation(fields, privKeyObj, issuerPubB64url) {
  const claim = checkpointUniquenessClaim(fields);
  const sig = edSign(null, Buffer.from(canon(claim), 'utf8'), privKeyObj).toString('base64url');
  return { claim, issuer_id: keyId(issuerPubB64url), sig: { alg: 'Ed25519', key_id: keyId(issuerPubB64url), pub: issuerPubB64url, sig } };
}
export function verifyCheckpointUniqueness(attestations, { domain_shard, genesis_epoch, sequence, checkpoint, trustRoots = {}, domains = {}, threshold = 2 } = {}) {
  if (!Array.isArray(attestations) || attestations.length === 0) return { attested: false, detail: 'no attestations' };
  // P0-4 (rc.35 audit) — a POSITIVE INTEGER quorum. threshold ≤ 0 made `0 distinct domains ≥ 0` earn `attested` from an
  // EMPTY witness set (the strongest freshness rung for free). No admissible-domain cap needed: the seenDomains ≥ threshold
  // test already bounds the upper side (you cannot meet a threshold higher than the distinct domains actually present).
  if (!Number.isInteger(threshold) || threshold < 1) return { attested: false, detail: 'threshold must be a positive integer (got ' + threshold + ')' };
  let ref = null; const seenDomains = new Set(), seenIssuers = new Set(), witnesses = [];
  for (const a of attestations) {
   // P1 (rc.35 audit) — a malformed remote witness statement (e.g. a non-string leaf → canon throws E-CANON) must be
   // SKIPPED, never propagate a throw through deriveCheckpointFreshness (a denial-of-verifiability). Total, fail-closed.
   try {
    const { claim, issuer_id, sig } = a || {};
    if (!claim || !issuer_id || !sig || !sig.sig || !sig.pub) continue;
    if (claim.purpose !== 'ust:checkpoint-uniqueness-attestation') continue;            // uniqueness, not bare observation
    if ('trust_domain' in claim || 'issuer_id' in claim) continue;                      // self-declared independence rejected (P0-2)
    if (claim.domain_shard !== domain_shard || claim.genesis_epoch !== genesis_epoch || String(claim.sequence) !== String(sequence) || claim.checkpoint !== checkpoint) continue;
    const cc = canon(claim);
    if (ref === null) ref = cc; else if (cc !== ref) continue;                          // all witnesses sign the BYTE-IDENTICAL claim
    const root = trustRoots[issuer_id]; const pub = typeof root === 'string' ? root : root?.pub;
    if (!pub || pub !== sig.pub || keyId(sig.pub) !== issuer_id) continue;              // consumer-accepted issuer only
    if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, cc, sig.sig)) continue;
    if (seenIssuers.has(issuer_id)) continue;                                           // one issuer counts once
    const dom = domains[issuer_id]; if (dom === undefined) continue;                    // consumer-resolved trust domain, else unadmitted
    seenIssuers.add(issuer_id); seenDomains.add(dom); witnesses.push(issuer_id);
   } catch { continue; }
  }
  return seenDomains.size >= threshold
    ? { attested: true, basis: 'accepted-witness-quorum', threshold: String(threshold), accepted_witnesses: witnesses, trust_domains: [...seenDomains] }
    : { attested: false, detail: 'quorum not met: ' + seenDomains.size + ' distinct trust domains < ' + threshold };
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
  if (!proof || !Array.isArray(proof.siblings) || proof.siblings.length !== SMT_DEPTH) return false;
  const hex = smtHex(key);
  let node = value === null ? smtDefaults[SMT_DEPTH] : smtLeaf(key, value);
  for (let d = SMT_DEPTH - 1; d >= 0; d--) node = smtBit(hex, d) === 0 ? H('ust:smt-node', node + '|' + proof.siblings[d]) : H('ust:smt-node', proof.siblings[d] + '|' + node);
  return node === root;
}
// TYPED, domain-separated key/value spaces — one map may serve both predicates with NO collision (a checkpoint proof
// is not a name proof). Exported so operators/verifiers build leaves without recomputing the hashing.
export const checkpointMapLeaf = ({ domain_shard, genesis_epoch, sequence, checkpoint }) => ({ key: H('ust:checkpoint-map-key', canon({ domain_shard, genesis_epoch, sequence: String(sequence) })), value: H('ust:checkpoint-map-value', canon({ checkpoint })) });
export const nameMapLeaf = ({ domain_shard, active_genesis }) => ({ key: H('ust:name-map-key', canon({ domain_shard })), value: H('ust:name-map-value', canon({ active_genesis })) });
// TWO distinct TYPED predicates over the SAME map infra — never a generic `verifyMapInclusion(flag)`:
export function verifyCheckpointMapUniqueness(proof, { domain_shard, genesis_epoch, sequence, checkpoint, mapRoot } = {}) {
  const { key, value } = checkpointMapLeaf({ domain_shard, genesis_epoch, sequence, checkpoint });
  if (smtVerify(mapRoot, key, value, proof)) return { attested: true, basis: 'authenticated-map-uniqueness', map_root: mapRoot };
  if (smtVerify(mapRoot, key, null, proof)) return { attested: false, absent: true, detail: 'no checkpoint bound at (domain, genesis_epoch, sequence) under mapRoot (proven non-membership)' };
  return { attested: false, detail: 'checkpoint not the unique value at (domain, genesis_epoch, sequence) under mapRoot (a rival value is bound)' };
}
export function verifyActiveGenesisUniqueness(proof, { domain_shard, active_genesis, mapRoot } = {}) {
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
export function verifyKeylogTerminality({ root, length, head } = {}, proof = {}) {
  let L; try { L = BigInt(length); } catch { return { terminal: false, detail: 'length is not an integer' }; }
  if (L < 1n) return { terminal: false, detail: 'empty key-log' };
  const hp = proof.headProof || proof;
  if (!hp || !Array.isArray(hp.siblings) || String(hp.index) !== String(L - 1n)) return { terminal: false, detail: 'head proof missing or index ≠ length-1' };
  // P0-5 (rc.35 audit) — the proof depth MUST be EXACTLY ceil(log2(width)), width = next-pow2(L). An UNDER-DEPTH proof
  // (fewer siblings than the tree has levels) recomputes the root over a SMALLER tree; with an attacker-chosen `root`
  // it FORGES terminality for a key-log that actually has successors — re-opening the P0-02 false-terminality class.
  let width = 1n, depth = 0n; while (width < L) { width <<= 1n; depth++; }
  if (BigInt(hp.siblings.length) !== depth) return { terminal: false, detail: 'proof depth ' + hp.siblings.length + ' ≠ ceil(log2(width))=' + depth + ' for length ' + L + ' (under/over-depth proof)' };
  let node = keylogLeaf(head), i = L - 1n;
  for (let d = 0; d < hp.siblings.length; d++) {
    const sib = hp.siblings[d], weAreLeft = (i & 1n) === 0n;                            // LEFT child ⇒ sibling is to the RIGHT (higher indices) ⇒ MUST be an empty subtree
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
export function deriveCheckpointFreshness(chain, { genesis, genesisAuthority, pinnedPrior, target, commitment, terminality, uniqueness, trust } = {}) {
  const chn = verifyAuthorityCheckpointChain(chain, { genesis, genesisAuthority, pinnedPrior });
  if (chn.result !== 'VALID') return chn.result === 'INDETERMINATE' ? chn
    : { result: 'INVALID', error: chn.error, detail: 'checkpoint chain not authorized: ' + (chn.detail || chn.error), keylog_freshness: 'unverified' };
  const b = chain[chain.length - 1].body, headId = chn.head;
  if (target) {                                                                         // bind to the target's authority epoch + domain
    if (target.active_genesis !== undefined && b.active_genesis !== target.active_genesis) return { result: 'INVALID', error: 'E-GENESIS', detail: 'checkpoint active_genesis ≠ target', keylog_freshness: 'unverified' };
    if (target.domain_shard !== undefined && b.domain_shard !== target.domain_shard) return { result: 'INVALID', error: 'E-GENESIS', detail: 'checkpoint domain ≠ target', keylog_freshness: 'unverified' };
  }
  const term = verifyKeylogTerminality({ root: b.keylog?.root, length: b.keylog?.length, head: b.keylog?.head }, terminality || {});  // head = LAST entry (position L-1) AND no successor at L
  if (!term.terminal) return { result: 'INDETERMINATE', reason: 'terminality_unproven', detail: term.detail || 'key-log head terminality not proven', keylog_freshness: 'unverified' };
  if (!commitment || commitment.subject !== headId)                                     // external commitment must be VERIFIED evidence BOUND to this checkpoint id
    return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'no external-commitment evidence bound to the checkpoint id', keylog_freshness: 'unverified' };
  if (!target || !target.anchor) return { result: 'INDETERMINATE', reason: 'unavailable', detail: 'no target anchor evidence to order against', keylog_freshness: 'unverified' };
  if (!temporalOrderCapable(commitment) || !temporalOrderCapable(target.anchor))       // Phase 2: proof_kind must ESTABLISH temporal order (content-addressed / map / opaque cannot)
    return { result: 'INDETERMINATE', reason: 'order_unproven', detail: 'commitment/anchor evidence class does not establish temporal order (capability check: ' + evidenceClass(commitment?.proof_kind) + ')', keylog_freshness: 'unverified' };
  const ord = compareEvidenceOrder(commitment, target.anchor);                          // F.5g proof relation, NOT a timestamp compare
  if (ord !== 'proven-after') return { result: 'INDETERMINATE', reason: 'order_unproven', detail: 'checkpoint commitment not proven-after the target (' + ord + ')', keylog_freshness: 'unverified' };
  // corroborated holds. Phase C — an INDEPENDENT anti-equivocation proof over THIS checkpoint upgrades to `attested`.
  // Uniqueness on an UNAUTHORIZED/UNBOUND checkpoint never reaches here (the corroborated conjunction above already
  // failed) ⇒ `attested ⇒ corroborated ∧ independent-uniqueness`; uniqueness alone never earns `attested`.
  if (uniqueness) {
    let uq = null;                                                                       // two INDEPENDENT bases for the SAME predicate
    if (uniqueness.map && mapRootAdmitted(trust, uniqueness.map.mapRoot)) uq = verifyCheckpointMapUniqueness(uniqueness.map.proof, { domain_shard: b.domain_shard, genesis_epoch: b.genesis_epoch, sequence: b.sequence, checkpoint: headId, mapRoot: uniqueness.map.mapRoot });   // Phase 1: map root must be consumer-admitted (trust.mapRoots)
    if ((!uq || !uq.attested) && uniqueness.attestations) uq = verifyCheckpointUniqueness(uniqueness.attestations, { domain_shard: b.domain_shard, genesis_epoch: b.genesis_epoch, sequence: b.sequence, checkpoint: headId, trustRoots: uniqueness.trustRoots, domains: uniqueness.domains, threshold: uniqueness.threshold });
    if (uq && uq.attested) return { result: 'VALID', keylog_freshness: 'attested', basis: uq.basis, anti_equivocation: 'attested',
      ...(uq.threshold ? { threshold: uq.threshold, accepted_witnesses: uq.accepted_witnesses, trust_domains: uq.trust_domains } : {}),
      ...(uq.map_root ? { map_root: uq.map_root } : {}), head: headId, sequence: b.sequence, active_genesis: b.active_genesis };
  }
  return { result: 'VALID', keylog_freshness: 'corroborated', basis: 'publisher-checkpoint', anti_equivocation: 'unverified',  // ceiling without independent uniqueness
    head: headId, sequence: b.sequence, active_genesis: b.active_genesis };
}

// ─── #78 ASSURANCE PRODUCT-LATTICE (formal-model F.5 revision, CODE realization — the math must pass through code +
//     vectors + guard before it ships). The linear tier LIGHT ⊆ HIGH ⊆ TOP is ONE policy projection of a PRODUCT of
//     FIVE orthogonal, independently-strengthening information axes — identity and freshness strengthen SEPARATELY
//     (F.5 gap 1/3, `A_id` ⊥ `A_fresh`). Each axis is a total order (a rank); AssuranceState is their product under
//     the componentwise (partial) order — a LATTICE: meet = per-axis min, join = per-axis max. `projectTier` reads
//     ONLY identity+time (the classic tier); freshness+evidence ride alongside, never folded in.
export const ASSURANCE_AXES = {
  integrity: ['invalid', 'valid'],                                            // the §14 floor (canon/hash/sig) — the Integrity axis
  identity:  ['self-asserted', 'pinned', 'corroborated', 'authoritative'],    // A_id: name-binding + active-genesis uniqueness (§12.1a)
  freshness: ['unverified', 'fresh', 'corroborated', 'attested'],             // A_fresh: terminality + order + checkpoint uniqueness (§12.2a / §12.3.5)
  time:      ['unproven', 'anchored'],                                        // Fₜ: the anchor filtration (§11.2)
  evidence:  ['opaque', 'inclusion', 'inclusion+order', 'inclusion+order+time'],  // EvidenceBasis: Variant A — only `inclusion+order+time` may enter Fₜ (§12.3.5)
};
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
export const assuranceLE = (a, b) => AXES.every((ax) => axisLE(ax, a[ax], b[ax]));
const axisMin = (axis, a, b) => (axisRank(axis, a) <= axisRank(axis, b) ? a : b);
const axisMax = (axis, a, b) => (axisRank(axis, a) >= axisRank(axis, b) ? a : b);
export const meetAssurance = (a, b) => Object.fromEntries(AXES.map((ax) => [ax, axisMin(ax, a[ax], b[ax])]));
export const joinAssurance = (a, b) => Object.fromEntries(AXES.map((ax) => [ax, axisMax(ax, a[ax], b[ax])]));
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

// ─── #oy8 CANONICAL REGISTRY — the SINGLE SOURCE OF TRUTH for the protocol's machine-checkable STRING SETS. The spec's
//     registry blocks (§15/§17) are GENERATED from this (tools/gen-spec-registry.mjs), and tools/spec-code-sync.mjs
//     asserts the code's ACTUAL literal usage (H/Hbytes domains, `purpose:` strings, thrown `E-` codes) equals these
//     sets — so spec prose, this registry, and code usage cannot silently diverge (the spec↔code drift seam). Enums
//     that already exist as code (ASSURANCE_AXES, TIER_RANK) are REFERENCED, never re-declared.
export const REGISTRY = {
  // hash domain tags (§7/§17) — the tag passed to H()/Hbytes(). MEASURED against actual usage by spec-code-sync.
  hashDomains: ['ust:state', 'ust:shard', 'ust:seed', 'ust:keylog', 'ust:leaf', 'ust:node',
    'ust:authority-checkpoint', 'ust:checkpoint-map-key', 'ust:checkpoint-map-value', 'ust:name-map-key', 'ust:name-map-value',
    'ust:keylog-empty', 'ust:keylog-leaf', 'ust:keylog-node', 'ust:keylog-commit', 'ust:smt-empty', 'ust:smt-node', 'ust:smt-leaf'],
  // signed `canon` preimage purposes (§12.1a/§12.3) — domain-separated, never interchangeable.
  purposes: ['ust:name-no-fork', 'ust:authority-checkpoint', 'ust:authority-checkpoint-signature',
    'ust:checkpoint-authority-recovery', 'ust:genesis-epoch-transition', 'ust:checkpoint-uniqueness-attestation'],
  // INVALID error codes (§15) — every code the verifier/API can emit. Ordered as §15 lists them.
  errorCodes: ['E-MALFORMED', 'E-CANON', 'E-BOUNDS', 'E-CYCLE', 'E-SIG', 'E-KEY', 'E-GENESIS', 'E-ANCHOR',
    'E-COMMIT', 'E-ROOT', 'E-SEED', 'E-PREV', 'E-AUTHORITY', 'E-SEQ', 'E-EVIDENCE', 'E-ASSURANCE'],
  // INDETERMINATE reasons — the §14 document-verifier's CLOSED set, and the §12.3.6 authority-checkpoint set (distinct).
  indeterminateReasons: { document: ['unavailable', 'unsupported_alg', 'resource_limit', 'stale_keylog'],
    checkpoint: ['authority_unresolved', 'terminality_unproven', 'order_unproven'] },
  tiers: Object.keys(TIER_RANK),                                    // NONE/LIGHT/HIGH/TOP — single-sourced from TIER_RANK
  assuranceAxes: ASSURANCE_AXES,                                    // single-sourced from the #78 lattice (§F.5.0)
  evidenceOrder: ['proven-after', 'not-after', 'unproven'],        // compareEvidenceOrder returns (§12.3.5)
  verifiedEvidenceFields: { required: ['proof_kind', 'subject', 'source_id', 'facts'], optional: ['verifier_id', 'verifier_version'] },
};

// ─── TOP §11.3 completeness: a sequenced stream is prev-chained; first frame's prev = genesis content_hash
//     (M4); per-frame validity is verified too (X2 — completeness ≠ validity); duplicate ust_id / shared prev
//     = a fork ⇒ E-PREV (Y1). A covering checkpoint (M5) proves 'chain-consistent' (no-deletion); the open tail
//     is 'provisional'. 'complete' (no-omission, needs the signed-cadence grid, F.4) is a future rung (#69 C).
export function verifyStream(frames, { genesis, keylog, checkpoint, cadenceLog, requirePerFrameValid = true } = {}) {
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  let prevHash = genesis ? contentHash(genesis) : null;
  const authority = frames[0].state.id.domain_shard;                   // §11.3: a stream belongs to ONE authority
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
  if (!claimWindow || claimWindow.from === undefined || claimWindow.to === undefined) return 'not-applicable';
  if (streamResult?.complete !== 'chain-consistent' && streamResult?.complete !== 'complete') return 'publisher-asserted';
  const iv = streamResult.interval;   // the range verifyStream ITSELF validated (first==from,last==to,no frame outside) — not a caller checkpoint, so unspoofable
  if (!iv || iv.from === undefined || iv.to === undefined) return 'publisher-asserted';
  const w0 = ustToEpoch(claimWindow.from), w1 = ustToEpoch(claimWindow.to), i0 = ustToEpoch(iv.from), i1 = ustToEpoch(iv.to);
  if ([w0, w1, i0, i1].some((x) => x === null) || !(i0 <= w0 && i1 >= w1)) return 'publisher-asserted';   // the verified interval must CONTAIN the window
  if (streamResult.complete !== 'complete') return 'no-deletion-only';   // chain-consistent: no-deletion only, an omitted slot could still hide the event
  if (!Array.isArray(frames)) return 'observation-unchecked';            // complete, but no frames to confirm the publisher actually observed each slot
  const blind = frames.some((f) => { const e = ustToEpoch(f?.state?.id?.ust_id); return e !== null && e >= w0 && e <= w1 && Object.values(f?.state?.data || {}).some((p) => p && p.kind === 'absence' && p.value?.reason === 'unreachable'); });
  return blind ? 'observation-gap' : 'completeness-backed';              // a blind (unreachable) covered slot means a hidden event is not impossible
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
  // P0-2 — a caller-supplied no-fork basis (verified `noForkEvidence`, or the raw `noForkConfirmed` override) skips the
  // witness auto-query; otherwise the served genesis-log is queried and only ever CORROBORATES (never independent).
  let witnessConfirmed = false, noFork = 'unconfirmed';
  const callerNoFork = opts.noForkEvidence !== undefined || opts.noForkConfirmed;
  if (!callerNoFork && !opts.offline) {
    const w = await witnessNoFork(shard, genesisHash, { fetchImpl, substrateVerify });
    if (w.status === 'fork') return { verdict: bad('E-GENESIS', w.detail), resolution: { publisher: shard, fork: true, detail: w.detail } };
    witnessConfirmed = w.status === 'confirmed';
    noFork = witnessConfirmed ? 'served-list (corroborated)' : 'HIGH pending — ' + w.detail;
  }
  // VERIFIED served-list evidence (bound to THIS genesis) — the ONLY way the stateless core earns `corroborated`; a
  // bare boolean would be a mere assertion (self-audit rc.35). Present only when witnessNoFork actually confirmed.
  let servedNoFork; if (witnessConfirmed) { servedNoFork = { confirmed: true, active_genesis: genesisHash }; VERIFIED_SERVED.add(servedNoFork); }   // P0-1: mint the trusted token ONLY after witnessNoFork confirmed
  const authOpts = { genesis, keylog, noForkConfirmed: opts.noForkConfirmed, noForkEvidence: opts.noForkEvidence, trustRoots: opts.trustRoots, servedNoFork };
  const auth = resolveAuthority(doc, authOpts);
  if (auth.error) return { verdict: base, resolution: { error: auth.error + (auth.detail ? ' — ' + auth.detail : '') } };
  if (callerNoFork) noFork = auth.independently_verified ? 'accepted-external-witness (authoritative)' : 'caller-asserted (consumer-override)';
  const verdict = await verifyAsync(doc, { ...opts, genesis, keylog, noForkConfirmed: opts.noForkConfirmed, servedNoFork, capacity: auth.capacity, substrateVerify });   // #69 E1 — await the doc's own anchor substrate (TOP)
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
