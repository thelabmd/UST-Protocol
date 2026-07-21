// SPDX-License-Identifier: Apache-2.0
// ust-lite — the UST 1.0 LIGHT floor, standalone. Publish and verify a signed, canonical, addressable,
// string-only, bounded JSON state with a CARRIED key — no genesis, key-log, anchoring, checkpoints, or the
// assurance lattice. A ust-lite document is a valid UST document: it verifies VALID:LIGHT under the full
// `ust-protocol` verifier, and this verifier accepts any UST document at the LIGHT floor. Zero-dependency
// (node:crypto: Ed25519 + SHA-256). The canon/hash/sign primitives are BYTE-IDENTICAL to the reference impl;
// the point of "lite" is the SMALL surface, readable and re-implementable in an afternoon. §-refs are UST-1.0.md.
import { createHash, sign as edSign, verify as edVerify, createPublicKey, generateKeyPairSync } from 'node:crypto';

const err = (code, detail) => Object.assign(new Error(code), { code, detail });

// ─── §6 Canonicalization (JCS, tightened): UTF-16-sorted keys, no whitespace, STRING-ONLY leaves, NFC, unique names.
export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') throw err('E-CANON', 'non-string leaf');
  if (typeof v === 'string') { if (v.normalize('NFC') !== v) throw err('E-CANON', 'non-NFC string'); return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') {
    const k = Object.keys(v);
    if (new Set(k).size !== k.length) throw err('E-CANON', 'duplicate key');
    for (const x of k) if (x.normalize('NFC') !== x) throw err('E-CANON', 'non-NFC member name');
    return '{' + k.slice().sort().map((x) => JSON.stringify(x) + ':' + canon(v[x])).join(',') + '}';
  }
  throw err('E-CANON', 'unsupported');
}

// ─── §7 domain-separated hash: H_t(x) = "sha256:" || hex(SHA256(ascii(t) || 0x00 || x)).
const sha = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
export const H = (tag, str) => sha(Buffer.concat([Buffer.from(tag, 'ascii'), Buffer.from([0]), Buffer.from(str, 'utf8')]));
const Hbytes = (tag, raw) => sha(Buffer.concat([Buffer.from(tag, 'ascii'), Buffer.from([0]), raw]));
// §12.2/§17 key_id = H("ust:keylog", raw_pub_bytes) — raw = base64url-decode(pub), NOT SHA256(pub).
export const keyId = (pubB64url) => Hbytes('ust:keylog', Buffer.from(pubB64url, 'base64url'));
// §4.4 per-partition hash: public → over {domain_shard, ust_id, partition, value}; private → over its `commit`.
const partitionHash = ({ domain_shard, ust_id, name, value, commit }) => commit !== undefined
  ? Hbytes('ust:shard', Buffer.from(commit, 'utf8'))
  : H('ust:shard', canon({ domain_shard, ust_id, partition: name, value }));
// §7 signed content + content_hash.
export const signedContent = (doc) => canon({ ust: doc.ust, state: doc.state });
export const contentHash = (doc) => H('ust:state', signedContent(doc));

// ─── strict Ed25519 (I4 raw-byte determinism / cross-language agreement): exact 32B pub, 64B canonical sig.
const pubKeyObj = (b64) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b64, 'base64url')]), format: 'der', type: 'spki' });
const strictB64url = (s, bytes) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  let buf; try { buf = Buffer.from(s, 'base64url'); } catch { return null; }
  if (buf.length !== bytes || buf.toString('base64url') !== s) return null;
  return buf;
};
const edVerifyStrict = (pub, msg, sig) => { try { return edVerify(null, Buffer.from(msg, 'utf8'), pubKeyObj(pub), Buffer.from(sig, 'base64url')); } catch { return false; } };

// ─── registries / shape (LIGHT subset of §17) ────────────────────────────────────────────────────────
const RESERVED = { transcript: ['ust', 'state', 'sig', 'proof'], state: ['id', 'time', 'data', 'hashes', 'provenance'],
  id: ['domain_shard', 'ust_id', 'key_id', 'class', 'parent_ust'], envelope: ['kind', 'value', 'privacy', 'commit', 'enc'] };
const RES_PARTITION = new Set([...RESERVED.transcript, ...RESERVED.state, ...RESERVED.id, ...RESERVED.envelope,
  'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
const KINDS = ['captured', 'computed'], PRIVACY = ['blinded', 'encrypted'];
const CLASSES = ['observation', 'attestation', 'derivation', 'genesis', 'key', 'cadence'];
const TS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
const USTID = /^ust:\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\.([01]\d|2[0-3])(([0-5]\d)([0-5]\d)?)?$/;
// round-49 P0-01 — the regex is a SHAPE floor only (`2026-02-31` passes it); the full verifier requires a REAL calendar date,
// so lite must too, or a lite-VALID doc is core-INVALID. Same rule as core's calendarValid — round-trip through Date.UTC and
// require the components to survive (deterministic on every engine). Kept BYTE-IDENTICAL to core; the differential gate pins it.
const calOk = (y, mo, d) => { const t = new Date(Date.UTC(+y, +mo - 1, +d)); return t.getUTCFullYear() === +y && t.getUTCMonth() === +mo - 1 && t.getUTCDate() === +d; };
const tsCalOk = (ts) => calOk(ts.slice(0, 4), ts.slice(5, 7), ts.slice(8, 10));
const ustIdCalOk = (u) => calOk(u.slice(4, 8), u.slice(8, 10), u.slice(10, 12));
// round-50 P0-01 — lite must enforce the SAME LIGHT semantic obligations as the full verifier, or a lite-VALID doc is
// core-INVALID (GPT round-50: an omitted-schema partition + a raw-Unicode domain read VALID:LIGHT in lite / INVALID in core).
// Kept BYTE-IDENTICAL to core (§4.4 closed envelope XOR, §4.3a A-label homograph guard, AEAD enc block); the differential pins it.
const AEAD_ALGS = ['AES-256-GCM', 'XChaCha20-Poly1305'], B64URL = /^[A-Za-z0-9_-]+$/, HASH = /^sha256:[0-9a-f]{64}$/;
const FLOOR = { partitions: 64, sizeBytes: 1048576 };   // §13 anonymous LIGHT floor (full UST raises these via a genesis grant)

// ─── producer: keypair → buildState (auto per-partition hashes) → seal (sign the carried key) ─────────
export function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  return { privateKey, pub, key_id: keyId(pub) };
}
export function buildState(id, time, data) {
  if (id.class !== undefined && id.class !== 'observation') throw err('E-MALFORMED', 'ust-lite builds class:"observation" only — use ust-protocol for attestation/derivation/genesis/key/cadence');
  id = { ...id, class: 'observation' };   // round-49 P0-01 — class is REQUIRED (the verifier now rejects an absent class); ust-lite always stamps observation
  const n = Object.keys(data).length;
  if (n > FLOOR.partitions) throw err('E-BOUNDS', `${n} partitions > LIGHT floor ${FLOOR.partitions} (raise via a genesis grant on full UST)`);
  const hashes = {};
  for (const [name, part] of Object.entries(data))
    hashes[name] = part.commit !== undefined ? partitionHash({ commit: part.commit })
      : partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value });
  const state = { id, time, data, hashes };
  const bytes = Buffer.byteLength(signedContent({ ust: '1.0', state }), 'utf8');
  if (bytes > FLOOR.sizeBytes) throw err('E-BOUNDS', `signed content ${bytes} B > LIGHT floor ${FLOOR.sizeBytes}`);
  return state;
}
export function seal(state, privateKey, pubB64url) {
  const doc = { ust: '1.0', state };
  const sig = edSign(null, Buffer.from(signedContent(doc), 'utf8'), privateKey).toString('base64url');
  return { ust: '1.0', state, sig: { alg: 'Ed25519', key_id: state.id.key_id, pub: pubB64url, sig } };
}

// ─── verifier — the LIGHT floor (§14 steps 1,2,4,5). VALID:LIGHT (integrity + a CLAIMED key), or a §15 error.
//     LIGHT does NOT resolve name authority or time — those are HIGH/TOP (full UST). Identity is `self-asserted`.
export function verify(doc) {
  const bad = (error, detail) => ({ result: 'INVALID', error, detail });
  // totality (round-46 self-audit) — snapshot the doc ONCE into an inert record BEFORE any field read: a hostile getter/Proxy
  // would otherwise throw a host exception at the first `doc.ust` access (or split a two-face payload across the reads below).
  // JSON round-trip preserves the canonical values, so signedContent/signature are unaffected; a throwing getter → structured reject.
  try { doc = JSON.parse(JSON.stringify(doc)); } catch { return bad('E-MALFORMED', 'document is not an inert record'); }
  // 1) structural admission + reserved-key isolation (no unsigned surface beside a VALID verdict)
  if (typeof doc !== 'object' || doc === null) return bad('E-MALFORMED', 'not an object');
  if (doc.ust === undefined || doc.state === undefined || doc.sig === undefined) return bad('E-MALFORMED', 'missing ust/state/sig');
  if (doc.ust !== '1.0') return bad('E-MALFORMED', 'unknown version ' + doc.ust);
  for (const k of Object.keys(doc)) if (!RESERVED.transcript.includes(k)) return bad('E-MALFORMED', 'unknown top-level member: ' + k);
  const st = doc.state;
  for (const k of Object.keys(st)) if (!RESERVED.state.includes(k)) return bad('E-MALFORMED', 'reserved-key: state.' + k);
  if (!st.id || !st.time || !st.data || !st.hashes) return bad('E-MALFORMED', 'state missing id/time/data/hashes');
  for (const k of Object.keys(st.id)) if (!RESERVED.id.includes(k)) return bad('E-MALFORMED', 'reserved-key: id.' + k);
  if (Object.keys(st.data).length < 1) return bad('E-MALFORMED', 'no partition');
  for (const [name, part] of Object.entries(st.data)) {
    if (RES_PARTITION.has(name)) return bad('E-MALFORMED', 'reserved partition name: ' + name);
    if (!part || typeof part !== 'object') return bad('E-MALFORMED', 'partition not an object: ' + name);
    for (const k of Object.keys(part)) if (!RESERVED.envelope.includes(k)) return bad('E-MALFORMED', 'reserved-key: data.' + name + '.' + k);
    if (!KINDS.includes(part.kind)) return bad('E-MALFORMED', 'unknown partition kind: ' + name);
    if (part.privacy !== undefined && !PRIVACY.includes(part.privacy)) return bad('E-MALFORMED', 'unknown privacy: ' + name);
    // round-50 P0-01 — §4.4 CLOSED envelope XOR (the per-partition hash is taken over `commit` WHENEVER present, so a public
    // partition ALSO carrying a commit would bind the hash to the commit while DISPLAYING an unrelated value — "what you see ≠
    // what is signed"). PUBLIC carries value + no commit/enc; PRIVATE carries commit + no plaintext value; ENCRYPTED a typed AEAD enc.
    if (part.privacy === undefined) {
      if (part.commit !== undefined || part.enc !== undefined) return bad('E-MALFORMED', 'public partition must not carry commit/enc (§4.4 public = {kind,value}): ' + name);
      if (part.value === undefined) return bad('E-MALFORMED', 'public partition requires value (§4.4): ' + name);
    } else {
      if (part.commit === undefined) return bad('E-MALFORMED', 'private partition requires commit (§4.4): ' + name);
      if (!HASH.test(part.commit)) return bad('E-MALFORMED', 'private partition commit not sha256:hex (§4.4): ' + name);   // round-51 P0-01 — TYPE the commitment (core does); a non-hash commit was lite-VALID/core-INVALID
      if (part.value !== undefined) return bad('E-MALFORMED', 'private partition must not carry a plaintext value (§4.4): ' + name);
      if (part.privacy === 'encrypted') { const e = part.enc; if (!e || typeof e !== 'object' || !AEAD_ALGS.includes(e.alg) || typeof e.key_id !== 'string' || !B64URL.test(e.ct || '')) return bad('E-MALFORMED', 'encrypted partition missing/invalid enc{alg,key_id,ct} (§4.4): ' + name); }
    }
  }
  // 2) canonical, content_hash, hashes⇄data bijection, per-partition hash recompute (§4.4, G19)
  let S; try { S = signedContent(doc); } catch (e) { return bad('E-CANON', e.detail || 'canon'); }
  const dk = Object.keys(st.data).sort(), hk = Object.keys(st.hashes).sort();
  if (dk.length !== hk.length || dk.some((k, i) => k !== hk[i])) return bad('E-MALFORMED', 'hashes⇄data not a bijection (G19)');
  for (const [name, part] of Object.entries(st.data)) {
    let recomputed; try {
      recomputed = part.commit !== undefined ? partitionHash({ commit: part.commit })
        : partitionHash({ domain_shard: st.id.domain_shard, ust_id: st.id.ust_id, name, value: part.value });
    } catch { return bad('E-CANON', 'partition canon: ' + name); }
    if (recomputed !== st.hashes[name]) return bad('E-CANON', 'partition hash mismatch: ' + name);
  }
  // 3) shape (§8/§6): ust_id, RFC3339-Z times, valid_from ≤ valid_to, class registry, key-form self-certification
  if (!USTID.test(st.id.ust_id) || !ustIdCalOk(st.id.ust_id)) return bad('E-MALFORMED', 'ust_id shape or date not on the calendar');
  if (!TS.test(st.time.generated_at) || !TS.test(st.time.valid_from) || !TS.test(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp not RFC3339-Z');
  if (!tsCalOk(st.time.generated_at) || !tsCalOk(st.time.valid_from) || !tsCalOk(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp date not on the calendar');   // round-49 P0-01 — real date, not just shape
  if (st.time.valid_from > st.time.valid_to) return bad('E-MALFORMED', 'valid_from > valid_to');
  // §14.5 / N10 class↔provenance: ust-lite carries NO provenance, so it handles `observation` (data) ONLY, and class is
  // REQUIRED — the full verifier rejects an absent/unknown class (round-49 P0-01: an omitted class read VALID:LIGHT here while
  // core returned INVALID). `attestation`/`derivation` REQUIRE provenance; `genesis`/`key`/`cadence` are the HIGH/TOP layer.
  if (st.id.class !== 'observation')
    return bad('E-MALFORMED', `ust-lite verifies class:"observation" only (class is required) — "${st.id.class}" needs provenance or the HIGH/TOP layer; use ust-protocol`);
  const shardKeyForm = /^sha256:[0-9a-f]{64}$/.test(st.id.domain_shard);
  if (shardKeyForm && st.id.domain_shard !== st.id.key_id) return bad('E-MALFORMED', 'key-form domain_shard ≠ key_id');
  // round-50 P0-01 — §4.3a homograph guard: a NAME-form domain_shard MUST be an A-label (ASCII; punycode xn-- for IDN), never
  // raw Unicode ('аpple.com' with Cyrillic U+0430 renders as 'apple.com' but is a different string). Core rejects it; lite must too.
  if (!shardKeyForm && /[^\x00-\x7f]/.test(st.id.domain_shard)) return bad('E-MALFORMED', 'name-form domain_shard must be an A-label (ASCII; punycode xn-- for IDN), not raw Unicode glyphs (§4.3a homograph guard)');
  // 4) authenticity (the FLOOR): key_id == keyId(sig.pub) == state.id.key_id, strict Ed25519 over S
  const s = doc.sig;
  if (!s || s.alg !== 'Ed25519' || typeof s.pub !== 'string' || typeof s.sig !== 'string') return bad('E-MALFORMED', 'malformed sig');
  for (const k of Object.keys(s)) if (!['alg', 'key_id', 'pub', 'sig'].includes(k)) return bad('E-MALFORMED', 'reserved-key: sig.' + k);
  if (strictB64url(s.pub, 32) === null) return bad('E-SIG', 'pub not canonical 32-byte b64url');
  if (strictB64url(s.sig, 64) === null) return bad('E-SIG', 'sig not canonical 64-byte b64url');
  if (keyId(s.pub) !== s.key_id || s.key_id !== st.id.key_id) return bad('E-SIG', 'key_id ≠ H(ust:keylog, pub) or ≠ state.id.key_id');
  if (!edVerifyStrict(s.pub, S, s.sig)) return bad('E-SIG', 'Ed25519 verify failed');
  return { result: 'VALID:LIGHT', tier: 'LIGHT', identity: 'self-asserted', publisher_claimed: st.id.domain_shard,
    ust_id: st.id.ust_id, key_id: st.id.key_id, content_hash: contentHash(doc), completeness: 'not_evaluated' };
}
