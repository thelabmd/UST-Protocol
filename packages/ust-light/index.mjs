// SPDX-License-Identifier: Apache-2.0
// ust-light — the UST 1.0 LIGHT floor, standalone. Publish and verify a signed, canonical, addressable,
// string-only, bounded JSON state with a CARRIED key — no genesis, key-log, anchoring, checkpoints, or the
// assurance lattice. A ust-light document is a valid UST document: it verifies VALID:LIGHT under the full
// `ust-protocol` verifier, and this verifier accepts any UST document at the LIGHT floor. Zero-dependency
// (WebCrypto: Ed25519 + SHA-256). The canon/hash/sign primitives are BYTE-IDENTICAL to the reference impl;
// the point of "lite" is the SMALL surface, readable and re-implementable in an afternoon. §-refs are UST-1.0.md.
//
// #143 — ASYNCHRONOUS, AND ON PURPOSE. This floor used `node:crypto`'s synchronous primitives and therefore ran
// in exactly one place. A browser offers Ed25519 and SHA-256 only through `crypto.subtle`, which is async, so a
// synchronous floor is a Node floor — and a floor that refuses the browser is not a floor: the browser is where
// a verifier meant to be re-implementable in an afternoon is wanted most.
//
// The reference core made the OPPOSITE call and kept its synchrony, because there it is STRUCTURAL. Here it was
// INCIDENTAL — nothing depended on it — so the smaller answer is one async surface rather than a sync build and
// an async build drifting apart. Everything touching a hash or a signature returns a promise; `canon` and
// `signedContent` are pure and stay synchronous.
//
// Byte helpers are inlined rather than imported from the reference package. That is not duplication by neglect:
// this file's whole value is being an INDEPENDENT second implementation that agrees, and one that borrows the
// other's internals proves nothing by agreeing with it. The cross-implementation vectors are the guard.

const te = new TextEncoder();
const utf8 = (s) => te.encode(s);
const cat = (parts) => { let n = 0; for (const p of parts) n += p.length; const o = new Uint8Array(n); let a = 0; for (const p of parts) { o.set(p, a); a += p.length; } return o; };
const hex = (b) => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
const b64uTo = (b) => { let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
// Permissive exactly like Node's decoder was: canonicality is decided by the re-encode in strictB64url, not here.
const b64uFrom = (s) => { if (typeof s !== 'string') return new Uint8Array(0); const c = s.replace(/[^A-Za-z0-9+/_-]/g, '').replace(/-/g, '+').replace(/_/g, '/'); let bin; try { bin = atob(c + '='.repeat((4 - (c.length % 4)) % 4)); } catch { return new Uint8Array(0); } const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; };

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
const sha = async (bytes) => 'sha256:' + hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
export const H = (tag, str) => sha(cat([utf8(tag), new Uint8Array([0]), utf8(str)]));
const Hbytes = (tag, raw) => sha(cat([utf8(tag), new Uint8Array([0]), raw]));
// §12.2/§17 key_id = H("ust:keylog", raw_pub_bytes) — raw = base64url-decode(pub), NOT SHA256(pub).
export const keyId = (pubB64url) => Hbytes('ust:keylog', b64uFrom(pubB64url));
// §4.4 per-partition hash: public → over {domain_shard, ust_id, partition, value}; private → over its `commit`.
const partitionHash = ({ domain_shard, ust_id, name, value, commit }) => commit !== undefined
  ? Hbytes('ust:shard', utf8(commit))
  : H('ust:shard', canon({ domain_shard, ust_id, partition: name, value }));
// §7 signed content + content_hash.
export const seed = (contentHashes) => H('ust:seed', canon(contentHashes));
// §9.2 Merkle root over a cited SET — byte-ascending sort, ust:leaf / ust:node, odd node promoted.
export async function merkleRoot(contentHashes) {
  let lvl = [];
  for (const h of contentHashes.slice().sort()) lvl.push(await Hbytes('ust:leaf', utf8(h)));
  while (lvl.length > 1) {
    const nx = [];
    for (let i = 0; i < lvl.length; i += 2)
      nx.push(i + 1 < lvl.length ? await Hbytes('ust:node', utf8(lvl[i] + lvl[i + 1])) : lvl[i]);
    lvl = nx;
  }
  return lvl[0];
}           // pinned signed order — byte-identical to core §9.4
export const signedContent = (doc) => canon({ ust: doc.ust, state: doc.state });
export const contentHash = (doc) => H('ust:state', signedContent(doc));

// ─── strict Ed25519 (I4 raw-byte determinism / cross-language agreement): exact 32B pub, 64B canonical sig.
const importPub = (b64) => crypto.subtle.importKey('raw', b64uFrom(b64), { name: 'Ed25519' }, false, ['verify']);
const strictB64url = (s, bytes) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  let buf; try { buf = b64uFrom(s); } catch { return null; }
  if (buf.length !== bytes || b64uTo(buf) !== s) return null;
  return buf;
};
const edVerifyStrict = async (pub, msg, sig) => { try { return await crypto.subtle.verify({ name: 'Ed25519' }, await importPub(pub), b64uFrom(sig), utf8(msg)); } catch { return false; } };

// ─── registries / shape (LIGHT subset of §17) ────────────────────────────────────────────────────────
const RESERVED = { transcript: ['ust', 'state', 'sig', 'proof'], state: ['id', 'time', 'data', 'hashes', 'provenance'],
  id: ['domain_shard', 'ust_id', 'key_id', 'class', 'parent_ust'], envelope: ['kind', 'value', 'privacy', 'commit', 'enc'] };
const RES_PARTITION = new Set([...RESERVED.transcript, ...RESERVED.state, ...RESERVED.id, ...RESERVED.envelope,
  'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
// §4.4 registers THREE kinds, and this floor carried two. Measured 2026-09-02 (#177) — CLOSED 2026-09-02: an
// `absence` partition — the notary's other half, a signed NON-occurrence — was refused here as an unknown kind,
// so an honest document of the reference operator would not verify at the floor. This is #154 recurring in the
// implementation that round did not sweep: it added `absence` to the browser verifier and the extension and
// left this one, and no test could see the gap because the light corpus leg did not exist until now.
// The list is duplicated rather than imported ON PURPOSE — this package is zero-dependency and standalone —
// so the corpus comparison in `test.mjs` is what keeps it equal to `REGISTRY.partitionKinds`.
const KINDS = ['captured', 'computed', 'absence'], PRIVACY = ['blinded', 'encrypted'];
const FORGES_STRUCTURE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const CLASSES = ['observation', 'attestation', 'derivation', 'genesis', 'key', 'cadence'];
// #142 — TWO AXES, and conflating them is the defect this replaces. `genesis`/`key`/`cadence` are the
// AUTHORITY layer: excluding them from a floor with no key log is principled, there is nothing here that could
// resolve them. `attestation`/`derivation` were excluded for a different reason entirely — the BUILDER does
// not produce them — and a fact about the builder was deciding what the VERIFIER accepts. An attestation is
// LIGHT when its key is carried and nothing resolves authority, exactly as an observation is.
const DATA_CLASSES = ['observation', 'attestation', 'derivation'];
const PREV_ONLY_SUBTYPES = ['checkpoint', 'gap', 'anchor'];
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
const FLOOR = { partitions: 64, sizeBytes: 1048576, breadth: 64 };   // §13 anonymous LIGHT floor (full UST raises these via a genesis grant)

// ─── producer: keypair → buildState (auto per-partition hashes) → seal (sign the carried key) ─────────
export async function keypair() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = b64uTo(new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)));
  return { privateKey, pub, key_id: await keyId(pub) };
}
// §10 PRIVATE PARTITIONS — the floor can now MAKE one, not only refuse a malformed one. Measured 2026-09-02
// (#177), CLOSED 2026-09-02 by the two producers below and step 8 in `verify`: this package validated the `enc`
// SHAPE and had no producer and no step 8, so every fixture it could
// hold described its own verifier. A mode with a reader and no writer cannot be attacked by its own tests.
//
// WHY THIS BELONGS AT THE FLOOR. §10's privacy is per-PARTITION and needs no genesis, no anchor and no lattice —
// it is LIGHT by construction. Keeping it out would have made "the floor" mean "the parts of the floor that
// happen to be synchronous", which is the shape #143 already removed from this file once.
export async function blindPartition(name, value, { domain_shard, ust_id, nonce, kind = 'captured' }) {
  const commit = await H('ust:shard', canon({ domain_shard, ust_id, nonce, partition: name, value }));
  return { partition: { kind, privacy: 'blinded', commit }, hash: await partitionHash({ commit }) };
}

// AES-256-GCM only, and that is a CEILING honestly reported rather than a gap: WebCrypto offers no ChaCha, and
// this floor will not hand-roll a cipher (the rule that keeps a hand-written Ed25519 out of the browser core).
// `XChaCha20-Poly1305` stays registered and unimplemented here — §17's OPTIONAL tier is exactly this situation.
//
// The IV is DERIVED, never random: `H('ust:enc-iv', commit)[0..12]`, so IV uniqueness reduces to commitment
// uniqueness, which §10 already demands of the producer. A random 96-bit IV would collide by birthday bound long
// before a busy publisher's key rotates, and GCM under a repeated IV is catastrophic.
export async function encryptPartition(name, value, { domain_shard, ust_id, nonce, key_id, key, kind = 'captured' }) {
  const commit = await H('ust:shard', canon({ domain_shard, ust_id, nonce, partition: name, value }));
  const plaintext = canon({ nonce, partition: name, value });          // EXACTLY what step 8 compares against
  const iv = b64uFrom((await H('ust:enc-iv', commit)).slice(7)).subarray(0, 12);
  const k = await crypto.subtle.importKey('raw', b64uFrom(key), { name: 'AES-GCM' }, false, ['encrypt']);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, utf8(plaintext)));
  const ct = b64uTo(cat([iv, sealed]));                                  // nonce ‖ body ‖ tag (§17 layout)
  return { partition: { kind, privacy: 'encrypted', commit, enc: { alg: 'AES-256-GCM', key_id, ct } }, hash: await partitionHash({ commit }) };
}

export async function buildState(id, time, data, provenance) {
  if (id.class !== undefined && id.class !== 'observation') throw err('E-MALFORMED', 'ust-light builds class:"observation" only — use ust-protocol for attestation/derivation/genesis/key/cadence');
  id = { ...id, class: 'observation' };   // round-49 P0-01 — class is REQUIRED (the verifier now rejects an absent class); ust-light always stamps observation
  const n = Object.keys(data).length;
  if (n > FLOOR.partitions) throw err('E-BOUNDS', `${n} partitions > LIGHT floor ${FLOOR.partitions} (raise via a genesis grant on full UST)`);
  const hashes = {};
  for (const [name, part] of Object.entries(data))
    hashes[name] = part.commit !== undefined ? await partitionHash({ commit: part.commit })
      : await partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value });
  const state = { id, time, data, hashes };
  // UST-jls — lite can now BUILD the chains it was already verifying. The producer refuses what its own verifier would
  // refuse: a builder that emits documents its verifier rejects is worse than one that cannot build them at all.
  // Member insertion order matches core exactly, because canon is order-preserving and byte-identity is the contract.
  if (provenance !== undefined) {
    if (typeof provenance !== 'object' || provenance === null || Array.isArray(provenance)) throw err('E-MALFORMED', 'provenance must be an object');
    if (provenance.constituents !== undefined || provenance.root !== undefined) throw err('E-MALFORMED', 'observation MUST NOT carry constituents/root — an attestation is ust-protocol');
    if (provenance.based_on !== undefined) {
      if (!Array.isArray(provenance.based_on) || provenance.based_on.some((b) => !b || !HASH.test(b.hash || ''))) throw err('E-MALFORMED', 'based_on entries must carry sha256:hex `hash`');
      if (new Set(provenance.based_on.map((b) => b.hash)).size !== provenance.based_on.length) throw err('E-MALFORMED', 'duplicate hash in based_on (§9.4)');
      if (await seed(provenance.based_on.map((b) => b.hash)) !== provenance.seed) throw err('E-SEED', 'seed must be H(ust:seed, canon(based_on hashes)) — build it with the exported seed()');
    }
    if (provenance.prev !== undefined && !HASH.test(provenance.prev)) throw err('E-MALFORMED', 'prev must be a sha256:hex content_hash');
    state.provenance = provenance;
  }
  const bytes = utf8(signedContent({ ust: '1.0', state })).length;
  if (bytes > FLOOR.sizeBytes) throw err('E-BOUNDS', `signed content ${bytes} B > LIGHT floor ${FLOOR.sizeBytes}`);
  return state;
}
export async function seal(state, privateKey, pubB64url) {
  const doc = { ust: '1.0', state };
  const sig = b64uTo(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, utf8(signedContent(doc)))));
  return { ust: '1.0', state, sig: { alg: 'Ed25519', key_id: state.id.key_id, pub: pubB64url, sig } };
}

// ─── verifier — the LIGHT floor (§14 steps 1,2,4,5). VALID:LIGHT (integrity + a CLAIMED key), or a §15 error.
//     LIGHT does NOT resolve name authority or time — those are HIGH/TOP (full UST). Identity is `self-asserted`.
export async function verify(doc, opts = {}) {
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
    // §6 — a partition NAME travels into `disclosed`, so it is an identifier the verdict quotes. Tester without
    // `/g`: a global regex keeps `lastIndex` between calls and answers FALSE on its third invocation.
    if (FORGES_STRUCTURE.test(name)) return bad('E-MALFORMED', 'partition name carries a control or bidi-override character (§6)');
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
      // §4.4 — the two private alternatives are SEPARATE productions, and `enc` belongs to `encrypted` alone.
      // Measured 2026-09-02 (#177) — CLOSED here: this floor is the THIRD implementation of the rule, and it
      // admitted the shape after both others refused it. A ciphertext under a `blinded` declaration falls under
      // no obligation: the AEAD branch is keyed on the MODE, so nothing ever examines it.
      if (part.privacy === 'blinded' && part.enc !== undefined) return bad('E-MALFORMED', 'blinded partition carries an enc block — a channel its mode does not declare (§4.4): ' + name);
      if (part.privacy === 'encrypted' && typeof part.enc?.key_id === 'string' && FORGES_STRUCTURE.test(part.enc.key_id))
        return bad('E-MALFORMED', 'enc.key_id carries a control or bidi-override character — an identifier the verdict quotes may not forge structure (§6): ' + name);
      if (part.privacy === 'encrypted') { const e = part.enc; if (!e || typeof e !== 'object' || !AEAD_ALGS.includes(e.alg) || typeof e.key_id !== 'string' || !B64URL.test(e.ct || '')) return bad('E-MALFORMED', 'encrypted partition missing/invalid enc{alg,key_id,ct} (§4.4): ' + name); }
    }
  }
  // 2) canonical, content_hash, hashes⇄data bijection, per-partition hash recompute (§4.4, G19)
  let S; try { S = signedContent(doc); } catch (e) { return bad('E-CANON', e.detail || 'canon'); }
  const dk = Object.keys(st.data).sort(), hk = Object.keys(st.hashes).sort();
  if (dk.length !== hk.length || dk.some((k, i) => k !== hk[i])) return bad('E-MALFORMED', 'hashes⇄data not a bijection (G19)');
  for (const [name, part] of Object.entries(st.data)) {
    let recomputed; try {
      recomputed = part.commit !== undefined ? await partitionHash({ commit: part.commit })
        : await partitionHash({ domain_shard: st.id.domain_shard, ust_id: st.id.ust_id, name, value: part.value });
    } catch { return bad('E-CANON', 'partition canon: ' + name); }
    if (recomputed !== st.hashes[name]) return bad('E-CANON', 'partition hash mismatch: ' + name);
  }
  // 3) shape (§8/§6): ust_id, RFC3339-Z times, valid_from ≤ valid_to, class registry, key-form self-certification
  if (!USTID.test(st.id.ust_id) || !ustIdCalOk(st.id.ust_id)) return bad('E-MALFORMED', 'ust_id shape or date not on the calendar');
  if (!TS.test(st.time.generated_at) || !TS.test(st.time.valid_from) || !TS.test(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp not RFC3339-Z');
  if (!tsCalOk(st.time.generated_at) || !tsCalOk(st.time.valid_from) || !tsCalOk(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp date not on the calendar');   // round-49 P0-01 — real date, not just shape
  if (st.time.valid_from > st.time.valid_to) return bad('E-MALFORMED', 'valid_from > valid_to');
  // §14.5 / N10 class↔provenance: ust-light handles `observation` (data) ONLY, and class is REQUIRED — the full verifier
  // rejects an absent/unknown class (round-49 P0-01: an omitted class read VALID:LIGHT here while core returned INVALID).
  // `attestation`/`derivation` are the classes lite does not build; `genesis`/`key`/`cadence` are the HIGH/TOP layer.
  if (!DATA_CLASSES.includes(st.id.class))
    return bad('E-MALFORMED', `ust-light verifies class:"observation" only (class is required) — "${st.id.class}" needs the HIGH/TOP layer or the full builder family; use ust-protocol`);
  // UST-jls — every §14a provenance obligation reachable at LIGHT, in CORE'S ORDER and with core's reasons, so a document
  // violating several rules gets the same code from both. lite previously carried NO provenance checks at all while
  // HAPPILY VERIFYING chained documents: 14 shapes read VALID:LIGHT here that core calls INVALID. A floor that admits what
  // the ceiling rejects is not a subset — it is different semantics wearing the same name.
  const pr = st.provenance;
  if (pr !== undefined && (typeof pr !== 'object' || pr === null || Array.isArray(pr))) return bad('E-MALFORMED', 'provenance must be an object');
  // §S4/F4 — class ↔ provenance, dispatched on the class instead of assuming there is only one.
  if (st.id.class === 'observation' && (pr?.constituents !== undefined || pr?.root !== undefined))
    return bad('E-MALFORMED', 'observation MUST NOT carry constituents/root');
  if (st.id.class === 'derivation' && (pr?.based_on === undefined || pr?.seed === undefined))
    return bad('E-MALFORMED', 'derivation MUST carry based_on + seed');
  // §13 breadth — `based_on` / `constituents` are bounded per node at 64, and this one is STRUCTURAL: no
  // declaration raises it (F.9.5), so it is not a tier question and the floor owes it exactly as the core does.
  // Measured 2026-09-02 (#177), CLOSED 2026-09-02 by the loop below: this floor accepted a document the core
  // refuses with E-BOUNDS, and the corpus comparison that found it did not exist before this round.
  for (const member of ['based_on', 'constituents'])
    if (Array.isArray(pr?.[member]) && pr[member].length > FLOOR.breadth)
      return bad('E-BOUNDS', `${member} ${pr[member].length} > ${FLOOR.breadth} per node (§13, a structural bound no declaration raises)`);
  if (st.id.class === 'attestation') {
    // §11.3 C2 — the subtype is a NAMED DATA PARTITION, never a shape: a prev-only attestation carrying no named
    // partition COLLIDES a checkpoint with a gap record. And the root FOLLOWS the subtype in BOTH directions,
    // because a rule enforced on one side only is not enforced.
    const empty = pr?.constituents === undefined || pr.constituents.length === 0;
    if (empty) {
      if (pr?.prev === undefined) return bad('E-MALFORMED', 'a no-constituents attestation MUST carry provenance.prev (checkpoint, gap or anchor)');
      const named = PREV_ONLY_SUBTYPES.filter((n) => st.data?.[n] !== undefined);
      if (named.length !== 1) return bad('E-MALFORMED', 'a prev-only attestation MUST carry EXACTLY ONE of ' + PREV_ONLY_SUBTYPES.map((n) => 'data.' + n).join(', '));
      const rooted = named[0] === 'anchor';
      if (rooted && pr?.root === undefined) return bad('E-MALFORMED', 'an anchor attestation MUST carry provenance.root');
      if (!rooted && pr?.root !== undefined) return bad('E-MALFORMED', 'a ' + named[0] + ' attestation MUST NOT carry a root');
    } else if (pr?.root === undefined) return bad('E-MALFORMED', 'a set attestation MUST carry constituents + root');
    // The root is RECOMPUTED, never merely required to be present: a root nobody re-derives binds nothing.
    if (pr?.root !== undefined && pr?.constituents !== undefined && await merkleRoot(pr.constituents) !== pr.root)
      return bad('E-ROOT', 'attestation root mismatch');
  }
  if (pr?.based_on !== undefined) {
    if (!Array.isArray(pr.based_on) || pr.based_on.some((b) => !b || !HASH.test(b.hash || ''))) return bad('E-MALFORMED', 'based_on entries must carry sha256:hex `hash`');
    if (new Set(pr.based_on.map((b) => b.hash)).size !== pr.based_on.length) return bad('E-MALFORMED', 'duplicate hash in based_on (citing a referent twice has no composite meaning, §9.4)');
    // The seed is the ONLY thing binding a document to the set of inputs it cites. Accepting a based_on whose seed does
    // not recompute accepts a provenance claim bound to nothing.
    if (await seed(pr.based_on.map((b) => b.hash)) !== pr.seed) return bad('E-SEED', 'derivation seed != H(ust:seed, canon(based_on hashes))');
  }
  if (pr?.prev !== undefined && !HASH.test(pr.prev)) return bad('E-MALFORMED', 'prev must be a sha256:hex content_hash');
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
  if (await keyId(s.pub) !== s.key_id || s.key_id !== st.id.key_id) return bad('E-SIG', 'key_id ≠ H(ust:keylog, pub) or ≠ state.id.key_id');
  if (!(await edVerifyStrict(s.pub, S, s.sig))) return bad('E-SIG', 'Ed25519 verify failed');
  // round-53 (UST-ybn — the LIGHT ambiguity fix, unified rule): authentic, but ust-light is the LIGHT floor with NO
  // binding capability (no genesis/key-log), so it CANNOT confirm a name-form DOMAIN CLAIM ⇒ "cannot confirm ⇒
  // INDETERMINATE", never a bare VALID (the forgery-misread). A self-asserted KEY-IDENTITY uses key-form domain_shard.
  if (!shardKeyForm) return { result: 'INDETERMINATE', reason: 'unavailable', ust_id: st.id.ust_id, key_id: st.id.key_id, content_hash: await contentHash(doc), detail: 'name-form domain_shard is a domain claim ust-light cannot confirm (no binding): use key-form domain_shard = key_id for a self-asserted key-identity document (→ VALID:LIGHT), or verify with genesis+key-log via ust-protocol (→ HIGH). "cannot confirm" ⇒ INDETERMINATE (UST-ybn)' };
  // §14 step 8 — PRIVACY, and authorization is per-CHANNEL. A `blinded` partition has ONE channel (the
  // commitment, opened by `{nonce,value}`); an `encrypted` one has TWO (that, plus the AEAD opened by the key),
  // and a reader may hold either. `disclosed` therefore means EVERY channel the publisher declared was checked;
  // a partition opened by the commitment alone is reported apart, so the plain reading of a verdict is never
  // true of a state nobody verified. Measured 2026-09-02 (#177) — CLOSED here: this floor had no step 8 at all,
  // so a WRONG pair would have been accepted in silence had anyone thought to pass one.
  const disclosed = [], disclosedPartial = [];
  for (const [name, part] of Object.entries(st.data)) {
    const d = opts.disclosures?.[name];
    if (part.privacy === undefined || !d) continue;
    const reproduced = await H('ust:shard', canon({ domain_shard: st.id.domain_shard, ust_id: st.id.ust_id, nonce: d.nonce, partition: name, value: d.value }));
    if (reproduced !== part.commit) return bad('E-COMMIT', 'blinded commit mismatch: ' + name);
    if (part.privacy === 'encrypted') {
      const key = opts.decKeys?.[part.enc.key_id];
      if (!key) { disclosedPartial.push({ partition: name, checked: 'commit', unchecked: 'aead', needs_key_id: part.enc.key_id }); continue; }
      if (part.enc.alg !== 'AES-256-GCM')   // §17 OPTIONAL: this build's limit, never the document's defect
        return { result: 'INDETERMINATE', reason: 'unsupported_alg', detail: 'AEAD ' + part.enc.alg + ' is not implemented by ust-light (WebCrypto offers no ChaCha): ' + name };
      let pt = null;
      try {
        const raw = b64uFrom(part.enc.ct);
        const k = await crypto.subtle.importKey('raw', b64uFrom(key), { name: 'AES-GCM' }, false, ['decrypt']);
        pt = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, k, raw.subarray(12)));
      } catch { pt = null; }               // authentication failure — the DOCUMENT's defect
      if (pt === null || pt !== canon({ nonce: d.nonce, partition: name, value: d.value })) return bad('E-COMMIT', 'AEAD↔commit mismatch: ' + name);
    }
    disclosed.push(name);
  }
  return { result: 'VALID:LIGHT', tier: 'LIGHT', identity: 'self-asserted', publisher_claimed: st.id.domain_shard,
    disclosed, ...(disclosedPartial.length ? { disclosed_partial: disclosedPartial } : {}),
    ust_id: st.id.ust_id, key_id: st.id.key_id, content_hash: await contentHash(doc), completeness: 'not_evaluated' };
}
