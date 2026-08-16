// SPDX-License-Identifier: Apache-2.0
// ust-verify — the canonical BROWSER verifier for UST 1.0, WebCrypto-only, ZERO dependencies. A clean-room
// implementation written FROM THE SPEC (it does NOT import ust-protocol) and cross-checked against ust-protocol on
// the conformance vectors — a second, independent conforming verifier, not a re-export. Runs in browsers, Workers,
// and Node (global crypto.subtle); async. Backs the findable web verifier at
// https://verify.ustprotocol.com/ and is the zero-dep verifier an AI can fetch from the CANONICAL source
// (this repo) — never from a sender's blob. LIGHT floor + stream completeness.
const te = (s) => new TextEncoder().encode(s);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };

// §6 canon (JCS, tightened): string-only leaves, NFC, sorted+unique keys. Throws E-CANON.
export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') throw { code: 'E-CANON', detail: 'non-string leaf' };
  if (typeof v === 'string') { if (v.normalize('NFC') !== v) throw { code: 'E-CANON', detail: 'non-NFC' }; return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const k = Object.keys(v); if (new Set(k).size !== k.length) throw { code: 'E-CANON', detail: 'dup key' };
  for (const x of k) if (x.normalize('NFC') !== x) throw { code: 'E-CANON', detail: 'non-NFC key' };   // F6 — names too
  return '{' + k.sort().map((x) => JSON.stringify(x) + ':' + canon(v[x])).join(',') + '}';
}
// §7 domain-separated hash: "sha256:" + hex(SHA256(ascii(tag) || 0x00 || body))
async function digest(tag, body) { return 'sha256:' + hex(await crypto.subtle.digest('SHA-256', concat(concat(te(tag), new Uint8Array([0])), body))); }
export const H = (tag, str) => digest(tag, te(str));
export const Hbytes = (tag, bytes) => digest(tag, bytes);
export const keyId = (pub) => Hbytes('ust:keylog', b64url(pub));               // §12.2 over RAW pubkey bytes
export async function merkleRoot(contentHashes) {                       // §9.2 byte-ascending, ust:leaf/ust:node
  let lvl = await Promise.all(contentHashes.slice().sort().map((h) => Hbytes('ust:leaf', te(h))));
  while (lvl.length > 1) {
    const nx = [];
    for (let i = 0; i < lvl.length; i += 2)
      nx.push(i + 1 < lvl.length ? await Hbytes('ust:node', te(lvl[i] + lvl[i + 1])) : lvl[i]);
    lvl = nx;
  }
  return lvl[0];
}
export async function partitionHash({ domain_shard, ust_id, name, value, commit }) {
  if (commit !== undefined) return H('ust:shard', commit);                     // §10 private
  return H('ust:shard', canon({ domain_shard, ust_id, partition: name, value }));  // uniform; name as VALUE (non-colliding), no domain-less
}
export const contentHash = (doc) => H('ust:state', canon({ ust: doc.ust, state: doc.state }));

// §7 strict Ed25519: WebCrypto verify + MANUAL canonical-S (reject S >= L). WebCrypto does NOT expose the
// malleability check, so we enforce it ourselves — this is exactly the kind of gap two implementations surface.
const L = new Uint8Array([0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x14,0xde,0xf9,0xde,0xa2,0xf7,0x9c,0xd6,0x58,0x12,0x63,0x1a,0x5c,0xf5,0xd3,0xed]);
export function canonicalS(sig) {
  const b = b64url(sig); if (b.length !== 64) return false;
  const S = b.slice(32).reverse();                                            // little-endian → big-endian
  for (let i = 0; i < 32; i++) { if (S[i] < L[i]) return true; if (S[i] > L[i]) return false; }
  return false;                                                               // S == L → not < L → reject
}
// #144 — THE THIRD OUTCOME IS NOT `false`. A single `catch` here used to answer the same `false` to two
// unrelated facts: *this signature is bad* and *this browser cannot check Ed25519 at all*. The caller turns
// `false` into `INVALID:E-SIG`, so on any engine whose WebCrypto lacks Ed25519 every honest document read as
// FORGED — an accusation against a document that was fine, from a verifier that had not looked. The reference
// closed this by letting the primitive THROW and routing that to INDETERMINATE; this file kept the collapse
// while `llms.txt` recommends it to machines as the fetchable verifier.
//
// The split follows the DOM spec rather than a guess: an unrecognised algorithm is `NotSupportedError`, while
// malformed key material is `DataError`. So a missing FACULTY is re-thrown as E-UNSUPPORTED and becomes
// INDETERMINATE below; a bad INPUT stays `false`, which is what `false` always meant.
export async function edVerifyRaw(pub, msg, sig) {                             // WebCrypto ONLY (no strict-S) — to observe its behavior
  try { const k = await crypto.subtle.importKey('raw', b64url(pub), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, k, b64url(sig), te(msg)); }
  catch (e) {
    if (e?.name === 'NotSupportedError' || /unrecognized|unsupported|not supported/i.test(String(e?.message || '')))
      throw { code: 'E-UNSUPPORTED', detail: 'Ed25519 is not available in this build\'s crypto.subtle — the signature was NOT checked' };
    return false;
  }
}
export const edVerifyStrict = async (pub, msg, sig) => canonicalS(sig) && (await edVerifyRaw(pub, msg, sig));

const bad = (code, detail) => ({ result: 'INVALID', error: code, detail });
const TS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;  // valid ranges, reject leap :60
// §14.5 semantic consistency — dates must exist on the REAL calendar (Feb 31 passes the range regex, is not a date).
const calOk = (y, mo, d) => { const t = new Date(Date.UTC(+y, +mo - 1, +d)); return t.getUTCFullYear() === +y && t.getUTCMonth() === +mo - 1 && t.getUTCDate() === +d; };
const tsCal = (ts) => calOk(ts.slice(0, 4), ts.slice(5, 7), ts.slice(8, 10));
const idCal = (u) => calOk(u.slice(4, 8), u.slice(8, 10), u.slice(10, 12));
const KEYID_FORM = /^sha256:[0-9a-f]{64}$/;   // §4/§12 typed identity: key-form shard MUST equal key_id
const USTID = /^ust:\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\.([01]\d|2[0-3])(([0-5]\d)([0-5]\d)?)?$/;  // F8 valid UTC frame
// `cadence` was MISSING here while line ~183 below already exempted it from the key-form shard rule — so this
// clean-room verifier returned INVALID('bad class') on a legitimate §11.3 cadence entry that the reference verifier
// accepts as VALID:LIGHT. A measured divergence between two conforming verifiers, which is the one thing the README
// promises cannot happen. The parity gate exists for exactly this class (rev83's name-form rule diverged the same way)
// but its battery carried no cadence-class document, so the hole survived the gate. Battery extended alongside this fix.
const CLASSES = ['observation', 'attestation', 'derivation', 'genesis', 'key', 'cadence'];
const TRANSCRIPT = ['ust', 'state', 'sig', 'proof'], SIGK = ['alg', 'key_id', 'pub', 'sig'];
const RES_NAMES = new Set(['ust', 'state', 'sig', 'proof', 'id', 'time', 'data', 'hashes', 'provenance', 'domain_shard', 'ust_id', 'key_id', 'class', 'parent_ust', 'kind', 'value', 'privacy', 'commit', 'enc', 'sources', 'constituents', 'based_on', 'root', 'seed', 'prev', 'alg', 'pub', 'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
// §4.4/§5 domain K (REGISTRY.partitionKinds, F.1.1). A clean-room verifier must NOT import the core, so this
// literal is the second enumeration BY DESIGN — and `spec-code-sync` diffs it against the registry, because
// #154: omitting `absence` refused every live document of the reference operator with E-MALFORMED. The
// obligation is EQUALITY with K, in both directions.
const KINDS = ['captured', 'computed', 'absence'], PRIVACY = ['blinded', 'encrypted'];

// §14 LIGHT floor verify (from the spec). Async. Returns {result, identity, publisher, ust_id, class, content_hash}.
export async function verify(doc, opts = {}) {
  try {
    if (!doc || typeof doc !== 'object') return bad('E-MALFORMED', 'not an object');
    if (doc.ust !== '1.0') { const m = /^(\d+)\.(\d+)$/.exec(doc.ust || ''); return bad('E-MALFORMED', m && m[1] === '1' ? 'minor > 0 unsupported' : 'unsupported ust version'); }
    for (const k of Object.keys(doc)) if (!TRANSCRIPT.includes(k)) return bad('E-MALFORMED', 'unknown top-level member: ' + k);  // §4.1 fail-closed
    const st = doc.state; if (!st || !st.id || !st.time || !st.data || !st.hashes) return bad('E-MALFORMED', 'missing state members');
    const id = st.id;
    if (!USTID.test(id.ust_id || '')) return bad('E-MALFORMED', 'bad ust_id');
    if (!idCal(id.ust_id)) return bad('E-MALFORMED', 'ust_id date not on the calendar');
    if (!CLASSES.includes(id.class)) return bad('E-MALFORMED', 'bad class');
    if (!TS.test(st.time.generated_at || '') || !TS.test(st.time.valid_from || '') || !TS.test(st.time.valid_to || '')) return bad('E-MALFORMED', 'bad timestamp (not ISO-Z)');
    for (const t of [st.time.generated_at, st.time.valid_from, st.time.valid_to]) if (!tsCal(t)) return bad('E-MALFORMED', 'timestamp date not on the calendar');
    if (KEYID_FORM.test(id.domain_shard) && id.domain_shard !== id.key_id) return bad('E-MALFORMED', 'key-form domain_shard != key_id (self-certifying)');
    // W3 / F.5e.4 — the verification ROLE is a PARTITION of classes, and a partition enforced on ONE SIDE is not
    // one. This file checked only the first line for a year: an `observation`, `attestation` or `derivation`
    // presented in the KEY context was admitted here and refused by the reference — three more permissive-
    // direction cells, found the moment this gate started enumerating the corpus instead of a hand battery.
    // The set is written ONCE and read in both directions, because two hand-typed lists is how it went one-sided.
    const AUTHORITY_CLASSES = ['genesis', 'key', 'cadence'];
    const isAuthority = AUTHORITY_CLASSES.includes(id.class);
    if (opts.context === 'data' && isAuthority) return bad('E-MALFORMED', 'class ' + id.class + ' not valid in data context (W3)');
    if (opts.context === 'key' && !isAuthority) return bad('E-MALFORMED', 'class ' + id.class + ' not valid in key context (W3) — the key role admits exactly ' + AUTHORITY_CLASSES.join('/'));
    // step 2 — content_hash + bijection + per-partition
    const ch = await contentHash(doc);
    // §13 structural bounds — the SAME hard ceilings as the reference verifier (I4:
    // two conforming verifiers must never disagree; the 2026-07-12 boundary probe
    // caught this file admitting 65+ partitions the reference rejects).
    {
      // rc.12 P0-1: UTF-8 BYTES (TextEncoder), never UTF-16 .length — Cyrillic/CJK diverge 2×.
      // Cheap DoS gate here; the NORMATIVE size decision moves to the canonical S below (same
      // metric as the reference — transport formatting can never flip a verdict).
      if (new TextEncoder().encode(JSON.stringify(doc)).byteLength > 67_108_864) return bad('E-BOUNDS', 'transcript > 64 MiB');
      const depthOf = (v, d = 0) => (v && typeof v === 'object'
        ? (d > 8 ? d : Math.max(d, ...Object.values(v).map((x) => depthOf(x, d + 1))))
        : d);
      if (depthOf(st) > 8) return bad('E-BOUNDS', 'nesting depth > 8');
      const arrTooLong = (v) => Array.isArray(v) ? (v.length > 4096 || v.some(arrTooLong))
        : (v && typeof v === 'object' ? Object.values(v).some(arrTooLong) : false);
      if (arrTooLong(st)) return bad('E-BOUNDS', 'array length > 4096');
      const nParts = Object.keys(st.data).length;
      if (nParts > 4096) return bad('E-BOUNDS', 'partitions > 4096');
      // §13 capacity ladder: a TRUSTED grant (opts.capacity — the OUTPUT of authority resolution,
      // e.g. ./ust-resolve.mjs; never a raw caller-attached genesis) admits above the floor, ABS stays.
      if (nParts > 64 && !(Number(opts.capacity?.maxPartitions) >= nParts)) {
        if (/^sha256:[0-9a-f]{64}$/.test(st.id.domain_shard)) return bad('E-BOUNDS', `partitions ${nParts} > 64 anonymous floor (key-form)`);
        return { result: 'INDETERMINATE', reason: 'unavailable', detail: `partitions ${nParts} > 64 floor — capacity is genesis-declared; supply the publisher genesis to a genesis-aware verifier` };
      }
      const pr0 = st.provenance;
      for (const f of ['based_on', 'constituents'])
        if (pr0 && Array.isArray(pr0[f]) && pr0[f].length > 64) return bad('E-BOUNDS', f + ' breadth > 64');
    }
    const dk = Object.keys(st.data), hk = Object.keys(st.hashes);
    if (dk.length === 0) return bad('E-MALFORMED', 'no partitions');
    if (dk.length !== hk.length || !dk.every((k) => k in st.hashes)) return bad('E-MALFORMED', 'data⇄hashes bijection broken');
    const HASH = /^sha256:[0-9a-f]{64}$/, B64URL = /^[A-Za-z0-9_-]+$/, AEAD = ['AES-256-GCM', 'XChaCha20-Poly1305'];
    for (const name of dk) {
      if (RES_NAMES.has(name)) return bad('E-MALFORMED', 'reserved partition name: ' + name);
      const part = st.data[name];
      if (!KINDS.includes(part.kind)) return bad('E-MALFORMED', 'unknown partition kind: ' + name + '.' + part.kind);
      if (part.privacy === undefined) { if (part.value === undefined) return bad('E-MALFORMED', 'public partition without value: ' + name); }
      else {
        if (!PRIVACY.includes(part.privacy)) return bad('E-MALFORMED', 'unknown privacy: ' + name);
        if (!HASH.test(part.commit || '')) return bad('E-MALFORMED', 'private commit not sha256:hex: ' + name);       // F5
        if (part.privacy === 'encrypted') { const e = part.enc; if (!e || !AEAD.includes(e.alg) || typeof e.key_id !== 'string' || !B64URL.test(e.ct || '')) return bad('E-MALFORMED', 'encrypted missing/invalid enc: ' + name); }
      }
      const want = await partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value, commit: part.commit });
      if (want !== st.hashes[name]) return bad('E-MALFORMED', 'partition hash mismatch: ' + name);
    }
    // §S4/F4 — class ↔ provenance consistency (signed gap record = the only attestation with empty constituents)
    const pr = st.provenance;
    if (id.class === 'observation' && (pr?.constituents !== undefined || pr?.root !== undefined)) return bad('E-MALFORMED', 'observation MUST NOT carry constituents/root');
    if (id.class === 'derivation' && (pr?.based_on === undefined || pr?.seed === undefined)) return bad('E-MALFORMED', 'derivation MUST carry based_on + seed');
    // §11.3 — a cadence entry is the key-log pattern for the stream grid: it MUST be chained and MUST carry the op, or a
    // bare doc with the same domain could pose as a cadence declaration. Mirrors the reference rule exactly.
    if (id.class === 'cadence' && (pr?.prev === undefined || st.data?.cadence_op === undefined)) return bad('E-MALFORMED', 'cadence entry MUST carry provenance.prev + a cadence_op partition');
    // §14a obligations: every commitment-bearing provenance member is RECOMPUTED (no present-but-unchecked).
    const HASHREF = /^sha256:[0-9a-f]{64}$/;
    if (pr?.based_on !== undefined) {
      if (!Array.isArray(pr.based_on) || pr.based_on.some((b) => !b || !HASHREF.test(b.hash || ''))) return bad('E-MALFORMED', 'based_on entries must carry sha256:hex hash');
      if (new Set(pr.based_on.map((b) => b.hash)).size !== pr.based_on.length) return bad('E-MALFORMED', 'duplicate hash in based_on');
      if ((await H('ust:seed', canon(pr.based_on.map((b) => b.hash)))) !== pr.seed) return bad('E-SEED', 'derivation seed mismatch');
    }
    if (pr?.constituents !== undefined) {
      if (!Array.isArray(pr.constituents) || pr.constituents.some((h) => !HASHREF.test(h))) return bad('E-MALFORMED', 'constituents must be sha256:hex');
      if (new Set(pr.constituents).size !== pr.constituents.length) return bad('E-MALFORMED', 'duplicate hash in constituents');
      if (pr.root !== undefined && (await merkleRoot(pr.constituents)) !== pr.root) return bad('E-ROOT', 'attestation root mismatch');
    }
    // §11.3 C2 — the attestation SUBTYPE is the named data partition, never a shape. This used to read "prev +
    // empty constituents ⇒ a gap, the only exception", which is the PRE-C2 rule: it admitted a bare prev-only
    // attestation (the checkpoint/gap collision C2 closed), a checkpoint or gap carrying a root, and two named
    // subtypes at once — seven cells where this verifier answered VALID:LIGHT and the reference answered
    // E-MALFORMED, in the permissive direction, on a surface a stranger runs in a browser. The parity battery
    // was green because no vector exercised a subtype. Declared here rather than imported: this file is
    // clean-room BY DESIGN, so the two lists are meant to be independent and the parity gate is what keeps
    // them honest — which is why that gate now enumerates the whole corpus instead of a hand-written sample.
    if (id.class === 'attestation') {
      const empty = pr?.constituents === undefined || pr.constituents.length === 0;
      if (empty) {
        if (pr?.prev === undefined) return bad('E-MALFORMED', 'a no-constituents attestation MUST carry provenance.prev (checkpoint, gap or anchor)');
        const named = ['checkpoint', 'gap', 'anchor'].filter((n) => st.data?.[n] !== undefined);
        if (named.length !== 1) return bad('E-MALFORMED', 'a prev-only attestation MUST carry EXACTLY ONE of data.checkpoint / data.gap / data.anchor');
        const rooted = named[0] === 'anchor';                       // `root` FOLLOWS the subtype, in both directions
        if (rooted && pr?.root === undefined) return bad('E-MALFORMED', 'an anchor attestation MUST carry provenance.root');
        if (!rooted && pr?.root !== undefined) return bad('E-MALFORMED', 'a ' + named[0] + ' attestation MUST NOT carry a root');
      } else if (pr?.root === undefined) return bad('E-MALFORMED', 'a set attestation MUST carry constituents + root');
    }
    // step 4 — authenticity: closed sig schema + alg + key_id consistency + strict Ed25519 over canon({ust,state})
    const S = canon({ ust: doc.ust, state: st });
    // §13 NORMATIVE size ladder at LIGHT (rc.12): metric = UTF-8 bytes of S. This verifier takes no
    // capacity grants, so above the floor a key-form shard fails closed and a name-form shard is
    // honestly UNDECIDABLE here (a genesis-aware verifier with a trusted grant can admit it).
    {
      const sBytes = new TextEncoder().encode(S).byteLength;
      if (sBytes > 67_108_864) return bad('E-BOUNDS', `canonical transcript ${sBytes} B > 64 MiB ABS`);
      if (sBytes > 1_048_576 && !(Number(opts.capacity?.maxTranscriptBytes) >= sBytes)) {
        if (/^sha256:[0-9a-f]{64}$/.test(st.id.domain_shard)) return bad('E-BOUNDS', `canonical size ${sBytes} B > 1 MiB anonymous floor (key-form)`);
        return { result: 'INDETERMINATE', reason: 'unavailable', detail: `canonical size ${sBytes} B > 1 MiB floor — capacity requires a trusted grant this LIGHT verifier does not take` };
      }
    }
    if (!doc.sig || typeof doc.sig !== 'object') return bad('E-SIG', 'sig missing');
    for (const k of Object.keys(doc.sig)) if (!SIGK.includes(k)) return bad('E-SIG', 'unknown sig member: ' + k);
    if (doc.sig.alg !== 'Ed25519') return bad('E-SIG', 'sig.alg must be Ed25519');
    if (doc.sig.key_id !== id.key_id) return bad('E-SIG', 'sig.key_id != state.id.key_id');
    if (doc.sig.pub === undefined) return bad('E-KEY', 'no carried pub (LIGHT)');
    if ((await keyId(doc.sig.pub)) !== id.key_id) return bad('E-SIG', 'key_id != H(ust:keylog, pub)');
    if (!(await edVerifyStrict(doc.sig.pub, S, doc.sig.sig))) return bad('E-SIG', 'Ed25519 (strict) verify failed');
    // round-53 retired the `pinned`/TOFU rung: a domain claim survives hijack / key-loss / compromise ONLY through
    // genesis, so a bare key is `self-asserted` and nothing else. This file kept the rung after the reference dropped
    // it, and the divergence was a VERDICT one, not a label one — measured: with `pinnedKeys` naming other keys the
    // reference returned VALID:LIGHT while this file returned INVALID E-KEY on the SAME document. The parity battery
    // never passed the option, so it compared two implementations only on inputs where they happened to agree.
    const strength = 'self-asserted';
    // §12: a TRUSTED authority result (the OUTPUT of resolution with a confirmed no-fork witness)
    // lifts the tier — the NAME becomes the verified publisher. Without it: §Y3, claimed label only.
    const provOut = { depth: 0, referents: (pr?.based_on?.length || pr?.constituents?.length) ? 'unverified' : 'none' };
    if (opts.authority && opts.authority.publisher === id.domain_shard) {
      return { result: 'VALID:HIGH', tier: 'HIGH', identity: { strength: 'authoritative', status: 'verified', mode: 'name' }, publisher: id.domain_shard, ust_id: id.ust_id, class: id.class, content_hash: ch,
        provenance: provOut, completeness: 'not_evaluated' };
    }
    // round-53 (UST-ybn) — PARITY with ust-protocol: at the LIGHT floor (no authority above) a NAME-FORM domain_shard is a
    // domain claim this verifier cannot confirm ⇒ INDETERMINATE (never a bare VALID — the forgery-misread). A key-form shard
    // = a self-asserted key-identity stays VALID:LIGHT. Exempt the authority-establishing classes (a genesis DECLARES its name;
    // key/cadence continue the key-log) — they are name-form by nature and verified via their own chain.
    if (!KEYID_FORM.test(id.domain_shard) && id.class !== 'genesis' && id.class !== 'key' && id.class !== 'cadence')
      return { result: 'INDETERMINATE', reason: 'unavailable', identity: { strength, status: 'verified', mode: 'name' }, ust_id: id.ust_id, class: id.class, content_hash: ch,
        detail: 'name-form domain_shard is a domain claim the LIGHT floor cannot confirm — supply genesis to bind the name (→ HIGH), or use key-form domain_shard = key_id for a key-identity document (→ VALID:LIGHT). "cannot confirm" ⇒ INDETERMINATE (UST-ybn)', provenance: provOut, completeness: 'not_evaluated' };
    return { result: 'VALID:LIGHT', tier: 'LIGHT', identity: { strength, status: 'verified', mode: KEYID_FORM.test(id.domain_shard) ? 'key' : 'name' }, publisher_claimed: id.domain_shard, ust_id: id.ust_id, class: id.class, content_hash: ch,
      provenance: provOut,
      completeness: 'not_evaluated' };
  // #144 — inability leaves by its OWN door. An E-UNSUPPORTED reaching this catch is the verifier saying it
  // could not look; answering INVALID would convert that into an accusation, which is the defect this file
  // carried. Mirrors the reference: INDETERMINATE(unsupported_alg), never a verdict about the document.
  } catch (e) {
    if (e?.code === 'E-UNSUPPORTED') return { result: 'INDETERMINATE', reason: 'unsupported_alg', detail: e.detail || String(e) };
    return bad(e.code || 'E-MALFORMED', e.detail || String(e));
  }
}

// §11.3 completeness — verify a RANGE as ONE authority's prev-chained stream (LIGHT per-frame + chain + authority).
// Async (per-frame verify + contentHash are async). Mirrors ust-protocol.verifyStream so the two cross-check.
//
// It did NOT mirror it, and the comment above went unchecked for as long as it existed: this returned
// `complete: 'proven'` — a word the reference vocabulary (none | provisional | chain-consistent | complete) does not
// contain — on nothing more than chain consistency plus a matching head and frame_count. That evidence is exactly what
// the reference calls `chain-consistent`: no-deletion. Meanwhile the reference, holding the SAME bytes for a stream with
// a missing grid slot, refused completeness and NAMED the hole. The public page was telling a user "proven" while a
// frame was absent — our own verifier crossing the assurance-never-self-declared line. Nothing compared the two: the
// parity gate covered verify() only, so the stream path had never been measured against the reference at all.
//
// Now: the reference vocabulary, the interval-faithfulness check, and the cadence grid. `complete` (no-omission) is
// reachable ONLY through grid equality; without a resolved cadence the ceiling is `chain-consistent`, stated as such.
export async function verifyStream(frames, { genesis, checkpoint, cadence, keylog = [] } = {}) {
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  const authority = frames[0].state.id.domain_shard;
  let prevHash = genesis ? await contentHash(genesis) : null;
  // §12.2 — the authority's key set, resolved from the SIGNED genesis and its key log. A key_id maps to the
  // exact `pub` the authority declared, so a frame reusing a bound key_id under a different key is refused too.
  // Revocation WINDOWS need anchored time and are not decided here (the same boundary ust-resolve.mjs states);
  // what IS decided is membership, which is what impersonation turns on.
  let boundKeys = null;
  if (genesis) {
    if (genesis.state?.id?.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'genesis domain_shard != stream authority (' + authority + ')' };
    if (!Array.isArray(keylog)) return { error: 'E-MALFORMED', detail: 'key log must be an array' };
    boundKeys = new Map([[genesis.state.id.key_id, genesis.state.data?.genesis?.value?.pub]]);
    let kprev = prevHash;
    for (const [i, e] of keylog.entries()) {
      const ev = await verify(e, { context: 'key' });
      if (ev.error) return { error: 'E-AUTHORITY', detail: 'key-log entry ' + i + ' does not verify: ' + ev.error };
      if (e.state.id.class !== 'key') return { error: 'E-AUTHORITY', detail: 'key-log entry ' + i + ' is not class:key' };
      if (e.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'key-log entry ' + i + ' domain mismatch' };
      if (e.state.provenance?.prev !== kprev) return { error: 'E-AUTHORITY', detail: 'key-log entry ' + i + ' does not chain' };
      if (!boundKeys.has(e.sig.key_id)) return { error: 'E-AUTHORITY', detail: 'key-log entry ' + i + ' is not signed by a then-current key' };
      const op = e.state.data?.key_op?.value ?? {};
      if (op.op === 'add' && op.pub) boundKeys.set(await keyId(op.pub), op.pub);
      if (op.op === 'revoke' && op.pub) boundKeys.delete(await keyId(op.pub));
      kprev = await contentHash(e);
    }
  }
  const seenUstId = new Set(), seenPrev = new Set();
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    const v = await verify(f, { context: 'data' });
    // round-53 (UST-ybn), swept here in rev85: fail only on a real INTEGRITY error. A name-form frame with a
    // valid signature is INDETERMINATE — identity is unconfirmed at bare LIGHT — and that is a SEPARATE axis
    // from the stream's completeness. Demanding `VALID:` here answered E-SIG, a forgery signal, for an honest
    // name-form stream: the reference fixed this two rounds ago and the clean-room copy never received it.
    if (v.error) return { error: 'E-SIG', detail: 'frame ' + i + ' invalid: ' + v.error };
    if (f.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' domain_shard != stream authority' };
    // #75 P0-03b, swept here in rev85 — WITHOUT this, an impostor's frames chained onto a VICTIM'S genesis hash
    // were reported `complete` UNDER THE VICTIM'S NAME. The reference closed it after an external audit; this
    // clean-room copy never received it, and the parity battery could not see it because every hand-written
    // stream case was key-form, where `domain_shard == key_id` makes impersonation impossible by construction.
    // The LIGHT `domain_shard` is a CLAIM; binding to the authority's key set is the proof.
    if (boundKeys && boundKeys.get(f.state.id.key_id) !== f.sig.pub) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' key not bound to the authority key-log — impersonation (key ∉ K_A, §12.2)' };
    if (seenUstId.has(f.state.id.ust_id)) return { error: 'E-PREV', detail: 'duplicate ust_id (fork): ' + f.state.id.ust_id };
    seenUstId.add(f.state.id.ust_id);
    const p = f.state.provenance?.prev;
    if (i === 0) { if (genesis && p !== prevHash) return { error: 'E-PREV', detail: 'first frame prev != genesis content_hash' }; }
    else if (p !== prevHash) return { error: 'E-PREV', detail: 'frame ' + i + ' prev dangling' };
    if (p && seenPrev.has(p)) return { error: 'E-PREV', detail: 'two frames share a prev (fork)' };
    if (p) seenPrev.add(p);
    prevHash = await contentHash(f);
  }
  if (checkpoint) {
    if (!genesis) return { complete: 'provisional', head: prevHash, reason: 'origin-unbound: no genesis (TOP needs a HIGH origin)' };   // F2
    const cv = await verify(checkpoint, { context: 'data' });
    // The SAME pre-round-53 rule stood twice in this one function — once per frame, once here. A name-form
    // checkpoint carries a valid signature and INDETERMINATE identity, which is not an integrity failure, so
    // fixing only the frame loop would have left the identical defect one screen down. Integrity error only.
    if (cv.error || checkpoint.state.id.class !== 'attestation') return { error: 'E-PREV', detail: 'invalid checkpoint' };
    if (checkpoint.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'checkpoint not from the stream authority' };
    const a = checkpoint.state.data.checkpoint?.value;
    if (!a || a.head !== prevHash || String(a.frame_count) !== String(frames.length)) return { error: 'E-PREV', detail: 'checkpoint contradicts observed set' };
    if (a.from === undefined || a.to === undefined) return { complete: 'chain-consistent', head: prevHash };
    // The interval MUST faithfully BOUND the observed set, or the checkpoint covers a different range than the one in
    // hand: first == from, last == to, and no frame outside. Without this a valid checkpoint for a NEIGHBOURING range
    // would license this one.
    const ustE = (u) => { const m = /^ust:(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})?(\d{2})?$/.exec(u || ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +(m[5] ?? 0), +(m[6] ?? 0)) / 1000 : null; };
    const fromE = ustE(a.from), toE = ustE(a.to);
    if (frames[0].state.id.ust_id !== a.from) return { error: 'E-PREV', detail: 'first frame != checkpoint `from` (' + a.from + ')' };
    if (frames[frames.length - 1].state.id.ust_id !== a.to) return { error: 'E-PREV', detail: 'last frame != checkpoint `to` (' + a.to + ')' };
    for (const f of frames) { const e = ustE(f.state.id.ust_id); if (e === null || fromE === null || toE === null || e < fromE || e > toE) return { error: 'E-PREV', detail: 'frame outside the checkpoint interval: ' + f.state.id.ust_id }; }

    // §11.3 — no-omission needs the SIGNED grid. The caller resolves the cadence (resolveCadence in ./ust-resolve.mjs)
    // and passes seconds; absent or unresolved, the ceiling is `chain-consistent` and it is reported as that, never more.
    const secs = typeof cadence === 'string' && /^[1-9]\d*$/.test(cadence) ? Number(cadence) : (Number.isSafeInteger(cadence) && cadence > 0 ? cadence : null);
    if (secs === null) return { complete: 'chain-consistent', head: prevHash, interval: { from: a.from, to: a.to } };
    const prec = secs % 3600 === 0 ? 'h' : (secs % 60 === 0 ? 'm' : 's');
    const pad = (n) => String(n).padStart(2, '0');
    const toUst = (e) => { const d = new Date(e * 1000); const base = `ust:${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}.${pad(d.getUTCHours())}`; return prec === 'h' ? base : (prec === 'm' ? base + pad(d.getUTCMinutes()) : base + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds())); };
    const grid = [];
    for (let e = fromE; e <= toE; e += secs) { grid.push(toUst(e)); if (grid.length > 200000) return { complete: 'chain-consistent', head: prevHash, interval: { from: a.from, to: a.to }, detail: 'grid exceeds the §13 bound — not evaluated' }; }
    const gridSet = new Set(grid), covered = new Set();
    for (const f of frames) {
      const c = f.state.id.class;
      const slotBearing = c === 'observation' || c === 'derivation' || (c === 'attestation' && f.state.data?.gap !== undefined);
      if (!slotBearing) continue;
      if (!gridSet.has(f.state.id.ust_id)) return { error: 'E-PREV', detail: 'off-grid frame ' + f.state.id.ust_id + ' is not a slot of the signed cadence grid' };
      covered.add(f.state.id.ust_id);
    }
    const hole = grid.find((s) => !covered.has(s));
    if (hole) return { complete: 'chain-consistent', head: prevHash, interval: { from: a.from, to: a.to }, hole, detail: 'grid slot ' + hole + ' has no frame and no signed gap record' };
    return { complete: 'complete', head: prevHash, interval: { from: a.from, to: a.to }, cadence: String(secs), grid_slots: String(grid.length) };
  }
  return { complete: 'provisional', head: prevHash };
}
