// SPDX-License-Identifier: Apache-2.0
// ust-verify — the canonical BROWSER verifier for UST 1.0, WebCrypto-only, ZERO dependencies. A clean-room
// implementation written FROM THE SPEC (it does NOT import ust-protocol) and cross-checked against ust-protocol on
// the conformance vectors — a second, independent conforming verifier, not a re-export. Runs in browsers, Workers,
// and Node (global crypto.subtle); async. Backs the findable web verifier at
// https://thelabmd.github.io/UST-Protocol/ and is the zero-dep verifier an AI can fetch from the CANONICAL source
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
export async function edVerifyRaw(pub, msg, sig) {                             // WebCrypto ONLY (no strict-S) — to observe its behavior
  try { const k = await crypto.subtle.importKey('raw', b64url(pub), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, k, b64url(sig), te(msg)); } catch { return false; }
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
const CLASSES = ['observation', 'attestation', 'derivation', 'genesis', 'key'];
const TRANSCRIPT = ['ust', 'state', 'sig', 'proof'], SIGK = ['alg', 'key_id', 'pub', 'sig'];
const RES_NAMES = new Set(['id', 'time', 'data', 'hashes', 'provenance', 'domain_shard', 'ust_id', 'key_id', 'class', 'parent_ust', 'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
const KINDS = ['captured', 'computed'], PRIVACY = ['blinded', 'encrypted'];

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
    if (opts.context === 'data' && (id.class === 'key' || id.class === 'genesis')) return bad('E-MALFORMED', 'class ' + id.class + ' not valid in data context (W3)');
    // step 2 — content_hash + bijection + per-partition
    const ch = await contentHash(doc);
    const dk = Object.keys(st.data), hk = Object.keys(st.hashes);
    if (dk.length === 0) return bad('E-MALFORMED', 'no partitions');
    if (dk.length !== hk.length || !dk.every((k) => k in st.hashes)) return bad('E-MALFORMED', 'data⇄hashes bijection broken');
    const HASH = /^sha256:[0-9a-f]{64}$/, B64URL = /^[A-Za-z0-9_-]+$/, AEAD = ['AES-256-GCM', 'XChaCha20-Poly1305'];
    for (const name of dk) {
      if (RES_NAMES.has(name)) return bad('E-MALFORMED', 'reserved partition name: ' + name);
      const part = st.data[name];
      if (!KINDS.includes(part.kind)) return bad('E-MALFORMED', 'unknown kind: ' + name);
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
    // §14a obligations: every commitment-bearing provenance member is RECOMPUTED (no present-but-unchecked).
    const HASHREF = /^sha256:[0-9a-f]{64}$/;
    if (pr?.based_on !== undefined) {
      if (!Array.isArray(pr.based_on) || pr.based_on.some((b) => !b || !HASHREF.test(b.hash || ''))) return bad('E-MALFORMED', 'based_on entries must carry sha256:hex hash');
      if ((await H('ust:seed', canon(pr.based_on.map((b) => b.hash)))) !== pr.seed) return bad('E-SEED', 'derivation seed mismatch');
    }
    if (pr?.constituents !== undefined) {
      if (!Array.isArray(pr.constituents) || pr.constituents.some((h) => !HASHREF.test(h))) return bad('E-MALFORMED', 'constituents must be sha256:hex');
      if (pr.root !== undefined && (await merkleRoot(pr.constituents)) !== pr.root) return bad('E-ROOT', 'attestation root mismatch');
    }
    if (id.class === 'attestation') { const isGap = pr?.prev !== undefined && (pr?.constituents === undefined || pr.constituents.length === 0); if (!isGap && (pr?.constituents === undefined || pr?.root === undefined)) return bad('E-MALFORMED', 'attestation MUST carry constituents + root'); }
    // step 4 — authenticity: closed sig schema + alg + key_id consistency + strict Ed25519 over canon({ust,state})
    const S = canon({ ust: doc.ust, state: st });
    if (!doc.sig || typeof doc.sig !== 'object') return bad('E-SIG', 'sig missing');
    for (const k of Object.keys(doc.sig)) if (!SIGK.includes(k)) return bad('E-SIG', 'unknown sig member: ' + k);
    if (doc.sig.alg !== 'Ed25519') return bad('E-SIG', 'sig.alg must be Ed25519');
    if (doc.sig.key_id !== id.key_id) return bad('E-SIG', 'sig.key_id != state.id.key_id');
    if (doc.sig.pub === undefined) return bad('E-KEY', 'no carried pub (LIGHT)');
    if ((await keyId(doc.sig.pub)) !== id.key_id) return bad('E-SIG', 'key_id != H(ust:keylog, pub)');
    if (!(await edVerifyStrict(doc.sig.pub, S, doc.sig.sig))) return bad('E-SIG', 'Ed25519 (strict) verify failed');
    // §3.1 pinned (TOFU): a key not in the caller's pin set is INVALID; else self-asserted (LIGHT — never authoritative here).
    let strength = 'self-asserted';
    if (opts.pinnedKeys) { if (!opts.pinnedKeys.includes(id.key_id)) return bad('E-KEY', 'key_id not in the pinned set (§3.1 TOFU)'); strength = 'pinned'; }
    // §Y3: not authoritative → `domain_shard` is a claimed LABEL, surfaced as `publisher_claimed`.
    return { result: 'VALID:LIGHT', tier: 'LIGHT', identity: { strength, status: 'verified', mode: KEYID_FORM.test(id.domain_shard) ? 'key' : 'name' }, publisher_claimed: id.domain_shard, ust_id: id.ust_id, class: id.class, content_hash: ch,
      provenance: { depth: 0, referents: (pr?.based_on?.length || pr?.constituents?.length) ? 'unverified' : 'none' } };
  } catch (e) { return bad(e.code || 'E-MALFORMED', e.detail || String(e)); }
}

// §11.3 completeness — verify a RANGE as ONE authority's prev-chained stream (LIGHT per-frame + chain + authority).
// Async (per-frame verify + contentHash are async). Mirrors ust-protocol.verifyStream so the two cross-check.
export async function verifyStream(frames, { genesis, checkpoint } = {}) {
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  const authority = frames[0].state.id.domain_shard;
  let prevHash = genesis ? await contentHash(genesis) : null;
  const seenUstId = new Set(), seenPrev = new Set();
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    const v = await verify(f, { context: 'data' });
    if (v.result.slice(0,6) !== 'VALID:') return { error: 'E-SIG', detail: 'frame ' + i + ' invalid: ' + v.error };
    if (f.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' domain_shard != stream authority' };
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
    if (cv.result.slice(0,6) !== 'VALID:' || checkpoint.state.id.class !== 'attestation') return { error: 'E-PREV', detail: 'invalid checkpoint' };
    if (checkpoint.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'checkpoint not from the stream authority' };
    const a = checkpoint.state.data.checkpoint?.value;
    if (!a || a.head !== prevHash || String(a.frame_count) !== String(frames.length)) return { error: 'E-PREV', detail: 'checkpoint contradicts observed set' };
    return { complete: 'proven', head: prevHash };
  }
  return { complete: 'provisional', head: prevHash };
}
