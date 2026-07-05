// ust-protocol — reference implementation of UST 1.0 (the official STATELESS base; the public verification lib) (REV 24), LIGHT floor first.
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
// §10 encrypted: AEAD-decrypt to recover the committed plaintext canon({nonce,<name>:value}). AES-256-GCM here
// (node:crypto); XChaCha20-Poly1305 needs @noble/ciphers (browsers/Workers). enc.ct = b64url(iv12 || ct || tag16).
function aeadDecrypt(enc, keyRawB64url) {
  try {
    if (enc.alg !== 'AES-256-GCM') return null;                         // XChaCha20-Poly1305: use @noble/ciphers
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

// ─── producer: §7 seal — sign canon({ust,state}) with an Ed25519 private key ─────────────────────────
export function seal(state, privKeyObj, pubB64url) {
  const doc = { ust: '1.0', state };
  const sig = edSign(null, Buffer.from(signedContent(doc), 'utf8'), privKeyObj).toString('base64url');
  return { ust: '1.0', state, sig: { alg: 'Ed25519', key_id: state.id.key_id, pub: pubB64url, sig } };
}

// ─── producer helpers: assemble a State with the per-partition `hashes` auto-computed (§4.4). `seal` signs it.
//     `id` = {domain_shard, ust_id, key_id[, parent_ust]}. `data` = {name: {kind,value} | {kind,privacy,commit,enc?}}.
export function buildState(id, time, data, provenance) {
  const hashes = {};
  for (const [name, part] of Object.entries(data))
    hashes[name] = part.commit !== undefined ? partitionHash({ commit: part.commit })
      : partitionHash({ domain_shard: id.domain_shard, ust_id: id.ust_id, name, value: part.value });
  const state = { id, time, data, hashes };
  if (provenance) state.provenance = provenance;
  return state;
}
export const buildAttestation = (id, time, data, constituents, prev) =>            // §9.2 constituents + Merkle root
  buildState({ ...id, class: 'attestation' }, time, data, { constituents, root: merkleRoot(constituents), ...(prev !== undefined ? { prev } : {}) });
export const buildDerivation = (id, time, data, basedOn, prev) =>                  // §9.3/§9.4 based_on + seed
  buildState({ ...id, class: 'derivation' }, time, data, { based_on: basedOn, seed: seed(basedOn.map(b => b.hash)), ...(prev !== undefined ? { prev } : {}) });
export const buildGenesis = (id, time, pub) =>                                     // §12.1 self-signed name-binding root
  buildState({ ...id, class: 'genesis' }, time, { genesis: { kind: 'captured', value: { pub, role: 'name-binding-root' } } });
export const buildKeyLogEntry = (id, time, keyOp, prev) =>                         // §12.2 add|rotate|revoke
  buildState({ ...id, class: 'key' }, time, { key_op: { kind: 'captured', value: keyOp } }, { prev });
export const buildCheckpoint = (id, time, head, frameCount, prev) =>              // §11.3 M5
  buildState({ ...id, class: 'attestation' }, time, { checkpoint: { kind: 'computed', value: { head, frame_count: String(frameCount) } } }, { prev });

// ─── reserved-key sets (§3/§4.2/§17) ─────────────────────────────────────────────────────────────────
const RESERVED = { transcript: ['ust','state','sig','proof'], state: ['id','time','data','hashes','provenance'],
  id: ['domain_shard','ust_id','key_id','class','parent_ust'], envelope: ['kind','value','privacy','commit','enc'],
  sig: ['alg','key_id','pub','sig'] };
const RES_PARTITION_NAMES = new Set([...RESERVED.state, ...RESERVED.id, 'partition', 'nonce', '__proto__', 'constructor', 'prototype']);
const KINDS = ['captured', 'computed'], PRIVACY = ['blinded', 'encrypted'];
const CLASSES = ['observation','attestation','derivation','genesis','key'];
// §6 pinned RFC3339 UTC-Z with VALID RANGES — month 01-12, day 01-31, hour 00-23, min/sec 00-59.
// Rejects leap seconds (:60) and out-of-range (:99, hour 99) so two conforming verifiers ALWAYS agree (I4).
// Publishers MUST smear leap seconds to :59 (there is no representable :60).
const TS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
const USTID = /^ust:\d{8}\.\d{2}(\d{2}(\d{2})?)?$/;                        // §8

// ─── §13 structural bounds — hard ceilings; exceed ⇒ E-BOUNDS ─────────────────────────────────────────
const BOUNDS = { depth: 8, array: 4096, partitions: 64, breadth: 64, sizeBytes: 1048576 };
export function checkBounds(doc) {
  if (Buffer.byteLength(JSON.stringify(doc), 'utf8') > BOUNDS.sizeBytes) return 'size > 1 MiB';
  if (doc.state?.data && Object.keys(doc.state.data).length > BOUNDS.partitions) return 'partitions > 64';
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
      if (part.privacy === undefined) { if (!KINDS.includes(part.kind)) return bad('E-MALFORMED', 'unknown partition kind: ' + name + '.' + part.kind); }
      else if (!PRIVACY.includes(part.privacy)) return bad('E-MALFORMED', 'unknown privacy mode: ' + name + '.' + part.privacy);
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
      if (recomputed !== st.hashes[name]) return bad('E-CANON', 'partition hash mismatch: ' + name);
    }
    // step 5 — well-formed shape (§14.5)
    if (!USTID.test(st.id.ust_id)) return bad('E-MALFORMED', 'ust_id shape');
    if (!TS.test(st.time.generated_at) || !TS.test(st.time.valid_from) || !TS.test(st.time.valid_to)) return bad('E-MALFORMED', 'timestamp not pinned RFC3339-Z');
    if (st.time.valid_from > st.time.valid_to) return bad('E-MALFORMED', 'valid_from > valid_to');
    if (!CLASSES.includes(st.id.class)) return bad('E-MALFORMED', 'unknown class ' + st.id.class);
    if (dk.length < 1) return bad('E-MALFORMED', 'no partition');
    for (const name of dk) {                                            // private partitions carry a commit
      const part = st.data[name];
      if (part.privacy !== undefined && part.commit === undefined) return bad('E-MALFORMED', 'private partition without commit: ' + name);
      if (part.privacy === undefined && part.value === undefined) return bad('E-MALFORMED', 'public partition without value: ' + name);
    }
    // W3 class-context: a data verify must not accept a key-log/genesis transcript as data
    if (opts.context === 'data' && (st.id.class === 'key' || st.id.class === 'genesis')) return bad('E-MALFORMED', 'class ' + st.id.class + ' not valid in data context (W3)');
    // step 4 — authenticity (§14.4): closed sig schema + declared alg + key_id consistency + strict Ed25519 over S
    if (typeof doc.sig !== 'object' || doc.sig === null) return bad('E-SIG', 'sig missing');
    for (const k of Object.keys(doc.sig)) if (!RESERVED.sig.includes(k)) return bad('E-SIG', 'unknown sig member: ' + k);
    if (doc.sig.alg !== 'Ed25519') return bad('E-SIG', 'sig.alg must be Ed25519');
    if (doc.sig.key_id !== st.id.key_id) return bad('E-SIG', 'sig.key_id != state.id.key_id');
    if (doc.sig.pub === undefined) return bad('E-KEY', 'no carried pub (LIGHT)');
    if (keyId(doc.sig.pub) !== st.id.key_id) return bad('E-SIG', 'key_id != H(ust:keylog, pub)');
    if (!edVerifyStrict(doc.sig.pub, S, doc.sig.sig)) return bad('E-SIG', 'Ed25519 verify failed');
    // step 3 — name authority (HIGH, §12/§14.3): resolved ONLY if the caller supplies genesis+keylog.
    const identity = opts.genesis ? resolveAuthority(doc, opts) : { strength: 'self-asserted', status: 'verified' };
    if (identity.error) return bad(identity.error, identity.detail);              // forked genesis / broken key-log
    if (opts.requireAuthoritative && !(identity.strength === 'authoritative' && identity.status === 'verified'))
      return identity.status === 'unavailable'
        ? { result: 'INDETERMINATE', reason: 'unavailable', identity, detail: identity.detail }   // W1: retry, NOT failure
        : bad('E-GENESIS', 'authoritative required but ' + identity.strength + '/' + identity.status);
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
    // §14.9 attestation: recompute the Merkle root from constituents (⇒ E-ROOT on mismatch).
    if (st.id.class === 'attestation' && st.provenance?.constituents && st.provenance?.root !== undefined)
      if (merkleRoot(st.provenance.constituents) !== st.provenance.root) return bad('E-ROOT', 'attestation root mismatch');
    return { result: 'VALID', identity, disclosed, sources,
      publisher: st.id.domain_shard, ust_id: st.id.ust_id, class: st.id.class, content_hash: ch,
      time: { strength: 'unproven', status: doc.proof ? 'present' : 'none' } };
  } catch (e) {
    return bad(e.code || 'E-MALFORMED', e.detail || String(e));         // fail-closed (§14/I10)
  }
}

// ─── §12 HIGH name-authority resolution. STATELESS: the caller (ustate/engine) supplies the genesis +
//     key-log transcripts (retrieval is the stateful layer's job) and asserts no-fork from the witness (W1).
export function resolveAuthority(doc, { genesis, keylog = [], noForkConfirmed = false, anchorTime } = {}) {
  if (!genesis) return { strength: 'self-asserted', status: 'verified' };         // LIGHT — nothing to resolve
  const gv = verify(genesis);                                                     // genesis is itself a UST transcript
  if (gv.result !== 'VALID') return { error: 'E-GENESIS', detail: 'genesis invalid: ' + gv.error };
  if (genesis.state.id.class !== 'genesis') return { error: 'E-GENESIS', detail: 'not class:genesis' };
  if (genesis.sig.key_id !== genesis.state.id.key_id) return { error: 'E-GENESIS', detail: 'genesis not self-signed' };
  if (genesis.state.id.domain_shard !== doc.state.id.domain_shard) return { error: 'E-GENESIS', detail: 'genesis domain mismatch' };
  if (keylog.length > 256) return { error: 'E-BOUNDS', detail: 'key-log > 256 (§13)' };
  let prevHash = contentHash(genesis);
  const validPubs = new Set([genesis.sig.pub]);                                   // genesis key signs the first entry
  const addedKeyIds = new Set([genesis.state.id.key_id]);
  const revoked = new Map();                                                      // §12.2 X1: key_id → {reason, compromised_since, at}
  for (const [i, e] of keylog.entries()) {                                        // §12.2 walk: prev-chained, self-signed
    const ev = verify(e, { context: 'key' });
    if (ev.result !== 'VALID') return { error: 'E-KEY', detail: 'key-log entry ' + i + ' invalid: ' + ev.error };
    if (e.state.id.class !== 'key') return { error: 'E-KEY', detail: 'entry ' + i + ' not class:key' };
    if (e.state.provenance?.prev !== prevHash) return { error: 'E-PREV', detail: 'entry ' + i + ' prev not chained' };
    if (!validPubs.has(e.sig.pub)) return { error: 'E-KEY', detail: 'entry ' + i + ' not signed by a current valid key' };
    const op = e.state.data.key_op.value;
    if (op.op === 'add' || op.op === 'rotate') { validPubs.add(op.pub); addedKeyIds.add(op.new_key_id); }
    else if (op.op === 'revoke') revoked.set(keyId(op.pub), { reason: op.reason, compromised_since: op.compromised_since, at: e.state.time.generated_at });
    prevHash = contentHash(e);
  }
  if (!addedKeyIds.has(doc.state.id.key_id))
    return { strength: 'self-asserted', status: 'verified', detail: 'doc key not in this key-log' };
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
  // W1 — authoritative REQUIRES a positive no-fork confirmation (the witness), the caller/ustate's job.
  if (!noForkConfirmed) return { strength: 'authoritative', status: 'unavailable',
    detail: 'no-fork not confirmed (W1: witness check is the caller job) → authoritative DENIED, retry' };
  return { strength: 'authoritative', status: suspect ? 'suspect' : 'verified' };
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
  if (!sub) return { inclusion: true, time: 'unproven', status: 'unavailable', detail: 'substrate unreachable' };
  if (!sub.final) return { inclusion: true, time: 'unproven', status: 'verified', detail: 'substrate not final (e.g. <6 conf)' };
  return { inclusion: true, time: 'anchored', status: 'verified', anchorTime: sub.time };
}

// ─── TOP §11.3 completeness: a sequenced stream is prev-chained; first frame's prev = genesis content_hash
//     (M4); per-frame validity is verified too (X2 — completeness ≠ validity); duplicate ust_id / shared prev
//     = a fork ⇒ E-PREV (Y1). 'proven' needs a covering checkpoint (M5); else the open tail is 'provisional'.
export function verifyStream(frames, { genesis, checkpoint, requirePerFrameValid = true } = {}) {
  if (!Array.isArray(frames) || !frames.length) return { complete: 'none' };
  let prevHash = genesis ? contentHash(genesis) : null;
  const authority = frames[0].state.id.domain_shard;                   // §11.3: a stream belongs to ONE authority
  const seenUstId = new Set(), seenPrev = new Set();
  for (const [i, f] of frames.entries()) {
    if (requirePerFrameValid) { const v = verify(f, { context: 'data' }); if (v.result !== 'VALID') return { error: 'E-SIG', detail: 'frame ' + i + ' invalid: ' + v.error }; } // X2
    if (f.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'frame ' + i + ' domain_shard != stream authority (' + authority + ') — mixed-authority stream' };
    if (seenUstId.has(f.state.id.ust_id)) return { error: 'E-PREV', detail: 'duplicate ust_id (fork, Y1): ' + f.state.id.ust_id };
    seenUstId.add(f.state.id.ust_id);
    const p = f.state.provenance?.prev;
    if (i === 0) { if (genesis && p !== prevHash) return { error: 'E-PREV', detail: 'first frame prev != genesis content_hash (M4)' }; }
    else if (p !== prevHash) return { error: 'E-PREV', detail: 'frame ' + i + ' prev dangling (broken chain)' };
    if (p && seenPrev.has(p)) return { error: 'E-PREV', detail: 'two frames share a prev (fork, Y1)' };
    if (p) seenPrev.add(p);
    prevHash = contentHash(f);
  }
  // M5 — a COVERING checkpoint (class:attestation asserting head + frame_count) closes the interval → 'proven'.
  if (checkpoint) {
    const cv = verify(checkpoint, { context: 'data' });
    if (cv.result !== 'VALID' || checkpoint.state.id.class !== 'attestation') return { error: 'E-PREV', detail: 'invalid checkpoint' };
    if (checkpoint.state.id.domain_shard !== authority) return { error: 'E-AUTHORITY', detail: 'checkpoint not from the stream authority (' + authority + ') — TOP completeness cannot cross authority' };
    const a = checkpoint.state.data.checkpoint?.value;
    if (!a || a.head !== prevHash || String(a.frame_count) !== String(frames.length))
      return { error: 'E-PREV', detail: 'checkpoint contradicts observed set (M5)' };
    return { complete: 'proven', head: prevHash };
  }
  return { complete: 'provisional', head: prevHash };                  // no checkpoint → open tail (P5)
}

function err(code, detail) { const e = new Error(code); e.code = code; e.detail = detail; return e; }
function bad(code, detail) { return { result: 'INVALID', error: code, detail }; }
