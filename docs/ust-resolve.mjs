// SPDX-License-Identifier: Apache-2.0
// Clean-room §12 AUTHORITY RESOLUTION for the web verifier — the genesis-aware half that ust-verify.mjs
// (the deliberate LIGHT floor) points to. Walks genesis → key-log, derives the capacity grant, and says
// HONESTLY what a browser can and cannot conclude:
//   · it CAN check the chain (self-signed genesis, prev-links, key_id = H(pub), domain binding);
//   · it CANNOT check revocation windows (X1 needs ANCHORED time) — reported, never guessed;
//   · it CANNOT confirm no-fork by itself (§12.1 needs a witness) — the CALLER asserts that, explicitly.
// The result feeds ust-verify.mjs as TRUSTED opts ({capacity, authority}) — the grant flows FROM
// resolution, never from a raw caller-attached genesis (rc.12).
import { verify, contentHash, keyId } from './ust-verify.mjs';

// SSRF guard (mirror of ust-protocol.isPublicDnsShard): the domain_shard is UNTRUSTED — a document must
// never point this page's fetch at an internal address. Public DNS names only; no IP/localhost/port/path.
export function isPublicDnsShard(shard) {
  if (typeof shard !== 'string' || !shard || shard.length > 253) return false;
  if (/[:/@\s]/.test(shard)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(shard)) return false;
  if (/^[0-9a-f]*:[0-9a-f:]*$/i.test(shard)) return false;
  const lower = shard.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.local') ||
      lower.endsWith('.internal') || lower.endsWith('.home.arpa') || lower.endsWith('.onion')) return false;
  const labels = lower.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return false;
  if (!/^[a-z]{2,}$/.test(labels[labels.length - 1])) return false;
  return true;
}

export async function resolveAuthority(doc, { genesis, keylog = [], noForkConfirmed = false } = {}) {
  if (!genesis) return { error: 'no genesis supplied' };
  const gv = await verify(genesis, { context: 'key' });
  if (gv.result !== 'VALID:LIGHT') return { error: 'genesis does not verify: ' + (gv.error || gv.result) };
  const gid = genesis.state.id;
  if (gid.class !== 'genesis') return { error: 'not class:genesis (class ' + gid.class + ')' };
  if (genesis.sig.key_id !== gid.key_id) return { error: 'genesis is not self-signed' };
  if (gid.domain_shard !== doc.state.id.domain_shard) return { error: `genesis is for ${gid.domain_shard}, the document claims ${doc.state.id.domain_shard}` };
  if (!Array.isArray(keylog)) return { error: 'key log must be an array' };
  if (keylog.length > 256) return { error: 'key log > 256 entries (§13)' };

  const gval = genesis.state.data.genesis?.value ?? {};
  const capacity = {
    ...(gval.max_partitions !== undefined ? { maxPartitions: Number(gval.max_partitions) } : {}),
    ...(gval.max_transcript_bytes !== undefined ? { maxTranscriptBytes: Number(gval.max_transcript_bytes) } : {}),
  };

  // §12.2 walk: each entry is a normal transcript, verified by the same §14, chained by content_hash,
  // signed by a then-current key. add/rotate register keys; revocation WINDOWS are anchored-time
  // semantics a browser cannot decide — surfaced as `revocation: 'not_evaluated'`, never guessed.
  let prev = await contentHash(genesis);
  const valid = new Set([gid.key_id]);
  for (const [i, e] of keylog.entries()) {
    const ev = await verify(e, { context: 'key' });
    if (ev.result !== 'VALID:LIGHT') return { error: `key-log entry ${i} does not verify: ` + (ev.error || ev.result) };
    if (e.state.id.class !== 'key') return { error: `key-log entry ${i} is not class:key` };
    if (e.state.id.domain_shard !== gid.domain_shard) return { error: `key-log entry ${i} domain mismatch` };
    if (e.state.provenance?.prev !== prev) return { error: `key-log entry ${i} does not chain (prev != previous content_hash)` };
    if (!valid.has(e.sig.key_id)) return { error: `key-log entry ${i} is not signed by a then-current key` };
    const op = e.state.data.key_op?.value ?? {};
    if ((op.op === 'add' || op.op === 'rotate') && op.pub) {
      const kid = await keyId(op.pub);
      if (op.new_key_id !== undefined && op.new_key_id !== kid) return { error: `key-log entry ${i}: new_key_id != H(ust:keylog, pub)` };
      valid.add(kid);
    }
    prev = await contentHash(e);
  }

  if (!valid.has(doc.state.id.key_id)) return { error: 'the document key is NOT in the resolved key set of ' + gid.domain_shard };
  return {
    publisher: gid.domain_shard,
    capacity,
    keyResolved: true,
    noFork: noForkConfirmed ? 'asserted-by-caller' : 'unconfirmed',
    revocation: 'not_evaluated',   // X1 windows need anchored time — beyond a browser's information set
    genesisHash: await contentHash(genesis),
  };
}

// ─── §11.3 CADENCE — the grid a completeness claim is measured against. The publisher signs it, so a verifier can
// count: with a declared cadence a missing slot is a NAMED hole, without one the publisher's silence is unfalsifiable
// and its ceiling is no-deletion. This is the clean-room half; the reference implementation is the authority on
// semantics and both are pinned by the `cadence-resolve` vectors.
//
// ONE deliberate refusal rather than a weaker answer: the reference requires a CURRENTLY-ACTIVE signer — a retired,
// rotated-out or revoked key cannot move the grid. This verifier does not model that state machine (revocation windows
// need anchored time, which is why `resolveAuthority` reports `revocation: 'not_evaluated'`), and its key set is
// ever-registered, not active. Where the two coincide — a key log of pure add/rotate, which is the ordinary case — the
// answer is exact. Where a revoke/retire exists the set would be WIDER than the reference's, so this returns
// `unresolved` instead of a number it cannot stand behind. A verifier that accepts a signer the reference rejects is
// the divergence class this file already paid for once.
export async function resolveCadence(genesis, cadenceLog = [], atTime, { keylog = [] } = {}) {
  const INT = /^([1-9]\d*)$/;                                     // canonical positive integer seconds — no sign, no fraction, no leading zero
  const parseSecs = (s) => (typeof s === 'string' && INT.test(s) && Number(s) <= 31622400 ? Number(s) : null);
  const epoch = (u) => {
    const m = /^ust:(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})?(\d{2})?$/.exec(u || '');
    return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +(m[5] ?? 0), +(m[6] ?? 0)) / 1000 : null;
  };
  if (!genesis) return { error: 'no genesis supplied' };
  if (!Array.isArray(cadenceLog)) return { error: 'E-MALFORMED', detail: 'cadenceLog must be an array' };
  if (cadenceLog.length > 256) return { error: 'E-BOUNDS', detail: 'cadence-log > 256 (§13)' };
  const gCad = genesis.state?.data?.genesis?.value?.cadence;
  if (gCad !== undefined && parseSecs(gCad) === null) return { error: 'E-MALFORMED', detail: 'genesis cadence is not canonical integer seconds (§11.3)' };
  let cadence = gCad !== undefined ? parseSecs(gCad) : null;      // the genesis value is authorized by construction (self-signed)
  if (!cadenceLog.length) return { cadence };

  const auth = await resolveAuthority(cadenceLog[0], { genesis, keylog });
  if (auth.error && !/document key is NOT in/.test(auth.error)) return { error: 'E-AUTHORITY', detail: 'cadence authority: ' + auth.error };
  if (keylog.some((e) => { const op = e?.state?.data?.key_op?.value?.op; return op && op !== 'add' && op !== 'rotate'; }))
    return { unresolved: 'the key log contains a revoke/retire — deciding a CURRENTLY-ACTIVE signer needs anchored time, which this verifier does not evaluate' };

  // §F.5e.3 / #107 — cadence mutation is ROOT-ONLY. This resolver used to accumulate every key the log ADDED and
  // accept any of them, which is precisely the hole the reference carried: an operational key could re-declare the
  // grid and rewrite what `complete` means. The root is a single key known from the genesis, so the second
  // implementation needs no key accumulation here at all — and the revoked-root case is already the `unresolved`
  // above, since this verifier does not evaluate anchored time.
  const rootKid = genesis.state.id.key_id;

  const atE = epoch(atTime);
  let prev = await contentHash(genesis), lastEff = null;
  for (const [i, e] of cadenceLog.entries()) {
    const ev = await verify(e, { context: 'key' });
    if (ev.result !== 'VALID:LIGHT') return { error: 'E-KEY', detail: `cadence entry ${i} invalid: ` + (ev.error || ev.result) };
    if (e.state.id.class !== 'cadence') return { error: 'E-MALFORMED', detail: `cadence-log entry ${i} not class:cadence` };
    if (e.state.id.domain_shard !== genesis.state.id.domain_shard) return { error: 'E-AUTHORITY', detail: `cadence entry ${i} domain mismatch` };
    if (e.state.provenance?.prev !== prev) return { error: 'E-PREV', detail: `cadence entry ${i} not chained` };
    if (e.sig.key_id !== rootKid) return { error: 'E-KEY', detail: `cadence entry ${i} cadence mutation requires the GENESIS ROOT (§F.5e.3, §11.3) — an operational key may sign documents, not redefine what "complete" means` };
    const op = e.state.data.cadence_op?.value ?? {};
    const effE = epoch(op.effective_from);
    if (effE === null) return { error: 'E-MALFORMED', detail: `cadence entry ${i} bad effective_from` };
    if (lastEff !== null && effE < lastEff) return { error: 'E-PREV', detail: `cadence effective_from not monotonic (entry ${i})` };
    if (parseSecs(op.cadence) === null) return { error: 'E-MALFORMED', detail: `cadence entry ${i} cadence not canonical integer seconds` };
    if (atE !== null && effE <= atE) cadence = parseSecs(op.cadence);      // the latest change in force at atTime wins
    lastEff = effE; prev = await contentHash(e);
  }
  return { cadence };
}

// Discovery fetch (§20.1 pair) — pull the publisher's OWN genesis + key log from the standard locations.
// TLS to the claimed name is the observation; the chain math above is what actually binds the key.
export async function fetchIdentity(domain, fetchImpl = fetch) {
  if (!isPublicDnsShard(domain)) throw new Error('domain_shard is not a public DNS name — discovery refused (SSRF guard)');
  const get = async (path) => {
    const r = await fetchImpl(`https://${domain}${path}`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error(`HTTP ${r.status} at ${path}`);
    return r.json();
  };
  const genesis = await get('/.well-known/ust-genesis');
  // ABSENT and UNREADABLE are different facts (§20.1, round-18 P0-03), and this browser half used to collapse them with
  // a bare `catch {}`: an oversize or 5xx key-log became `keylog = []`, which ERASES a real retirement and can accept a
  // post-retirement document — the exact hole the core closes. Only 404/410 means "not served"; anything else is carried
  // out as `indeterminate` so the caller reports it instead of quietly verifying against a surface it never read.
  let keylog = [], cadenceLog = [], indeterminate = null;
  const optional = async (path, label) => {
    try { return await get(path); }
    catch (e) {
      if (!/HTTP (404|410) /.test(e.message || '')) indeterminate = { surface: label, detail: e.message || String(e) };
      return null;
    }
  };
  const k = await optional('/.well-known/ust-keylog', 'key-log');
  if (Array.isArray(k)) keylog = k;
  // §11.3 — the cadence log declares the completeness GRID. Absent is the common, honest case (one fixed cadence needs
  // no log at all); unreadable must never look like undeclared, or a range gets judged against the superseded grid.
  const c = await optional('/.well-known/ust-cadence', 'cadence-log');
  if (Array.isArray(c)) cadenceLog = c;
  return { genesis, keylog, cadenceLog, ...(indeterminate ? { indeterminate } : {}) };
}

// ─── WITNESS auto-query (#68) — the browser half. Same honesty ladder as the CLI/MCP: fetch the witness
// log, cross-check each active genesis's anchor against its substrate — the endpoint is only an index, the
// Merkle math decides. Two independent substrates, both browser-native: Rekor (RFC 6962 inclusion via
// WebCrypto over the embedded proof) and Bitcoin-OTS (OpenTimestamps proof parsed to its block attestation,
// matched against a real block header from a read-only explorer). One anchored active genesis (== the
// resolved one) ⇒ no-fork EVIDENCE ⇒ automatic HIGH, no manual checkbox; two ⇒ a fork is visible.
const sha256raw = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const teu = (s) => new TextEncoder().encode(s);
const hexToU8 = (h) => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; };
const u8hex = (u) => [...u].map((x) => x.toString(16).padStart(2, '0')).join('');
const u8eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// RFC 6962 §2.1.1 inclusion (canonical, right-edge while-shift) — async because WebCrypto digest is async.
//
// TREE INDICES ARE UNBOUNDED NATURALS AND MUST NOT BE NARROWED (#155). RFC 6962 §2.1.1 defines the path over
// naturals and the wire form is uint64; JavaScript's `>>` and `&` coerce to SIGNED 32-BIT, so an index at or
// above 2^31 goes negative mid-climb. The connector package met this on a live log on 2026-07-28 and moved to
// BigInt; THIS clean-room copy did not, because the gate written that day read the package by name and a
// conformance check separately required this file to contain the narrowing form verbatim. Measured 2026-08-13:
// every anchor of the reference operator written after the public log passed 2,147,483,648 entries failed here,
// for sixteen days, and the page reported it as a limit of the reader's browser.
// number | string | bigint are all accepted: a log serving a uint64 past 2^53 must send it as a string, and
// refusing that would reinstate the same ceiling one power higher.
// TOTALITY (#155, swept from the connector's round-46 self-audit) — an inclusion proof is UNTRUSTED input, and this
// is an EXPORT, so a null argument or a hostile Proxy with a throwing getter must be a structured `false`, never a
// host throw. Destructuring in the SIGNATURE threw on `null` where the connector returned false; the parity corpus
// found it the first time the two were compared directly instead of source-pinned.
export async function rekorInclusion(proof) {
  try {
    if (!proof || typeof proof !== 'object') return false;
    const { leafHash, index, treeSize, hashes, rootHash } = proof;
    if (!Array.isArray(hashes)) return false;
    let fn, sn;
    try { fn = BigInt(index); sn = BigInt(treeSize) - 1n; } catch { return false; }
    if (fn < 0n || sn < 0n || fn > sn) return false;
    let hash = leafHash;
    for (const sibHex of hashes) {
      const sib = hexToU8(sibHex);
      if (fn === sn || (fn & 1n) === 1n) {
        hash = await sha256raw(concatU8([new Uint8Array([1]), sib, hash]));
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      } else {
        hash = await sha256raw(concatU8([new Uint8Array([1]), hash, sib]));
      }
      fn >>= 1n; sn >>= 1n;
    }
    return fn === 0n && u8hex(hash) === String(rootHash).replace(/^sha256:/, '');
  } catch { return false; }
}
const concatU8 = (arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; };

// #69 A1 — the inclusion proof reaches proof.rootHash, but rootHash must be a root the LOG SIGNED, else a
// fabricated treeSize=1 tree passes. rekor.sigstore.dev's checkpoint (signed tree head) is an ECDSA-P256
// signature over "origin\nsize\nroothash\n". Pinned key (trust anchor, NOT fetched from the entry surface):
const REKOR_SPKI_B64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==';
const b64ToU8 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
let _rekorKey;
const rekorKey = () => (_rekorKey ||= crypto.subtle.importKey('spki', b64ToU8(REKOR_SPKI_B64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']));

// ASN.1 DER ECDSA (SEQ{INT r, INT s}) → IEEE-P1363 raw r||s (64 B) that WebCrypto verify expects.
function derToRaw(der) {
  let p = 2; if (der[1] & 0x80) p += der[1] & 0x7f;            // skip SEQ tag+len (incl. long-form)
  const readInt = () => { p++; let len = der[p++]; let s = p; p += len; while (der[s] === 0 && len > 32) { s++; len--; } const o = new Uint8Array(32); o.set(der.subarray(s, s + len), 32 - len); return o; };
  const r = readInt(), s = readInt();
  return concatU8([r, s]);
}

// Verify rekor.sigstore.dev's signed checkpoint: its ECDSA signature over the note text, and that the signed
// root/size equal the inclusion proof's. Returns true ONLY if the pinned log key signed rootHex@treeSize.
async function rekorCheckpoint(checkpoint, rootHex, treeSize) {
  if (typeof checkpoint !== 'string' || checkpoint.indexOf('\n\n') < 0) return false;
  const lines = checkpoint.split('\n');
  if (lines.length < 5 || lines[1] !== String(treeSize)) return false;
  let ckRootHex; try { ckRootHex = u8hex(b64ToU8(lines[2])); } catch { return false; }
  if (ckRootHex !== rootHex.replace(/^sha256:/, '')) return false;
  const origin = lines[0].split(' ')[0];
  const body = teu(checkpoint.slice(0, checkpoint.indexOf('\n\n') + 1));
  const key = await rekorKey();
  for (const line of checkpoint.slice(checkpoint.indexOf('\n\n') + 2).split('\n')) {
    const m = line.match(/^— (\S+) (\S+)$/);
    if (!m || m[1] !== origin) continue;
    let sig; try { sig = b64ToU8(m[2]); } catch { continue; }
    if (sig.length <= 4) continue;
    try { if (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(sig.subarray(4)), body)) return true; } catch { /* shape */ }
  }
  return false;
}

// Verify a rekor anchor (browser): the entry attests THIS root, the inclusion proof reaches rootHash, AND
// rootHash is a root Rekor signed (#69 A1). All three or it is not final — and the refusal NAMES which one
// failed, from REGISTRY.anchorRefusalReasons (#155, F.5.1b). The three conjuncts belong to DIFFERENT terms of
// the F.5.1 table, so one shared `false` tells the reader nothing about who can act, and the prose that used to
// stand in for it named the reader's own browser — a claim the reader cannot disprove from where they stand.
async function rekorFinal(anchorInner, rootSha) {
  const proof = anchorInner.inclusionProof, bodyB64 = anchorInner.body;
  if (!proof || !bodyB64) return { ok: false, reason: 'proof-absent' };
  // (1) the entry must attest THIS root by the EXACT hashedrekord schema. A substring scan of the body passes an
  // entry that merely CONTAINS the hash in some other field (#71) — fixed in the connector, and swept here.
  let entry;
  try { entry = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(bodyB64), (c) => c.charCodeAt(0)))); }
  catch { return { ok: false, reason: 'unreadable-entry' }; }
  if (entry?.kind !== 'hashedrekord') return { ok: false, reason: 'unsupported-proof-form' };
  const artifactHash = u8hex(await sha256raw(teu(String(rootSha).replace(/^sha256:/, ''))));   // Rekor stores sha256(root-hex)
  const h = entry?.spec?.data?.hash;
  if (!h || h.algorithm !== 'sha256' || h.value !== artifactHash) return { ok: false, reason: 'entry-attests-another-root' };
  // (2) the inclusion path reaches proof.rootHash
  const leafHash = await sha256raw(concatU8([new Uint8Array([0]), Uint8Array.from(atob(bodyB64), (c) => c.charCodeAt(0))]));
  if (!await rekorInclusion({ leafHash, index: proof.logIndex, treeSize: proof.treeSize, hashes: proof.hashes || [], rootHash: proof.rootHash }))
    return { ok: false, reason: 'inclusion-failed' };
  // (3) #69 A1 — bind that root to a head the pinned log key signed
  if (!await rekorCheckpoint(proof.checkpoint, proof.rootHash, proof.treeSize)) return { ok: false, reason: 'checkpoint-unsigned' };
  return { ok: true };
}

// ─── Bitcoin-OTS witness substrate (browser clean-room, #68) ─────────────────────────────────
// A TRUSTLESS Bitcoin check parses the OpenTimestamps proof — a Merkle tree of ops — down to its
// BitcoinBlockHeaderAttestation, recomputes the committed value, and matches it against a REAL block
// header pulled from a read-only block explorer (the header is public consensus; the explorer is only a
// mirror of it, swap freely). Canonical `Timestamp.deserialize` grammar: 0xff separates sibling branches
// at a node, an op recurses into a sub-timestamp on the transformed message, an attestation fixes the
// message AT its node. sha256/append/prepend only — OTS Bitcoin paths never need ripemd160; an
// unsupported op throws and the whole parse fails CLOSED (→ null → honest "unconfirmed", never a fake).
const OTS_BTC_TAG = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
const BTC_EXPLORERS = ['https://blockstream.info/api', 'https://mempool.space/api'];

async function parseOtsBitcoin(ots) {
  let pos = 31; pos++; /* major version */ pos++; /* file-hash op (sha256) */
  const digest = ots.slice(pos, pos + 32); pos += 32;
  const readVarint = () => { let r = 0, sh = 0; for (;;) { const b = ots[pos++]; r += (b & 0x7f) * (2 ** sh); if (!(b & 0x80)) break; sh += 7; } return r; };
  let found = null;
  const applyOp = async (tag, msg) => {
    if (tag === 0xf0) { const n = readVarint(); const a = ots.slice(pos, pos + n); pos += n; return concatU8([msg, a]); }
    if (tag === 0xf1) { const n = readVarint(); const a = ots.slice(pos, pos + n); pos += n; return concatU8([a, msg]); }
    if (tag === 0x08) return sha256raw(msg);
    throw new Error('ots op 0x' + tag.toString(16) + ' unsupported in browser');
  };
  const doOne = async (tag, msg) => {
    if (tag === 0x00) {
      const at = ots.slice(pos, pos + 8); pos += 8; const len = readVarint(); const payload = ots.slice(pos, pos + len); pos += len;
      if (u8eq(at, OTS_BTC_TAG)) { let h = 0, sh = 0, p = 0; for (;;) { const b = payload[p++]; h += (b & 0x7f) * (2 ** sh); if (!(b & 0x80)) break; sh += 7; } found = { height: h, merkle: msg }; }
    } else { await deserialize(await applyOp(tag, msg)); }
  };
  async function deserialize(msg) { let tag = ots[pos++]; while (tag === 0xff) { await doOne(ots[pos++], msg); tag = ots[pos++]; } await doOne(tag, msg); }
  await deserialize(digest);
  return found ? { height: found.height, merkle: found.merkle, digest } : null;
}

// Verify a bitcoin-ots anchor (browser): the proof starts at THIS anchor's root, and the value it commits
// to a Bitcoin block equals that block's real merkle root (display order = internal bytes reversed).
// Same refusal discipline as rekorFinal (#155): every NO carries a reason from REGISTRY.anchorRefusalReasons,
// because "no explorer answered" is the consumer's term and "this proof commits to another root" is not.
async function bitcoinFinal(anchorInner, rootRef, fetchImpl) {
  try {
    if (!anchorInner.ots) return { ok: false, reason: 'proof-absent' };
    const ots = Uint8Array.from(atob(anchorInner.ots), (c) => c.charCodeAt(0));
    let parsed;
    // an op this build does not implement is the RULESET term, not a broken proof — parseOtsBitcoin throws by name.
    try { parsed = await parseOtsBitcoin(ots); }
    catch (e) { return { ok: false, reason: /unsupported/.test(e?.message || '') ? 'unsupported-proof-form' : 'unreadable-entry' }; }
    // parsed but carrying no Bitcoin attestation yet — the ordinary pending-OTS case, and the publisher's to wait out.
    if (!parsed) return { ok: false, reason: 'proof-absent' };
    if (u8hex(parsed.digest) !== (rootRef || '').replace(/^sha256:/, '')) return { ok: false, reason: 'entry-attests-another-root' };
    const wantMerkle = u8hex(parsed.merkle.slice().reverse());
    for (const base of BTC_EXPLORERS) {
      try {
        const hash = (await (await fetchImpl(`${base}/block-height/${parsed.height}`, { signal: AbortSignal.timeout(10000) })).text()).trim();
        if (!/^[0-9a-f]{64}$/.test(hash)) continue;
        const blk = await (await fetchImpl(`${base}/block/${hash}`, { signal: AbortSignal.timeout(10000) })).json();
        if (blk && blk.merkle_root === wantMerkle) return { ok: true, time: blk.timestamp, height: parsed.height };
        return { ok: false, reason: 'inclusion-failed' };   // a definitive answer from a reachable explorer — a mismatch is a real NO
      } catch { /* explorer unreachable — try the next */ }
    }
    return { ok: false, reason: 'substrate-unreachable' };
  } catch { return { ok: false, reason: 'unreadable-entry' }; }
}

// The CLOSED anchor-refusal set (§11.2, F.5.1b) mapped to the term of the F.5.1 table each reason belongs to —
// which is to say, WHO can act: `evidence` the publisher, `faculties` the consumer, `ruleset` neither party.
// Clean-room: this file may NOT import the core, so the literal lives here and `spec-code-sync` diffs it against
// REGISTRY.anchorRefusalReasons. #154 is why that diff exists — four independent enumerations of one set is how
// they diverge, and the divergence surfaces as a false verdict on somebody's live document.
export const REFUSAL_TERMS = {
  'proof-absent': 'evidence',
  'unreadable-entry': 'evidence',
  'unsupported-proof-form': 'ruleset',
  'entry-attests-another-root': 'evidence',
  'inclusion-failed': 'evidence',
  'checkpoint-unsigned': 'evidence',
  'substrate-unreachable': 'faculties',
};

// Fetch the witness log for `domain` and decide no-fork by cross-checking each active genesis's anchors.
export async function witnessNoFork(domain, genesisHash, fetchImpl = fetch) {
  if (!isPublicDnsShard(domain)) return { status: 'skipped' };
  let log;
  try {
    const r = await fetchImpl(`https://${domain}/.well-known/ust-witness`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    log = await r.json();
  } catch (e) { return { status: 'unreachable', detail: 'witness endpoint unreachable (' + (e.message || e) + ')' }; }
  if (!log || log.domain_shard !== domain || !Array.isArray(log.genesis_log)) return { status: 'unreachable', detail: 'witness log malformed' };
  const active = log.genesis_log.filter((g) => g && !g.superseded_by && /^sha256:[0-9a-f]{64}$/.test(g.content_hash || ''));
  const anchored = [], refusals = [];
  for (const g of active) {
    const anchors = Array.isArray(g.anchors) ? g.anchors : (g.anchor ? [g.anchor] : []);
    if (!anchors.length) refusals.push({ substrate: 'none', root: g.content_hash, reason: 'proof-absent' });
    let ok = false;
    for (const a of anchors) {
      const inner = a.anchor ?? a;
      const root = a.root || g.content_hash;
      let r;
      if (inner.substrate === 'rekor') r = await rekorFinal(inner, root);
      else if (inner.substrate === 'bitcoin-ots') r = await bitcoinFinal(inner, root, fetchImpl);
      else r = { ok: false, reason: 'unsupported-proof-form' };
      if (r.ok) { ok = true; break; }
      refusals.push({ substrate: String(inner.substrate ?? 'unknown'), root, reason: r.reason });
    }
    if (ok) anchored.push(g);
  }
  if (anchored.length >= 2) return { status: 'fork', detail: 'two anchored active genesis roots — a rival exists' };
  if (anchored.length === 1) {
    if (anchored[0].content_hash !== genesisHash) return { status: 'fork', detail: 'the anchored genesis differs from the served one' };
    return { status: 'confirmed', detail: 'a single anchored active genesis (Rekor and/or Bitcoin) — no rival root' };
  }
  // F.5.1b — the refusal NAMES its conjunct. What stood here was a guess at the reader's environment ("explorer/log
  // unreachable, or an unsupported proof"), and for sixteen days it was wrong about a defect in this very file.
  if (!active.length) return { status: 'pending', detail: 'no active genesis in the witness log', reasons: [] };
  return {
    status: 'pending',
    detail: 'no anchor of the active genesis verifies — ' + refusals
      .map((r) => `${r.substrate} ${String(r.root).slice(0, 14)}…: ${r.reason} (${REFUSAL_TERMS[r.reason] ?? 'unclassified'})`)
      .join('; '),
    reasons: refusals,
  };
}
