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
  let keylog = [];
  try { const k = await get('/.well-known/ust-keylog'); if (Array.isArray(k)) keylog = k; } catch { /* not served — resolution may still fail on key membership */ }
  return { genesis, keylog };
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
async function rekorInclusion({ leafHash, index, treeSize, hashes, rootHash }) {
  if (index >= treeSize || index < 0) return false;
  let hash = leafHash, fn = index, sn = treeSize - 1;
  for (const sibHex of hashes) {
    const sib = hexToU8(sibHex);
    if (fn === sn || (fn & 1) === 1) {
      hash = await sha256raw(concatU8([new Uint8Array([1]), sib, hash]));
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
    } else {
      hash = await sha256raw(concatU8([new Uint8Array([1]), hash, sib]));
    }
    fn >>= 1; sn >>= 1;
  }
  return fn === 0 && u8hex(hash) === rootHash.replace(/^sha256:/, '');
}
const concatU8 = (arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; };

// Verify a rekor anchor (browser): the entry attests THIS root AND its inclusion proof verifies.
async function rekorFinal(anchorInner, rootSha) {
  const proof = anchorInner.inclusionProof, bodyB64 = anchorInner.body;
  if (!proof || !bodyB64) return false;
  const body = atob(bodyB64);
  const rootHex = rootSha.replace(/^sha256:/, '');
  const artifactHash = u8hex(await sha256raw(teu(rootHex)));   // Rekor stores sha256(root-hex)
  if (!body.includes(artifactHash)) return false;
  const entryBytes = Uint8Array.from(body, (c) => c.charCodeAt(0));   // NB: atob → binary string
  const leafHash = await sha256raw(concatU8([new Uint8Array([0]), Uint8Array.from(atob(bodyB64), (c) => c.charCodeAt(0))]));
  return rekorInclusion({ leafHash, index: proof.logIndex, treeSize: proof.treeSize, hashes: proof.hashes || [], rootHash: proof.rootHash });
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
async function bitcoinFinal(anchorInner, rootRef, fetchImpl) {
  try {
    if (!anchorInner.ots) return null;
    const ots = Uint8Array.from(atob(anchorInner.ots), (c) => c.charCodeAt(0));
    const parsed = await parseOtsBitcoin(ots);
    if (!parsed) return null;
    if (u8hex(parsed.digest) !== (rootRef || '').replace(/^sha256:/, '')) return null;  // binds to this genesis root
    const wantMerkle = u8hex(parsed.merkle.slice().reverse());
    for (const base of BTC_EXPLORERS) {
      try {
        const hash = (await (await fetchImpl(`${base}/block-height/${parsed.height}`, { signal: AbortSignal.timeout(10000) })).text()).trim();
        if (!/^[0-9a-f]{64}$/.test(hash)) continue;
        const blk = await (await fetchImpl(`${base}/block/${hash}`, { signal: AbortSignal.timeout(10000) })).json();
        if (blk && blk.merkle_root === wantMerkle) return { final: true, time: blk.timestamp, height: parsed.height };
        return null;   // a definitive answer from a reachable explorer — a mismatch is a real NO, not "try another"
      } catch { /* explorer unreachable — try the next */ }
    }
    return null;
  } catch { return null; }
}

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
  const anchored = [];
  for (const g of active) {
    const anchors = Array.isArray(g.anchors) ? g.anchors : (g.anchor ? [g.anchor] : []);
    let ok = false;
    for (const a of anchors) {
      const inner = a.anchor ?? a;
      if (inner.substrate === 'rekor' && await rekorFinal(inner, a.root || g.content_hash)) { ok = true; break; }
      if (inner.substrate === 'bitcoin-ots' && await bitcoinFinal(inner, a.root || g.content_hash, fetchImpl)) { ok = true; break; }
    }
    if (ok) anchored.push(g);
  }
  if (anchored.length >= 2) return { status: 'fork', detail: 'two anchored active genesis roots — a rival exists' };
  if (anchored.length === 1) {
    if (anchored[0].content_hash !== genesisHash) return { status: 'fork', detail: 'the anchored genesis differs from the served one' };
    return { status: 'confirmed', detail: 'a single anchored active genesis (Rekor and/or Bitcoin) — no rival root' };
  }
  return { status: 'pending', detail: active.length ? 'genesis in the witness log but no anchor verifies here (explorer/log unreachable, or an unsupported proof)' : 'no active genesis in the witness log' };
}
