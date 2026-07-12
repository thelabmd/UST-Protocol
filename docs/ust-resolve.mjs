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
