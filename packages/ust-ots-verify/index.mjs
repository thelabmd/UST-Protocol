// SPDX-License-Identifier: Apache-2.0
// @ust-protocol/ots-verify — the OPT-IN Bitcoin substrateVerify for UST anchors (#68 Ф1b / #69 A2).
//
// WHY A SEPARATE PACKAGE: the zero-dependency reference verifier (ust-protocol) must never embed a
// blockchain / the heavy opentimestamps lib. resolveByDiscovery / verifyAnchor take `substrateVerify` as an
// OPTIONAL injection: without it, an anchor is honestly `unproven`; WITH this package it is cross-checked
// against Bitcoin.
//
// #69 A2 (P0) — `isTimestampComplete()` only means "a Bitcoin attestation EXISTS in the .ots tree"; it does
// NOT mean that block actually commits the root, nor that it is buried. A fabricated 'complete' .ots would
// pass. So finality now REQUIRES: (1) the .ots attests THIS root; (2) the committed value equals the REAL
// merkle root of the Bitcoin block at the attested height (fetched from a read-only explorer — public
// consensus, the explorer only mirrors it); (3) the block is buried under >= minConfirmations (default 6,
// §17). The explorer is untrusted: a wrong answer fails the merkle match (claim ≠ proof); unreachable →
// `unproven`, never a false `final`.
import { createHash } from 'node:crypto';
// The `.ots` codec is OURS (`./ots-codec.mjs`), and that is a deliberate reversal of the previous design.
//
// Reading a timestamp used to require the `opentimestamps` package, loaded lazily so that merely importing
// this module would not pull it. The laziness treated the symptom: the dependency drags `bitcore-lib`,
// `request`/`request-promise` (deprecated since 2020) and `fs@0.0.1-security` — a placeholder under a squatted
// name — for 12 advisories, 2 critical (measured 2026-08-07, clean install). Consumers' scanners flagged the
// dependent package, so for some of them the "optional" peer was not installable at all.
//
// Worse, the decline was INVISIBLE: with the peer absent this returned `null`, which also means "not my
// substrate". A consumer one `npm i` away from a proof received the same value as one running Rekor.
// The format is two screens of binary. The dependency was the only heavy thing about it.
// CLOSED 2026-08-07 — the codec is `./ots-codec.mjs`, the peer declaration is gone, and the shipped tree
// carries no third-party code on this path. Kept as the evidence the reversal rests on, not as a live hole.
import { parseOts, serializeOts, bitcoinAttestations, isComplete, upgradeOts, labelled } from './ots-codec.mjs';

const EXPLORERS = ['https://blockstream.info/api', 'https://mempool.space/api'];
const OTS_BTC_TAG = Buffer.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
const sha256 = (b) => createHash('sha256').update(b).digest();
const hexToBytes = (hex) => Buffer.from(hex.replace(/^sha256:/, ''), 'hex');
const bytesEq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

// Parse an OpenTimestamps proof (canonical Timestamp.deserialize grammar: 0xff separates sibling branches at
// a node, an op recurses into a sub-timestamp on the transformed message, an attestation fixes the node's
// message) down to its BitcoinBlockHeaderAttestation → { height, merkle (internal byte order) }. sha256/
// append/prepend only — an unsupported op throws and the parse fails closed. (Same logic proven in the web
// verifier docs/ust-resolve.mjs, against a live block header.)
export function parseOtsBitcoin(ots) {
  let pos = 31; pos++; /* major version */ pos++; /* file-hash op */
  const digest = ots.subarray(pos, pos + 32); pos += 32;
  const readVarint = () => { let r = 0, sh = 0; for (;;) { const b = ots[pos++]; r += (b & 0x7f) * (2 ** sh); if (!(b & 0x80)) break; sh += 7; } return r; };
  let found = null;
  const applyOp = (tag, msg) => {
    if (tag === 0xf0) { const n = readVarint(); const a = ots.subarray(pos, pos + n); pos += n; return Buffer.concat([msg, a]); }
    if (tag === 0xf1) { const n = readVarint(); const a = ots.subarray(pos, pos + n); pos += n; return Buffer.concat([a, msg]); }
    if (tag === 0x08) return sha256(msg);
    throw new Error('ots op 0x' + tag.toString(16) + ' unsupported');
  };
  const doOne = (tag, msg) => {
    if (tag === 0x00) {
      const at = ots.subarray(pos, pos + 8); pos += 8; const len = readVarint(); const payload = ots.subarray(pos, pos + len); pos += len;
      if (at.equals(OTS_BTC_TAG)) { let h = 0, sh = 0, p = 0; for (;;) { const b = payload[p++]; h += (b & 0x7f) * (2 ** sh); if (!(b & 0x80)) break; sh += 7; } found = { height: h, merkle: Buffer.from(msg) }; }
    } else { deserialize(applyOp(tag, msg)); }
  };
  function deserialize(msg) { let tag = ots[pos++]; while (tag === 0xff) { doOne(ots[pos++], msg); tag = ots[pos++]; } doOne(tag, msg); }
  deserialize(digest);
  return found ? { height: found.height, merkle: found.merkle, digest } : null;
}

// `upgrade` DEFAULTS OFF, reversing the previous default, and the reason is not hygiene.
//
// Completing a pending proof means fetching the missing half from a calendar. That leaks which digest is
// being checked to a party with no role in the proof, makes a verdict depend on a remote service — the same
// bytes answering differently on different days — and, worst, performs the PUBLISHER's job invisibly: an
// operator whose upgrade loop is broken keeps serving pending proofs forever, because every consumer patches
// the gap on their behalf and no one ever sees a failure.
//
// `pending` is a true answer. Turning it into `final` by calling out is a different act, and it belongs to
// whoever publishes the proof — `upgradeOts` is exported for exactly that, on the operator's side.
// #43 — this connector reaches a THIRD-PARTY service, so its requests carry a label. The label is written once,
// in `ots-codec.mjs`, and imported here. It is not shared with the OTHER connectors: those are separate packages
// that declare no dependencies, and taking one for a string would cost more than the copy — agreement between
// those copies is held by `tools/user-agent-gate.mjs`, which reads each version from its own package.json. A copy
// whose agreement is CHECKED is a second witness; an unchecked one is drift. (`signed` is imported above.)
export function makeSubstrateVerify({ upgrade = false, fetchImpl = labelled(fetch), explorers = EXPLORERS, minConfirmations = 6, quorum = 2 } = {}) {
  return async function substrateVerify(anchor, root) {
    // totality (round-46 self-audit) — the anchor is UNTRUSTED: read its fields behind a guard so a hostile getter/Proxy declines
    // (null → the router tries the next plugin), never a host throw. The integrated path passes an inert admitted proof; this covers a direct call.
    let sub, otsB64;
    try { sub = anchor?.substrate ?? anchor?.anchor?.substrate; otsB64 = anchor?.ots ?? anchor?.anchor?.ots; } catch { return null; }
    if (sub && sub !== 'bitcoin-ots') return null;                 // not ours → router delegates onward
    if (!otsB64 || typeof root !== 'string') return null;
    // ADDRESSED vs GUESSING, and the whole discrimination below turns on it. When the anchor NAMES this substrate,
    // no later plugin can answer for it, so a definitive NO must be STATED — reported as a decline it would send
    // the router looking for someone else and the consumer would be told nobody could reach the substrate. When
    // the anchor names nothing, this plugin is inferring from the presence of an `ots` field, and a mismatch may
    // well belong to another connector: declining is then the honest answer, not a shrug.
    const addressed = sub === 'bitcoin-ots';
    let det;
    try { det = parseOts(Buffer.from(otsB64, 'base64')); }
    catch { return addressed ? { final: false, time: 'unproven', reason: 'unreadable-proof' } : null; }
    // The .ots MUST attest THIS root — otherwise it proves nothing about our genesis. Addressed, that is a
    // definitive claim-is-not-proof failure and the consumer is owed the word for it; unaddressed, the proof may
    // simply be someone else's.
    if (!bytesEq(det.digest, hexToBytes(root))) {
      return addressed ? { final: false, time: 'unproven', reason: 'proof-attests-another-root' } : null;
    }
    if (!isComplete(det) && upgrade) {
      // Opt-in only, and the result is a CANDIDATE: a well-formed reply belonging to another commitment
      // splices cleanly, and only the explorer comparison below tells the two apart.
      try { det = (await upgradeOts(det, { fetchImpl })).candidate; } catch { /* calendar unreachable → pending */ }
    }
    if (!isComplete(det)) return { final: false, time: 'unproven', reason: 'pending' };

    // #69 A2 — parse to the Bitcoin attestation and PROVE it against the real chain (not just structure).
    let parsed;
    try { parsed = parseOtsBitcoin(serializeOts(det)); } catch { return { final: false, time: 'unproven' }; }
    if (!parsed || typeof parsed.height !== 'number') return { final: false, time: 'unproven' };
    const wantMerkle = Buffer.from(parsed.merkle).reverse().toString('hex');   // block header displays reversed

    // #71 — TRUST TERMINATION HONESTY. A SINGLE explorer is a TRUSTED ORACLE (it could serve a self-consistent
    // fake block/merkle/tip). So finality REQUIRES AGREEMENT across ≥ `quorum` INDEPENDENT explorers, and the
    // result is labelled `explorer-corroborated` — NOT trustless Bitcoin finality. Trustless needs a real node /
    // SPV header-chain (PoW-validated); that is an OPERATOR plugin injected through this SAME substrateVerify
    // seam. This plugin is honest about its ceiling; a reachable explorer that DISAGREES on the merkle root is a
    // definitive NO.
    const need = Math.max(1, Math.min(quorum, explorers.length));
    // #71-followup P1 — query ALL configured explorers BEFORE deciding: a disagreement by a LATER source must
    // still count (early-returning on quorum could miss it). ANY reachable source that disagrees on the merkle
    // root is a DEFINITIVE NO, even if others agree. And a quorum of ONE is NOT `corroborated` — it is a single
    // trusted oracle, honestly labelled `explorer-single`.
    let agree = 0, time = null, conflict = false;
    for (const base of explorers) {
      try {
        const hash = (await (await fetchImpl(`${base}/block-height/${parsed.height}`, { signal: AbortSignal.timeout(10000) })).text()).trim();
        if (!/^[0-9a-f]{64}$/.test(hash)) continue;
        const blk = await (await fetchImpl(`${base}/block/${hash}`, { signal: AbortSignal.timeout(10000) })).json();
        if (!blk || typeof blk.merkle_root !== 'string') continue;
        if (blk.merkle_root !== wantMerkle) { conflict = true; continue; }     // an independent source DISAGREES — keep querying, but this is a NO
        const tip = Number((await (await fetchImpl(`${base}/blocks/tip/height`, { signal: AbortSignal.timeout(10000) })).text()).trim());
        if (!Number.isFinite(tip) || tip - parsed.height + 1 < minConfirmations) continue;   // this source lags on burial → don't count
        agree++;
        time = time || (blk.timestamp ? new Date(blk.timestamp * 1000).toISOString().slice(0, 19) + 'Z' : 'bitcoin-block-' + parsed.height);
      } catch { /* explorer unreachable — try the next */ }
    }
    if (conflict) return { final: false, time: 'unproven' };                   // ANY reachable disagreement → definitive NO
    if (agree < need) return { final: false, time: 'unproven', detail: `only ${agree}/${need} independent explorers corroborated` };
    return { final: true, time, block_height: String(parsed.height), assurance: need >= 2 ? 'explorer-corroborated' : 'explorer-single', explorers: agree };
  };
}

// P1-06 — emit a TYPED, capability-bearing VerifiedEvidence from a FINAL substrate result, so the core's freshness
// derivation consumes a CONNECTOR-produced record (proof_kind bounds its capability), never a caller-fabricated one.
// A non-final / incomplete result yields null (no evidence). `pow-header-chain` ⇒ order+time capable (EVIDENCE_CAPS).
export function toVerifiedEvidence(subject, result, source_id = 'bitcoin-ots') {
  if (!result || result.final !== true || result.block_height === undefined) return null;
  const isoZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  return { proof_kind: 'pow-header-chain', subject, source_id,
    facts: { substrate: 'bitcoin', position: String(result.block_height), ...(isoZ.test(result.time || '') ? { not_before: result.time } : {}) } };
}

// Convenience default (upgrade-on-verify). Pass to resolveByDiscovery/verifyAnchor as `substrateVerify`.
export const substrateVerify = makeSubstrateVerify();
