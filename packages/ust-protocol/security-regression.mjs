// SPDX-License-Identifier: Apache-2.0
// Phase 0 — rc.33 external-audit remediation (epic UST-1o6). Each of the 5 P0 + key P1 attacks is encoded as an
// assertion of the SECURE outcome. It is RED now (the code is still vulnerable); it is the acceptance gate that must
// go GREEN, one vector at a time, as the STRUCTURAL fix lands (UST-0ol). NOT yet wired into the blocking CI — that
// happens in the fix commit, when this reaches all-FIXED. Constructions mirror the auditor's reproduced repros
// (rnd/audits/UST_1.0_rc33_independent_audit_bundle/audit-repros{,-extra}.mjs), independently confirmed against live.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as P from './index.mjs';

const kp = (hex) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pub, key_id: P.keyId(pub) };
};
const K0 = kp('00'.repeat(32)), KA = kp('22'.repeat(32)), KB = kp('33'.repeat(32));
const R1 = kp('44'.repeat(32)), R2 = kp('55'.repeat(32)), R3 = kp('66'.repeat(32));
const D = 'example.com';
const T0 = { generated_at: '2026-07-01T00:00:00Z', valid_from: '2026-07-01T00:00:00Z', valid_to: '2027-07-01T00:00:00Z' };
const T5 = { generated_at: '2026-07-05T00:00:00Z', valid_from: '2026-07-05T00:00:00Z', valid_to: '2027-07-05T00:00:00Z' };
const T9 = { generated_at: '2026-07-09T00:00:00Z', valid_from: '2026-07-09T00:00:00Z', valid_to: '2027-07-09T00:00:00Z' };
const leafProof = (h, kind) => ({ root: P.Hbytes('ust:leaf', Buffer.from(h, 'utf8')), path: [], anchor: { kind } });

let red = 0, green = 0; const rows = [];
// sec(id, bd, desc, isSecure): isSecure() returns true iff the live code ALREADY behaves securely. A throw inside
// isSecure counts as VULNERABLE unless the vector explicitly treats the throw as the secure outcome.
const sec = (id, bd, desc, isSecure) => {
  let ok = false; try { ok = !!isSecure(); } catch { ok = false; }
  if (ok) { green++; rows.push(['  ✓ FIXED', id, bd, desc]); } else { red++; rows.push(['  ✗ VULN ', id, bd, desc]); }
};

// ─── shared fixtures ────────────────────────────────────────────────────────────────────────────
const gen = P.seal(P.buildGenesis({ domain_shard: D, ust_id: 'ust:20260701.00', key_id: K0.key_id }, T0, K0.pub), K0.priv, K0.pub);
const doc = P.seal(P.buildState({ domain_shard: D, ust_id: 'ust:20260709.00', key_id: K0.key_id, class: 'observation' }, T9, { x: { kind: 'captured', value: { v: '1' } } }), K0.priv, K0.pub);
const entryHash = 'sha256:' + 'ab'.repeat(32);
const kc = P.buildKeylogCommitment([entryHash]);
const cbody = P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: 'sha256:' + 'cd'.repeat(32), sequence: '0', active_genesis: P.contentHash(gen), current_key_id: K0.key_id, keylog: { root: kc.root, length: kc.length, head: kc.head } });
const cp = P.sealAuthorityCheckpoint(cbody, K0.priv, K0.pub); const cpId = P.authorityCheckpointId(cp);
const target = { domain_shard: D, active_genesis: P.contentHash(gen), anchor: P.verifiedEvidence({ proof_kind: 'pow-header-chain', subject: 'target', source_id: 'target-source', facts: { substrate: 'chain-x', position: '10' } }) };

// ─── P0-01 — evidence supplies its own root of authority ──────────────────────────────────────────
const nleaf = P.nameMapLeaf({ domain_shard: D, active_genesis: P.contentHash(gen) });
const nmap = P.buildVerifiableMap([nleaf]);
sec('P0-01a', 'UST-8o0', 'self-supplied name-map root must NOT earn identity=authoritative', () =>
  P.verify(doc, { genesis: gen, keylog: [], nameMap: { proof: nmap.prove(nleaf.key), mapRoot: nmap.root }, context: 'data' }).identity?.strength !== 'authoritative');

const cleaf = P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: cbody.genesis_epoch, sequence: '0', checkpoint: cpId });
const cmap = P.buildVerifiableMap([cleaf]);
sec('P0-01b', 'UST-8o0', 'self-supplied checkpoint-map root must NOT earn freshness=attested', () =>
  P.deriveCheckpointFreshness([cp], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub }, target,
    commitment: P.verifiedEvidence({ proof_kind: 'pow-header-chain', subject: cpId, source_id: 'chain', facts: { substrate: 'chain-x', position: '11' } }),
    terminality: { headProof: kc.headProof, successorProof: kc.successorProof },
    uniqueness: { map: { proof: cmap.prove(cleaf.key), mapRoot: cmap.root } } }).keylog_freshness !== 'attested');

// ─── P0-02 — terminality is a SIZE-BOUND vector commitment; a truncated view of a longer log is NOT terminal ──────
const e0t = 'sha256:' + '01'.repeat(32), e1t = 'sha256:' + '02'.repeat(32), e2t = 'sha256:' + '03'.repeat(32);
const realLog = P.buildKeylogCommitment([e0t, e1t, e2t]);                           // real length-3 log (e1 a later revoke)
sec('P0-02', 'UST-t8r', 'terminality must be FALSE when a later entry is hidden (log truncated to the head)', () =>
  P.verifyKeylogTerminality({ root: realLog.root, length: '1', head: e0t }, { headProof: realLog.prove(0) }).terminal === false);

// ─── P0-03 — legacy keylogHeadAnchor accepts a stale prefix as attested ────────────────────────────
const revoke = P.seal(P.buildKeyLogEntry({ domain_shard: D, ust_id: 'ust:20260705.00', key_id: K0.key_id }, T5, { op: 'revoke', pub: K0.pub, reason: 'retired' }, P.contentHash(gen)), K0.priv, K0.pub);
void revoke;
const lateDoc = structuredClone(doc); lateDoc.proof = leafProof(P.contentHash(lateDoc), 'doc');
const substrateVerify = (anchor) => anchor?.kind === 'doc' ? { final: true, time: '2026-07-10T00:00:00Z', assurance: 'test' } : { final: true, time: '2026-07-01T00:00:00Z', assurance: 'test' };
const staleOpts = { genesis: gen, keylog: [], noForkConfirmed: true, acceptConsumerOverride: true, requireFreshKeylog: true, keylogHeadAnchor: leafProof(P.contentHash(gen), 'old-head'), substrateVerify, context: 'data' };
sec('P0-03', 'UST-dh1', 'a stale anchored prefix must NOT earn freshness=attested (revoke followed it)', () =>
  P.verify(lateDoc, staleOpts).identity?.freshness !== 'attested');

// ─── P0-04 — content-addressed evidence must not satisfy temporal ordering ─────────────────────────
sec('P0-04', 'UST-9on', 'content-addressed evidence must NOT earn corroborated (no temporal capability)', () =>
  P.deriveCheckpointFreshness([cp], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub }, target,
    commitment: P.verifiedEvidence({ proof_kind: 'content-addressed', subject: cpId, source_id: 'fake-cas', facts: { substrate: 'chain-x', position: '11' } }),
    terminality: { headProof: kc.headProof, successorProof: kc.successorProof } }).keylog_freshness !== 'corroborated');

// ─── P0-05 — recovery split-view + unvalidated threshold ───────────────────────────────────────────
const b0 = P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: cbody.genesis_epoch, sequence: '0', active_genesis: P.contentHash(gen), current_key_id: K0.key_id, next_key_id: KA.key_id, next_pub: KA.pub, effective_sequence: '1', keylog: { root: kc.root, length: kc.length, head: kc.head } });
const C0 = P.sealAuthorityCheckpoint(b0, K0.priv, K0.pub); const id0 = P.authorityCheckpointId(C0);
const rf = (K) => ({ domain_shard: D, genesis_epoch: cbody.genesis_epoch, last_accepted_checkpoint: id0, replacement_key_id: K.key_id, replacement_pub: K.pub, reason: 'lost', effective_sequence: '1' });
const A1 = P.buildRecoveryStatement(rf(KA), R1.priv, R1.pub), A2 = P.buildRecoveryStatement(rf(KA), R2.priv, R2.pub);
const B2 = P.buildRecoveryStatement(rf(KB), R2.priv, R2.pub), B3 = P.buildRecoveryStatement(rf(KB), R3.priv, R3.pub);
const rkeys = Object.fromEntries([[R1.key_id, R1.pub], [R2.key_id, R2.pub], [R3.key_id, R3.pub]]);
const vr = (xs, threshold = 2) => P.verifyCheckpointRecovery(xs, { domain_shard: D, genesis_epoch: cbody.genesis_epoch, last_accepted_checkpoint: id0, effective_sequence: '1', recoveryKeys: rkeys, threshold });
sec('P0-05a', 'UST-6hx', 'two conflicting threshold-quorums must be a CONFLICT (deterministic reject)', () =>
  vr([A1, A2, B2, B3]).recovered === false && vr([B2, B3, A1, A2]).recovered === false);
sec('P0-05b', 'UST-6hx', 'threshold=0 must be rejected (1 <= threshold <= |recoveryKeys|)', () =>
  vr([A1], 0).recovered === false);

// ─── P1-01 — authority-checkpoint fixed schema must be enforced ────────────────────────────────────
const weirdBody = { ...cbody, version: '999', evil_extension: 'accepted', keylog: { root: 'not-a-hash', length: 'bogus', head: 'not-a-hash' }, checkpoint_authority: { ...cbody.checkpoint_authority, unknown: 'accepted' } };
const weird = P.sealAuthorityCheckpoint(weirdBody, K0.priv, K0.pub);
sec('P1-01', 'UST-dqj', 'malformed checkpoint body (version:999 / junk / bad keylog) must NOT be VALID', () =>
  P.verifyAuthorityCheckpointChain([weird], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } }).result !== 'VALID');

// ─── P1-02 — compareEvidenceOrder must be total/fail-closed, never throw ───────────────────────────
sec('P1-02', 'UST-dqj', 'compareEvidenceOrder(position:NaN) must return a verdict, never throw', () => {
  const r = P.compareEvidenceOrder({ facts: { substrate: 'x', position: 'NaN' } }, { facts: { substrate: 'x', position: '1' } });
  return typeof r === 'string';
});

// ─── P1-05 — verifiable-map must reject duplicate typed keys ────────────────────────────────────────
const dupA = P.nameMapLeaf({ domain_shard: 'a.example', active_genesis: 'sha256:' + 'aa'.repeat(32) });
const dupB = { key: dupA.key, value: P.nameMapLeaf({ domain_shard: 'a.example', active_genesis: 'sha256:' + 'bb'.repeat(32) }).value };
sec('P1-05', 'UST-dqj', 'buildVerifiableMap must REJECT duplicate typed keys (one value per key)', () => {
  try { P.buildVerifiableMap([dupA, dupB]); return false; } catch { return true; }
});

// ─── rc.35 adversarial pass (independent agents) — 5 confirmed findings ─────────────────────────────
// P0 — a PUBLIC partition carrying `commit` decouples its displayed value from the signed hash (hash is taken over
// commit); a §4.4-faithful verifier (mode-by-privacy) disagrees (I4). Must reject: public = {kind,value}, no commit/enc.
sec('rc35-A', 'UST-kdb', 'public partition carrying commit must be E-MALFORMED (value must not decouple from the hash)', () =>
  P.verify(P.seal(P.buildState({ domain_shard: D, ust_id: 'ust:20260709.10', key_id: K0.key_id, class: 'observation' }, T9, { q: { kind: 'captured', value: { v: '999' }, commit: 'sha256:' + 'ab'.repeat(32) } }), K0.priv, K0.pub), { context: 'data' }).error === 'E-MALFORMED');
sec('rc35-B', 'UST-kdb', 'public partition carrying enc must be E-MALFORMED (closed envelope XOR enforced)', () =>
  P.verify(P.seal(P.buildState({ domain_shard: D, ust_id: 'ust:20260709.11', key_id: K0.key_id, class: 'observation' }, T9, { q: { kind: 'captured', value: { v: '1' }, enc: { alg: 'AES-256-GCM', key_id: 'k', ct: 'AA' } } }), K0.priv, K0.pub), { context: 'data' }).error === 'E-MALFORMED');
// D — a bare `corroborated:true` boolean is a caller assertion, not a verified predicate: consumer-override, never HIGH.
sec('rc35-D', 'UST-kdb', 'bare corroborated:true must NOT reach VALID:HIGH (self-declared assurance)', () =>
  P.verify(doc, { genesis: gen, corroborated: true, context: 'data' }).result !== 'VALID:HIGH');
// C — a no-event window in which the publisher was UNREACHABLE at every slot is NOT completeness-backed (blind ≠ no-event).
sec('rc35-C', 'UST-kdb', 'a blind (all-unreachable) window must NOT earn no-event completeness-backed', () => {
  const g = P.seal(P.buildGenesis({ domain_shard: D, ust_id: 'ust:20260701.00', key_id: K0.key_id }, T0, K0.pub, undefined, undefined, 3600), K0.priv, K0.pub);
  const su = ['ust:20260701.00', 'ust:20260701.01', 'ust:20260701.02']; let pv = P.contentHash(g); const fr = [];
  for (const u of su) { const f = P.seal(P.buildAbsence({ domain_shard: D, ust_id: u, key_id: K0.key_id }, T0, 'quake', 'unreachable', {}, pv), K0.priv, K0.pub); fr.push(f); pv = P.contentHash(f); }
  const c = P.seal(P.buildCheckpoint({ domain_shard: D, ust_id: 'ust:20260701.03', key_id: K0.key_id }, T0, P.contentHash(fr[2]), 3, P.contentHash(fr[2]), { from: su[0], to: su[2] }), K0.priv, K0.pub);
  return P.noEventBacking({ from: su[0], to: su[2] }, P.verifyStream(fr, { genesis: g, checkpoint: c }), fr) !== 'completeness-backed';
});

// ─── rc.35 adversarial audit (GPT + 2 agents) — deep checkpoint/quorum/terminality core + servedNoFork ─────────────
sec('rc35-P0a', 'UST-b64', 'servedNoFork look-alike object must NOT reach corroborated/HIGH (unforgeable token)', () =>
  P.verify(doc, { genesis: gen, servedNoFork: { confirmed: true, active_genesis: P.contentHash(gen) }, context: 'data' }).identity?.strength !== 'corroborated');
sec('rc35-P0b', 'UST-b64', 'an unsigned/malformed genesis must NOT install a checkpoint authority root', () =>
  P.verifyAuthorityCheckpointChain([cp], { genesis: { state: { data: { genesis: { value: { checkpoint_authority: { key_id: K0.key_id, pub: K0.pub } } } } } } }).authority_root !== 'genesis');
sec('rc35-P0c', 'UST-b64', 'a nonzero singleton signed by the genesis key must NOT re-root the chain (bypass rotations)', () => {
  const C42 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: 'sha256:' + 'cd'.repeat(32), sequence: '42', active_genesis: P.contentHash(gen), current_key_id: K0.key_id, keylog: { root: kc.root, length: kc.length, head: kc.head } }), K0.priv, K0.pub);
  return P.verifyAuthorityCheckpointChain([C42], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } }).result !== 'VALID';
});
sec('rc35-P0d', 'UST-b64', 'threshold < 1 must NOT earn attested from an empty quorum', () =>
  P.verifyCheckpointUniqueness([{}], { domain_shard: D, threshold: 0 }).attested === false);
sec('rc35-P0e', 'UST-b64', 'an under-depth keylog terminality proof must NOT be terminal (P0-02 class stays closed)', () => {
  const KL_EMPTY = P.H('ust:keylog-empty', ''), klN = (l, r) => P.H('ust:keylog-node', l + '|' + r);
  const head = 'sha256:' + 'a2'.repeat(32), node = klN(P.keylogLeaf(head), KL_EMPTY);
  const root = P.H('ust:keylog-commit', P.canon({ length: '3', merkle_root: node }));
  return P.verifyKeylogTerminality({ root, length: '3', head }, { headProof: { index: '2', siblings: [KL_EMPTY] } }).terminal !== true;
});
sec('rc35-P1', 'UST-b64', 'a malformed uniqueness attestation (non-string leaf) must fail-closed, never throw (DoS)', () => {
  try { return P.verifyCheckpointUniqueness([{ claim: { purpose: 'ust:checkpoint-uniqueness-attestation', domain_shard: D, genesis_epoch: 'sha256:' + 'cd'.repeat(32), sequence: '0', checkpoint: cpId, as_of: 1 }, issuer_id: 'x', sig: { alg: 'Ed25519', pub: 'AA', sig: 'BB' } }], { domain_shard: D, genesis_epoch: 'sha256:' + 'cd'.repeat(32), sequence: '0', checkpoint: cpId, threshold: 1 }).attested === false; } catch { return false; }
});

// ─── report ────────────────────────────────────────────────────────────────────────────────────
console.log('\n  rc.33 audit — security regression (Phase 0, epic UST-1o6): SECURE-expectation gate');
for (const [s, id, bd, d] of rows) console.log(s + '  ' + id.padEnd(8) + bd.padEnd(9) + d);
console.log(`\n  ${green} FIXED   ${red} VULNERABLE   — target: all FIXED before rc.34 (then wire into CI)`);
process.exit(red ? 1 : 0);
