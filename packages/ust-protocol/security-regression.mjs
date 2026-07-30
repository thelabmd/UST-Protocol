// SPDX-License-Identifier: Apache-2.0
// @assurance 4 canfail:no — our own reproductions of past external-audit findings
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

sec('rc35-P2', 'UST-b64', 'no-event with a blind slot (any non-positive reason) OR subject-mismatch is NOT completeness-backed', () => {
  const iv = { from: 'ust:20260628.10', to: 'ust:20260628.13' }, sr = { complete: 'complete', interval: iv };
  const blind = [{ state: { id: { ust_id: 'ust:20260628.11' }, data: { q: { kind: 'absence', value: { reason: 'source-timeout' } } } } }];
  const mism = [{ state: { id: { ust_id: 'ust:20260628.11' }, data: { weather: { kind: 'captured', value: { t: '20' } } } } }];
  return P.noEventBacking({ from: 'ust:20260628.10', to: 'ust:20260628.12' }, sr, blind) !== 'completeness-backed'
    && P.noEventBacking({ from: 'ust:20260628.10', to: 'ust:20260628.12', subject: 'quake' }, sr, mism) !== 'completeness-backed';
});

// rc.35 round-2 (M2 refactor) — a publisher-CHOSEN genesis_epoch is rejected: the uniqueness namespace is canonical
// (genesis_epoch = H(active_genesis)), so two rival C0 cannot occupy different map slots and both attest (epoch-split).
sec('rc35-P0f', 'UST-6vj', 'a non-canonical (publisher-chosen) genesis_epoch is rejected — no rival uniqueness namespace', () => {
  const AG = 'sha256:' + '22'.repeat(32), klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const cp0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: 'sha256:' + 'ee'.repeat(32), sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  return P.verifyAuthorityCheckpointChain([cp0], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } }).result !== 'VALID';
});

// rc.35 round-2 (M3 refactor) — verifiedEvidence-forge: `verifiedEvidence()` was an exported constructor ANY caller
// could invoke; deriveCheckpointFreshness trusted its facts (substrate/position) and granted `corroborated` from a
// MINTED object no connector ever verified. Post-M3, evidence enters only through the seam (a SIGNED receipt of a
// consumer-admitted connector, scope+subject-bound); a minted look-alike earns nothing.
sec('rc35-P0g', 'UST-6vj', 'a caller-minted evidence object (no signed receipt, no admission) cannot earn corroborated freshness', () => {
  const AG = 'sha256:' + '33'.repeat(32), EPg = P.genesisEpoch(AG);
  const klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const cp0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPg, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const headId = P.authorityCheckpointId(cp0);
  const mint = (subj, pos) => P.verifiedEvidence({ proof_kind: 'pow-header-chain', subject: subj, source_id: 'btc', facts: { substrate: 'bitcoin', position: String(pos) } });
  const r = P.deriveCheckpointFreshness([cp0], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub },
    target: { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: mint('ust:target', 800) },
    commitment: mint(headId, 900), terminality: { headProof: klc.headProof, successorProof: klc.successorProof } });
  return r.keylog_freshness !== 'corroborated' && r.keylog_freshness !== 'attested' && r.result !== 'VALID';
});

// rc.35 round-2 (M4 refactor) — keylog-rewind: the corroborated conjunction required each checkpoint be terminal for
// its OWN snapshot but never related successive snapshots — C₀ could commit length 2 and C₁ (linking C₀) commit
// length 1: a SIGNED rewind, both individually terminal. Post-M4.2 the chain enforces append-only: monotone length,
// equal length ⇒ identical snapshot, and an optional full prefix-extension witness (the entry vector itself).
sec('rc35-P0h', 'UST-6vj', 'a signed key-log rewind across checkpoints (shorter/rewritten history) is rejected', () => {
  const AG = 'sha256:' + '44'.repeat(32), EPh = P.genesisEpoch(AG);
  const E = ['sha256:' + 'e1'.repeat(32), 'sha256:' + 'e2'.repeat(32)];
  const kc = (n) => { const c = P.buildKeylogCommitment(E.slice(0, n)); return { root: c.root, length: c.length, head: c.head }; };
  const mk = (seq, prevId, kl) => P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPh, sequence: seq, ...(prevId ? { previous_checkpoint: prevId } : {}), active_genesis: AG, current_key_id: K0.key_id, keylog: kl }), K0.priv, K0.pub);
  const c0 = mk('0', null, kc(2));
  const rewind = P.verifyAuthorityCheckpointChain([c0, mk('1', P.authorityCheckpointId(c0), kc(1))], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } });
  const rewrite = P.verifyAuthorityCheckpointChain([c0, mk('1', P.authorityCheckpointId(c0), (() => { const c = P.buildKeylogCommitment(['sha256:' + 'e1'.repeat(32), 'sha256:' + 'ff'.repeat(32)]); return { root: c.root, length: c.length, head: c.head }; })())], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } });
  return rewind.result !== 'VALID' && rewrite.result !== 'VALID';
});

// rc.35 round-2 (M5 refactor) — quorum-poison: the canonical group reference was locked to the FIRST binding claim
// BEFORE its signature/admission was checked, so an attacker prepending a claim VARIANT with a garbage signature
// suppressed the honest quorum (denial-of-attested). Post-M5 grouping happens AFTER admission; the honest quorum wins.
sec('rc35-P0i', 'UST-6vj', 'an unauthenticated first claim-variant cannot suppress the honest witness quorum', () => {
  const EPq = P.genesisEpoch('sha256:' + '55'.repeat(32)), CP = 'sha256:' + 'ce'.repeat(32);
  const base = { domain_shard: D, genesis_epoch: EPq, sequence: '0', checkpoint: CP };
  const roots = { [KA.key_id]: KA.pub, [KB.key_id]: KB.pub }, doms = { [KA.key_id]: 'op-a', [KB.key_id]: 'op-b' };
  const poison = { claim: P.checkpointUniquenessClaim({ ...base, as_of: '2026-01-01T00:00:00Z' }), issuer_id: KA.key_id, sig: { alg: 'Ed25519', key_id: KA.key_id, pub: KA.pub, sig: 'AA' } };
  const r = P.verifyCheckpointUniqueness([poison, P.buildUniquenessAttestation(base, KA.priv, KA.pub), P.buildUniquenessAttestation(base, KB.priv, KB.pub)], { ...base, trustRoots: roots, domains: doms, threshold: 2 });
  return r.attested === true;
});

// rc.35 round-2 (M5) — ValidThreshold must be uniform: quorumTrustDomains accepted threshold ≤ 0 and returned
// met:true from an EMPTY evidence list (the P0-4 sibling the point-fix missed).
sec('rc35-P1b', 'UST-6vj', 'quorumTrustDomains with threshold ≤ 0 never reports met', () => {
  return P.quorumTrustDomains([], { domains: {}, threshold: 0 }).met !== true
    && P.quorumTrustDomains([{ source_id: 'x' }], { domains: { x: 'd' }, threshold: -1 }).met !== true;
});

// rc.35 round-2 (V2 census) — cross-domain/scope evidence: a receipt issued for ANOTHER authority scope (different
// active_genesis/domain) must never satisfy THIS chain's corroborated conjunction (M3 check 4, scope binding).
sec('rc35-P0j', 'UST-6vj', 'evidence bound to a FOREIGN authority scope cannot earn corroborated freshness here', () => {
  const AG1 = 'sha256:' + '55'.repeat(32), AG2 = 'sha256:' + '66'.repeat(32), EP1 = P.genesisEpoch(AG1);
  const klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const cp0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP1, sequence: '0', active_genesis: AG1, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const headId = P.authorityCheckpointId(cp0);
  const connectors = { [KA.key_id]: { pub: KA.pub, trust_domain: 'w', allowed_proof_kinds: ['pow-header-chain'] } };
  const foreign = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG2, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KA.priv, KA.pub);
  const r = P.deriveCheckpointFreshness([cp0], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub },
    target: { active_genesis: AG1, domain_shard: D, subject: 'ust:target', anchor: foreign('ust:target', 800) },
    commitment: foreign(headId, 900), terminality: { headProof: klc.headProof, successorProof: klc.successorProof }, trust: { connectors } });
  return r.keylog_freshness !== 'corroborated' && r.result !== 'VALID';
});

// rc.35 round-2 (V2 census) — recovery-DoS: a canon-throwing malformed recovery leaf must not throw through chain
// verification (denial-of-verifiability), and must admit nothing.
sec('rc35-P1c', 'UST-6vj', 'a malformed recovery statement never throws through chain verification', () => {
  const AG = 'sha256:' + '77'.repeat(32), EPr = P.genesisEpoch(AG);
  const klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const cp0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPr, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const cp1 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPr, sequence: '1', previous_checkpoint: P.authorityCheckpointId(cp0), active_genesis: AG, current_key_id: KA.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), KA.priv, KA.pub);
  const bomb = [{ claim: { purpose: 'ust:checkpoint-authority-recovery', domain_shard: D, genesis_epoch: EPr, last_accepted_checkpoint: P.authorityCheckpointId(cp0), effective_sequence: '1', replacement_authority: { key_id: KA.key_id, pub: KA.pub }, junk: undefined }, issuer_id: KA.key_id, sig: { sig: 'AA', pub: KA.pub } }];
  try { const r = P.verifyAuthorityCheckpointChain([cp0, cp1], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub }, recoveries: { '1': bomb }, recoveryKeys: { [KA.key_id]: KA.pub }, recoveryThreshold: 1 }); return r.result !== 'VALID'; } catch { return false; }
});

// rc.35 round-2 (V2 census) — resource bound BEFORE work: a keylogEntries witness above the §13 ceiling is rejected
// as E-BOUNDS before any Merkle recomputation (no CPU-amplification via a huge witness).
sec('rc35-P1d', 'UST-6vj', 'a keylogEntries witness above the §13 ceiling (257) is E-BOUNDS before Merkle work', () => {
  const AG = 'sha256:' + '88'.repeat(32), EPb = P.genesisEpoch(AG);
  const klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const cp0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPb, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const r = P.verifyAuthorityCheckpointChain([cp0], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub }, keylogEntries: Array.from({ length: 257 }, () => 'sha256:' + 'ab'.repeat(32)) });
  return r.result === 'INVALID' && r.error === 'E-BOUNDS';
});

// rc.36 round-3 (K3 opaque handles) — forged verified-context: the chain 'context' branch accepted ANY
// {scope_id, checkpoint_authority} shape, so a caller minted a verified-context and rooted an arbitrary chain
// (round-3 P0-1). Post-K3 the context MUST be a branded GenesisHandle (minted only by verifiedGenesisContext).
sec('r3-P0-1', 'UST-znh', 'a caller-shaped context (not a branded GenesisHandle) cannot root a checkpoint chain', () => {
  const AG = 'sha256:' + '22'.repeat(32), klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const c0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: P.genesisEpoch(AG), sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const forged = { scope_id: P.authorityScopeId(AG), active_genesis: AG, domain: D, genesis_epoch: P.genesisEpoch(AG), checkpoint_authority: { key_id: K0.key_id, pub: K0.pub } };
  return P.verifyAuthorityCheckpointChain([c0], { context: forged }).result !== 'VALID';
});

// rc.36 round-3 (K3) — forged assembler input: deriveAssurance trusted caller-shaped identity/freshness/anchor by
// shape (round-3 P0-4). Post-K3 it takes ONLY a branded PredicateGraph; a shaped object earns no coordinate.
sec('r3-P0-4', 'UST-znh', 'deriveAssurance rejects a caller-shaped verdict object (only a branded PredicateGraph lifts a coordinate)', () => {
  const forged = P.deriveAssurance({ identity: { status: 'verified', strength: 'authoritative' }, freshness: { result: 'VALID', keylog_freshness: 'attested' }, anchor: { inclusion: true, time: 'anchored' } });
  return forged.error === 'E-ASSURANCE' && P.isVerifiedHandle('predicate-graph', { atoms: {}, support: [] }) === false;
});

// round-25 (K3/P0-01) — the deeper cut: the EXPORTED provePredicates itself minted the branded PredicateGraph from
// caller-shaped labels, so `deriveAssurance(provePredicates({authoritative…}))` blessed TOP with zero verified evidence.
// Post-fix provePredicates is the UNBRANDED pure mapper; only verify() (module-private sealPredicateGraph) mints the brand.
sec('r25-P0-1', 'UST-znh', 'provePredicates is not a public brand-minting oracle — a caller cannot lift a tier from labels', () => {
  const graph = P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' }, freshness: { result: 'VALID', keylog_freshness: 'attested' }, anchor: { inclusion: true, time: 'anchored' } });
  return P.isVerifiedHandle('predicate-graph', graph) === false && P.deriveAssurance(graph).error === 'E-ASSURANCE';
});

// rc.36 round-3 (K5) — scope-free pinnedPrior: a bare {checkpoint_id, authority, sequence} pin let a continuation
// jump into a NEW domain/genesis without an epoch transition (round-3 P0-2). Post-K5 a pin MUST be a full scoped
// PinnedCheckpointState (or a branded chain handle), and the continuation must live in the pin's scope.
sec('r3-P0-2', 'UST-znh', 'a scope-free pinnedPrior cannot root a continuation into a new domain/genesis', () => {
  const AG2 = 'sha256:' + '33'.repeat(32), klc = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const c42 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'evil.example', genesis_epoch: P.genesisEpoch(AG2), sequence: '42', previous_checkpoint: 'sha256:' + 'aa'.repeat(32), active_genesis: AG2, current_key_id: K0.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), K0.priv, K0.pub);
  const bare = P.verifyAuthorityCheckpointChain([c42], { pinnedPrior: { checkpoint_id: 'sha256:' + 'aa'.repeat(32), authority: { key_id: K0.key_id, pub: K0.pub }, sequence: '41' } });
  return bare.result !== 'VALID';
});

// rc.36 round-3 (K5) — growth key-log rewrite: a checkpoint that GROWS the key-log length to an UNRELATED vector
// ([A]→[X,Y], not a prefix) used to pass on length monotonicity alone (round-3 P0-3). Post-K5 a growth edge without
// the prefix-extension witness is INDETERMINATE, never VALID.
sec('r3-P0-3', 'UST-znh', 'a growth key-log rewrite (non-prefix) without a consistency witness is not VALID', () => {
  const AG = 'sha256:' + '44'.repeat(32), EPk = P.genesisEpoch(AG);
  const A = 'sha256:' + '01'.repeat(32), X = 'sha256:' + '02'.repeat(32), Y = 'sha256:' + '03'.repeat(32);
  const kc = (arr) => { const c = P.buildKeylogCommitment(arr); return { root: c.root, length: c.length, head: c.head }; };
  const c0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPk, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: kc([A]) }), K0.priv, K0.pub);
  const c1 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPk, sequence: '1', previous_checkpoint: P.authorityCheckpointId(c0), active_genesis: AG, current_key_id: K0.key_id, keylog: kc([X, Y]) }), K0.priv, K0.pub);
  return P.verifyAuthorityCheckpointChain([c0, c1], { genesisAuthority: { key_id: K0.key_id, pub: K0.pub } }).result !== 'VALID';
});

// ─── report ────────────────────────────────────────────────────────────────────────────────────
console.log('\n  rc.33 audit — security regression (Phase 0, epic UST-1o6): SECURE-expectation gate');
for (const [s, id, bd, d] of rows) console.log(s + '  ' + id.padEnd(8) + bd.padEnd(9) + d);
console.log(`\n  ${green} FIXED   ${red} VULNERABLE   — target: all FIXED before rc.34 (then wire into CI)`);
process.exit(red ? 1 : 0);
