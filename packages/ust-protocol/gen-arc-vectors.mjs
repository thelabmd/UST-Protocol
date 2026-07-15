// SPDX-License-Identifier: Apache-2.0
// Generate LANGUAGE-NEUTRAL conformance vectors for the assurance arc (authority-checkpoint chain, freshness,
// recovery, epoch transition, terminality, uniqueness, no-fork). Each vector carries PRE-SIGNED inputs + the expected
// verdict, so ANY implementation (a second runner, e.g. a Go SDK, #34) can execute the SAME contract without
// generating keys. Deterministic (fixed seeds) — regenerating yields byte-identical vectors. Emits vectors/arc-vectors.json.
import { writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as P from './index.mjs';

const kp = (seedHex) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pub, key_id: P.keyId(pub) };
};
const s = (n) => n.toString(16).padStart(2, '0').repeat(32);          // deterministic 32-byte seed from a small int
const D = 'noosphere.md', AG = 'sha256:' + 'a2'.repeat(32), EP = P.genesisEpoch(AG);   // canonical epoch (M2): EP = H('ust:genesis-epoch', active_genesis)
const gAuth = (k) => ({ key_id: k.key_id, pub: k.pub });
const V = [];
const add = (id, op, fields) => V.push({ id, op, ...fields });

// ─── authority-checkpoint chain (F.5h) — genesis roots C₀; Cₙ₋₁ authorizes Cₙ; a checkpoint never authorizes itself ───
{
  const K0 = kp(s(1)), K1 = kp(s(2)), K2 = kp(s(3)), KX = kp(s(9));
  const KL = { length: '1', root: 'sha256:' + 'c0'.repeat(32), head: 'sha256:' + 'd0'.repeat(32) };
  const bc = (seq, prev, cur, nxt) => P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: seq, previous_checkpoint: prev, active_genesis: AG, current_key_id: cur.key_id, ...(nxt ? { next_key_id: nxt.k.key_id, next_pub: nxt.k.pub, effective_sequence: nxt.at } : {}), keylog: KL });
  const C0 = P.sealAuthorityCheckpoint(bc('0', null, K0, { k: K1, at: '1' }), K0.priv, K0.pub), id0 = P.authorityCheckpointId(C0);
  const C1 = P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), K1.priv, K1.pub), id1 = P.authorityCheckpointId(C1);
  const C2 = P.sealAuthorityCheckpoint(bc('2', id1, K2, null), K2.priv, K2.pub);
  add('ac-valid-chain', 'verifyAuthorityCheckpointChain', { chain: [C0, C1, C2], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'VALID' } });
  add('ac-unauthorized-signer', 'verifyAuthorityCheckpointChain', { chain: [C0, P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), KX.priv, KX.pub)], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'INVALID', error: 'E-AUTHORITY' } });
  add('ac-retroactive-self-auth', 'verifyAuthorityCheckpointChain', { chain: [C0, P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), K2.priv, K2.pub)], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'INVALID', error: 'E-AUTHORITY' } });
  add('ac-sequence-skip', 'verifyAuthorityCheckpointChain', { chain: [C0, P.sealAuthorityCheckpoint(bc('2', id0, K1, null), K1.priv, K1.pub)], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'INVALID', error: 'E-SEQ' } });
  add('ac-cold-start-unresolved', 'verifyAuthorityCheckpointChain', { chain: [C0, C1, C2], opts: {}, expect: { result: 'INDETERMINATE', reason: 'authority_unresolved' } });
}

// ─── freshness (F.5i/F.5j/F.5k) — corroborated conjunction + attested via witness quorum and via map. M3: the
//     commitment/anchor evidence is a SIGNED CONNECTOR RECEIPT verified against consumer-admitted connectors
//     (trust.connectors) — a caller-minted facts object is the rc.35 round-2 forge and earns nothing. ───
{
  const K0 = kp(s(0x11)), Wa = kp(s(0x21)), Wb = kp(s(0x22)), KC = kp(s(0x31)), KU = kp(s(0x32));
  const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const keylog = { length: kl.length, root: kl.root, head: kl.head }, term = { headProof: kl.headProof, successorProof: kl.successorProof };
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), K0.priv, K0.pub);
  const headId = P.authorityCheckpointId(C0);
  const connectors = { [KC.key_id]: { pub: KC.pub, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } };
  const rcpt = (K, pos, subj) => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, K.priv, K.pub);
  const btc = (pos, subj) => rcpt(KC, pos, subj);
  const target = { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: btc(800, 'ust:target') };
  const scope = { domain_shard: D, active_genesis: AG, genesis_epoch: EP };
  add('evidence-receipt-verify', 'verifyEvidenceReceipt', { receipt: btc(900, headId), opts: { subject: headId, scope, connectors }, expect: { result: 'VALID' } });
  add('evidence-receipt-tampered', 'verifyEvidenceReceipt', { receipt: { ...btc(900, headId), claim: { ...btc(900, headId).claim, facts: { substrate: 'bitcoin', position: '999999' } } }, opts: { subject: headId, scope, connectors }, expect: { result: 'INVALID', error: 'E-EVIDENCE' } });
  add('evidence-receipt-unadmitted-issuer', 'verifyEvidenceReceipt', { receipt: rcpt(KU, 900, headId), opts: { subject: headId, scope, connectors }, expect: { result: 'INDETERMINATE', reason: 'evidence_unverified' } });
  add('evidence-receipt-kind-not-allowed', 'verifyEvidenceReceipt', { receipt: btc(900, headId), opts: { subject: headId, scope, connectors: { [KC.key_id]: { pub: KC.pub, allowed_proof_kinds: ['content-addressed'] } } }, expect: { result: 'INDETERMINATE', reason: 'evidence_unverified' } });
  add('fresh-corroborated', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, trust: { connectors } }, expect: { keylog_freshness: 'corroborated' } });
  add('fresh-order-unproven', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(700, headId), terminality: term, trust: { connectors } }, expect: { result: 'INDETERMINATE', reason: 'order_unproven' } });
  add('fresh-evidence-forge-rejected', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: { proof_kind: 'pow-header-chain', subject: headId, source_id: 'btc', facts: { substrate: 'bitcoin', position: '900' } }, terminality: term, trust: { connectors } }, expect: { result: 'INDETERMINATE', reason: 'evidence_unverified', keylog_freshness: 'unverified' } });
  add('fresh-unadmitted-connector-rejected', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: rcpt(KU, 900, headId), terminality: term, trust: { connectors } }, expect: { result: 'INDETERMINATE', reason: 'evidence_unverified' } });
  const ua = (W) => P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }, W.priv, W.pub);
  const domains = { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b' }, trustRoots = { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub };
  add('fresh-attested-witness-quorum', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, trust: { connectors }, uniqueness: { attestations: [ua(Wa), ua(Wb)], trustRoots, domains, threshold: 2 }, allowExperimentalAttested: true }, expect: { keylog_freshness: 'attested', basis: 'accepted-witness-quorum' } });
  add('fresh-attested-withheld-in-stable', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, trust: { connectors }, uniqueness: { attestations: [ua(Wa), ua(Wb)], trustRoots, domains, threshold: 2 } }, expect: { keylog_freshness: 'corroborated', attested_withheld: 'experimental-gate' } });   // K1: stable path caps attested
  const cpLeaf = P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId });
  const cmap = P.buildVerifiableMap([cpLeaf, P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '1', checkpoint: 'sha256:' + 'ee'.repeat(32) })]);
  add('fresh-attested-map', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, uniqueness: { map: { proof: cmap.prove(cpLeaf.key), mapRoot: cmap.root } }, trust: { connectors, mapRoots: [cmap.root] }, allowExperimentalAttested: true }, expect: { keylog_freshness: 'attested', basis: 'authenticated-map-uniqueness' } });
}

// ─── recovery (F.5l) + epoch (F.5m) + terminality (F.5n) ───
{
  const K0 = kp(s(0x31)), K1 = kp(s(0x32)), KR = kp(s(0x3a)), R1 = kp(s(0x41)), R2 = kp(s(0x42)), R3 = kp(s(0x43));
  const KL = { length: '1', root: 'sha256:' + 'c0'.repeat(32), head: 'sha256:' + 'd0'.repeat(32) };
  const bc = (seq, prev, cur, nxt) => P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: seq, previous_checkpoint: prev, active_genesis: AG, current_key_id: cur.key_id, ...(nxt ? { next_key_id: nxt.k.key_id, next_pub: nxt.k.pub, effective_sequence: nxt.at } : {}), keylog: KL });
  const C0 = P.sealAuthorityCheckpoint(bc('0', null, K0, { k: K1, at: '1' }), K0.priv, K0.pub), id0 = P.authorityCheckpointId(C0);
  const rKeys = { [R1.key_id]: R1.pub, [R2.key_id]: R2.pub, [R3.key_id]: R3.pub };
  const rf = { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: id0, replacement_key_id: KR.key_id, replacement_pub: KR.pub, reason: 'lost', effective_sequence: '1' };
  const recs = [P.buildRecoveryStatement(rf, R1.priv, R1.pub), P.buildRecoveryStatement(rf, R2.priv, R2.pub)];
  const C1r = P.sealAuthorityCheckpoint(bc('1', id0, KR, null), KR.priv, KR.pub);
  add('recovery-2of3', 'verifyAuthorityCheckpointChain', { chain: [C0, C1r], opts: { genesisAuthority: gAuth(K0), recoveries: { '1': recs }, recoveryKeys: rKeys, recoveryThreshold: 2 }, expect: { result: 'VALID' } });
  add('recovery-below-threshold', 'verifyAuthorityCheckpointChain', { chain: [C0, C1r], opts: { genesisAuthority: gAuth(K0), recoveries: { '1': [recs[0]] }, recoveryKeys: rKeys, recoveryThreshold: 2 }, expect: { result: 'INVALID', error: 'E-AUTHORITY' } });

  const KA0 = kp(s(0x51)), KB0 = kp(s(0x52)), AGB = 'sha256:' + 'b2'.repeat(32), EPB = P.genesisEpoch(AGB);   // canonical epoch for the post-transition genesis
  const C0a = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: KA0.key_id, keylog: KL }), KA0.priv, KA0.pub);
  const idA = P.authorityCheckpointId(C0a);
  const et = P.buildEpochTransition({ domain_shard: D, from_genesis_epoch: EP, from_final_checkpoint: idA, to_active_genesis: AGB, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pub, to_initial_sequence: '0' }, KA0.priv, KA0.pub);   // M4.4: binds the destination genesis
  const C0b = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPB, sequence: '0', previous_epoch_final_checkpoint: idA, active_genesis: AGB, current_key_id: KB0.key_id, keylog: KL }), KB0.priv, KB0.pub);
  add('epoch-transition-valid', 'verifyAuthorityCheckpointChain', { chain: [C0a, C0b], opts: { genesisAuthority: gAuth(KA0), epochTransitions: { [EPB]: et } }, expect: { result: 'VALID' } });
  add('epoch-silent-reset', 'verifyAuthorityCheckpointChain', { chain: [C0a, C0b], opts: { genesisAuthority: gAuth(KA0) }, expect: { result: 'INVALID', error: 'E-MALFORMED' } });
  add('epoch-transition-labels-only-rejected', 'verifyAuthorityCheckpointChain', { chain: [C0a, C0b], opts: { genesisAuthority: gAuth(KA0), epochTransitions: { [EPB]: P.buildEpochTransition({ domain_shard: D, from_genesis_epoch: EP, from_final_checkpoint: idA, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pub, to_initial_sequence: '0' }, KA0.priv, KA0.pub) } }, expect: { result: 'INVALID' } });   // M4.4: a transition without to_active_genesis is a free label — rejected

  // M4.2 ChainConsistent — the key log is append-only ACROSS same-epoch checkpoints (closes keylog-rewind).
  const EV = ['sha256:' + '05'.repeat(32), 'sha256:' + '06'.repeat(32), 'sha256:' + '07'.repeat(32)];
  const kcn = (n) => { const c = P.buildKeylogCommitment(EV.slice(0, n)); return { root: c.root, length: c.length, head: c.head }; };
  const CC0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog: kcn(2) }), K0.priv, K0.pub);
  const ccid = P.authorityCheckpointId(CC0);
  const CC1 = (kl) => P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '1', previous_checkpoint: ccid, active_genesis: AG, current_key_id: K0.key_id, keylog: kl }), K0.priv, K0.pub);
  add('keylog-grows-across-checkpoints', 'verifyAuthorityCheckpointChain', { chain: [CC0, CC1(kcn(3))], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'VALID' } });
  add('keylog-rewind-rejected', 'verifyAuthorityCheckpointChain', { chain: [CC0, CC1(kcn(1))], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'INVALID', error: 'E-COMMIT' } });
  add('keylog-same-length-rewrite-rejected', 'verifyAuthorityCheckpointChain', { chain: [CC0, CC1((() => { const c = P.buildKeylogCommitment([EV[0], 'sha256:' + '0f'.repeat(32)]); return { root: c.root, length: c.length, head: c.head }; })())], opts: { genesisAuthority: gAuth(K0) }, expect: { result: 'INVALID', error: 'E-COMMIT' } });
  add('keylog-prefix-witness-valid', 'verifyAuthorityCheckpointChain', { chain: [CC0, CC1(kcn(3))], opts: { genesisAuthority: gAuth(K0), keylogEntries: EV }, expect: { result: 'VALID' } });
  add('keylog-prefix-witness-mismatch', 'verifyAuthorityCheckpointChain', { chain: [CC0, CC1(kcn(3))], opts: { genesisAuthority: gAuth(K0), keylogEntries: [EV[0], 'sha256:' + '0f'.repeat(32), EV[2]] }, expect: { result: 'INVALID', error: 'E-COMMIT' } });

  const e0 = 'sha256:' + '01'.repeat(32), e1 = 'sha256:' + '02'.repeat(32);
  const kl2 = P.buildKeylogCommitment([e0, e1]);
  add('terminality-honest', 'verifyKeylogTerminality', { keylog: { root: kl2.root, length: kl2.length, head: kl2.head }, proof: { headProof: kl2.headProof, successorProof: kl2.successorProof }, expect: { terminal: true } });
  add('terminality-hidden-successor', 'verifyKeylogTerminality', { keylog: { root: kl2.root, length: '1', head: e0 }, proof: { headProof: kl2.prove(0) }, expect: { terminal: false } });
}

// ─── Phase A connector evidence algebra (F.5g) — order proof-relation, quorum by consumer-resolved domains, class ───
{
  const ev = (facts) => ({ proof_kind: 't', subject: 'ust:x', source_id: 's', facts });
  add('order-same-substrate-after', 'compareEvidenceOrder', { a: ev({ substrate: 'bitcoin', position: '900' }), b: ev({ substrate: 'bitcoin', position: '800' }), expect: { value: 'proven-after' } });
  add('order-two-upper-bounds-unproven', 'compareEvidenceOrder', { a: ev({ not_after: '2027-02-01T00:00:00Z' }), b: ev({ not_after: '2027-01-01T00:00:00Z' }), expect: { value: 'unproven' } });
  add('quorum-distinct-domains', 'quorumTrustDomains', { list: [{ source_id: 'a1' }, { source_id: 'b1' }, { source_id: 'a2' }], opts: { domains: { a1: 'op-a', a2: 'op-a', b1: 'op-b' }, threshold: 2 }, expect: { count: 2, met: true } });
  add('class-transparency-log-not-nonmembership', 'evidenceClass', { proof_kind: 'transparency-log', expect: { value: 'append-only-inclusion+consistency' } });
  add('class-unknown-opaque', 'evidenceClass', { proof_kind: 'made-up', expect: { value: 'opaque' } });
  add('evidence-facts-only-rejects-self-declared', 'verifiedEvidence', { fields: { proof_kind: 'k', subject: 'x', source_id: 's', facts: { assurance: 'attested' } }, expect: { error: 'E-EVIDENCE' } });
}

// ─── P0-2 name no-fork (F.5a.1) — authoritative EARNED from a consumer-trusted witness; independence never self-declared ───
{
  const W = kp(s(0x61));
  const good = P.buildNoForkEvidence({ domain_shard: D, active_genesis: AG }, W.priv, W.pub);
  add('nofork-verified-witness', 'verifyNoForkEvidence', { evidence: good, opts: { domain_shard: D, active_genesis: AG, trustRoots: { [W.key_id]: W.pub } }, expect: { ok: true, witness_id: W.key_id } });
  add('nofork-untrusted-issuer', 'verifyNoForkEvidence', { evidence: good, opts: { domain_shard: D, active_genesis: AG, trustRoots: {} }, expect: { ok: false } });
  add('nofork-self-declared-trust-domain', 'verifyNoForkEvidence', { evidence: { claim: { ...good.claim, trust_domain: 'independent-7' }, issuer_id: W.key_id, sig: good.sig }, opts: { domain_shard: D, active_genesis: AG, trustRoots: { [W.key_id]: W.pub } }, expect: { ok: false } });
}

// ─── uniqueness units (F.5j/F.5k) — witness quorum + map, both bases; and name-map authoritative ───
{
  const EPc = 'sha256:' + 'e1'.repeat(32), CP = 'sha256:' + 'ce'.repeat(32);
  const Wa = kp(s(0x71)), Wb = kp(s(0x72)), Wc = kp(s(0x73));
  const ua = (W) => P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP }, W.priv, W.pub);
  const domains = { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b', [Wc.key_id]: 'op-a' }, trustRoots = { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub, [Wc.key_id]: Wc.pub };
  const uOpts = (a) => ({ attestations: a, opts: { domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP, trustRoots, domains, threshold: 2 } });
  add('uniqueness-witness-quorum-attested', 'verifyCheckpointUniqueness', { ...uOpts([ua(Wa), ua(Wb)]), expect: { attested: true, basis: 'accepted-witness-quorum' } });
  add('uniqueness-witness-same-domain-not-met', 'verifyCheckpointUniqueness', { ...uOpts([ua(Wa), ua(Wc)]), expect: { attested: false } });
  // M5 — one quorum algebra: group AFTER admission (no poison), >1 winner = conflict (never first-wins).
  const Wd = kp(s(0x74)), roots4 = { ...trustRoots, [Wd.key_id]: Wd.pub }, doms4 = { ...domains, [Wc.key_id]: 'op-c', [Wd.key_id]: 'op-d' };
  const uav = (W) => P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP, observed_map_root: 'sha256:' + 'aa'.repeat(32) }, W.priv, W.pub);
  const u4 = (a) => ({ attestations: a, opts: { domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP, trustRoots: roots4, domains: doms4, threshold: 2 } });
  add('uniqueness-quorum-poison-rejected', 'verifyCheckpointUniqueness', { ...u4([{ claim: P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP, as_of: '2026-01-01T00:00:00Z' }), issuer_id: Wa.key_id, sig: { alg: 'Ed25519', key_id: Wa.key_id, pub: Wa.pub, sig: 'AA' } }, ua(Wa), ua(Wb)]), expect: { attested: true } });
  add('uniqueness-rival-quorums-conflict', 'verifyCheckpointUniqueness', { ...u4([ua(Wa), ua(Wb), uav(Wc), uav(Wd)]), expect: { attested: false, conflict: true } });
  const cpLeaf = P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP });
  const cmap = P.buildVerifiableMap([cpLeaf, P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EPc, sequence: '1', checkpoint: 'sha256:' + 'ff'.repeat(32) })]);
  add('uniqueness-map-attested', 'verifyCheckpointMapUniqueness', { proof: cmap.prove(cpLeaf.key), opts: { domain_shard: D, genesis_epoch: EPc, sequence: '0', checkpoint: CP, mapRoot: cmap.root }, expect: { attested: true, basis: 'authenticated-map-uniqueness' } });
  const nLeaf = P.nameMapLeaf({ domain_shard: D, active_genesis: AG }), nmap = P.buildVerifiableMap([nLeaf]), empty = P.buildVerifiableMap([]);
  add('name-map-authoritative', 'verifyActiveGenesisUniqueness', { proof: nmap.prove(nLeaf.key), opts: { domain_shard: D, active_genesis: AG, mapRoot: nmap.root }, expect: { authoritative: true, basis: 'authenticated-map-uniqueness' } });
  add('name-map-absent-nonmembership', 'verifyActiveGenesisUniqueness', { proof: empty.prove(nLeaf.key), opts: { domain_shard: D, active_genesis: AG, mapRoot: empty.root }, expect: { authoritative: false, absent: true } });
}

// ─── recovery + epoch units (F.5l/F.5m) ───
{
  const R1 = kp(s(0x81)), R2 = kp(s(0x82)), R3 = kp(s(0x83)), KR = kp(s(0x8a));
  const rKeys = { [R1.key_id]: R1.pub, [R2.key_id]: R2.pub, [R3.key_id]: R3.pub };
  const last = 'sha256:' + 'ac'.repeat(32);
  const rf = { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: last, replacement_key_id: KR.key_id, replacement_pub: KR.pub, reason: 'lost', effective_sequence: '1' };
  const st = (W) => P.buildRecoveryStatement(rf, W.priv, W.pub);
  const rOpts = { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: last, effective_sequence: '1', recoveryKeys: rKeys, threshold: 2 };
  add('recovery-unit-2of3', 'verifyCheckpointRecovery', { statements: [st(R1), st(R2)], opts: rOpts, expect: { recovered: true } });
  add('recovery-unit-below-threshold', 'verifyCheckpointRecovery', { statements: [st(R1)], opts: rOpts, expect: { recovered: false } });
  const KA = kp(s(0x91)), KB = kp(s(0x92)), KXe = kp(s(0x9f)), idA = 'sha256:' + 'a5'.repeat(32), AGBu = 'sha256:' + 'b6'.repeat(32), EPB = P.genesisEpoch(AGBu);
  const ef = { domain_shard: D, from_genesis_epoch: EP, from_final_checkpoint: idA, to_active_genesis: AGBu, to_genesis_epoch: EPB, to_key_id: KB.key_id, to_pub: KB.pub, to_initial_sequence: '0' };
  const eOpts = { domain_shard: D, from_genesis_epoch: EP, from_final_checkpoint: idA, fromAuthority: { key_id: KA.key_id, pub: KA.pub } };
  add('epoch-unit-valid', 'verifyEpochTransition', { statement: P.buildEpochTransition(ef, KA.priv, KA.pub), opts: eOpts, expect: { ok: true } });
  add('epoch-unit-wrong-signer', 'verifyEpochTransition', { statement: P.buildEpochTransition(ef, KXe.priv, KXe.pub), opts: eOpts, expect: { ok: false } });
  add('epoch-unit-free-label-rejected', 'verifyEpochTransition', { statement: P.buildEpochTransition({ ...ef, to_active_genesis: undefined }, KA.priv, KA.pub), opts: eOpts, expect: { ok: false } });   // M4.4
}

// ─── #78 ASSURANCE PRODUCT-LATTICE vectors — pure axis-tuple contracts (no keys): tier projection, the product
//     order (independence witnesses), and the ℐ_C cap. A second impl reproduces projectTier/assuranceLE/capAssurance.
{
  // M1.1 — STRENGTH is four chains (64 states); capability SUPPORT is a separate Boolean lattice, not a coordinate.
  const TOP = { integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' };
  const HIGH = { integrity: 'valid', identity: 'corroborated', freshness: 'corroborated', time: 'unproven' };
  const LIGHT = { integrity: 'valid', identity: 'self-asserted', freshness: 'unverified', time: 'unproven' };
  const idUp = { integrity: 'valid', identity: 'authoritative', freshness: 'unverified', time: 'unproven' };
  const frUp = { integrity: 'valid', identity: 'self-asserted', freshness: 'attested', time: 'unproven' };
  add('lat-tier-top', 'projectTier', { state: TOP, expect: { value: 'TOP' } });
  add('lat-tier-high', 'projectTier', { state: HIGH, expect: { value: 'HIGH' } });
  add('lat-tier-light', 'projectTier', { state: LIGHT, expect: { value: 'LIGHT' } });
  add('lat-tier-none-integrity-floor-unmet', 'projectTier', { state: { ...TOP, integrity: 'invalid' }, expect: { value: 'NONE' } });
  add('lat-authoritative-but-unanchored-is-HIGH-not-TOP', 'projectTier', { state: { ...TOP, time: 'unproven' }, expect: { value: 'HIGH' } });
  add('lat-freshness-does-not-lift-the-tier', 'projectTier', { state: frUp, expect: { value: 'LIGHT' } });
  add('lat-orthogonal-id-up-vs-fresh-up-incomparable', 'assuranceLE', { a: idUp, b: frUp, expect: { le: false } });
  add('lat-orthogonal-fresh-up-vs-id-up-incomparable', 'assuranceLE', { a: frUp, b: idUp, expect: { le: false } });
  add('lat-le-light-below-top', 'assuranceLE', { a: LIGHT, b: TOP, expect: { le: true } });
  add('lat-cap-no-trust-roots-drops-TOP-to-LIGHT', 'capAssurance', { state: TOP, ceiling: { identity: 'self-asserted', freshness: 'corroborated' }, expect: { identity: 'self-asserted', freshness: 'corroborated', tier: 'LIGHT' } });
  add('lat-cap-no-ceiling-unchanged', 'capAssurance', { state: TOP, ceiling: null, expect: { identity: 'authoritative', tier: 'TOP' } });
}

const out = { version: 'UST 1.0 assurance-arc vectors (' + P.VERSION.spec + ')', note: 'language-neutral contract: pre-signed inputs + expected verdict, executable by any implementation (see run-arc-vectors.mjs)', count: V.length, vectors: V };
writeFileSync(new URL('../../vectors/arc-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log('  generated vectors/arc-vectors.json — ' + V.length + ' language-neutral arc vectors (' + P.VERSION.spec + ')');
