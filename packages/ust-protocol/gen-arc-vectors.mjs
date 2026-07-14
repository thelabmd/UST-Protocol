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
const D = 'noosphere.md', EP = 'sha256:' + 'a1'.repeat(32), AG = 'sha256:' + 'a2'.repeat(32);
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

// ─── freshness (F.5i/F.5j/F.5k) — corroborated conjunction + attested via witness quorum and via map ───
{
  const K0 = kp(s(0x11)), Wa = kp(s(0x21)), Wb = kp(s(0x22));
  const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const keylog = { length: kl.length, root: kl.root, head: kl.head }, term = { headProof: kl.headProof, successorProof: kl.successorProof };
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), K0.priv, K0.pub);
  const headId = P.authorityCheckpointId(C0);
  const btc = (pos, subj) => P.verifiedEvidence({ proof_kind: 'pow-header-chain', subject: subj, source_id: 'btc', facts: { substrate: 'bitcoin', position: String(pos) } });
  const target = { active_genesis: AG, domain_shard: D, anchor: btc(800, 'ust:target') };
  const base = { chain: [C0], genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term };
  add('fresh-corroborated', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term }, expect: { keylog_freshness: 'corroborated' } });
  add('fresh-order-unproven', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(700, headId), terminality: term }, expect: { result: 'INDETERMINATE', reason: 'order_unproven' } });
  const ua = (W) => P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }, W.priv, W.pub);
  const domains = { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b' }, trustRoots = { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub };
  add('fresh-attested-witness-quorum', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, uniqueness: { attestations: [ua(Wa), ua(Wb)], trustRoots, domains, threshold: 2 } }, expect: { keylog_freshness: 'attested', basis: 'accepted-witness-quorum' } });
  const cpLeaf = P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId });
  const cmap = P.buildVerifiableMap([cpLeaf, P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '1', checkpoint: 'sha256:' + 'ee'.repeat(32) })]);
  add('fresh-attested-map', 'deriveCheckpointFreshness', { chain: [C0], opts: { genesisAuthority: gAuth(K0), target, commitment: btc(900, headId), terminality: term, uniqueness: { map: { proof: cmap.prove(cpLeaf.key), mapRoot: cmap.root } } }, expect: { keylog_freshness: 'attested', basis: 'authenticated-map-uniqueness' } });
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

  const KA0 = kp(s(0x51)), KB0 = kp(s(0x52)), EPB = 'sha256:' + 'b1'.repeat(32), AGB = 'sha256:' + 'b2'.repeat(32);
  const C0a = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: KA0.key_id, keylog: KL }), KA0.priv, KA0.pub);
  const idA = P.authorityCheckpointId(C0a);
  const et = P.buildEpochTransition({ domain_shard: D, from_genesis_epoch: EP, from_final_checkpoint: idA, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pub, to_initial_sequence: '0' }, KA0.priv, KA0.pub);
  const C0b = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPB, sequence: '0', previous_epoch_final_checkpoint: idA, active_genesis: AGB, current_key_id: KB0.key_id, keylog: KL }), KB0.priv, KB0.pub);
  add('epoch-transition-valid', 'verifyAuthorityCheckpointChain', { chain: [C0a, C0b], opts: { genesisAuthority: gAuth(KA0), epochTransitions: { [EPB]: et } }, expect: { result: 'VALID' } });
  add('epoch-silent-reset', 'verifyAuthorityCheckpointChain', { chain: [C0a, C0b], opts: { genesisAuthority: gAuth(KA0) }, expect: { result: 'INVALID', error: 'E-MALFORMED' } });

  const e0 = 'sha256:' + '01'.repeat(32), e1 = 'sha256:' + '02'.repeat(32);
  const kl2 = P.buildKeylogCommitment([e0, e1]);
  add('terminality-honest', 'verifyKeylogTerminality', { keylog: { root: kl2.root, length: kl2.length, head: kl2.head }, proof: { headProof: kl2.headProof, successorProof: kl2.successorProof }, expect: { terminal: true } });
  add('terminality-hidden-successor', 'verifyKeylogTerminality', { keylog: { root: kl2.root, length: '1', head: e0 }, proof: { headProof: kl2.map.prove(P.keylogPosKey(0)), successorProof: kl2.map.prove(P.keylogPosKey(1)) }, expect: { terminal: false } });
}

const out = { version: 'UST 1.0 assurance-arc vectors (' + P.VERSION.spec + ')', note: 'language-neutral contract: pre-signed inputs + expected verdict, executable by any implementation (see run-arc-vectors.mjs)', count: V.length, vectors: V };
writeFileSync(new URL('../../vectors/arc-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log('  generated vectors/arc-vectors.json — ' + V.length + ' language-neutral arc vectors (' + P.VERSION.spec + ')');
