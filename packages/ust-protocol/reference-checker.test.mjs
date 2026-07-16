// SPDX-License-Identifier: Apache-2.0
// Reference-checker vectors — the checker ACCEPTS a genuine corroborated proof, and every past P0 is either an
// UNBUILDABLE term or a structured reject. An UNTRUSTED prover (this file) proposes packages; check_C is the oracle.
import * as P from './index.mjs';
import { checkAuthorityProof, witnessId, REFERENCE_CHECKER_RULES } from './reference-checker.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
const kp = (h) => { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(h, 'hex')]), format: 'der', type: 'pkcs8' }); const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url'); return { priv, pub, key_id: P.keyId(pub) }; };
const T = { generated_at: '2026-07-16T00:00:00Z', valid_from: '2026-07-16T00:00:00Z', valid_to: '2026-07-16T01:00:00Z' };
let pass = 0, fail = 0; const fails = [];
const check = (name, cond) => { if (cond) pass++; else { fail++; fails.push(name); } };

// ── an untrusted prover: build a genuine corroborated ProofPackage over good.example ──
const G = kp('cc'.repeat(32)), KC = kp('64'.repeat(32)), Wa = kp('a1'.repeat(32)), Wb = kp('a2'.repeat(32));
const gen = P.seal(P.buildGenesis({ domain_shard: 'good.example', ust_id: 'ust:20260716.00', key_id: G.key_id }, T, G.pub, undefined, undefined, undefined, { key_id: G.key_id, pub: G.pub }), G.priv, G.pub);
const AG = P.contentHash(gen), EP = P.genesisEpoch(AG);
const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
const head = P.authorityCheckpointId(C0);
const term = { headProof: kl.headProof };
const rc = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pub);
const commit = rc(head, 900), anchor = rc('ust:target', 800);
const ua = (W) => P.buildUniquenessAttestation({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);

// witness store (content-addressed) + node helpers
const witnesses = {};
const put = (o) => { const id = witnessId(o); witnesses[id] = o; return id; };
const node = (rule, children = [], wids = [], params) => ({ rule, children, witnesses: wids, ...(params ? { params } : {}) });
const gW = put(gen), c0W = put(C0), tW = put(term), commitW = put(commit), anchorW = put(anchor);

const πGenesis = node('Genesis', [], [gW]);
const πChain = node('CheckpointZero', [πGenesis], [c0W]);
const πCommit = node('ConnectorEvidence', [πGenesis], [commitW], { subject: head });
const πTarget = node('ConnectorEvidence', [πGenesis], [anchorW], { subject: 'ust:target' });
const πAfter = node('AfterOrder', [πCommit, πTarget]);
const πCorr = node('Corroborated', [πChain, πCommit, πTarget, πAfter], [tW]);   // terminality of the head

const CONN = { connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } } };
const CFG = { ...CONN, witnesses: { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub }, domains: { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b' }, policy: { uniqueness_threshold: 2 } };

// ── ACCEPT: a genuine corroborated derivation ──
{
  const r = checkAuthorityProof({ term: πCorr, witnesses }, CFG);
  check('ACCEPT corroborated: VALID, base corroborated, empty anti-equivocation, support carries order caps', r.result === 'VALID' && r.judgment.kind === 'Freshness' && r.judgment.base === 'corroborated' && !r.judgment.aeq.quorum && !r.judgment.aeq.map && r.judgment.support.includes('order') && r.judgment.h === head && r.judgment.s === P.authorityScopeId(AG));
}
// ── ACCEPT: reinforce with quorum → witness-basis; and the proof_hash/config_id are present ──
{
  const uaW = [put(ua(Wa)), put(ua(Wb))];
  const πQuorum = node('QuorumAgreement', [πGenesis], uaW, { n: '0', h: head });
  const πWitness = node('ReinforceQuorum', [πCorr, πQuorum]);
  const r = checkAuthorityProof({ term: πWitness, witnesses }, CFG);
  check('ACCEPT reinforce-quorum: quorum basis present, map null (NOT collapsed to attested), support has quorum', r.result === 'VALID' && r.judgment.aeq.quorum && r.judgment.aeq.quorum.domains.length === 2 && !r.judgment.aeq.map && r.judgment.support.includes('quorum') && typeof r.proof_hash === 'string');
}

// ── round-3 P0-1 / round-4 P0-1: there is no Verified/PredicateGraph constructor — a caller CANNOT introduce a label ──
{
  const forged = node('PredicateGraph', [], [], { identity: 'authoritative', freshness: 'attested' });
  const r = checkAuthorityProof({ term: forged, witnesses }, CFG);
  check('REJECT forged-assembler/mint-oracle: unknown rule (closed enum) → INVALID', r.result === 'INVALID' && /unknown rule/.test(r.reason));
}
// forged context: there is no way to root a chain except a Genesis leaf over real bytes
{
  const fakeGen = { rule: 'CheckpointZero', children: [{ rule: 'Genesis', children: [], witnesses: [put({ state: { id: { class: 'genesis' } }, sig: {} })] }], witnesses: [c0W, tW] };
  const r = checkAuthorityProof({ term: fakeGen, witnesses }, CFG);
  check('REJECT forged-context: a non-verifying genesis witness → INVALID(genesis integrity)', r.result === 'INVALID' && /Genesis/.test(r.reason));
}

// ── round-4 P0-2: uniqueness trust comes from C, never the term — attacker witnesses not in C are not counted ──
{
  const Ea = kp('e1'.repeat(32)), Eb = kp('e2'.repeat(32));  // ATTACKER witnesses, NOT in CFG.witnesses/domains
  const eua = (W) => P.buildUniquenessAttestation({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);
  const πQ = node('QuorumAgreement', [πGenesis], [put(eua(Ea)), put(eua(Eb))], { n: '0', h: head });
  const r = checkAuthorityProof({ term: node('ReinforceQuorumBad', []), witnesses });  // wrong rule name → closed enum
  const r2 = checkAuthorityProof({ term: node('ReinforceQuorum', [πCorr, πQ]), witnesses }, CFG);
  check('REJECT self-trust: attacker witnesses (∉ C) do not reach quorum → INDETERMINATE, never attested', r2.result === 'INDETERMINATE' && /quorum not met/.test(r2.reason));
}

// ── round-4 P0-4: cross-scope cannot be typed — a checkpoint in a foreign scope does not unify ──
{
  const gen2 = P.seal(P.buildGenesis({ domain_shard: 'evil.example', ust_id: 'ust:20260716.00', key_id: G.key_id }, T, G.pub, undefined, undefined, undefined, { key_id: G.key_id, pub: G.pub }), G.priv, G.pub);
  const AG2 = P.contentHash(gen2), EP2 = P.genesisEpoch(AG2);
  const c0evil = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'evil.example', genesis_epoch: EP2, sequence: '0', active_genesis: AG2, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
  const gW2 = put(gen2), c0W2 = put(c0evil), headEvil = P.authorityCheckpointId(c0evil);
  const πGen2 = node('Genesis', [], [gW2]);
  const πChainEvil = node('CheckpointZero', [πGen2], [c0W2]);           // chain in scope(gen2)
  // try to corroborate the evil chain with GOOD-scope evidence → scope mismatch
  const πCorrX = node('Corroborated', [πChainEvil, πCommit, πTarget, πAfter], [tW]);  // πCommit/πTarget are in scope(gen)
  const r = checkAuthorityProof({ term: πCorrX, witnesses }, CFG);
  check('REJECT cross-scope: chain scope ≠ evidence scope → INVALID (does not unify)', r.result === 'INVALID' && /scope/.test(r.reason));
}

// ── round-4 P0-4 (fully-consistent forgery): checkpoint + receipts all claim a foreign domain, active_genesis=good.
//    §2.y — a diagnostic wire field (domain_shard) MUST agree with the scope; check_C rejects (the old stack accepts).
{
  const c0evil = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'evil.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
  const headE = P.authorityCheckpointId(c0evil);
  const rcE = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: 'evil.example', active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pub);
  const gWx = put(gen), c0Wx = put(c0evil), tWx = put(term), cmx = put(rcE(headE, 900)), anx = put(rcE('ust:target', 800));
  const πGx = node('Genesis', [], [gWx]);
  const πChx = node('CheckpointZero', [πGx], [c0Wx]);
  const r = checkAuthorityProof({ term: πChx, witnesses }, CFG);
  check('REJECT foreign-domain (§2.y): checkpoint domain_shard ≠ genesis domain → INVALID even when active_genesis matches', r.result === 'INVALID' && /domain_shard ≠ genesis domain/.test(r.reason));
}

// ── round-4 P0-5: epoch activation REQUIRES a verified Genesis[sB] child — a hash cannot introduce it ──
{
  const KB = kp('b0'.repeat(32)), AGB = 'sha256:' + '99'.repeat(32);
  const commitB = P.buildEpochTransition({ domain_shard: 'good.example', from_genesis_epoch: EP, from_final_checkpoint: head, to_active_genesis: AGB, to_genesis_epoch: P.genesisEpoch(AGB), to_key_id: KB.key_id, to_pub: KB.pub, to_initial_sequence: '0' }, G.priv, G.pub);
  const πFuture = node('FutureGenesisCommitment', [πChain], [put(commitB)]);
  // ActivateGenesis needs a Genesis child for B; the attacker has no genesis B bytes, only the hash → cannot build it.
  const noGenB = node('ActivateGenesis', [πFuture, node('Genesis', [], [put({ state: { id: { class: 'genesis' } }, sig: {} })])], [], {});
  const r = checkAuthorityProof({ term: noGenB, witnesses }, CFG);
  check('REJECT unverified-epoch: ActivateGenesis without a VERIFIED Genesis[sB] → INVALID', r.result === 'INVALID');
}

// ── round-4 P0-3: there are no handles — witnesses are content-addressed bytes; mutating a parsed object is moot ──
{
  const tampered = { term: πCorr, witnesses: { ...witnesses } };
  // flip a byte in the genesis witness AFTER content-addressing → the content address no longer matches → reject
  tampered.witnesses[gW] = { ...witnesses[gW], sig: { ...witnesses[gW].sig, sig: 'AAAA' } };
  const r = checkAuthorityProof(tampered, CFG);
  check('REJECT mutated-witness: a post-hoc-mutated witness fails its content address → INVALID', r.result === 'INVALID' && /content address/.test(r.reason));
}

// ── round-4 P1-1: total — policy:null / config:null never throws ──
{
  const a = checkAuthorityProof({ term: πCorr, witnesses }, null);
  const b = checkAuthorityProof({ term: πCorr, witnesses }, { ...CFG, policy: null });
  check('TOTAL: config null → INVALID(config), never a throw', a.result === 'INVALID' && /config/.test(a.reason));
  check('TOTAL: policy null → normalized, still VALID', b.result === 'VALID');
}
// ── round-4 P1-2: support rides the DAG — corroborated with no evidence premise is unbuildable ──
{
  // Corroborated needs Evidence premises whose caps become support; a Corroborated with empty support has no term.
  const r = checkAuthorityProof({ term: πCorr, witnesses }, CFG);
  check('SUPPORT rides the DAG: corroborated carries non-empty support (no support:[] state)', r.result === 'VALID' && r.judgment.support.length > 0);
}
// ── bounds / cycle guard (§10) ──
{
  const cyc = node('Corroborated', []); cyc.children = [cyc];
  const r = checkAuthorityProof({ term: cyc, witnesses }, CFG);
  check('BOUNDS: a cyclic/shared term node → INVALID (not a tree), never infinite loop', r.result === 'INVALID');
}

// ── cluster A — §2 byte-semantics: the checker reads each caller input EXACTLY ONCE into an inert value ─────────────
// P0-05 INSTRUMENTATION GATE: a witness exposed as a getter is read exactly once by the checker (rules read the inert
// snapshot, not the live object) — so a value cannot differ between the hash read and a rule read.
{
  let reads = 0;
  const evil = { get headProof() { reads++; return kl.headProof; } };   // returns the CORRECT value; counts reads
  const evilW = witnessId(evil);                                        // (this addressing read is the prover's, not the checker's)
  witnesses[evilW] = evil;
  reads = 0;                                                            // count ONLY the checker's reads of the live object
  const πCorrEvil = node('Corroborated', [πChain, πCommit, πTarget, πAfter], [evilW]);
  const r = checkAuthorityProof({ term: πCorrEvil, witnesses }, CFG);
  check('BYTE-SEMANTICS single-read (P0-05): checker reads a live witness EXACTLY once → VALID and reads===1 (no hash/rule divergence)', r.result === 'VALID' && reads === 1);
}
// P1-02 prototype-planted witness: own-keys + null-proto store → an INHERITED witness is invisible AND unreachable.
{
  const proto = {}; proto[gW] = gen;                                    // the genesis planted on the prototype only
  const witnessesInherited = Object.create(proto);                     // zero own keys; gW resolves only via inheritance
  const r = checkAuthorityProof({ term: node('Genesis', [], [gW]), witnesses: witnessesInherited }, CFG);
  check('REJECT prototype-planted witness (P1-02): inherited witness is not in the own-key store → INVALID(missing)', r.result === 'INVALID' && /missing witness/.test(r.reason));
}
// P0-02 non-canonical coordinate: MapUnique at n="00" cannot decode to a CanonicalSeq, so it never aliases n=0.
{
  const dummyMap = put({ proof: {}, mapRoot: 'sha256:' + '00'.repeat(32) });
  const πMU = node('MapUnique', [πGenesis], [dummyMap], { n: '00', h: head });
  const r = checkAuthorityProof({ term: node('ReinforceMap', [πCorr, πMU]), witnesses }, CFG);
  check('REJECT non-canonical coordinate (P0-02): MapUnique n="00" → INVALID(CanonicalSeq), cannot alias n=0', r.result === 'INVALID' && /non-canonical sequence/.test(r.reason));
}
// P1-05 config snapshot: the consumer config is read once into an inert value; a getter fires exactly once.
{
  let creads = 0;
  const cfgAccessor = { get connectors() { creads++; return CONN.connectors; }, witnesses: CFG.witnesses, domains: CFG.domains, policy: CFG.policy };
  const r = checkAuthorityProof({ term: πCorr, witnesses }, cfgAccessor);
  check('CONFIG snapshot (P1-05): config read once into an inert value → VALID and connectors getter read exactly once', r.result === 'VALID' && creads === 1);
}

// ── cluster B — proof-relevant indexed judgments (M-REL / M-ERA): a relation is indexed by every object it relates ──
// P0-01 detached After: an After that orders UNRELATED evidences does not satisfy Corroborated over commit/target.
{
  const o1 = put(rc('ust:other', 500)), o2 = put(rc('ust:other2', 100));
  const πo1 = node('ConnectorEvidence', [πGenesis], [o1], { subject: 'ust:other' });
  const πo2 = node('ConnectorEvidence', [πGenesis], [o2], { subject: 'ust:other2' });
  const πAfterForeign = node('AfterOrder', [πo1, πo2]);                              // proves 500>100 — over other1/other2
  const πCorrDetached = node('Corroborated', [πChain, πCommit, πTarget, πAfterForeign], [tW]);
  const r = checkAuthorityProof({ term: πCorrDetached, witnesses }, CFG);
  check('REJECT detached After (P0-01): After must order THESE commit/target evidences → INVALID (M-REL)', r.result === 'INVALID' && /detached After|does not order/.test(r.reason));
}
// P0-07 typed order: a time-only kind (rfc3161-tsa) with a planted position fact cannot assert a substrate order.
{
  const KT = kp('7a'.repeat(32));
  const tsaWithPos = P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: 'ust:target', proof_kind: 'rfc3161-tsa', facts: { substrate: 'bitcoin', position: '999999' }, issued_at: '2026-01-01T00:00:00Z' }, KT.priv, KT.pub);
  const CFG_T = { connectors: { [KC.key_id]: CONN.connectors[KC.key_id], [KT.key_id]: { pub: KT.pub, trust_domain: 'tsa', allowed_proof_kinds: ['rfc3161-tsa'] } } };
  const πTsa = node('ConnectorEvidence', [πGenesis], [put(tsaWithPos)], { subject: 'ust:target' });
  const πAfterTsa = node('AfterOrder', [πCommit, πTsa]);                             // pow(position) vs tsa(planted position)
  const r = checkAuthorityProof({ term: node('Corroborated', [πChain, πCommit, πTsa, πAfterTsa], [tW]), witnesses }, CFG_T);
  check('REJECT tsa-position (P0-07): position order and interval order are incomparable → INDETERMINATE', r.result === 'INDETERMINATE' && /incomparable|order/.test(r.reason));
}
// P0-03 foreign-domain quorum: votes attesting a foreign domain are not counted in the good-scope quorum.
{
  const uaEvil = (W) => P.buildUniquenessAttestation({ domain_shard: 'evil.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);
  const πQevil = node('QuorumAgreement', [πGenesis], [put(uaEvil(Wa)), put(uaEvil(Wb))], { n: '0', h: head });
  const r = checkAuthorityProof({ term: node('ReinforceQuorum', [πCorr, πQevil]), witnesses }, CFG);
  check('REJECT foreign-domain quorum (P0-03): votes for a foreign domain are not counted → quorum not met', r.result === 'INDETERMINATE' && /quorum not met/.test(r.reason));
}
// P1-01 positive monotonicity: an unadmitted junk vote listed FIRST does not starve the genuine quorum (admit-then-group).
{
  const Ez = kp('ee'.repeat(32));                                                   // attacker witness, NOT in CFG
  const junk = P.buildUniquenessAttestation({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, Ez.priv, Ez.pub);
  const πQpoison = node('QuorumAgreement', [πGenesis], [put(junk), put(ua(Wa)), put(ua(Wb))], { n: '0', h: head });
  const r = checkAuthorityProof({ term: node('ReinforceQuorum', [πCorr, πQpoison]), witnesses }, CFG);
  check('RESIST quorum poison (P1-01): a junk vote first does not break the genuine quorum → VALID witness-basis (monotonicity)', r.result === 'VALID' && r.judgment.aeq.quorum && r.judgment.aeq.quorum.domains.length === 2);
}
// P1-04 §13 ceiling: a checkpoint claiming a 257-length key-log is rejected at introduction.
{
  const c0big = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: '257', head: kl.head } }), G.priv, G.pub);
  const r = checkAuthorityProof({ term: node('CheckpointZero', [πGenesis], [put(c0big)]), witnesses }, CFG);
  check('REJECT over-ceiling key-log (P1-04): C0 length 257 > 256 → INVALID(ceiling)', r.result === 'INVALID' && /ceiling/.test(r.reason));
}

// ── cluster C — specification ↔ code correspondence ────────────────────────────────────────────────────────────────
// P2-01 the term carries NO conclusion: a node with a stored `expected`/`conclusion` is rejected (never trusted).
{
  const forged = { rule: 'Genesis', children: [], witnesses: [gW], expected: { kind: 'Assurance', tier: 'TOP' } };
  const r = checkAuthorityProof({ term: forged, witnesses }, CFG);
  check('REJECT stored conclusion (P2-01): a node carrying `expected` → INVALID (checker recomputes, never trusts)', r.result === 'INVALID' && /must not carry a conclusion/.test(r.reason));
}
// P2-02 grammar↔RULES parity: the exported registry is exactly the 15 implemented constructors, and a reserved/folded
// name (DirectEvidence, NameAuthoritative, SnapshotTerminal, WitnessVote, EpochCheckpointZero) is unknown → INVALID.
{
  const EXPECTED = ['Genesis', 'CheckpointZero', 'CheckpointStep', 'ConnectorEvidence', 'AfterOrder', 'Corroborated', 'MapUnique', 'QuorumAgreement', 'ReinforceMap', 'ReinforceQuorum', 'FutureGenesisCommitment', 'ActivateGenesis', 'NameBound', 'Anchored', 'ProjectAssurance'];
  const parity = REFERENCE_CHECKER_RULES.length === EXPECTED.length && EXPECTED.every((rule, i) => REFERENCE_CHECKER_RULES[i] === rule);
  const reserved = ['DirectEvidence', 'NameAuthoritative', 'SnapshotTerminal', 'WitnessVote', 'EpochCheckpointZero'];
  const allReservedInvalid = reserved.every((rule) => { const r = checkAuthorityProof({ term: node(rule, [], []), witnesses }, CFG); return r.result === 'INVALID' && /unknown rule/.test(r.reason); });
  check('PARITY grammar↔RULES (P2-02): registry == 15 implemented constructors, reserved/folded names → INVALID(unknown)', parity && allReservedInvalid);
}
// P0-06 terminality location: it is required at FRESHNESS (Corroborated), NOT at CheckpointZero — spec (rev2) and code
// now agree. A bare chain is VALID without terminality; Corroborated with a non-terminal head is INDETERMINATE.
{
  const rBareChain = checkAuthorityProof({ term: πChain, witnesses }, CFG);
  const badTerm = put({ headProof: ['sha256:' + 'cd'.repeat(32)] });
  const πCorrNoTerm = node('Corroborated', [πChain, πCommit, πTarget, πAfter], [badTerm]);
  const rNoTerm = checkAuthorityProof({ term: πCorrNoTerm, witnesses }, CFG);
  check('SPEC-SYNC terminality (P0-06): K0 needs none (bare chain VALID); Corroborated demands it (non-terminal → INDETERMINATE)', rBareChain.result === 'VALID' && rBareChain.judgment.kind === 'Chain' && rNoTerm.result === 'INDETERMINATE' && /terminal/.test(rNoTerm.reason));
}

console.log('\n  reference-checker vectors (' + (typeof pass === 'number' ? '' : '') + 'L1)   PASS ' + pass + '   FAIL ' + fail);
if (fails.length) { fails.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ check_C accepts a genuine corroborated proof; every past P0 is unbuildable or a structured reject');
