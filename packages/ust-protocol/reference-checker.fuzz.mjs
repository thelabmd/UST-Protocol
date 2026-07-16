// SPDX-License-Identifier: Apache-2.0
// Reference-checker robustness fuzz — hardens the TCB (check_C) directly. The checker is the ONLY trusted function of
// the authority layer, so its core invariants must hold under adversarial input: TOTAL (never throws), CLOSED
// tri-state (VALID | INVALID | INDETERMINATE), DETERMINISTIC (same input → same output), and never a false accept
// (a tampered witness / garbage term is never VALID). This is exactly the boundary round-5 will probe.
import * as P from './index.mjs';
import { checkAuthorityProof, buildAuthorityProof, witnessId } from './reference-checker.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const kp = (h) => { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(h, 'hex')]), format: 'der', type: 'pkcs8' }); const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url'); return { priv, pub, key_id: P.keyId(pub) }; };
const mulberry32 = (a) => () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const T = { generated_at: '2026-07-16T00:00:00Z', valid_from: '2026-07-16T00:00:00Z', valid_to: '2026-07-16T01:00:00Z' };
const TRISTATE = new Set(['VALID', 'INVALID', 'INDETERMINATE']);
let throws = 0, nontristate = 0, nondeterministic = 0, falseAccept = 0, ran = 0;
const problems = [];

// a genuine valid package (the accept baseline) via the untrusted prover
const G = kp('cc'.repeat(32)), KC = kp('64'.repeat(32));
const gen = P.seal(P.buildGenesis({ domain_shard: 'good.example', ust_id: 'ust:20260716.00', key_id: G.key_id }, T, G.pub, undefined, undefined, undefined, { key_id: G.key_id, pub: G.pub }), G.priv, G.pub);
const AG = P.contentHash(gen), EP = P.genesisEpoch(AG);
const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
const head = P.authorityCheckpointId(C0);
const rc = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pub);
const validInputs = { genesis: gen, checkpoints: [C0], target: { active_genesis: AG, domain_shard: 'good.example', subject: 'ust:target', anchor: rc('ust:target', 800) }, commitment: rc(head, 900), terminality: { headProof: kl.headProof } };
const validPkg = buildAuthorityProof(validInputs);
const validCfg = { connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } } };

// harness: run once, record totality/tri-state/determinism; optionally require "never VALID".
function probe(pkg, cfg, { mustNotAccept = false, label = '' } = {}) {
  ran++;
  let r1, r2;
  try { r1 = checkAuthorityProof(pkg, cfg); } catch (e) { throws++; problems.push('THROW ' + label + ': ' + (e && e.message)); return; }
  try { r2 = checkAuthorityProof(pkg, cfg); } catch { throws++; problems.push('THROW-2 ' + label); return; }
  if (!r1 || !TRISTATE.has(r1.result)) { nontristate++; problems.push('NON-TRISTATE ' + label + ': ' + JSON.stringify(r1 && r1.result)); }
  if (JSON.stringify(r1) !== JSON.stringify(r2)) { nondeterministic++; problems.push('NON-DETERMINISTIC ' + label); }
  if (mustNotAccept && r1.result === 'VALID') { falseAccept++; problems.push('FALSE-ACCEPT ' + label); }
}

// 1) the genuine package accepts, and is deterministic
{ const r = checkAuthorityProof(validPkg, validCfg); if (r.result !== 'VALID') { falseAccept++; problems.push('baseline valid package NOT accepted: ' + JSON.stringify(r)); } probe(validPkg, validCfg, { label: 'baseline' }); }

// 2) tamper every witness in turn → content-address breaks → never VALID, always total
for (const wid of Object.keys(validPkg.witnesses)) {
  const tampered = { term: validPkg.term, witnesses: { ...validPkg.witnesses, [wid]: { ...validPkg.witnesses[wid], __tamper: 'x' } } };
  probe(tampered, validCfg, { mustNotAccept: true, label: 'tamper:' + wid.slice(0, 12) });
}

// 3) random adversarial + garbage terms — total, tri-state, deterministic (no accept requirement; just no crash)
const RULES = ['Genesis', 'CheckpointZero', 'CheckpointStep', 'ConnectorEvidence', 'AfterOrder', 'Corroborated', 'MapUnique', 'QuorumAgreement', 'ReinforceMap', 'ReinforceQuorum', 'FutureGenesisCommitment', 'ActivateGenesis', 'NameBound', 'Anchored', 'ProjectAssurance', 'Verified', 'PredicateGraph', 'Trusted', '__bogus'];
const rng = mulberry32(0xC0FFEE);
const pick = (a) => a[Math.floor(rng() * a.length)];
const randWid = () => Object.keys(validPkg.witnesses).concat(['sha256:' + 'de'.repeat(32), 'not-a-hash', ''])[Math.floor(rng() * (Object.keys(validPkg.witnesses).length + 3))];
function randTerm(depth) {
  if (depth > 6 || rng() < 0.25) return pick([null, 42, 'str', {}, { rule: pick(RULES) }, { rule: pick(RULES), children: [], witnesses: [randWid()], params: { n: '0', h: 'x', subject: 'y' } }]);
  const nc = Math.floor(rng() * 4);
  return { rule: pick(RULES), children: Array.from({ length: nc }, () => randTerm(depth + 1)), witnesses: Array.from({ length: Math.floor(rng() * 3) }, randWid), params: rng() < 0.5 ? { n: String(Math.floor(rng() * 3)), h: 'sha256:' + 'aa'.repeat(32), subject: 'ust:x' } : undefined };
}
const randConfig = () => pick([validCfg, null, {}, { connectors: null }, { connectors: { x: { pub: 'p', allowed_proof_kinds: 'not-array' } }, policy: null }, { mapRoots: 'no', witnesses: 5 }]);
for (let i = 0; i < 4000; i++) {
  const term = randTerm(0);
  const witnesses = rng() < 0.5 ? validPkg.witnesses : Object.fromEntries(Object.keys(validPkg.witnesses).slice(0, Math.floor(rng() * 5)).map((k) => [k, validPkg.witnesses[k]]));
  probe(rng() < 0.1 ? pick([null, {}, { term }, { witnesses }, 'nope', 7]) : { term, witnesses }, randConfig(), { label: 'rand#' + i });
}

// 4) a self-referential (cyclic) term must be rejected, not loop forever
{ const cyc = { rule: 'Corroborated', children: [], witnesses: [] }; cyc.children = [cyc]; probe({ term: cyc, witnesses: validPkg.witnesses }, validCfg, { mustNotAccept: true, label: 'cycle' }); }

console.log('\n  reference-checker robustness fuzz — check_C is the TCB   (' + ran + ' probes)');
console.log('    throws=' + throws + '  non-tristate=' + nontristate + '  non-deterministic=' + nondeterministic + '  false-accept=' + falseAccept);
if (problems.length) { problems.slice(0, 12).forEach((p) => console.log('    ✗ ' + p)); process.exit(1); }
console.log('  ✓ check_C is TOTAL, closed tri-state, DETERMINISTIC, and never false-accepts a tampered/garbage package');
