// SPDX-License-Identifier: Apache-2.0
// Independent runner for the LANGUAGE-NEUTRAL assurance-arc vectors (vectors/arc-vectors.json). It loads only the JSON
// + the public API and asserts each pre-signed vector's verdict — so this file IS the template a SECOND implementation
// (e.g. a Go SDK, #34) mirrors to prove the SAME contract. No key generation, no internal state: the vectors carry it.
import { readFileSync } from 'node:fs';
import * as P from './index.mjs';

const V = JSON.parse(readFileSync(new URL('../../vectors/arc-vectors.json', import.meta.url)));
const call = {
  verifyAuthorityCheckpointChain: (v) => P.verifyAuthorityCheckpointChain(v.chain, v.opts),
  deriveCheckpointFreshness: (v) => P.deriveCheckpointFreshness(v.chain, v.opts),
  verifyKeylogTerminality: (v) => P.verifyKeylogTerminality(v.keylog, v.proof),
  compareEvidenceOrder: (v) => P.compareEvidenceOrder(v.a, v.b),
  quorumTrustDomains: (v) => P.quorumTrustDomains(v.list, v.opts),
  evidenceClass: (v) => P.evidenceClass(v.proof_kind),
  verifiedEvidence: (v) => P.verifiedEvidence(v.fields),
  verifyNoForkEvidence: (v) => P.verifyNoForkEvidence(v.evidence, v.opts),
  verifyCheckpointUniqueness: (v) => P.verifyCheckpointUniqueness(v.attestations, v.opts),
  verifyCheckpointMapUniqueness: (v) => P.verifyCheckpointMapUniqueness(v.proof, v.opts),
  verifyActiveGenesisUniqueness: (v) => P.verifyActiveGenesisUniqueness(v.proof, v.opts),
  verifyCheckpointRecovery: (v) => P.verifyCheckpointRecovery(v.statements, v.opts),
  verifyEpochTransition: (v) => P.verifyEpochTransition(v.statement, v.opts),
};

let pass = 0, fail = 0; const fails = [];
for (const v of V.vectors) {
  const fn = call[v.op];
  if (!fn) { fail++; fails.push(v.id + ' — unknown op ' + v.op); continue; }
  let r; try { r = fn(v); } catch (e) { r = { error: e.code || 'THROW', detail: String(e) }; }
  if (typeof r === 'string') r = { value: r };                                 // ops returning a bare string (compareEvidenceOrder, evidenceClass)
  const ok = Object.entries(v.expect).every(([k, val]) => r[k] === val);       // expect is a SUBSET match of the verdict
  if (ok) pass++; else { fail++; fails.push(v.id + ' — expected ' + JSON.stringify(v.expect) + ' got ' + JSON.stringify(Object.fromEntries(Object.keys(v.expect).map((k) => [k, r[k]])))); }
}

console.log('\n  arc-vectors (' + V.version + ')   PASS ' + pass + '   FAIL ' + fail);
if (fails.length) fails.forEach((f) => console.log('    ✗ ' + f));
else console.log('  ✓ the language-neutral assurance-arc contract holds — any implementation can run these');
process.exit(fail ? 1 : 0);
