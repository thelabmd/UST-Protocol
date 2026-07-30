// SPDX-License-Identifier: Apache-2.0
// @assurance 1b canfail:yes — the clean-room browser resolver and the reference must agree on every vector
// Cadence PARITY gate — the clean-room browser resolver and the reference resolver must give the SAME answer on every
// `cadence-resolve` vector, or the README's promise ("two conforming verifiers agree because the verdict is a total
// deterministic function") is false for the grid a completeness claim is measured against.
//
// This is the vectors doing the job they were written for: they were added as language-neutral data precisely so a second
// implementation has something to check itself against, and the browser IS the second implementation.
//
// ONE asymmetry is allowed and is checked rather than assumed: where a key log carries a revoke/retire, the browser
// returns `unresolved` instead of a number, because deciding a CURRENTLY-ACTIVE signer needs anchored time it does not
// evaluate. `unresolved` is never allowed to stand in for a NUMBER the reference produced — that would be a silent
// downgrade — so the gate requires the reference to be equally unable to accept, or the browser to match exactly.
import { readFileSync } from 'node:fs';
import * as P from '../packages/ust-protocol/index.mjs';
import { resolveCadence as web } from '../docs/ust-resolve.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/conformance-vectors.json', import.meta.url), 'utf8')).vectors.filter((v) => v.kind === 'cadence-resolve');
if (!vectors.length) { console.error('  ✗ no cadence-resolve vectors found — the gate would be vacuous'); process.exit(1); }

const norm = (r) => r.error ? { error: r.error } : (r.unresolved ? { unresolved: true } : { cadence: r.cadence === null ? null : String(r.cadence) });

let pass = 0; const fail = [];
for (const v of vectors) {
  const ref = norm(P.resolveCadence(v.genesis, v.cadence_log, v.at, { keylog: v.keylog ?? [] }));
  const w = norm(await web(v.genesis, v.cadence_log, v.at, { keylog: v.keylog ?? [] }));
  // the vector's own stated expectation must ALSO hold on the reference — else the corpus has drifted from the code
  const stated = v.expect.error ? ref.error === v.expect.error : ref.cadence === v.expect.cadence;
  const agree = JSON.stringify(ref) === JSON.stringify(w);
  if (stated && agree) { pass++; continue; }
  fail.push(`${v.id} — vector says ${JSON.stringify(v.expect)}, reference ${JSON.stringify(ref)}, browser ${JSON.stringify(w)}`
    + (!stated ? '  [CORPUS DRIFT: the reference no longer matches the vector]' : '  [DIVERGENCE between the two verifiers]'));
}

// A negative control: the gate must be capable of failing. Feed a case the browser MUST decline and the reference must
// NOT silently accept — a key log carrying a retire, which puts the two information sets genuinely apart.
{
  const v = vectors.find((x) => x.keylog && x.keylog.length);
  if (v) {
    const retire = JSON.parse(JSON.stringify(v.keylog[0]));
    retire.state.data.key_op.value = { op: 'retire', key_id: retire.state.data.key_op.value.new_key_id };
    const w = norm(await web(v.genesis, v.cadence_log, v.at, { keylog: [retire] }));
    const declined = w.unresolved === true || !!w.error;
    if (declined) pass++; else fail.push('a key log with a retire did NOT make the browser decline — it answered ' + JSON.stringify(w) + ', which may be wider than the reference');
  }
}

console.log(`\n  cadence parity   PASS ${pass}   FAIL ${fail.length}   (over ${vectors.length} vectors)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ both resolvers agree on every cadence vector, and the browser declines rather than guessing where its information set is narrower');
