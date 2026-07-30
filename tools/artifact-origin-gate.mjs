// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — artifact origin extracted from the source that constructs it
// Artifact-ORIGIN gate — an artifact the publish path CONSTRUCTS must be declared as such, and its construction must
// extend what is live rather than replace it.
//
// The distinction is not bookkeeping. A LOADED artifact is read from somewhere the operator controls: if the read
// fails, nothing is served and the failure is visible. A DERIVED artifact is built by the tool, and construction has
// a second failure mode loading does not — it can SUCCEED while producing less than what was already published.
//
// MEASURED, and this is the incident the gate exists for: the witness log was the one derived artifact, and it was
// rebuilt from the genesis alone. Every deploy therefore overwrote the served anchors, and the git mirror sat
// guard-frozen for two weeks refusing the shrunken form — correctly, and silently. One turn further, a re-ceremony
// would have deleted the predecessor identity outright, which §12.1 forbids in one sentence.
//
// It is the same seam as a cadence file the command did not read, one turn worse: that one failed to LOAD, this one
// failed to load AND overwrote. So the gate holds three things — the table is total over the artifact set, every
// derivation names the prior it extends, and the extension is checked by the protocol's own monotonicity rule.
import { readFileSync } from 'node:fs';

const U = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const SRC = U('packages/ust-cli/index.mjs');

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// read the declarations FROM SOURCE — a gate that imports them would pass on a table that disagrees with the code
const listOf = (name) => {
  const m = new RegExp(name + '\\s*=\\s*\\[([^\\]]*)\\]').exec(SRC);
  return m ? [...m[1].matchAll(/'([a-z-]+)'/g)].map((x) => x[1]) : null;
};
const tableOf = (name) => {
  const i = SRC.indexOf('export const ' + name + ' = {');
  if (i < 0) return null;
  const body = SRC.slice(i, SRC.indexOf('};', i));
  // no ^ anchor: a single-line object literal is as valid a declaration as a multi-line one, and requiring
  // line-start silently read the one-liner as EMPTY — which this gate then reported as "names no prior".
  return Object.fromEntries([...body.matchAll(/([a-z]+):\s*'([^']+)'/g)].map((m) => [m[1], m[2]]));
};

const ARTIFACTS = listOf('DISCOVERY_ARTIFACTS');
const ORIGIN = tableOf('ARTIFACT_ORIGIN');
const REQUIRES = tableOf('DERIVED_REQUIRES_PRIOR');

check(Array.isArray(ARTIFACTS) && ARTIFACTS.length >= 4, 'DISCOVERY_ARTIFACTS could not be read — the gate would be vacuous');
check(ORIGIN && Object.keys(ORIGIN).length > 0, 'ARTIFACT_ORIGIN could not be read');
if (!ARTIFACTS || !ORIGIN) { console.log('\n  artifact origin   PASS 0   FAIL ' + fail.length); fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }

// ── 1. the table is TOTAL over the artifact set, in both directions
for (const a of ARTIFACTS) check(a in ORIGIN, `${a} is served but its ORIGIN is not declared — loaded or derived? The answer decides whether it can overwrite published evidence.`);
for (const a of Object.keys(ORIGIN)) check(ARTIFACTS.includes(a), `ARTIFACT_ORIGIN declares ${a}, which is not in DISCOVERY_ARTIFACTS — a stale declaration is a second place to be wrong`);
for (const [a, o] of Object.entries(ORIGIN)) check(o === 'loaded' || o === 'derived', `${a} is declared "${o}" — the only honest answers are loaded or derived`);

// ── 2. every DERIVED artifact must name the prior it extends, and the code must actually pass one
const derived = Object.entries(ORIGIN).filter(([, o]) => o === 'derived').map(([a]) => a);
check(derived.length > 0, 'no artifact is declared derived — if that is true the incident could not have happened, so the table has drifted from the code');
for (const a of derived) {
  check(REQUIRES && a in REQUIRES, `${a} is DERIVED and names no prior in DERIVED_REQUIRES_PRIOR — a derivation that extends nothing is a replacement`);
  const contract = REQUIRES?.[a];
  if (!contract) continue;
  const call = contract.replace(/\s+/g, '');
  const found = SRC.replace(/\s+/g, '').includes(call);
  check(found, `${a}'s declared derivation \`${contract}\` does not appear in the assembler — the contract and the code disagree`);
  // the third argument is the prior: a two-argument call is the exact shape that overwrote the anchors
  const bare = new RegExp('build' + a[0].toUpperCase() + a.slice(1) + 'Log\\((?:[^(),]|\\([^)]*\\))*,(?:[^(),]|\\([^)]*\\))*\\)(?!\\s*,)', 'g');
  const twoArg = [...SRC.matchAll(bare)].filter((m) => m[0].split(',').length === 2);
  check(twoArg.length === 0, `${a} is built somewhere with only two arguments — no prior, so that call REPLACES the served log instead of extending it: ${twoArg[0]?.[0]?.slice(0, 80)}`);
}

// ── 3. the extension must be checked by the protocol's rule, not by this tool's opinion
check(/witnessSuccessor|witnessNoShrink/.test(SRC), 'the derivation no longer routes through the protocol monotonicity rule — a tool-local no-shrink opinion is a second implementation of a normative rule');

// ── 4. each leg must be able to fail
check(!('nonexistent' in ORIGIN), 'the totality probe accepts an artifact the table lacks');
check(tableOf('ARTIFACT_ORIGIN_THAT_DOES_NOT_EXIST') === null, 'the table reader invents tables that are not there');

console.log(`\n  artifact origin   PASS ${pass}   FAIL ${fail.length}   (${ARTIFACTS.length} served · ${derived.length} derived: ${derived.join(', ')})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every served artifact declares how it comes to exist, and every derivation extends a prior rather than replacing it');
