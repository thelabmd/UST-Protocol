// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — attribution extracted from the source, with mutants as the non-vacuity leg
// Verdict-attribution gate — a VALID verdict must name the rules that produced it, and the name must MOVE when they do.
//
// Why: until now a verdict said `VALID:TOP` and nothing else. Two verifiers on different revisions produced
// indistinguishable results, and a verdict kept as evidence could not later be re-checked against the vocabulary it was
// actually judged by. That makes every future change to the frozen sets a silent redefinition of verdicts already
// handed out — the opposite of what a stable protocol owes a consumer holding one.
//
// So each VALID verdict carries `verifier` (VERSION — wire/spec/revision of the DOCUMENT verifier, deliberately NOT the
// L1 authority checker, which has its own revision line) and `registry_digest`.
//
// What is asserted, by EXECUTING rather than reading:
//   1. every VALID verdict carries both fields; a refusal carries neither (nothing to attribute)
//   2. the digest is deterministic across processes — a constant of the build, not of the run
//   3. the digest is domain-separated and its tag is REGISTERED (spec-code-sync enforces the registry side)
//   4. the digest MOVES for every part of the frozen vocabulary — checked by mutating each in a child process
//   5. it does NOT move for an unrelated edit — otherwise it is a file hash pretending to be a vocabulary digest
//
// (4) and (5) are the load-bearing pair. A digest that never moves attributes nothing; one that moves on any edit
// attributes the file rather than the rules.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SRC = ROOT + 'packages/ust-protocol/index.mjs';

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

// ── a real document, built and sealed through the producer
const seed = Buffer.alloc(32, 11);
const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
const kid = P.keyId(pub);
const T = '2026-07-26T10:00:00Z';
const doc = P.seal(P.buildState({ domain_shard: kid, ust_id: 'ust:20260726.10', key_id: kid, class: 'observation' },
  { generated_at: T, valid_from: T, valid_to: T }, { x: { kind: 'captured', value: { v: '1' } } }), priv, pub);

// 1) present on VALID, absent on a refusal
const v = P.verify(doc, { context: 'data' });
ok('VALID verdict carries verifier', v.result === 'VALID:LIGHT' && !!v.verifier && v.verifier.spec && v.verifier.revision !== undefined);
ok('VALID verdict carries registry_digest', /^sha256:[0-9a-f]{64}$/.test(v.registry_digest || ''));
const refused = P.verify({ ...doc, sig: { ...doc.sig, sig: 'A'.repeat(86) } }, { context: 'data' });
ok('a refusal attributes nothing', !('verifier' in refused) && !('registry_digest' in refused), 'a refusal has no verdict to attribute');

// 2) deterministic across processes
const inChild = () => execFileSync(process.execPath, ['--input-type=module', '-e', `import * as P from '${SRC}'; process.stdout.write(P.registryDigest());`], { encoding: 'utf8' });
ok('digest is identical in a fresh process', inChild() === P.registryDigest(), 'it must be a constant of the build, not of the run');

// 3) the tag is registered — the domain-separation invariant this repo enforces everywhere else
ok('ust:registry is a REGISTERED hash domain', P.REGISTRY.hashDomains.includes('ust:registry'),
  'an unregistered tag would break the spec == REGISTRY == code invariant');

// 4)+5) mutation. Each edit is applied to a NAMED declaration and the harness refuses to judge an edit that did not land
// — a mutation that silently fails to apply would otherwise be reported as a pass.
const bak = readFileSync(SRC, 'utf8');
const base = P.registryDigest();
const block = (name, mutate) => {
  const i = bak.indexOf(name);
  if (i < 0) return null;
  const j = bak.indexOf('\n});', i) + 4;
  const b = bak.slice(i, j);
  const nb = mutate(b);
  return nb === b ? null : bak.slice(0, i) + nb + bak.slice(j);
};
const MUTANTS = [
  ['errorCodes: one removed', () => { const s = bak.replace(/(errorCodes:\s*\[)('[^']+',\s*)/, '$1'); return s === bak ? null : s; }],
  ['purposes: first changed', () => { const s = bak.replace(/(purposes:\s*\[\s*')([^']+)/, '$1changed-$2'); return s === bak ? null : s; }],
  ['hashDomains: one added', () => { const s = bak.replace(/(hashDomains:\s*\[[^\]]*)\]/, "$1, 'ust:invented']"); return s === bak ? null : s; }],
  ['TIER_RANK: a tier added', () => { const s = bak.replace(/const TIER_RANK = \{/, 'const TIER_RANK = { ULTRA: 9,'); return s === bak ? null : s; }],
  ['indeterminateReasons: one renamed', () => { const s = bak.replace("document: ['unavailable',", "document: ['not-available',"); return s === bak ? null : s; }],
  ['ASSURANCE_AXES: an axis reordered', () => block('export const ASSURANCE_AXES = deepFreeze({', (b) => {
    const m = /(\w+):\s*\[([^\]]+)\]/.exec(b);
    if (!m) return b;
    const p = m[2].split(',').map((x) => x.trim()).filter(Boolean);
    return p.length < 2 ? b : b.replace(m[0], m[1] + ': [' + [p[p.length - 1], ...p.slice(0, -1)].join(', ') + ']');
  })],
];
try {
  for (const [name, build] of MUTANTS) {
    const mutated = build();
    if (mutated === null) { fail.push(`mutation did not apply: ${name} — the gate proves nothing about it`); continue; }
    writeFileSync(SRC, mutated);
    let d; try { d = inChild(); } catch { d = 'ERROR'; }
    ok(`digest MOVES for ${name}`, d !== base && d !== 'ERROR', d === 'ERROR' ? 'the mutated module does not load' : 'the digest did not react');
    writeFileSync(SRC, bak);
  }
  // the negative control
  writeFileSync(SRC, bak.replace('// fail-closed (§14/I10)', '// fail-closed (§14/I10) — comment only'));
  ok('digest does NOT move for an unrelated comment edit', inChild() === base, 'it is hashing the file, not the vocabulary');
} finally {
  writeFileSync(SRC, bak);   // always restore, even on an assertion throw
}
ok('source restored byte-identically', readFileSync(SRC, 'utf8') === bak);

console.log(`\n  verdict attribution   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every VALID verdict names its vocabulary, the name moves with the vocabulary and not with the file');
