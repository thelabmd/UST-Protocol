// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — every theorem the model cites resolved against the EXECUTED check list
// MODEL ↔ CODE LOCKSTEP GUARD — "math is provable through code". The formal model (NON-NORMATIVE) cites each theorem's
// realization as an italicised conformance-check label: *"...check label..."*. This guard asserts every such citation
// is a REAL check in conformance.mjs — so a theorem cannot claim a property the running suite does not verify. Pair it
// with `node conformance.mjs` (which must be green): together they show each formal claim maps to a passing check.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ASSURANCE_AXES, EVIDENCE_CAPS_UNIVERSE } from './index.mjs';

const model = readFileSync(new URL('../../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');
const conf = readFileSync(new URL('./conformance.mjs', import.meta.url), 'utf8');

// rev86 (C2, presence → EXECUTION): a citation used to resolve against the conformance SOURCE TEXT. A source substring
// proves the label was TYPED, not that the check RAN — disable it, rename it, or strand it behind a branch that never
// executes and the citation still resolved, so the model kept claiming a realization the suite no longer performed.
// The bar is now the EXECUTED manifest (the ids that actually ran and passed), bound to the source it came from by
// recomputed digests so a stale manifest cannot restore the weaker behaviour. Measured at introduction: all 208
// citations already resolved against the manifest (173 exact + 35 by fragment), so this costs nothing today and closes
// the class permanently — the same shape the lockstep gate already applies to its registry records.
//
// THE ROSTER SPANS BOTH SUITES, for the reason `ladder-completeness-gate` already records about itself: a theorem
// is quantified over the protocol, not over one package, and its realization lands wherever the mechanism lives.
// F.9.5-c.3 is the worked example — the inclusion dual is a PRODUCER act (F.9.5-c.1 makes the walk a connector, so
// a base shipping a construction re-asserts the normativity it dropped), therefore both its trees are exercised in
// the operator suite and NEITHER could be cited here. Measured 2026-08-09: citing the reference-tree battery
// reported six executing, passing checks as MISSING. A gate whose domain is narrower than the claim it guards
// pushes the work into the exclusion column and calls the result green.
// CLOSED 2026-08-09 by round(187) — the roster below spans both suites, and the six citations resolve.
const srcHash = (rel) => createHash('sha256').update(readFileSync(new URL(rel, import.meta.url))).digest('hex');
const roster = (rel, sources) => {
  let m; try { m = JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8')); } catch { return { checks: [], stale: `${rel} is missing` }; }
  for (const [k, f] of Object.entries(sources))
    if (m.source?.[k] !== srcHash(f)) return { checks: [], stale: `${rel} was generated from a different ${f}` };
  return { checks: Array.isArray(m.checks) ? m.checks : [], stale: null };
};
const CORE_R = roster('../../vectors/conformance-checks.json', { conformance: './conformance.mjs', index: './index.mjs' });
const OP_R = roster('../../vectors/operator-checks.json', { conformance: '../ust-operator/conformance.mjs', index: '../ust-operator/index.mjs' });
for (const [who, r] of [['core', CORE_R], ['operator', OP_R]]) if (r.stale) {
  console.log(`  ✗ the ${who} executed manifest is STALE (${r.stale}) — regenerate it; a citation must resolve against checks that RAN, not against source text`);
  process.exit(1);
}
const EXECUTED = [...CORE_R.checks, ...OP_R.checks];
const EXECUTED_SET = new Set(EXECUTED);

// A citation NAMES a check, and a name has single spaces. Markdown wraps prose, so a citation long enough to be
// unambiguous is exactly the one that will straddle a line break — and rev98 hit that on the first try: two real,
// executing checks were reported MISSING because the extracted name carried a newline. Normalizing whitespace on
// BOTH sides is the correct reading of the format rather than a leniency; the line break is layout, not the name.
const norm = (s) => s.replace(/\s+/g, ' ').trim();
const EXECUTED_NORM = new Map(EXECUTED.map((label) => [norm(label), label]));
const cites = [...model.matchAll(/\*"([^"]+)"\*/g)].map((m) => norm(m[1]));
let ok = 0; const miss = [];
for (const c of cites) {
  // a citation may be fragmented with "..." (shared prefix elided); require its LONGEST verbatim fragment to name a
  // check that RAN AND PASSED — exact id first, then the fragment inside an executed id.
  const frag = c.split('...').map((s) => norm(s)).filter((s) => s.length >= 12).sort((a, b) => b.length - a.length)[0] || c;
  if (EXECUTED_SET.has(c) || EXECUTED_NORM.has(c) || [...EXECUTED_NORM.keys()].some((label) => label.includes(frag))) ok++;
  else miss.push({ c, frag, inSource: conf.includes(frag) });
}

console.log(`\n  model ↔ conformance: ${ok}/${cites.length} cited theorem checks RAN AND PASSED in the executed manifest`);
if (miss.length) {
  console.log('  ✗ a formal-model theorem cites a check that does not exist:');
  for (const m of miss) console.log('    ' + (m.inSource ? 'TYPED BUT NEVER EXECUTED' : 'MISSING') + ': "' + m.frag + '"   (cited as: "' + m.c + '")');
  process.exit(1);
}
console.log('  ✓ every theorem the formal model cites is a check that actually RAN (math ⇒ executed code, not merely typed)');

// ── INTERNAL MATH-CONSISTENCY (UST-1n1) — the rc.35 M1 contradiction class: the model DEFINED EvidenceBasis as a
//    SET yet COUNTED it as a 4-chain (2·4·4·2·4 = 256), and the citation guard above could not see it (it checks
//    labels exist, not that the model's numbers are consistent with the code's structures). This section recomputes
//    every NUMERIC claim the model makes about code-defined structures from the structures themselves.
const axisSizes = Object.values(ASSURANCE_AXES).map((vs) => vs.length);
const strengthCount = axisSizes.reduce((a, b) => a * b, 1);
const claims = [];
// a claim inside a documented-ERROR passage (the model quoting the rc.35 mistake it corrects) is exempt; the
// exemption is the CONTEXT naming the error, so a live section cannot smuggle a stale count.
const isHistorical = (idx) => /rc\.35|self-contradictory|category error|\*\*Error/i.test(model.slice(Math.max(0, idx - 300), idx + 100));
// every "a·b·c(·d…) = N" product claim over the strength axes must equal the LIVE product AND the live factorization
for (const m of model.matchAll(/`?(\d+(?:·\d+)+)\s*=\s*(\d+)`?/g)) {
  const factors = m[1].split('·').map(Number), stated = Number(m[2]);
  if (factors.length < 3 || isHistorical(m.index)) continue;                   // <3 factors = unrelated small products; historical = the quoted rc.35 error
  claims.push({ kind: 'strength product', text: m[0].trim(),
    ok: stated === strengthCount && factors.length === axisSizes.length && factors.every((f, i) => f === axisSizes[i])
      && factors.reduce((a, b) => a * b, 1) === stated });
}
// |Caps| and |P(Caps)| claims must match the single-sourced universe
for (const m of model.matchAll(/\|Caps\|\s*=\s*(\d+)/g)) { if (!isHistorical(m.index)) claims.push({ kind: '|Caps|', text: m[0], ok: Number(m[1]) === EVIDENCE_CAPS_UNIVERSE.length }); }
for (const m of model.matchAll(/\|P\(Caps\)\|\s*=\s*(\d+)/g)) { if (!isHistorical(m.index)) claims.push({ kind: '|P(Caps)|', text: m[0], ok: Number(m[1]) === 2 ** EVIDENCE_CAPS_UNIVERSE.length }); }
const bad = claims.filter((c) => !c.ok);
const audited = claims.length;
if (!audited) { console.log('  ✗ math-consistency: found NO numeric structure claims in the model — extraction broke'); process.exit(1); }
if (bad.length) {
  console.log('  ✗ math-consistency (UST-1n1): the model asserts a count its own code structures contradict:');
  for (const b of bad) console.log(`    ${b.kind}: "${b.text}" vs live ${b.kind === 'strength product' ? strengthCount + ' (axes ' + axisSizes.join('·') + ')' : b.kind === '|Caps|' ? EVIDENCE_CAPS_UNIVERSE.length : 2 ** EVIDENCE_CAPS_UNIVERSE.length}`);
  process.exit(1);
}
console.log(`  ✓ math-consistency (UST-1n1): ${audited} numeric structure claims recomputed from ASSURANCE_AXES/EVIDENCE_CAPS_UNIVERSE — axis-def ⟺ axis-claim ⟺ state-count`);
