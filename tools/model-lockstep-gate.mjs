// SPDX-License-Identifier: Apache-2.0
// model-lockstep gate (round-26 step 5) — the enforcement that stops the lockstep-lie CLASS.
//
// The recurring failure: the formal model writes a realization note asserting an invariant is ENFORCED, but cites only
// a POSITIVE-shape conformance check (the happy path). The `model↔conformance` gate passes on the positive check and
// never forces the ADVERSARIAL closure (the check that the ATTACK is rejected). So the class stays open while every
// gate is green — exactly how round-26 P0-01/P0-02/P0-03 and the F.9.6 budget hid behind rev23's green board.
//
// This gate targets the ENFORCEMENT realizations — the `**Realization (rev…` notes the audit adds to CLOSE a
// lockstep-lie (representation notes that merely NAME the realizing functions are exempt: they assert no enforcement).
// Each such note MUST cite at least one ADVERSARIAL-closure check (asserts INVALID/rejected/null/refusal), and each
// cited check MUST be a real conformance check. Plus a small explicit registry for enforcement claims that live in a
// prose bullet rather than a `**Realization**` block (e.g. F.9.6 T_witness).
//
// Add an enforcement realization ⇒ add its adversarial check, or this gate fails. That is the point.
import { readFileSync } from 'node:fs';

const MODEL = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');
const CONF = readFileSync(new URL('../packages/ust-protocol/conformance.mjs', import.meta.url), 'utf8');

// a cited check "looks adversarial" iff its NAME asserts the attack is refused (not just a positive shape)
const ADVERSARIAL = /INVALID|E-[A-Z]|REJECT|rejected|cannot|→ *null|\bnull\b|not terminal|UNBRANDED|no false|no host throw|does ?n[o']t|resource[- ]limit|not-?ok|not ok|earns nothing|never|is dropped|refus/i;
const quotesIn = (block) => [...block.matchAll(/\*"([^"]+)"\*/g)].map((m) => m[1]);
const checkExists = (name) => CONF.includes(JSON.stringify(name).slice(1, -1)) || CONF.includes(name);

const failures = [];

// 1) every `**Realization (rev…` enforcement note must cite ≥1 adversarial check, and each cited check must be real.
const blocks = [...MODEL.matchAll(/\*\*Realization \(rev[^\n]*?\*\*[\s\S]*?(?=\n\n|\n\*\*|\n#|\n- )/g)].map((m) => m[0]);
if (blocks.length === 0) failures.push('no `**Realization (rev…` enforcement notes found — the parser or the model changed');
for (const b of blocks) {
  const tag = (b.match(/\*\*Realization \((rev[0-9]+[^)]*)\)/) || [])[1] || b.slice(0, 40);
  const qs = quotesIn(b);
  if (qs.length === 0) { failures.push(`[${tag}] enforcement realization cites NO conformance check`); continue; }
  const missing = qs.filter((q) => !checkExists(q));
  if (missing.length) failures.push(`[${tag}] cites a check that is not in conformance.mjs: ${JSON.stringify(missing[0])}`);
  if (!qs.some((q) => ADVERSARIAL.test(q))) failures.push(`[${tag}] cites ONLY positive-shape checks — no adversarial-closure check (this is the lockstep-lie shape). Cited: ${qs.map((q) => q.slice(0, 40)).join(' | ')}`);
}

// 2) explicit registry — enforcement claims not carried in a `**Realization**` block (prose bullets, tables).
const REGISTRY = [
  { id: 'L4 F.9.6 T_witness threaded through the public entry',
    modelHas: 'threaded through the PUBLIC entry',
    adversarialCheck: 'round-26 P1-03/L4 resolveByDiscovery THREADS the consumer witness budget (maxWitnessOpMs) through the PUBLIC entry → a tight budget resource-limits the witness, no false served-list HIGH (F.9 ρ_v)' },
];
for (const r of REGISTRY) {
  if (!MODEL.includes(r.modelHas)) failures.push(`[${r.id}] the model no longer states "${r.modelHas}" — registry drift`);
  if (!checkExists(r.adversarialCheck)) failures.push(`[${r.id}] the registered adversarial check is not in conformance.mjs: ${JSON.stringify(r.adversarialCheck)}`);
  if (!ADVERSARIAL.test(r.adversarialCheck)) failures.push(`[${r.id}] the registered check name is not adversarial`);
}

if (failures.length) {
  console.error('✗ model-lockstep gate FAILED — an enforcement realization is not backed by an adversarial-closure check:');
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}
console.log(`✓ model-lockstep: ${blocks.length} enforcement realizations + ${REGISTRY.length} registry claim(s) each cite a real ADVERSARIAL-closure conformance check (no lockstep-lie)`);
