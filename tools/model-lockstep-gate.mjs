// SPDX-License-Identifier: Apache-2.0
// model-lockstep gate (round-26 step 5; REBUILT round-27 P1-02) — the enforcement that stops the lockstep-lie CLASS.
//
// The recurring failure: the formal model writes a realization note asserting an invariant is ENFORCED, but the only
// conformance check that backs it is POSITIVE-shape (the happy path). The `model↔conformance` gate passes on that
// positive check and never forces the ADVERSARIAL closure (the check that the ATTACK is refused). So the class stays
// open while every gate is green — how round-26 P0-01/02/03 and round-27's three P0s hid behind a green board.
//
// The FIRST version of this gate was itself a lockstep-lie (round-27 P1-02): it inferred "adversarial" from an English
// token regex (`never|null|reject|…`) over `**Realization (rev…` blocks. Two trivial bypasses: (A) an enforcement note
// without the `(rev…` tag was ignored; (B) a purely POSITIVE check named "valid inputs never fail on the happy path"
// matched `never` and passed. A heuristic lint is not sound enforcement.
//
// REBUILT as DATA (GPT round-27 recommendation): `lockstep-registry.json` is a machine-readable list of enforcement
// records — {id, rev, model_locus, conformance_check}. The gate does NOT read English tokens. Per record it asserts
// (1) the model still STATES the claim (model_locus is present verbatim) and (2) the EXACT adversarial-closure check is
// present in conformance (which, being green under `test`, PASSES → the attack is refused). EXHAUSTIVENESS: every
// `**Realization (revNN` block in the model must have a registry record for that rev — a NEW tagged enforcement note
// without a record fails the gate. Add an enforcement realization ⇒ add a record, or CI goes red.
import { readFileSync } from 'node:fs';

const MODEL = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');
const REG = JSON.parse(readFileSync(new URL('./lockstep-registry.json', import.meta.url), 'utf8'));
// round-28 P1-03 — the EXECUTED-check manifest (emitted by conformance.mjs on a green run): the set of check ids that
// actually RAN and PASSED. A registered adversarial check must be in THIS set, not merely a SOURCE SUBSTRING — else
// disabling a `check(...)` call while leaving its name in a comment (the round-28 bypass) would still pass the gate.
const EXECUTED = new Set(JSON.parse(readFileSync(new URL('../vectors/conformance-checks.json', import.meta.url), 'utf8')));

const failures = [];
const records = Array.isArray(REG.records) ? REG.records : [];
if (records.length === 0) failures.push('lockstep-registry.json has no records — the parser or the file changed');

// 1) each registry record: the model STATES the claim AND the exact adversarial check exists in conformance.
const ids = new Set();
for (const r of records) {
  if (!r.id || ids.has(r.id)) failures.push(`registry record has a missing/duplicate id: ${JSON.stringify(r.id)}`);
  ids.add(r.id);
  if (!r.model_locus || !MODEL.includes(r.model_locus)) failures.push(`[${r.id}] model no longer states its claim verbatim (model_locus not found): ${JSON.stringify((r.model_locus || '').slice(0, 60))}`);
  if (!r.conformance_check || !EXECUTED.has(r.conformance_check)) failures.push(`[${r.id}] its adversarial-closure check did not RUN+PASS in the executed manifest (a disabled/renamed check no longer fools the gate): ${JSON.stringify((r.conformance_check || '').slice(0, 70))}`);
}

// 2) EXHAUSTIVENESS by rev tag: every `**Realization (revNN` enforcement note must be registered for that rev.
const modelRevs = new Set([...MODEL.matchAll(/\*\*Realization \((rev[0-9]+)/g)].map((m) => m[1]));
const registeredRevs = new Set(records.map((r) => r.rev));
for (const rev of modelRevs) if (!registeredRevs.has(rev)) failures.push(`the model has a **Realization (${rev} …) enforcement note with NO registry record for ${rev} — register its adversarial check or the lockstep-lie is unguarded`);

// 3) EXHAUSTIVENESS by CITATION (closes round-27 P1-02 bypass A/B): any `**Realization` block — TAGGED OR NOT — that
//    cites a conformance check is an ENFORCEMENT note, and at least one cited check MUST be in the registry. An untagged
//    `**Realization.**` (bypass A) or a positive check named to look adversarial (bypass B), cited but unregistered, fails.
//    A representation note that cites NOTHING (just names the realizing functions) is exempt by construction.
const regChecks = new Set(records.map((r) => r.conformance_check));
for (const b of [...MODEL.matchAll(/\*\*Realization[^\n]*(?:\n(?!\n)[^\n]*)*/g)].map((m) => m[0])) {
  const cited = [...b.matchAll(/\*"([^"]+)"\*/g)].map((m) => m[1]);
  if (cited.length && !cited.some((c) => regChecks.has(c)))
    failures.push(`a **Realization note cites conformance check(s), NONE registered — an unregistered enforcement claim (round-27 P1-02): ${JSON.stringify(cited[0].slice(0, 55))}`);
}

if (failures.length) {
  console.error('✗ model-lockstep gate FAILED — an enforcement realization is not backed by a registered adversarial-closure check:');
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}
console.log(`✓ model-lockstep: ${records.length} registered enforcement records, each STATED in the model and backed by a real adversarial-closure conformance check; every **Realization (rev…) note is registered (no lockstep-lie, no English-token heuristic)`);
