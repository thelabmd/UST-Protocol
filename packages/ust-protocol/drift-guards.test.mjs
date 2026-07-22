// SPDX-License-Identifier: Apache-2.0
// test:drift-guards — the META-gate (owner, round-51: "жёсткая гарантия обновления либо ловли несоответствий без тихих багов").
// The from-code gates (R31 partition, capability-parity, spec-code-sync, BMC denominator, model-lockstep) are supposed to be
// FAIL-CLOSED: a new export / error code / interpreter rule / model note that is NOT registered must turn a gate RED, never ship
// silently. This test PROVES that continuously — on every run it INJECTS a fake drift for each extension vector, asserts the
// corresponding gate EXITS NON-ZERO (catches it), and restores the exact original bytes in a `finally`. If someone weakens a gate
// (or a gate's anchor moves), THIS fails. It touches only READ-ONLY gates — never conformance.mjs (which rewrites the manifest).
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
let pass = 0; const F = [];

// A gate "rejects" the drift iff its process EXITS NON-ZERO.
const gateRejects = (cmd) => { try { execSync(cmd, { cwd: root, stdio: 'pipe' }); return false; } catch { return true; } };

// Inject a drift into `rel`, assert `gate` rejects it, and ALWAYS restore the exact original bytes (even on throw).
function probe(name, rel, mutate, gate) {
  const path = root + rel;
  const backup = readFileSync(path);                          // Buffer — byte-identical restore
  const orig = backup.toString('utf8');
  try {
    const mutated = mutate(orig);
    if (mutated === orig) { F.push(`${name}: injection ANCHOR not found — the source moved; update this probe (a silent drift-guard hole)`); return; }
    writeFileSync(path, mutated);
    if (gateRejects(gate)) pass++;
    else F.push(`${name}: the gate did NOT reject the injected drift — it is NOT fail-closed (a NEW ${name.split('→')[0].trim()} could ship silently)`);
  } finally { writeFileSync(path, backup); }                  // restore no matter what
}

// 1) a new function export must be caught (untriaged capability / unclassified surface)
probe('new function export → capability-parity', 'packages/ust-protocol/index.mjs',
  (s) => s + '\nexport function __driftProbe(x) { return x; }\n', 'node tools/capability-parity.mjs');
// 2) a new L1-checker error code must be registered
probe('new checker error code → spec-code-sync', 'packages/ust-protocol/reference-checker.mjs',
  (s) => s + "\nconst __driftCode = 'E-DRIFT-PROBE';\n", 'node tools/spec-code-sync.mjs');
// 3) an interpreter rule dropped from the BMC coverage denominator must be caught (source-verified vs the interpreter)
probe('interpreter rule dropped from CHILD_SIG → BMC', 'packages/ust-protocol/bmc.mjs',
  (s) => s.replace("NameBound: ['Genesis'], ", ''), 'node packages/ust-protocol/bmc.mjs');
// 4) a model enforcement Realization without a registry record must be caught
probe('model Realization without a registry record → model-lockstep', 'spec/UST-1.0-formal-model.md',
  (s) => s + '\n**Realization (rev99 — drift probe).** A fake enforcement claim with no registry record.\n', 'node tools/model-lockstep-gate.mjs');
// 5) a 16th inference rule (a new RULE_CONTRACTS key) must be caught — the §14 decision-relation is FROZEN at 15 (round-52 S1 / Q1)
probe('new inference rule (16th RULE_CONTRACTS key) → rule-lockstep', 'packages/ust-protocol/reference-checker.mjs',
  (s) => s.replace('RULE_CONTRACTS = deepFreeze(Object.assign(Object.create(null), {', 'RULE_CONTRACTS = deepFreeze(Object.assign(Object.create(null), {\n  __DriftRule16: 1,'), 'node tools/rule-lockstep.mjs');

console.log(`\n  drift-guards (meta — every from-code gate is fail-closed)   PASS ${pass}   FAIL ${F.length}`);
if (F.length) { F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log(`  ✓ all ${pass} from-code drift gates REJECT their injected drift — a weakened gate (or a moved anchor) fails HERE, not silently`);
