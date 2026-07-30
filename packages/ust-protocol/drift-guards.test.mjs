// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — injects a fake drift into each from-code gate and requires it to fire
// test:drift-guards — the META-gate (owner, round-51: "жёсткая гарантия обновления либо ловли несоответствий без тихих багов").
// The from-code gates (R31 partition, capability-parity, spec-code-sync, BMC denominator, model-lockstep, model-domain,
// retired-mechanisms) are supposed to be FAIL-CLOSED: a new export / error code / interpreter rule / model note / retired
// mechanism that is NOT registered must turn a gate RED, never ship silently. This test PROVES that continuously — it
// INJECTS each mutation, asserts the corresponding gate EXITS NON-ZERO (catches it), and restores the exact original
// bytes in a `finally`. If someone weakens a gate (or a gate's anchor moves), THIS fails.
//
// rev89: the mutations moved to `tools/mutations.mjs` — ONE corpus, shared with the vacuity battery. This file asks
// "does the gate reject it?"; the battery asks "which registered checks notice?". The same edit used to be written out
// twice, once per file, and nothing would have caught the two copies drifting apart.
// It touches only READ-ONLY gates — never conformance.mjs (which rewrites the manifest); the battery owns that channel.
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MUTATIONS, applyMutation } from '../../tools/mutations.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
let pass = 0; const F = [];

// A gate "rejects" the drift iff its process EXITS NON-ZERO.
const gateRejects = (cmd) => { try { execSync(cmd, { cwd: root, stdio: 'pipe' }); return false; } catch { return true; } };

// Inject a mutation into its file, assert its gate rejects it, and ALWAYS restore the exact original bytes.
function probe(m) {
  const name = m.gateName || m.id;
  const path = root + m.file;
  const backup = readFileSync(path);                          // Buffer — byte-identical restore
  const orig = backup.toString('utf8');
  try {
    const mutated = applyMutation(m, orig);
    if (mutated === null) { F.push(`${name}: injection ANCHOR not found (or ambiguous) — the source moved; update the mutation in tools/mutations.mjs (a silent drift-guard hole)`); return; }
    writeFileSync(path, mutated);
    if (gateRejects(m.gate)) pass++;
    else F.push(`${name}: the gate did NOT reject the injected drift — it is NOT fail-closed (a NEW ${name.split('→')[0].trim()} could ship silently)`);
  } finally { writeFileSync(path, backup); }                  // restore no matter what
}

const gated = MUTATIONS.filter((m) => m.gate);
if (gated.length === 0) { console.log('  ✗ drift-guards: the shared corpus declares NO gated mutation — the import or the corpus changed'); process.exit(1); }
for (const m of gated) probe(m);

console.log(`\n  drift-guards (meta — every from-code gate is fail-closed)   PASS ${pass}   FAIL ${F.length}`);
if (F.length) { F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log(`  ✓ all ${pass} from-code drift gates REJECT their injected drift — a weakened gate (or a moved anchor) fails HERE, not silently`);
