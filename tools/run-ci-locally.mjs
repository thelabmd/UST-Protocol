// SPDX-License-Identifier: Apache-2.0
// Run EVERY step CI runs, enumerated from the workflow file — not a pattern that resembles them.
//
// MEASURED, 2026-07-28: a local sweep that grepped `npm run …` out of ci.yml reported "all 47 gates green" while CI
// failed. The workflow has 46 `run:` steps and one of them is `node tools/npm-drift-check.mjs` — no `npm run`, so the
// grep never saw it, and the version bump it exists to demand was never made. The claim was not wrong about the 47
// scripts; it was wrong about the DOMAIN, which is "what CI executes", not "what matches my pattern". That is the same
// failure this repository spends most of its gates preventing, committed in the tool used to check the gates.
//
// CLOSED 2026-07-28 — The bump was made in the commit that added this file — `ust-protocol` rc.36 → rc.37, all
// four version sites moved together, 2026-07-28. Recorded afterwards, because the sentence above stops at what
// the sweep missed. Noted 2026-08-05, appended rather than rewritten.
//
// So: parse the workflow, take every `run:` line in order, execute it, and report by step name. A step CI runs and
// this does not is now impossible without editing this file.
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const YML = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const lines = YML.split('\n');

const steps = [];
let pendingName = null;
for (const l of lines) {
// A step this runner happily parses can still be a workflow GitHub CANNOT LOAD. Measured 2026-07-31: a rename put
// `- name: @ust-protocol/operator …` into the file; `@` is a RESERVED INDICATOR in YAML, so the run reported zero
// jobs and "workflow file issue" while this runner reported 63/63 green. The local mirror validated the steps and
// never the document — the same shape as every other gate that passed on something the real system refuses.
// Narrow on purpose: an unquoted scalar may not OPEN with an indicator character. That is the rule that bit.
  const name = /^\s*-\s*name:\s*(.+?)\s*$/.exec(l);
  if (name) {
    if (/^[@`%&*!|>]/.test(name[1])) {
      console.error(`\n  ✗ workflow YAML: step name opens with the reserved indicator '${name[1][0]}' and is unquoted — GitHub will refuse to load this file:\n    ${name[1].slice(0, 90)}`);
      process.exit(1);
    }
    pendingName = name[1]; continue;
  }
  const run = /^\s*(?:-\s*)?run:\s*(.+?)\s*$/.exec(l);
  if (run) { steps.push({ name: pendingName ?? run[1], cmd: run[1] }); pendingName = null; }
}

// CLOSED 2026-07-31 by `df20308` — fix(ci): the workflow was unloadable and the local mirror reported it
// green. The guard this paragraph explains landed with it; noted 2026-08-05, appended rather than rewritten.

// `npm install` is the environment, not a gate; skip it locally where node_modules already exists.
const gates = steps.filter((s) => !/^npm (install|ci)\b/.test(s.cmd));
if (gates.length < 20) { console.error(`✗ only ${gates.length} steps parsed from ci.yml — the parser has gone blind, refusing to report a pass`); process.exit(1); }

const failed = [];
for (const [i, s] of gates.entries()) {
  process.stdout.write(`  [${String(i + 1).padStart(2)}/${gates.length}] ${s.name.slice(0, 78)}\r`);
  try { execSync(s.cmd, { cwd: new URL('..', import.meta.url).pathname, stdio: 'pipe' }); }
  catch (e) {
    failed.push({ s, out: (e.stdout?.toString() ?? '') + (e.stderr?.toString() ?? '') });
  }
}
process.stdout.write(' '.repeat(100) + '\r');

console.log(`\n  local CI   ${gates.length - failed.length}/${gates.length} steps green   (enumerated from .github/workflows/ci.yml)`);
for (const f of failed) {
  console.log(`\n  ✗ ${f.s.name}`);
  console.log(`    ${f.s.cmd}`);
  for (const l of f.out.split('\n').filter((x) => /✗|FAIL|Error/.test(x)).slice(0, 4)) console.log('      ' + l.trim().slice(0, 150));
}
if (failed.length) process.exit(1);
console.log('  ✓ every step CI runs passes here — the set is the workflow\'s, not a pattern that resembles it');
