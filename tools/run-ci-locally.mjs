// SPDX-License-Identifier: Apache-2.0
// Run EVERY step CI runs, enumerated from the workflow file — not a pattern that resembles them.
//
// MEASURED, 2026-07-28: a local sweep that grepped `npm run …` out of ci.yml reported "all 47 gates green" while CI
// failed. The workflow has 46 `run:` steps and one of them is `node tools/npm-drift-check.mjs` — no `npm run`, so the
// grep never saw it, and the version bump it exists to demand was never made. The claim was not wrong about the 47
// scripts; it was wrong about the DOMAIN, which is "what CI executes", not "what matches my pattern". That is the same
// failure this repository spends most of its gates preventing, committed in the tool used to check the gates.
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
  const name = /^\s*-\s*name:\s*(.+?)\s*$/.exec(l);
  if (name) { pendingName = name[1]; continue; }
  const run = /^\s*(?:-\s*)?run:\s*(.+?)\s*$/.exec(l);
  if (run) { steps.push({ name: pendingName ?? run[1], cmd: run[1] }); pendingName = null; }
}

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
