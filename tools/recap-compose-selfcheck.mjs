// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the generator is EXECUTED here and both directions of its refusal are observed.
// Nothing about the SHAPE is hand-typed: the forms are enumerated and their sections COUNTED, never named, so a
// form may change its headings without this check going stale. What it pins is that a form has a shape at all,
// that its judgment sections are left to a person, and that the refusal fires and lifts.
//
// THE GENERATOR'S OWN CHECK WAS NEVER RUN BY ANYTHING. Measured 2026-08-10 (round 174's own record said so, and
// grep confirms it again): `tools/recap-compose.mjs` appears in neither `package.json` nor `.github/workflows/`.
// Its `--check` — the refusal that makes the report shape binding — fired only when an author chose to type it.
// Round 174 recorded that as an exclusion rather than pointing the `test` layer at an unrun command, and was
// right to: a layer citing a command nobody runs is the defect this repository spends its gates on. It also
// said what should happen next, in as many words: *"wiring the generator's own check into the pipeline is the
// next round, not this one."* This is that round.
//
// WHY BOTH DIRECTIONS. A checker that only ever sees correct input proves nothing — it would pass while broken.
// So the skeleton is generated, `--check` must REFUSE it (markers present), the markers are then filled and
// `--check` must ACCEPT it. A detector that fires on the real defect and stays silent on correct input is the
// control; either half alone is decoration.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'ust-recap-selfcheck-'));
const skeleton = join(dir, 'skeleton.md');
const filled = join(dir, 'filled.md');

let fail = 0, pass = 0;
const check = (ok, msg) => { if (ok) { pass++; } else { fail++; console.log('  ✗ ' + msg); } };
const run = (args) => {
  try {
    const out = execFileSync('node', ['tools/recap-compose.mjs', ...args], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, out };
  } catch (e) { return { code: e.status ?? 1, out: String(e.stdout ?? '') + String(e.stderr ?? '') }; }
};

// ── 1. EVERY form composes, and each carries judgment markers.
// The three forms have DIFFERENT shapes on purpose — measured 2026-08-10: incident 8 top-level sections,
// audit 12, delivery 6 — so the check counts sections instead of naming them. Naming them was the first
// version of this file and it failed on its own first run: it hard-coded the incident headings and ran the
// audit form. A roster of headings would also freeze the shape, and the shape is allowed to change; what may
// not change is that a form HAS one and that its judgment sections are left to a person.
let markers = 0;
for (const form of ['incident', 'audit', 'delivery']) {
  const g = run(['--round', '999', '--issue', '999', '--form', form]);
  check(g.code === 0, `the generator failed to compose the ${form} form (exit ${g.code})`);
  const sections = (g.out.match(/^## /gm) ?? []).length;
  check(sections >= 6, `the ${form} form composed only ${sections} top-level section(s) — a form with no shape cannot be a contract`);
  const m = (g.out.match(/<<<FILL/g) ?? []).length;
  check(m > 0, `the ${form} form carries NO judgment markers — either the generator stopped emitting them or the form lost its judgment sections, and both make \`--check\` vacuous`);
  if (form === 'audit') { writeFileSync(skeleton, g.out); markers = m; }
}

// ── 3. REFUSES an unfilled skeleton
const refused = run(['--check', skeleton]);
check(refused.code !== 0, 'the check ACCEPTED a skeleton that still carries FILL markers — the refusal that makes the shape binding does not fire');

// ── 4. ACCEPTS the same document once the markers are gone
writeFileSync(filled, readFileSync(skeleton, 'utf8').replace(/<<<FILL:[\s\S]*?>>>/g, 'написано человеком'));
const accepted = run(['--check', filled]);
check(accepted.code === 0, `the check REFUSED a fully written report (exit ${accepted.code}) — a checker that never accepts is a checker nobody can satisfy: ${accepted.out.slice(0, 200)}`);

rmSync(dir, { recursive: true, force: true });

console.log(`\n  recap-compose selfcheck   PASS ${pass}   FAIL ${fail}   (${markers} judgment marker(s) in a fresh skeleton)`);
if (fail) { console.log('\n  ✗ the report generator does not hold its own contract\n'); process.exit(1); }
console.log('  ✓ the generator composes the full shape, refuses a skeleton, and accepts a written report\n');
