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
// next round, not this one."* This is that round. CLOSED 2026-08-10 (round 195): the wiring exists and CI calls
// it as `test:recap-selfcheck`.
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
// not change is that a form HAS one and that its judgment sections are left to a person. CLOSED 2026-08-10 in
// this same file: the heading roster is gone and sections are counted instead.
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
const REFUSAL = '> **no diagram** — the selfcheck fixture draws no relation, so there is nothing here to picture';
writeFileSync(filled, readFileSync(skeleton, 'utf8').replace(/<<<FILL:[\s\S]*?>>>/g,
  (m) => (/diagram|BOUNDARY|SURFACE map/.test(m) ? REFUSAL : 'написано человеком')));
const accepted = run(['--check', filled]);
check(accepted.code === 0, `the check REFUSED a fully written report (exit ${accepted.code}) — a checker that never accepts is a checker nobody can satisfy: ${accepted.out.slice(0, 200)}`);

// ── 5. the diagram-slot rule reaches EVERY form (#163). Before this, `audit` and `delivery` emitted an EMPTY
//    slot declaration, so `--check` looped zero times and passed for free — a claim over an empty domain, inside
//    the tool whose job is refusing exactly that. Per form: deleting the slot must be refused, stating a refusal
//    must be accepted, and an emptied declaration must be refused on its own.
for (const form of ['incident', 'audit', 'delivery']) {
  const g = run(['--round', '999', '--issue', '999', '--form', form]);
  const declared = /<!-- diagram-slots: ([^>]*?) -->/.exec(g.out);
  check(!!declared && declared[1].trim().length > 0,
    `the ${form} form declares no diagram slot — an empty domain makes the slot rule vacuous for this form`);

  const dropped = join(dir, `${form}-dropped.md`);
  writeFileSync(dropped, g.out.split('\n').filter((l) => !/<<<FILL:[^>]*(diagram|BOUNDARY|SURFACE map)/.test(l)).join('\n')
    .replace(/<<<FILL:[\s\S]*?>>>/g, 'написано человеком'));
  check(run(['--check', dropped]).code !== 0,
    `the ${form} form ACCEPTED a report whose diagram slot was DELETED — removing a slot is not deciding it, and this form does not say so`);

  // Distinct sections owe DISTINCT reasons — the composer refuses a reason pasted twice, and the incident form
  // has five slots, so a fixture that shrugs identically five times is refused by a rule that is working.
  let nth = 0;
  const stated = join(dir, `${form}-stated.md`);
  writeFileSync(stated, g.out.replace(/<<<FILL:[\s\S]*?>>>/g,
    (m) => (/diagram|BOUNDARY|SURFACE map/.test(m)
      ? `> **no diagram** — slot ${++nth} of this fixture relates nothing to anything, so a picture would invent the relation it claims to show`
      : 'написано человеком')));
  check(run(['--check', stated]).code === 0,
    `the ${form} form REFUSED a STATED no-diagram decision — the refusal shape must be the same in every form, or an author learns two conventions`);

  const emptied = join(dir, `${form}-empty.md`);
  writeFileSync(emptied, readFileSync(stated, 'utf8').replace(/<!-- diagram-slots: [^>]*-->/, '<!-- diagram-slots:  -->'));
  check(run(['--check', emptied]).code !== 0,
    `the ${form} form ACCEPTED an EMPTY slot declaration — a loop over an empty domain is green for free, which is the defect #163 measured`);
}

// ── 6. every ROW spans the same total (#164). One table means one column grid, so a cell whose content cannot
//    wrap sets a minimum width that a cell in a DIFFERENT row pays for. § 5 invites tool output — a fenced block
//    with an unwrappable longest line — and on the round-212 report that pinned column 2 at 611px, starved
//    column 4 to 119px and overflowed the comment. The fix lets a row be shorter and span the remainder, which is
//    only sound if the grid stays well formed. This leg asserts that, and it is what fails if the padding goes.
for (const form of ['incident', 'audit', 'delivery']) {
  const g = run(['--round', '999', '--issue', '999', '--form', form]);
  let ragged = 0, mixed = 0, tables = 0;
  for (const t of g.out.match(/<table[\s\S]*?<\/table>/g) ?? []) {
    tables++;
    const spans = (t.match(/<tr>[\s\S]*?<\/tr>/g) ?? []).map((r) => (r.match(/<td[^>]*>/g) ?? [])
      .reduce((n, c) => n + Number(/colspan="(\d+)"/.exec(c)?.[1] ?? 1), 0));
    if (new Set(spans).size > 1) ragged++;
    if (new Set((t.match(/<tr>[\s\S]*?<\/tr>/g) ?? []).map((r) => (r.match(/<td/g) ?? []).length)).size > 1) mixed++;
  }
  check(tables > 0 && ragged === 0,
    `the ${form} form emitted ${ragged} table(s) whose rows span DIFFERENT column totals — a ragged grid is not a table, and the row that is short is the one a reader loses`);
  if (form === 'incident') {
    check(mixed > 0,
      'no incident table mixes a four-up factual row with a full-width evidence row — the padding is unexercised, so this leg would pass over a grid that never needed it');
  }
}

rmSync(dir, { recursive: true, force: true });

console.log(`\n  recap-compose selfcheck   PASS ${pass}   FAIL ${fail}   (${markers} judgment marker(s) in a fresh skeleton)`);
if (fail) { console.log('\n  ✗ the report generator does not hold its own contract\n'); process.exit(1); }
console.log('  ✓ the generator composes the full shape, refuses a skeleton, and accepts a written report\n');
