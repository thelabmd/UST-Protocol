// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the step roster is enumerated from .github/workflows/ci.yml, the file CI itself runs
// ASSURANCE MAP — every CI step declares WHAT DECIDES ITS DISPUTE, and the declaration is checked against the code.
//
// WHY. Every gate here was placed by us, and a gate is only as strong as the DOMAIN it ranges over. A domain typed
// from memory is the author's judgment with a delay on it — MEASURED: `retired-mechanisms-gate` guards the spec and
// the formal model by design, and the key-log `rotate` op removed in rev97 kept being advertised to agents by the
// MCP tool description for THREE ROUNDS while that gate ran green. Two documents guarded, two producer-facing
// contracts not. thelabmd/UST-Protocol#110 graded all 56 steps by hand; a hand-written map goes stale exactly the
// way that contract did, so the map is a gate.
//
// THE GRADES, by what decides the dispute — strongest first:
//   1a  an external generator: a subprocess, the registry, the network, a live process. Authored by nobody here.
//   1b  two independent implementations must agree. Catches what did not occur to BOTH authors — who are both us.
//   2   the domain is EXTRACTED from the code that enforces it. Not independent of us, but it cannot DRIFT.
//   3   a roster typed by hand. Conditional on the author's memory at the time of typing.
//   4   our assertions against our own code. Internal consistency, nothing about the world.
//
// WHY A DECLARATION AND NOT INFERENCE. This gate cannot read intent, and a first attempt that tried failed on real
// files: it graded `root-inventory-gate` as external because it shells out to `git ls-files`, while its actual
// domain is a hand-typed map of declared filenames. Distinguishing a domain from a fixture is a judgment. So the
// tool DECLARES, and this gate refuses a declaration the code contradicts — the same shape as an `informational`
// check or an `excluded` layer reason: the claim is visible, and it is bounded by evidence.
//
// IT ONLY BLOCKS OVER-CLAIMS. Declaring WEAKER than the evidence supports always passes: a conservative grade is
// never a lie, and forcing an upgrade would make the gate argue for stronger claims, which is the wrong direction
// for anything called assurance.
//
// HONEST LIMIT, stated so the number is not read as more than it is: a declaration wrong in a way the evidence
// does not contradict still passes. A file that both extracts from source AND carries a literal roster can claim
// `2` truthfully about the extraction while the literal is the real domain — so grade ≤2 plus a literal roster
// demands an explicit `literal-ok:<reason>`, which forces the author to look at it rather than proving anything.
// What this gate does prove: no step is UNGRADED, and no step claims a strength its code cannot support.
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const U = (p) => readFileSync(ROOT + p, 'utf8');
const MIN_REASON = 60;

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// strength order — a HIGHER number is weaker, so a step's grade is the max over its tools
const RANK = { '1a': 1, '1b': 2, '2': 3, '3': 4, '4': 5 };
const NAME = { 1: '1a external generator', 2: '1b cross-implementation', 3: '2 derived from enforcing code', 4: '3 hand-typed roster', 5: '4 self-referential' };

// ── steps whose command runs no file of ours, so there is nowhere to put a marker. Each needs its reason HERE.
const NO_FILE = {
  'dependency audit': '`npm audit` runs no file of ours: the domain is the public advisory database, which nobody here authored or can edit. Grade 1a by construction — there is no roster to drift.',
};

// ── the DOMAIN: the steps CI actually runs, read from the workflow CI itself executes
const CI = U('.github/workflows/ci.yml');
const SCRIPTS = JSON.parse(U('package.json')).scripts;
const steps = [...CI.matchAll(/- name: (.+?)\n\s+run: ((?:.|\n(?!\s+- name))+?)\n(?=\s+- name|\s*$)/g)]
  .map((m) => ({ name: m[1].trim(), run: m[2].trim().split('\n').map((x) => x.trim()).join(' ') }));
check(steps.length > 20, `only ${steps.length} CI steps parsed — the roster has gone blind and this gate would pass vacuously`);

const expand = (cmd, depth = 0) => depth > 6 ? cmd
  : cmd.replace(/npm (?:run )?([\w:-]+)/g, (all, k) => SCRIPTS[k] ? expand(SCRIPTS[k], depth + 1) : all);
const glob = (p) => {
  if (!p.includes('*')) return [p];
  const d = dirname(p), base = p.slice(p.lastIndexOf('/') + 1).replace('*', '');
  try { return readdirSync(ROOT + d).filter((f) => f.endsWith(base)).map((f) => d + '/' + f); } catch { return []; }
};

// ── evidence, read from each tool's own source
const MARKER = /@assurance\s+(1a|1b|2|3|4)\s+canfail:(yes|no)([^\n]*)/;
// "external" = the CASES are not authored here. A subprocess or the network qualifies; so does pseudorandomness,
// which is why a fuzzer belongs in this row — the inputs are generated, not chosen by whoever wrote the file.
const EXTERNAL = /execFileSync\(|execSync\(|fetch\(|\bspawn\b|Math\.random|randomBytes|randomInt/;
// an implementation is identified by the PACKAGE (or clean-room surface) an import reaches, however it is spelled:
// `packages/ust-light/…`, `../ust-light/…` and `./index.mjs` from inside it are the same implementation.
const implsIn = (src, self) => {
  const hits = new Set();
  for (const m of src.matchAll(/from '([^']+\.mjs)'/g)) {
    const spec = m[1];
    const pk = /(?:packages\/|\.\.\/)(ust-[\w-]+|diarium)\//.exec(spec);
    if (pk) hits.add(pk[1]);
    else if (/docs\/ust-(verify|resolve)/.test(spec)) hits.add('docs-cleanroom');
    else if (/extension\//.test(spec)) hits.add('extension');
    else if (/^\.\/(index|reference-checker)\.mjs$/.test(spec)) hits.add(self);
  }
  return hits;
};
const SOURCEREAD = /(?:packages|docs|spec|extension|vectors|tools|\.github)\//;
const EXTRACTS = /matchAll\(|\.exec\(|\.match\(|new RegExp\(/;
// IMPORTING the implementation and exercising it is stronger evidence of "derived from the enforcing code" than
// regexing its text: the behaviour decides, not a pattern over the source. Regenerate-and-diff counts the same way.
const IMPORTS_IMPL = /^import .*from '[^']*(?:index|reference-checker|ust-verify|ust-resolve)\.mjs'/m;
const REGENERATES = /writeFileSync|--check|git diff|regenerat/i;
// A leg LABELLED `CONTROL` is the convention four gates now use, and the detector did not know it: round 92's
// controls were real, ran, and were reported as absent. The label is structural enough to count — it is the text a
// check prints when it fails — but it is still a word, which is why this axis is declared and not inferred.
const CANFAIL = /must be able to fail|able to FAIL|negative control|\bCONTROL\b|gone blind|vacuou|check\(!/i;
const ROSTER = /^(?:const|export const) [A-Z][A-Z_0-9]{2,}\s*=\s*(?:\[|new Set\(\[)[^\]]*'[^']+'\s*,\s*'[^']+'\s*,\s*'/m;

const graded = [];
for (const st of steps) {
  const files = [...new Set([...expand(st.run).matchAll(/node (?:--test )?([\w./*-]+\.mjs)/g)].flatMap((m) => glob(m[1])))];
  if (!files.length) {
    const key = Object.keys(NO_FILE).find((k) => st.name.startsWith(k));
    check(!!key, `step "${st.name.slice(0, 50)}" runs no file of ours and has no entry in NO_FILE — a step nobody graded is a step nobody checked`);
    if (key) check(NO_FILE[key].length >= MIN_REASON, `NO_FILE["${key}"] reason is ${NO_FILE[key].length} chars — under ${MIN_REASON} is a placeholder`);
    graded.push({ step: st.name, rank: 1, canfail: true, files: [] });
    continue;
  }
  let worst = 0, anyFail = true;
  for (const f of files) {
    let src;
    try { src = U(f); } catch { check(false, `step "${st.name.slice(0, 40)}" runs ${f}, which does not exist`); continue; }
    const m = MARKER.exec(src);
    check(!!m, `${f} carries no \`@assurance <1a|1b|2|3|4> canfail:<yes|no> — <what decides>\` marker. It runs in CI step "${st.name.slice(0, 46)}", so it makes a claim; an ungraded claim is the map going stale.`);
    if (!m) { worst = Math.max(worst, 5); anyFail = false; continue; }
    const [, g, cf, tail] = m;
    check(tail.includes('—') && tail.slice(tail.indexOf('—') + 1).trim().length >= 20,
      `${f}: the marker states no WHAT DECIDES clause after an em dash — a grade without a stated decider is a number, not a claim`);
    // over-claims only
    if (g === '1a') check(EXTERNAL.test(src), `${f} claims 1a (external generator) and spawns no subprocess and makes no network call — nothing outside this repo decides its dispute`);
    if (g === '1b') {
      const self = (/packages\/([\w-]+)\//.exec(f) ?? [, 'self'])[1];
      const hits = implsIn(src, self);
      check(hits.size >= 2, `${f} claims 1b (two implementations must agree) and reaches ${hits.size} implementation(s) [${[...hits].join(', ') || 'none'}] — cross-verification needs at least two, and an inline second model written in the same file by the same hand is not one`);
    }
    if (g === '2') check((SOURCEREAD.test(src) && EXTRACTS.test(src)) || IMPORTS_IMPL.test(src) || (SOURCEREAD.test(src) && REGENERATES.test(src)),
      `${f} claims 2 (derived from the enforcing code) and neither extracts from a source it reads, nor imports the implementation, nor regenerates-and-diffs`);
    if (RANK[g] <= 3 && ROSTER.test(src)) check(/literal-ok:/.test(tail),
      `${f} claims ${g} and carries a top-level literal roster of 3+ strings. Under the weaker-side rule that roster IS its domain unless stated otherwise: add \`literal-ok:<why this literal is not the domain>\` to the marker.`);
    if (cf === 'yes') check(CANFAIL.test(src), `${f} declares canfail:yes and carries no leg that proves it — no negative control, no blindness probe, no \`check(!…)\``);
    worst = Math.max(worst, RANK[g]);
    if (cf === 'no') anyFail = false;
  }
  graded.push({ step: st.name, rank: worst, canfail: anyFail, files });
}

// ── the distribution, and the quadrant that matters: domain from memory AND nothing proving the gate can fail
const dist = {};
for (const g of graded) dist[g.rank] = (dist[g.rank] ?? 0) + 1;
const quadrant = graded.filter((g) => g.rank >= 4 && !g.canfail);

// ── THE LEDGER. The distribution was computed every run and thrown away, so there was no trajectory: the quadrant
// could be claimed to be shrinking and nothing showed it. Rows carry ONLY computed numbers — no date and no commit,
// because git already knows when each row landed and a timestamp would make a re-run differ from itself. Runs-to-green
// is deliberately absent: it lives in the CI run history, which is an external generator, and copying it into a file
// I maintain would turn a measured fact into a reported one.
//
// The gate WRITES it with --record and VERIFIES it otherwise: a plain run asserts the last row equals a fresh
// computation, so a hand-edited row, or a grade that moved without being recorded, fails. Same shape as diarium.md
// against its store — the file is a view, the computation is the source.
const LEDGER = 'tools/assurance-ledger.jsonl';
const row = { steps: graded.length, '1a': dist[1] ?? 0, '1b': dist[2] ?? 0, '2': dist[3] ?? 0, '3': dist[4] ?? 0,
  '4': dist[5] ?? 0, canfail: graded.filter((g) => g.canfail).length,
  quadrant: quadrant.map((q) => q.step).sort() };
const rows = existsSync(ROOT + LEDGER)
  ? U(LEDGER).split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

if (process.argv.includes('--record')) {
  if (rows.length && same(rows[rows.length - 1], row)) {
    console.log(`\n  assurance ledger   nothing to record — the distribution is unchanged (${rows.length} row(s))`);
  } else {
    writeFileSync(ROOT + LEDGER, rows.concat([row]).map((r) => JSON.stringify(r)).join('\n') + '\n');
    console.log(`\n  assurance ledger   row ${rows.length + 1} recorded — quadrant ${row.quadrant.length}, hand-typed ${row['3']}`);
  }
  process.exit(0);
}
check(rows.length > 0, `${LEDGER} has no rows — record the first with \`node tools/assurance-map-gate.mjs --record\``);
if (rows.length) check(same(rows[rows.length - 1], row),
  `${LEDGER}'s last row disagrees with a fresh computation. A grade moved without being recorded, or the row was edited by hand — record it: \`node tools/assurance-map-gate.mjs --record\``);
// the trajectory must be able to be read, not only written
if (rows.length > 1) {
  const first = rows[0], last = rows[rows.length - 1];
  console.log(`  ↘  ledger: ${rows.length} rows · hand-typed ${first['3']} → ${last['3']} · quadrant ${first.quadrant.length} → ${last.quadrant.length}`);
}

check(graded.length === steps.length, 'a step was dropped between parsing and grading');
check(!graded.some((g) => g.rank === 0), 'a step graded 0 — the rank never got assigned');

console.log(`\n  assurance map   PASS ${pass}   FAIL ${fail.length}   (${graded.length} CI steps, graded from their own markers)`);
for (const r of [1, 2, 3, 4, 5]) if (dist[r]) console.log(`    ${NAME[r].padEnd(32)} ${dist[r]}`);
console.log(`    ${'declares a can-fail leg'.padEnd(32)} ${graded.filter((g) => g.canfail).length}`);
if (quadrant.length) {
  console.log(`  ⚠  WEAKEST QUADRANT — hand-typed domain AND no declared can-fail leg (${quadrant.length}):`);
  for (const q of quadrant) console.log(`       ${q.step.slice(0, 78)}`);
}
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every CI step is graded, and no step claims a strength its own code cannot support');
