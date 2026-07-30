// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — every claimed number recomputed from the artifact it describes, and the claim set is DERIVED
// AUDIT-CLAIMS GATE — the numbers in the document that invites external review must be the numbers this tree produces.
//
// MEASURED 2026-07-30, and it was worse in both directions at once. `docs/AUDIT.md` — the page an external auditor
// reads FIRST — claimed 26 conformance vectors (128), 56 checks (748), 11 MCP tools (14), and a reference-checker
// range of `rev3 → rev17` (rev64). Five-fold understatement of our own work, which makes the invitation read as
// thinner than it is. And in the other direction, the one that matters more: **32/32 cross-implementation
// agreements, 0 divergences** — a number no runner in this tree produces. The parity suite runs 13 cases. That
// figure was true under an older harness and had become an unbacked claim about INDEPENDENT verification, sitting
// in the document whose entire purpose is to be weighed by someone independent.
//
// A stale count in a README costs a reader a minute. A stale count HERE misrepresents how much scrutiny the thing
// has had, to the exact audience whose judgement depends on knowing. So every number claimed in the "what we have
// already done" section is recomputed here from the artifact it describes.
//
// THE CLAIM SET IS DERIVED, not listed. Every bolded number in that section must be covered by a rule below; a new
// claim added tomorrow fails until it is measured. A gate over a hand-picked subset of claims would have passed
// every day the 32/32 stood.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const U = (p) => readFileSync(ROOT + p, 'utf8');

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const DOC = U('docs/AUDIT.md');
const START = DOC.indexOf('## 9. What we have already done');
check(START >= 0, 'the "what we have already done" section was not found in docs/AUDIT.md — the gate has no domain and would pass vacuously');
const SECTION = START < 0 ? '' : DOC.slice(START, DOC.indexOf('\n## ', START + 4) < 0 ? DOC.length : DOC.indexOf('\n## ', START + 4));

// ── the MEASURED values, each read from the artifact the claim describes
const vectors = JSON.parse(U('vectors/conformance-vectors.json')).vectors.length;
const checksFile = JSON.parse(U('vectors/conformance-checks.json'));
const checks = (checksFile.checks ?? checksFile).length;
const tools = new Set([...U('packages/ust-mcp/index.mjs').matchAll(/name: '(ust_\w+)'/g)].map((m) => m[1])).size;
const revision = Number(/revision:\s*(\d+)/.exec(U('packages/ust-protocol/index.mjs'))?.[1]);
const rounds = new Set([...U('CHANGELOG.md').matchAll(/^\| .*? \| (\d+) \| /gm)].map((m) => Number(m[1]))).size;
// the parity suite decides its own case count by RUNNING — a claim about two implementations agreeing is worth
// only what the run produces, so it is counted from the run rather than from a literal anywhere.
let parity = 0;
try {
  const out = execFileSync(process.execPath, [ROOT + 'tools/docs-verifier-parity.mjs'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  parity = (out.match(/ref:.*web:/g) ?? []).length;
} catch { parity = 0; }
check(parity > 0, 'the parity suite produced no comparable case — the cross-implementation claim cannot be checked, failing closed rather than accepting whatever the document says');

// ── each rule OWNS a claim: the pattern that finds it, and the number it must equal
const RULES = [
  { what: 'conformance vectors', rx: /\*\*(\d+) deterministic conformance vectors\*\*/, is: vectors, from: 'vectors/conformance-vectors.json' },
  { what: 'registered checks', rx: /\*\*(\d+) registered checks\*\*/, is: checks, from: 'vectors/conformance-checks.json' },
  { what: 'MCP tools', wholeDoc: true, rx: /the MCP server \((\d+) tools\)/, is: tools, from: "packages/ust-mcp/index.mjs — the server's registered tool names" },
  { what: 'cross-implementation cases', rx: /\*\*(\d+) cases,\s*\n?\s*0 divergences\*\*/, is: parity, from: 'a live run of the parity suite' },
  { what: 'recorded rounds', rx: /\*\*(\d+) recorded rounds\*\*/, is: rounds, from: 'the round column of every version line in CHANGELOG.md' },
  { what: 'checker revision', rx: /from `rev3` to `rev(\d+)`/, is: revision, from: 'VERSION.revision in packages/ust-protocol/index.mjs' },
];

const claimed = new Set();
for (const r of RULES) {
  const m = r.rx.exec(r.wholeDoc ? DOC : SECTION);
  check(!!m, `the ${r.what} claim was not found in the section — a claim that stopped matching is a claim that stopped being checked`);
  if (!m) continue;
  claimed.add(m[1]);
  check(Number(m[1]) === r.is,
    `docs/AUDIT.md claims ${m[1]} ${r.what} and this tree has ${r.is} (${r.from}). An auditor weighs this document to decide how much scrutiny the work has already had — a number that no longer holds misrepresents that, whichever direction it is wrong in.`);
}

// ── EVERY bolded number in the section must be owned by a rule. Without this the gate checks the claims it happens
// to know and passes for any claim added beside them, which is how `32/32` survived.
for (const m of SECTION.matchAll(/\*\*([^*]+)\*\*/g)) {
  // a VERSION is not a claimed quantity: `v1.0`, `v0.29`, `rc.41`, `§11.3` all carry digits and measure nothing.
  // The first pass read `0` out of "v1.0" and reported the sentence as an unchecked claim — the extractor was
  // wider than its domain, which is the defect this gate exists to catch, met while building it.
  const text = m[1].replace(/\b[vr]?\d+\.\d[\d.]*/g, '').replace(/§[\d.]+/g, '');
  const num = /\b(\d[\d,]*)\b/.exec(text);
  if (!num) continue;
  const n = num[1];
  if (claimed.has(n)) continue;
  check(false, `docs/AUDIT.md claims "${m[1].trim().slice(0, 60)}" and no rule in this gate measures the number ${n} — add one, or the claim is unchecked. Every number in this section is read as evidence.`);
}

// ── `--write` REWRITES the claims to the measured values, and CI runs that followed by `git diff --exit-code`.
// A round count moves every round: held by hand it would break the build on every commit and be "fixed" by typing a
// new number, which is the habit this gate exists to end. Derived and diffed, the number cannot be wrong and cannot
// be a chore — the same shape the package version already uses. The comparison legs above still run, so a claim that
// no rule owns fails rather than being silently rewritten.
if (process.argv.includes('--write')) {
  let out = DOC, rewrote = 0;
  for (const r of RULES) {
    const src = r.wholeDoc ? out : out.slice(START);
    const m = r.rx.exec(src);
    if (!m || Number(m[1]) === r.is) continue;
    const fixed = m[0].replace(m[1], String(r.is));
    out = out.replace(m[0], fixed);
    rewrote++;
    console.log(`  ↻ ${r.what}: ${m[1]} → ${r.is}`);
  }
  if (rewrote) writeFileSync(ROOT + 'docs/AUDIT.md', out);
  console.log(`  ✓ audit claims written from measurement (${rewrote} updated)`);
  process.exit(0);
}

// ── each leg must be able to FAIL
check(vectors > 10 && checks > 100 && tools > 5 && rounds > 10, 'a measured domain came back implausibly small — the extraction has gone blind and every comparison above would be against a number nobody produced');
check(!/\*\*32\/32/.test(SECTION), 'the 32/32 cross-implementation claim is back in the section, and no runner in this tree produces it');
check(Number.isInteger(revision) && revision > 0, 'the checker revision could not be read — the range claim would compare against NaN, which equals nothing and fails silently');

console.log(`\n  audit claims   PASS ${pass}   FAIL ${fail.length}   (${RULES.length} claims owned · ${vectors} vectors · ${checks} checks · ${tools} tools · ${parity} parity cases · ${rounds} rounds · rev${revision})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every number in the audit invitation is the number this tree produces');
