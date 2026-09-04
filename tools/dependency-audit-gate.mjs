// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:yes — the domain is the public advisory database, which nobody here authored or can edit
//
// Dependency-audit gate — a clean audit and an UNREAD one are different facts, and `npm audit` gives them one exit code.
//
// The step was `npm audit --omit=dev --omit=optional --audit-level=critical`, and it is right about what it asks.
// What it cannot say is WHY it failed. Measured 2026-09-04, CLOSED 2026-09-04: the advisory endpoint returned
// `Service Unavailable` and the run went red printing
//
//     npm error audit endpoint returned an error
//
// which a reader scanning a red CI takes for a finding about this tree. It is a fact about registry.npmjs.org.
// Three runs today failed that way, two of them mine, and the repository has already named the class one file
// over: `pending-binding-gate` — *"the API was down" and "the reference is good" must never share an exit code.*
// Here the direction is safe — an unread database fails closed, as it must — but the DIAGNOSIS is wrong, and a red
// build whose message misnames its cause is how a team learns to scroll past red.
//
// So this wrapper separates the two and keeps both failing:
//   · clean          → pass
//   · advisories     → fail, naming the severity counts — a finding about THIS tree
//   · unread         → fail, saying the database could not be read — NOT a finding about this tree
//
// It retries first, because a transient outage is the common case and a gate that reports an outage as a defect on
// the first attempt is a gate that reports network weather. `npm-drift-check` already retries a freshly-published
// tarball for the same reason. What it will never do is PASS on an unread database: that would turn an outage into
// a clean bill of health, which is the one substitution this file exists to refuse.
import { execFileSync } from 'node:child_process';

const LEVEL = 'critical';
const TRIES = 3;

const run = () => {
  try {
    const out = execFileSync('npm', ['audit', '--omit=dev', '--omit=optional', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { ok: true, body: out };
  } catch (e) {
    // `npm audit` exits non-zero BOTH when it finds advisories at the level and when it cannot reach the endpoint.
    // The stdout payload is what tells them apart: a real audit carries `metadata.vulnerabilities`, an outage
    // carries a bare `{ message }`. Reading the exit code alone is the conflation this gate is about.
    return { ok: false, body: String(e.stdout ?? ''), err: String(e.stderr ?? e.message ?? '') };
  }
};

// THE THREE BRANCHES, DECIDED BY ONE PURE FUNCTION so each can be exercised without an outage and without a real
// advisory. A branch nobody has run is a branch that may be broken, and two of these three cannot be reached on
// demand: an outage is the registry's to have, and a critical advisory is not something to introduce in order to
// test the check that would find it.
export const decide = (payload) => {
  if (!payload || !payload.metadata || !payload.metadata.vulnerabilities) return { verdict: 'unread' };
  const v = payload.metadata.vulnerabilities;
  const at = Number(v[LEVEL] ?? 0);
  const total = Object.values(v).reduce((a, b) => a + Number(b || 0), 0);
  return at > 0 ? { verdict: 'advisories', at, v } : { verdict: 'clean', total, v };
};

if (process.argv.includes('--selftest')) {
  const cases = [
    ['clean', { metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } }, 'clean'],
    ['advisories', { metadata: { vulnerabilities: { info: 0, low: 1, moderate: 0, high: 2, critical: 3, total: 6 } } }, 'advisories'],
    ['unread (outage payload)', { message: 'network timeout at: …/security/advisories/bulk' }, 'unread'],
    ['unread (nothing parsed)', null, 'unread'],
    ['unread (shape moved)', { metadata: {} }, 'unread'],
  ];
  let bad = 0;
  for (const [name, payload, want] of cases) {
    const got = decide(payload).verdict;
    if (got !== want) { bad++; console.error(`  ✗ ${name}: expected ${want}, got ${got}`); }
  }
  // NEGATIVE CONTROL — the discrimination itself, and the one leg that proves this gate can fail. A clean read and
  // an unread database must NOT reach the same verdict: collapsing them is precisely the defect measured on
  // 2026-09-04, and a selftest that only checked three happy payloads would pass on a build that had lost it.
  // Verified by mutation: making `unread` return `clean` reddens three cases and this line.
  if (decide(cases[0][1]).verdict === decide(cases[2][1]).verdict) { bad++; console.error('  ✗ a clean audit and an unread database reach the same verdict — the conflation this gate exists to remove'); }
  console.log(bad ? `\n  ✗ dependency-audit selftest: ${bad} failure(s)` : `\n  ✓ dependency-audit selftest: ${cases.length} payloads, three verdicts, and clean ≠ unread`);
  process.exit(bad ? 1 : 0);
}

let last = null;
for (let i = 1; i <= TRIES; i++) {
  last = run();
  let parsed = null;
  try { parsed = JSON.parse(last.body); } catch { /* handled below */ }

  const d = decide(parsed);
  if (d.verdict === 'advisories') {
    console.error(`\n  ✗ ${d.at} ${LEVEL} advisory(ies) in the SHIPPED (production) tree — a finding about THIS tree`);
    console.error(`    all severities: ${Object.entries(d.v).map(([k, n]) => `${k} ${n}`).join(' · ')}`);
    process.exit(1);
  }
  if (d.verdict === 'clean') {
    console.log(`\n  dependency audit   ✓ no ${LEVEL} advisory in the production tree (${d.total} at any severity, read from the public database)`);
    process.exit(0);
  }

  // Not an audit result. Either the endpoint refused, or npm changed its payload — both mean the database was not
  // read, and both must be reported as that rather than as a verdict about our dependencies.
  if (i < TRIES) { try { execFileSync('sleep', ['5']); } catch { /* best effort */ } continue; }
}

const why = (() => {
  try { const j = JSON.parse(last.body); return j.message || j.error?.summary || ''; } catch { return ''; }
})() || last.err.split('\n').find((l) => l.includes('npm error')) || 'no readable reason';

console.error(`\n  ✗ the advisory database could NOT BE READ after ${TRIES} attempts — this is NOT a finding about this tree`);
console.error(`    ${why.slice(0, 200)}`);
console.error('    An unread database fails closed on purpose: passing here would turn an outage into a clean bill of health.');
console.error('    Re-run when the registry answers. If it answers and this still fails, the payload shape moved and the parse above is what to fix.');
process.exit(1);
