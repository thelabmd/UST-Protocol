// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — it mutates the code and observes, but WHICH checks must be covered is a pin
// VACUITY BATTERY (C3 — execution → NON-VACUITY). The third and last direction of the model↔code lockstep.
//
// What the other gates already prove, and what they cannot:
//   • `model-domain-totality` — every model SECTION is bound or explicitly declared (the DOMAIN, rev85).
//   • `model-correspondence`  — every citation names a check that RAN AND PASSED (presence → EXECUTION, rev91).
//   • conformance's in-process lockstep — a registered check must run in the SAME process over the live `executed`
//     set, so a disabled check cannot be forged by editing a committed manifest.
// None of them can tell a MEANINGFUL assertion from a tautological one. `check()` records its id whether it passed or
// failed, so a check that can never fail — the rev74 case, where a label promised it drove the combinator while the
// assertion was `typeof … === 'function'` and the mutant stayed green — runs, registers, and proves nothing.
//
// This gate attacks that directly: it breaks the implementation on purpose and asks which registered checks NOTICE.
// A check that still passes while the verifier is broken is not evidence of anything.
//
// HONEST BOUND — read this before trusting the number. A battery of N mutants proves non-vacuity only for the checks
// those N mutants reach. It does NOT prove the rest are vacuous, and it does NOT prove the suite is sound. What it does
// is convert an unknown into a MEASURED, PRINTED residual: `PROVEN` checks detected a real break, `UNPROVEN` ones were
// never exercised by any mutant and are named. The residual is PINNED, so it can shrink deliberately but never grow
// silently — adding a registered check without extending the battery raises the count and fails here.
//
// KNOWN LIMITS of this battery, named so they are not mistaken for coverage:
//   (a) the registry-observed residual is large: 13 of 66 registered checks are proven, 53 are not yet reached. The
//       normative TCB IS now reached (rev87, `tcb-stops-refusing`, observed through the byte-vector channel), and that
//       mutant taught the gate something: breaking the reference checker left `conformance.mjs` entirely GREEN while 12
//       byte-vectors caught it. Per-channel silence is therefore a coverage BOUNDARY, not a defect.
//   (b) a mutant is a JUDGEMENT about where the verdict is produced. A badly chosen seam gives false comfort: it
//       raises PROVEN without exercising anything that matters. Review a new mutant as adversarially as a new check.
//   (c) proving a check NOTICES a break says nothing about whether it checks the RIGHT property. That direction is
//       not gate-able and belongs to independent review and a second implementation.
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MUTATIONS, applyMutation } from './mutations.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const REG = JSON.parse(readFileSync(root + 'tools/lockstep-registry.json', 'utf8')).records || [];

// rev89 — the mutation corpus is SHARED with drift-guards (tools/mutations.mjs): one definition per deliberate break,
// two observers. This gate runs the ones whose channel list reaches the suite; the doc-only mutations are gate-only and
// would burn a suite execution to observe a guaranteed zero, so they are skipped here by their own declaration.
const MUTANTS = MUTATIONS.filter((m) => (m.observe || []).length > 0);

// The residual is pinned: registered checks not yet reached by any mutant. Lower it as the battery grows; it must
// never rise. (A new registered check with no mutant reaching it is EXPECTED to raise this — that is the point.)
// 53 → 54 (#95, rev91), and the one addition is NAMED rather than absorbed: `R91-f3-inclusion-consumer-owned` — "the
// connector is read from `opts` only" — is defended by TWO independent layers, so no SINGLE mutant can turn it red.
// `admitDeep` strips every field the verifier does not declare (measured: the seam's insertion point IS reachable, the
// planted field is not), and a function makes the whole proof non-inert and refused at the door. Breaking one layer
// leaves the other answering. The check asserts real behaviour; it is simply not singly falsifiable, and the corpus
// records that instead of carrying a decorative mutant to make the number look better.
const PINNED_UNPROVEN = 54;

const failures = [];
const caught = new Set();
const reachedOutputs = [];      // every mutant's conformance output, for suite-level coverage below
let corpusEvidence = 0;                       // byte-vectors that detected a broken TCB — a claim about the CORPUS, not the registry

for (const m of MUTANTS) {
  const path = root + m.file;
  const backup = readFileSync(path);
  const orig = backup.toString('utf8');
  const mutated = applyMutation(m, orig);
  if (mutated === null) {
    failures.push(`[${m.id}] its seam is absent or ambiguous — the source moved; update the mutation in tools/mutations.mjs, do not weaken it`);
    continue;
  }

  // Observation channels. `conformance` names the registered checks that noticed; `byte-vectors` is the TCB's own
  // language-neutral corpus, whose evidence is a vector count, not a registry id — the only way to reach the reference
  // checker at all. Neither suite writes a committed artifact on a red run, but both are protected anyway: this gate
  // must never be the reason a committed file changes.
  const channels = m.observe;
  const mfPath = root + 'vectors/conformance-checks.json';
  const mfBackup = readFileSync(mfPath);
  const bvPath = root + 'vectors/checker-byte-vectors.json';
  const bvBackup = readFileSync(bvPath);
  const run = (cmd) => {
    try { return { out: execSync(cmd, { cwd: root, encoding: 'utf8', stdio: 'pipe' }), green: true }; }
    catch (e) { return { out: (e.stdout || '') + (e.stderr || ''), green: false }; }
  };

  let confOut = '', vectorHits = 0, stayedGreen = [];
  try {
    writeFileSync(path, mutated);
    if (channels.includes('conformance')) {
      const r = run('node packages/ust-protocol/conformance.mjs');
      confOut = r.out; if (r.green) stayedGreen.push('conformance');
    }
    if (channels.includes('byte-vectors')) {
      const r = run('node packages/ust-protocol/run-byte-vectors.mjs');
      vectorHits = (r.out.match(/✗/g) || []).length; if (r.green) stayedGreen.push('byte-vectors');
    }
  } finally { writeFileSync(path, backup); writeFileSync(mfPath, mfBackup); writeFileSync(bvPath, bvBackup); }

  const hit = REG.filter((r) => r.conformance_check && confOut.includes(r.conformance_check));
  const detected = hit.length > 0 || vectorHits > 0;

  // A channel staying green is NOT a failure by itself — the suites cover different things on purpose. `tcb-stops-refusing`
  // proved that empirically at rev87: breaking the reference checker's refusal seam left `conformance.mjs` fully green
  // while 12 byte-vectors caught it, because the byte corpus is the NORMATIVE TCB conformance and the object-level suite
  // is adapter regression. So per-channel silence is reported as a COVERAGE BOUNDARY (information a reader needs), and
  // only a break that NO channel notices is a failure.
  for (const ch of stayedGreen)
    console.log(`    note: the ${ch} suite did not notice this seam — a coverage boundary, not a defect (another channel did)`);
  if (!detected && m.mustDetect)
    failures.push(`[${m.id}] NOTHING noticed this break on any channel — the mutant is decorative, or the checks that should cover this seam are vacuous`);
  if (!detected && !m.mustDetect)
    console.log(`    note: no registered check noticed it — harvest only; its own gate covers it (drift-guards)`);
  for (const r of hit) caught.add(r.id);
  reachedOutputs.push(confOut);
  corpusEvidence = Math.max(corpusEvidence, vectorHits);
  const bv = channels.includes('byte-vectors') ? `, ${vectorHits} byte-vector(s)` : '';
  console.log(`  mutant ${m.id}: ${hit.length} registered check(s)${bv} detected the break`);
}

// SUITE-LEVEL coverage (2026-07-26). The residual below is over the REGISTERED enforcement records, and it already NAMES
// its members — I claimed otherwise before measuring and was wrong. The real gap is larger: the suite has ~666 checks, so
// the great majority are never assessed for non-vacuity AT ALL. The vacuous check found today — `complete !== 'proven'`,
// an assertion against a word the vocabulary cannot produce — was one of those: not hidden inside a count, outside the
// measured set entirely.
//
// Reported as a RATIO with no pin, deliberately. A pin would fail on every new conformance check that has no mutant, which
// is most of them and legitimately so (positive-shape checks, vector-driven checks whose data no code mutation touches). A
// number that can only improve is honest; a tax on adding checks would simply get removed. For the class this number
// cannot pinpoint — an assertion against an impossible literal — the instrument is tools/verdict-vocabulary-gate.mjs,
// which derives the vocabulary from the core rather than guessing at it.
const suiteIds = (() => { try { return JSON.parse(readFileSync(root + 'vectors/conformance-checks.json', 'utf8')).checks || []; } catch { return []; } })();
const suiteReached = suiteIds.filter((id) => reachedOutputs.some((o) => o.includes(id)));
if (suiteIds.length) console.log(`  suite-level non-vacuity: ${suiteReached.length}/${suiteIds.length} conformance checks are reached by at least one mutant `
  + `(${suiteIds.length - suiteReached.length} unassessed — a BOUND on what this battery can speak for, NOT a claim they are vacuous)`);
const unproven = REG.filter((r) => !caught.has(r.id));
if (unproven.length > PINNED_UNPROVEN)
  failures.push(`the UNPROVEN residual grew: ${unproven.length} registered checks are reached by no mutant, pinned at ${PINNED_UNPROVEN}. Extend the battery to cover the new check, or lower the pin deliberately — the residual must never rise silently`);

if (failures.length) {
  console.error(`✗ vacuity battery FAILED:`);
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}

console.log(`✓ vacuity battery: ${caught.size}/${REG.length} registered checks PROVEN non-vacuous by ${MUTANTS.length} mutant(s) — they detected a real break`);
if (corpusEvidence > 0)
  console.log(`  byte-vector corpus: PROVEN non-vacuous — ${corpusEvidence} vector(s) detect a broken refusal inside the reference checker (the normative TCB, which no registry-observed mutant reaches)`);
console.log(`  UNPROVEN residual: ${unproven.length} (pinned ≤ ${PINNED_UNPROVEN}) — reached by no mutant yet, so NOT shown to be meaningful. This is a bound, not a clean bill:`);
for (const r of unproven) console.log(`    ${r.id}`);
