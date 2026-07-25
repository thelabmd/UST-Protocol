// SPDX-License-Identifier: Apache-2.0
// VACUITY BATTERY (C3 — execution → NON-VACUITY). The third and last direction of the model↔code lockstep.
//
// What the other gates already prove, and what they cannot:
//   • `model-domain-totality` — every model SECTION is bound or explicitly declared (the DOMAIN, rev85).
//   • `model-correspondence`  — every citation names a check that RAN AND PASSED (presence → EXECUTION, rev86).
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
//   (a) every mutant so far breaks `index.mjs`. The normative TCB itself — `reference-checker.mjs`, exercised by the
//       byte-vector corpus rather than by `conformance.mjs` — is reached by NO mutant, so the non-vacuity of the
//       byte-vector suite is not measured here at all. Extending to it needs a second observation channel.
//   (b) a mutant is a JUDGEMENT about where the verdict is produced. A badly chosen seam gives false comfort: it
//       raises PROVEN without exercising anything that matters. Review a new mutant as adversarially as a new check.
//   (c) proving a check NOTICES a break says nothing about whether it checks the RIGHT property. That direction is
//       not gate-able and belongs to independent review and a second implementation.
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const REG = JSON.parse(readFileSync(root + 'tools/lockstep-registry.json', 'utf8')).records || [];

// Each mutant names a VERDICT-PRODUCING seam and breaks it in one direction. `from` must appear exactly once.
const MUTANTS = [
  {
    id: 'verifier-stops-refusing',
    why: 'the single seam that constructs a refusal. Broken, the verifier accepts everything it should reject — every check whose evidence is "the attack is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "function bad(code, detail, fields) { return { result: 'INVALID', error: code, detail, ...(fields || null) }; }",
    to: "function bad(code, detail, fields) { return { result: 'VALID', tier: 'LIGHT' }; }",
  },
  {
    id: 'signature-always-verifies',
    why: 'the Ed25519 leaf. Broken, every forged or tampered signature passes — checks whose evidence is "a bad signature is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'export function edVerifyStrict(pubB64url, msgUtf8, sigB64url) {',
    to: 'export function edVerifyStrict(pubB64url, msgUtf8, sigB64url) { return true; /* mutant */',
  },
  {
    id: 'tier-always-top',
    why: 'the tier projection. Broken, every document reads as the strongest tier — checks whose evidence is "this evidence does NOT earn TOP/authoritative" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'export function projectTier(state) {',
    to: "export function projectTier(state) { return 'TOP'; /* mutant */",
  },
];

// The residual is pinned: registered checks not yet reached by any mutant. Lower it as the battery grows; it must
// never rise. (A new registered check with no mutant reaching it is EXPECTED to raise this — that is the point.)
const PINNED_UNPROVEN = 55;

const failures = [];
const caught = new Set();

for (const m of MUTANTS) {
  const path = root + m.file;
  const backup = readFileSync(path);
  const orig = backup.toString('utf8');
  const occurrences = orig.split(m.from).length - 1;
  if (occurrences !== 1) {
    failures.push(`[${m.id}] its seam appears ${occurrences} times (need exactly 1) — the source moved; update the mutant, do not weaken it`);
    continue;
  }
  let out = '', suiteStayedGreen = false;
  // conformance only writes the manifest on a GREEN run, so a mutant run cannot normally touch it — but back it up
  // anyway: this gate must not be the reason a committed artifact changes.
  const mfPath = root + 'vectors/conformance-checks.json';
  const mfBackup = readFileSync(mfPath);
  try {
    writeFileSync(path, orig.replace(m.from, m.to));
    try { out = execSync('node packages/ust-protocol/conformance.mjs', { cwd: root, encoding: 'utf8', stdio: 'pipe' }); suiteStayedGreen = true; }
    catch (e) { out = (e.stdout || '') + (e.stderr || ''); }        // a broken verifier SHOULD fail the suite
  } finally { writeFileSync(path, backup); writeFileSync(mfPath, mfBackup); }   // byte-identical restore, always
  if (suiteStayedGreen)
    failures.push(`[${m.id}] the ENTIRE suite stayed GREEN while the verifier was broken at this seam — nothing noticed at all, which is a finding in its own right`);

  const hit = REG.filter((r) => r.conformance_check && out.includes(r.conformance_check));
  if (hit.length === 0)
    failures.push(`[${m.id}] NO registered check noticed this break — the mutant is decorative, or the checks that should cover this seam are vacuous`);
  for (const r of hit) caught.add(r.id);
  console.log(`  mutant ${m.id}: ${hit.length} registered check(s) detected the break`);
}

const unproven = REG.filter((r) => !caught.has(r.id));
if (unproven.length > PINNED_UNPROVEN)
  failures.push(`the UNPROVEN residual grew: ${unproven.length} registered checks are reached by no mutant, pinned at ${PINNED_UNPROVEN}. Extend the battery to cover the new check, or lower the pin deliberately — the residual must never rise silently`);

if (failures.length) {
  console.error(`✗ vacuity battery FAILED:`);
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}

console.log(`✓ vacuity battery: ${caught.size}/${REG.length} registered checks PROVEN non-vacuous by ${MUTANTS.length} mutant(s) — they detected a real break`);
console.log(`  UNPROVEN residual: ${unproven.length} (pinned ≤ ${PINNED_UNPROVEN}) — reached by no mutant yet, so NOT shown to be meaningful. This is a bound, not a clean bill:`);
for (const r of unproven) console.log(`    ${r.id}`);
