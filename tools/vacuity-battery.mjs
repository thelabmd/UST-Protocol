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
  {
    // rev87 (a) — reaches the normative TCB itself, which no earlier mutant touched. Its evidence channel is the
    // byte-vector corpus, not conformance, so this mutant is observed through BOTH.
    id: 'tcb-stops-refusing',
    why: 'the refusal seam inside the reference checker — the normative TCB. Broken, `checkAuthorityProofBytes` accepts every package it should reject, so the language-neutral byte corpus must go red.',
    file: 'packages/ust-protocol/reference-checker.mjs',
    from: "  const INVALID = (reason) => ({ result: 'INVALID', reason });",
    to: "  const INVALID = (reason) => ({ result: 'VALID', tier: 'LIGHT' });",
    channels: ['conformance', 'byte-vectors'],
  },
  {
    // rev87 (b) — the STRUCTURAL family: from-code rosters/partitions do not fail when a verdict seam breaks, so the
    // verdict mutants above could never reach them. This one breaks what they actually guard: an unclassified export.
    id: 'unclassified-export',
    why: 'the from-code partition. A new export that no one classified must fail the roster checks — the family whose evidence is "a new surface cannot ship silently".',
    file: 'packages/ust-protocol/index.mjs',
    append: '\nexport function __vacuityProbeExport(x) { return x; }\n',
  },
];

// The residual is pinned: registered checks not yet reached by any mutant. Lower it as the battery grows; it must
// never rise. (A new registered check with no mutant reaching it is EXPECTED to raise this — that is the point.)
const PINNED_UNPROVEN = 53;

const failures = [];
const caught = new Set();
let corpusEvidence = 0;                       // byte-vectors that detected a broken TCB — a claim about the CORPUS, not the registry

for (const m of MUTANTS) {
  const path = root + m.file;
  const backup = readFileSync(path);
  const orig = backup.toString('utf8');
  let mutated;
  if (m.append) {
    mutated = orig + m.append;                                       // an ADDITIVE mutant (a new unclassified surface)
  } else {
    const occurrences = orig.split(m.from).length - 1;
    if (occurrences !== 1) {
      failures.push(`[${m.id}] its seam appears ${occurrences} times (need exactly 1) — the source moved; update the mutant, do not weaken it`);
      continue;
    }
    mutated = orig.replace(m.from, m.to);
  }

  // Observation channels. `conformance` names the registered checks that noticed; `byte-vectors` is the TCB's own
  // language-neutral corpus, whose evidence is a vector count, not a registry id — the only way to reach the reference
  // checker at all. Neither suite writes a committed artifact on a red run, but both are protected anyway: this gate
  // must never be the reason a committed file changes.
  const channels = m.channels || ['conformance'];
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
  if (!detected)
    failures.push(`[${m.id}] NOTHING noticed this break on any channel — the mutant is decorative, or the checks that should cover this seam are vacuous`);
  for (const r of hit) caught.add(r.id);
  corpusEvidence = Math.max(corpusEvidence, vectorHits);
  const bv = channels.includes('byte-vectors') ? `, ${vectorHits} byte-vector(s)` : '';
  console.log(`  mutant ${m.id}: ${hit.length} registered check(s)${bv} detected the break`);
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
if (corpusEvidence > 0)
  console.log(`  byte-vector corpus: PROVEN non-vacuous — ${corpusEvidence} vector(s) detect a broken refusal inside the reference checker (the normative TCB, which no registry-observed mutant reaches)`);
console.log(`  UNPROVEN residual: ${unproven.length} (pinned ≤ ${PINNED_UNPROVEN}) — reached by no mutant yet, so NOT shown to be meaningful. This is a bound, not a clean bill:`);
for (const r of unproven) console.log(`    ${r.id}`);
