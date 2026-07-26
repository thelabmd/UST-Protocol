// SPDX-License-Identifier: Apache-2.0
// CHANGELOG rev-ladder gate — the CHANGELOG can never silently go stale (owner rule: push = changelog).
//
// The current REFERENCE_CHECKER_VERSION rev MUST have a row in CHANGELOG.md's rev-ladder. A checker rev bump without a
// CHANGELOG entry FAILS CI, so every remediation round that bumps the checker is forced to record itself in the same
// commit — the same discipline as the npm-drift and spec-sync gates, but for the human-readable history.
import { readFileSync } from 'node:fs';
import { REFERENCE_CHECKER_VERSION } from '../packages/ust-protocol/reference-checker.mjs';

const m = REFERENCE_CHECKER_VERSION.match(/rev(\d+)/);
if (!m) { console.error('✗ could not parse a revN from REFERENCE_CHECKER_VERSION:', REFERENCE_CHECKER_VERSION); process.exit(1); }
const rev = m[0];   // e.g. 'rev17'
const changelog = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');

if (!new RegExp('\\*\\*' + rev + '\\*\\*').test(changelog)) {
  console.error(`✗ CHANGELOG rev-ladder gate — no **${rev}** row, but the checker is at ${REFERENCE_CHECKER_VERSION}.`);
  console.error('  RULE: a checker rev bump MUST add its CHANGELOG.md rev-ladder row in the SAME commit (push = changelog).');
  process.exit(1);
}
console.log(`✓ CHANGELOG rev-ladder gate — **${rev}** row present for ${REFERENCE_CHECKER_VERSION}`);

// ── rev numbers are ONE SHARED COUNTER (added 2026-07-26 after it bit) ───────────────────────────────────────────
// The ladder above and the formal model's `**Realization (revN …)**` notes number the SAME rounds. That was tacit, and
// tacit lost: a realization note was labelled rev86 from reading only the model (whose highest note was rev85) while the
// ladder had already spent 86–90. One number then meant two different rounds — the model said "#95 inclusion delegated",
// the ladder said "#90 lockstep". Nothing failed, because the old gate only checked that the CURRENT CHECKER rev has a
// row, and the checker had not moved.
//
// Two checks, both cheap, and the first is the one that would have caught it:
//   1. the model's HIGHEST rev == the ladder's HIGHEST rev. A note written under a stale number leaves the model behind
//      (86 < 90 → red). A round that bumps the ladder without leaving a mark in the model also goes red — deliberately:
//      the ladder's own description says each round is adjudicated against the formal model, so a silent one is worth
//      a look rather than a pass.
//   2. every rev cited in the model HAS a row. Catches a typo or an invented number, which check 1 alone would miss.
const modelText = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');
const changelogText = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
const modelRevs = [...new Set([...modelText.matchAll(/\*\*Realization \(rev(\d+)/g)].map((m) => Number(m[1])))].sort((a, b) => a - b);
const ladderRevs = [...new Set([...changelogText.matchAll(/^\| \*\*rev(\d+)\*\*/gm)].map((m) => Number(m[1])))].sort((a, b) => a - b);
if (!modelRevs.length || !ladderRevs.length) { console.error('✗ could not read the rev sets (model:' + modelRevs.length + ' ladder:' + ladderRevs.length + ')'); process.exit(1); }
const modelMax = modelRevs[modelRevs.length - 1], ladderMax = ladderRevs[ladderRevs.length - 1];
if (modelMax !== ladderMax) {
  console.error(`✗ rev counter split: the formal model's highest realization is rev${modelMax}, the CHANGELOG ladder's highest row is rev${ladderMax}.`);
  console.error('  They number the SAME rounds. A new round takes max+1 in BOTH — never a number that only LOOKS free in one of them.');
  process.exit(1);
}
const orphan = modelRevs.filter((r) => !ladderRevs.includes(r));
if (orphan.length) { console.error('✗ the model cites rev(s) with no CHANGELOG row: ' + orphan.map((r) => 'rev' + r).join(', ')); process.exit(1); }
console.log(`  ✓ rev counter shared: model max = ladder max = rev${modelMax}; all ${modelRevs.length} model revs have rows`);
