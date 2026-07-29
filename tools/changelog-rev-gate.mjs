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

// ── rev numbers were ONE SHARED COUNTER, and that counter is now CLOSED (2026-07-26, revised round 77) ───────────
// The ladder and the formal model's `**Realization (revN …)**` notes numbered the SAME rounds. That was tacit, and
// tacit lost: a realization note was labelled rev86 from reading only the model (whose highest note was rev85) while the
// ladder had already spent 86–90. One number then meant two different rounds.
//
// The ladder has since ENDED at rev95 — it recorded a finished reference-checker adversarial audit arc. So the checks
// are no longer about keeping two growing numbers together; they are about keeping a finished one finished:
//   1. neither the ladder nor the model may mint a rev ABOVE the close. This is the check that would have caught
//      round 76's misfiling, where the OLD equality rule actively pushed the record into the closed table.
//   2. every rev cited in the model HAS a row. Catches a typo or an invented number, which check 1 alone would miss.
//   3. the CURRENT CHECKER rev still has its row (below) — the checker's own version is a separate fact from the arc.
const modelText = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');
const changelogText = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
const modelRevs = [...new Set([...modelText.matchAll(/\*\*Realization \(rev(\d+)/g)].map((m) => Number(m[1])))].sort((a, b) => a - b);
const ladderRevs = [...new Set([...changelogText.matchAll(/^\| \*\*rev(\d+)\*\*/gm)].map((m) => Number(m[1])))].sort((a, b) => a - b);
if (!modelRevs.length || !ladderRevs.length) { console.error('✗ could not read the rev sets (model:' + modelRevs.length + ' ladder:' + ladderRevs.length + ')'); process.exit(1); }
// ── round 77: the ladder is CLOSED, and `modelMax === ladderMax` was the wrong rule for a finished table.
// It demanded that the two maxima MOVE TOGETHER, which is a growth rule. Applied to a closed ladder it did the
// opposite of catching a mistake: on 2026-07-29 a PROTOCOL round was labelled with the ladder's token, the gate
// dutifully demanded a matching ladder row, and so pushed the record INTO the closed table instead of objecting
// to the table. A gate whose remedy is to complete the error is worse than no gate on that axis.
// The rule that would have caught it is a CEILING, not an equality: nobody may mint a rev above the close.
const LADDER_CLOSED_AT = 95;   // the reference-checker adversarial audit arc ended here; only a NEW ladder reopens one
const modelMax = modelRevs[modelRevs.length - 1], ladderMax = ladderRevs[ladderRevs.length - 1];
if (ladderMax > LADDER_CLOSED_AT) {
  console.error(`✗ the CLOSED rev-ladder was extended: a row for rev${ladderMax} exists, but the ladder ended at rev${LADDER_CLOSED_AT}.`);
  console.error('  The ROUND counter is continuous (the ladder carried 1-61); round 62 onward live in the version-line tables (## rc.NN line).');
  console.error('  A finished arc does not take max+1. Opening a NEW ladder is a deliberate act — raise LADDER_CLOSED_AT then.');
  process.exit(1);
}
if (modelMax > LADDER_CLOSED_AT) {
  console.error(`✗ the formal model mints rev${modelMax}, above the closed ladder's rev${LADDER_CLOSED_AT}.`);
  console.error('  `**Realization (revN …)**` is the LADDER\'s namespace. A live round is not a ladder round: label it by');
  console.error('  its version-line `round` number instead, and account for it in tools/ladder-registry.json.');
  process.exit(1);
}
const orphan = modelRevs.filter((r) => !ladderRevs.includes(r));
if (orphan.length) { console.error('✗ the model cites rev(s) with no CHANGELOG row: ' + orphan.map((r) => 'rev' + r).join(', ')); process.exit(1); }
console.log(`  ✓ rev-ladder CLOSED at rev${LADDER_CLOSED_AT}: ladder max rev${ladderMax}, model max rev${modelMax}, neither above it; all ${modelRevs.length} model revs have rows`);
