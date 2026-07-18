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
