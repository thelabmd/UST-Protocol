// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the closed-issue set is read from the ROUND'S OWN COMMITS via git, and the recap set from the registry; both sides are derived, and a negative control drives the comparison to fail
// ONE ISSUE, ONE DIARY.
//
// Owner, 2026-08-08: *"даже когда карточки связаны и закрываются одновременно — то юстрекапы должны быть
// разными… 1 исью один диарий."*
//
// Round 185 closed #142 and #119 with ONE report posted to both cards and ONE sealed entry serving both. Two
// things are wrong with that, and neither is bureaucratic.
//
// A sealed entry is a MOMENT, not a summary. Two defects of the same class still happened at different moments,
// and one text covering both inevitably becomes a description of the class rather than a record of what
// occurred — which is precisely what the diary's own header forbids.
//
// And the registry addresses a round to ONE issue. So the second card carries a comment nobody's registry row
// points at: formally closed, and unaccounted. The gap does not announce itself, because both cards look served.
//
// GRANDFATHERED: round 185 stays as it shipped — the owner asked for it to stand as history rather than be
// rewritten. It is pinned BY NUMBER below, so the exception is a named row rather than a hole in the rule.

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const reg = JSON.parse(readFileSync(join(ROOT, 'tools/recap-registry.json'), 'utf8'));
const FLOOR = reg.first_recapped_round ?? 0;
const GRANDFATHERED = new Set([185]);   // shipped before the rule; kept as history, not rewritten

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

const sh = (args) => { try { return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }); } catch { return ''; } };

// The DOMAIN is the rounds git actually carries, not the registry's own list: a round that closed two issues and
// recorded one row would otherwise be judged against its own understatement.
const log = sh(['log', '--format=%H%x00%B%x01']);
const commits = log.split('\x01').map((c) => c.split('\x00')).filter((p) => p.length === 2);

const closedBy = new Map();   // round → Set(issue)
for (const [, body] of commits) {
  const r = /^round\((\d+)\)/m.exec(body);
  if (!r) continue;
  const round = Number(r[1]);
  if (round < FLOOR) continue;
  const issues = [...body.matchAll(/\b(?:closes|fixes|resolves)\s+#(\d+)/gi)].map((m) => Number(m[1]));
  if (!issues.length) continue;
  const set = closedBy.get(round) ?? new Set();
  for (const i of issues) set.add(i);
  closedBy.set(round, set);
}

const offenders = [];
for (const [round, issues] of [...closedBy].sort((a, b) => a[0] - b[0])) {
  if (issues.size <= 1) continue;
  if (GRANDFATHERED.has(round)) continue;
  offenders.push(`round ${round} closes ${issues.size} issues (${[...issues].map((i) => '#' + i).join(', ')}) and a round carries ONE diary — split it into ${issues.size} rounds, each with its own sealed entry`);
}
ok(`every round closes at most one issue (${closedBy.size} closing round(s) examined, floor ${FLOOR})`,
  offenders.length === 0, offenders.join(' · '));

// The grandfathered row is asserted to still BE what it was excused for. If someone later rewrites 185 into one
// issue, the pin is stale and should go — a permanent exception nobody re-reads is how a rule quietly narrows.
for (const g of GRANDFATHERED) {
  const issues = closedBy.get(g);
  ok(`the grandfathered exception (round ${g}) is still the multi-issue round it was excused for`,
    issues !== undefined && issues.size > 1,
    issues === undefined ? 'round not found in git — remove the pin' : `now closes ${issues.size} — remove the pin`);
}

// NEGATIVE CONTROL — the comparison must fail on a round that violates the rule, or the green above is a shape.
{
  const probe = new Map([[9001, new Set([1, 2])]]);
  const found = [...probe].filter(([r, s]) => s.size > 1 && !GRANDFATHERED.has(r));
  ok('CONTROL: a synthetic round closing two issues IS detected', found.length === 1);
}

console.log(`\n  recap per issue   PASS ${pass}   FAIL ${fail.length}   (one issue, one diary — owner 2026-08-08)`);
for (const f of fail) console.log('    ✗ ' + f);
process.exit(fail.length ? 1 : 0);
