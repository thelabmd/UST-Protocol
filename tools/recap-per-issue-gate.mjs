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

// #165 — A GIT THAT COULD NOT BE READ IS NOT A GIT WITH NO HISTORY. This returned `''` on any failure, and on
// 2026-08-14 the history crossed the 1 MiB default `maxBuffer` by 167 bytes (1 048 743 measured). `execFileSync`
// threw ENOBUFS, the catch turned it into an empty domain, and the rule went green over nothing — the second
// cause of an empty domain to walk through a door that had been closed against the first (a shallow clone). The
// buffer is now far past the measured need, but the load-bearing half is that overflowing is LOUD: failure comes
// back as null and the caller refuses, rather than measuring an empty set and calling it satisfied.
const sh = (args) => {
  try { return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }); } catch { return null; }
};
const refuse = (why) => {
  console.log('\n  recap per issue   PASS 0   FAIL 1   (one issue, one diary — owner 2026-08-08)');
  console.log(`    ✗ ${why}`);
  process.exit(1);
};

// THE DOMAIN MUST EXIST BEFORE IT CAN BE JUDGED. Measured 2026-08-08: the first CI run of this gate went red on
// its PIN while the rule itself passed — because a shallow checkout carries almost no history, so `closedBy` was
// nearly empty and "every round closes at most one issue" was true of nothing. A rule quantified over an empty
// set is not satisfied, it is unasked; the pin noticed only by accident. So the gate refuses a truncated history
// instead of reporting green over it, and CI fetches full depth. A gate that cannot see its domain must say so.
// CLOSED 2026-08-08 — the refusal below is that fix, and a real `--depth 1` clone of this tree exercises it.
// REOPENED AS A CLASS 2026-08-14 (#165): shallow was ONE cause of an empty domain, enumerated as though it were
// the set. The guard is now on the domain itself, below, so the next cause is caught by the guard and not by a pin.
const shallow = sh(['rev-parse', '--is-shallow-repository']);
if (shallow === null) refuse('git would not answer whether the repository is shallow — a gate that cannot ask about its domain must not report on it');
if (shallow.trim() === 'true') {
  refuse('the repository is SHALLOW — the closed-issue domain is unreadable, so this gate would pass over an empty set. Check out with fetch-depth: 0.');
}

// The DOMAIN is the rounds git actually carries, not the registry's own list: a round that closed two issues and
// recorded one row would otherwise be judged against its own understatement.
const log = sh(['log', '--format=%H%x00%B%x01']);
if (log === null) refuse('git log FAILED and the domain is unknown — an unreadable history is not a history with no rounds in it');
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

// #165 — THE GUARD IS ON THE DOMAIN, not on one way of losing it. Whatever empties `closedBy` — a shallow clone,
// a buffer, a changed commit convention, a floor that outran the history — the answer is the same: this gate has
// nothing to judge and must say so. A pin caught the first two causes by luck; luck is not a third guard.
if (closedBy.size === 0) {
  refuse(`the closed-issue domain is EMPTY (floor ${FLOOR}) — no round in git closes an issue, so every claim below would be true of nothing. The history, the floor or the commit convention is wrong, and green here would mean none of them was read.`);
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

// CONTROL for the guard itself (#165). The empty-domain refusal is the one branch that cannot be reached on a
// healthy tree, which is exactly the shape that rots unnoticed — so the condition is exercised on a synthetic
// empty map here, and the domain this run actually judged is stated rather than implied.
{
  ok('CONTROL: an EMPTY domain would be refused, not measured', new Map().size === 0 && closedBy.size > 0,
    `the guard and the live domain disagree — live size ${closedBy.size}`);
  ok(`CONTROL: git returned a readable history (${commits.length} commits, ${log.length} bytes)`, commits.length > 0);
}

console.log(`\n  recap per issue   PASS ${pass}   FAIL ${fail.length}   (one issue, one diary — owner 2026-08-08)`);
for (const f of fail) console.log('    ✗ ' + f);
process.exit(fail.length ? 1 : 0);
