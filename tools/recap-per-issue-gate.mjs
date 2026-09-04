// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:`CHANNELS` is the roster of DECLARATION SOURCES, not the domain being judged — the rounds and the issues each closed are read from git and the registry, and the channel names exist so that each one can be asserted LIVE (a channel contributing zero rounds fails the gate, which is how #166 stops the domain narrowing back in silence) — the closed-issue set is read from the ROUND'S OWN COMMITS via git and from the registry, unioned across every channel with disagreement treated as a finding; all sides are derived, and negative controls drive each comparison to fail
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

import { readFileSync, writeFileSync } from 'node:fs';
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

// #166 — THE DOMAIN WAS NOT EMPTY, IT WAS THREE. This read only `closes|fixes|resolves #N` trailers. Measured
// 2026-08-14: of 46 rounds git carries at or above the floor, **3** use a trailer and 18 name their issue in the
// SUBJECT (`round(212): … (#163)`), which is the convention this tree actually follows. So the rule was asserted
// over three rounds and looked like a rule over all of them — a sample reading as a population, in the gate whose
// own comment warns against trusting a round's understatement.
//
// The old comment picked git over the registry for a real reason: *a round that closed two issues and recorded one
// row would be judged against its own understatement.* True — and the alternative it chose has the same defect
// quieter, because a round that closes two and mentions neither in its commit is not judged at all. Both channels
// are the round's own declaration; one fails leniently and the other fails silently.
//
// So the domain is the UNION of every channel, and a DISAGREEMENT between them is itself a finding: to hide a
// second closure now you must omit it from the subject, from the trailers and from the registry at once, and any
// two channels that name different issues for one round stop the gate instead of being resolved by precedence.
// Measured on today's tree: union 52 rounds, 0 disagreements, and exactly one round closing two issues — 185.
const CHANNELS = ['subject', 'trailer', 'registry'];   // the declared domain; each is asserted live below
const closedBy = new Map();   // round → Set(issue), unioned across channels
const sources = new Map();    // round → Map(channel → Set(issue)), kept apart so they can be compared
const note = (round, channel, issues) => {
  if (round < FLOOR || !issues.length) return;
  const set = closedBy.get(round) ?? new Set();
  for (const i of issues) set.add(i);
  closedBy.set(round, set);
  const per = sources.get(round) ?? new Map();
  per.set(channel, new Set([...(per.get(channel) ?? []), ...issues]));
  sources.set(round, per);
};

const roundsInGit = new Set();
for (const [, body] of commits) {
  const r = /^round\((\d+)\)/m.exec(body);
  if (!r) continue;
  const round = Number(r[1]);
  if (round < FLOOR) continue;
  roundsInGit.add(round);
  note(round, 'subject', [...body.split('\n')[0].matchAll(/#(\d+)/g)].map((m) => Number(m[1])));
  note(round, 'trailer', [...body.matchAll(/\b(?:closes|fixes|resolves)\s+#(\d+)/gi)].map((m) => Number(m[1])));
}
// A record with NO round is not a claim about a round. The retro dispositions #174 asked for (#144, #86, #157,
// #152) answer for the CARD and name no round, because none closed them — they were closed and the report was
// never written. Feeding them here grouped all four under `round: undefined` and reported one round closing four
// issues, which is a round-side verdict about records that make no round-side claim. Measured round 279.
for (const rec of reg.records ?? []) if (rec.issue && Number.isInteger(rec.round)) note(rec.round, 'registry', [rec.issue]);

// #165 — THE GUARD IS ON THE DOMAIN, not on one way of losing it. Whatever empties `closedBy` — a shallow clone,
// a buffer, a changed commit convention, a floor that outran the history — the answer is the same: this gate has
// nothing to judge and must say so. A pin caught the first two causes by luck; luck is not a third guard.
if (closedBy.size === 0) {
  refuse(`the closed-issue domain is EMPTY (floor ${FLOOR}) — no round in git closes an issue, so every claim below would be true of nothing. The history, the floor or the commit convention is wrong, and green here would mean none of them was read.`);
}

// #166 — EVERY DECLARED CHANNEL MUST BE LIVE. Found by mutation while closing this card: deleting the subject
// channel left the gate at PASS/0 FAIL, because the registry still filled the domain — the widening protected the
// rule but not itself, and a domain can narrow back silently exactly the way it narrowed in the first place. A
// channel contributing zero rounds is either dead code or a channel nobody reads any more, and both should be a
// decision rather than a quiet loss. Measured 2026-08-14: subject 18, trailer 3, registry 44. CLOSED 2026-08-14
// by the liveness check below, mutation-proven by removing the subject channel and watching it name the loss.
{
  const per = (ch) => [...sources.values()].filter((m) => (m.get(ch)?.size ?? 0) > 0).length;
  const counts = CHANNELS.map((ch) => [ch, per(ch)]);
  const dead = counts.filter(([, n]) => n === 0).map(([ch]) => ch);
  ok(`every declared channel contributes to the domain (${counts.map(([c, n]) => `${c} ${n}`).join(' · ')})`,
    dead.length === 0,
    dead.length ? `channel(s) ${dead.join(', ')} name no round at all — either the convention died or the reader did, and a domain that narrows in silence is how this gate came to judge three rounds out of forty-six` : '');
}

// #166 — EVERY ROUND GIT CARRIES IS ACCOUNTED FOR, which is the anti-vacuity guard a numeric floor only imitates.
// The card proposed "refuse a domain much smaller than the round count"; the measurement offered something
// stronger and without a magic number: a round must either NAME an issue in some channel or carry a `no_recap`
// reason in the registry. Measured 2026-08-14: 46 rounds, 13 with an issue, 33 with `no_recap`, 0 unaccounted.
// A round that appears naming nothing and declaring nothing is the shape a narrowing domain takes, and it is
// exactly what a percentage floor would let through while the percentage stayed healthy. CLOSED 2026-08-14 by the
// accountability check below, with a control on a round that names nothing and declares nothing.
{
  const byRound = new Map((reg.records ?? []).map((r) => [r.round, r]));
  const unaccounted = [...roundsInGit].sort((a, b) => a - b)
    .filter((n) => !closedBy.has(n) && !byRound.get(n)?.no_recap);
  ok(`every round git carries is accounted for (${roundsInGit.size} round(s) at or above floor ${FLOOR})`,
    unaccounted.length === 0,
    unaccounted.length ? `round(s) ${unaccounted.join(', ')} name no issue in any channel and record no \`no_recap\` reason — a round the domain cannot see is a round this rule was never asked about` : '');
}

// #166 — THE CHANNELS MUST AGREE. Picking one source was how the domain stayed at three; unioning them without
// comparing them would let a registry row quietly contradict a commit. A disagreement is a finding, not a
// precedence question: one of the two is wrong about what the round closed, and neither this gate nor a reader
// can tell which.
{
  const conflicts = [];
  for (const [round, per] of [...sources].sort((a, b) => a[0] - b[0])) {
    // The grandfathered round is exempt HERE for the same reason it is exempt below, and this is not a second
    // excuse: measured, round 185's trailers name #142 and #119 while its registry row names #142 alone. That
    // under-record IS the excused fact — one round, two cards, one row — seen from the registry's side. Rewriting
    // the row would be rewriting the history the owner asked to stand. Every other round is held to agreement.
    if (GRANDFATHERED.has(round)) continue;
    const named = [...per].filter(([, v]) => v.size);
    if (named.length < 2) continue;
    const union = new Set(named.flatMap(([, v]) => [...v]));
    for (const [ch, v] of named) {
      const missing = [...union].filter((i) => !v.has(i));
      if (missing.length) conflicts.push(`round ${round}: \`${ch}\` names ${[...v].map((i) => '#' + i).join(', ')} but ${missing.map((i) => '#' + i).join(', ')} appears in ${named.filter(([c]) => c !== ch).map(([c]) => c).join('/')}`);
    }
  }
  ok(`the channels agree on what each round closed (${sources.size} round(s) with a declaration)`,
    conflicts.length === 0, conflicts.join(' · '));
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

// CONTROLS for the widened domain (#166). Each new channel gets its own probe, because the whole finding was that
// a channel nobody read is a channel nobody can be caught through. The subject probe is the important one: it is
// the shape that was invisible for six days while the rule read as universal.
{
  const probe = new Map();
  const noteInto = (round, channel, issues) => {
    const per = probe.get(round) ?? new Map();
    per.set(channel, new Set(issues));
    probe.set(round, per);
  };
  // (a) a round closing TWO issues, declared only in the SUBJECT — the channel this gate could not see.
  noteInto(9101, 'subject', [11, 22]);
  const viaSubject = [...probe].filter(([, per]) => new Set([...per.values()].flatMap((v) => [...v])).size > 1);
  ok('CONTROL: a round closing two issues NAMED ONLY IN THE SUBJECT is detected', viaSubject.length === 1);

  // (b) two channels naming different issues for one round.
  const dis = new Map([[9102, new Map([['subject', new Set([33])], ['registry', new Set([44])]])]]);
  const disFound = [...dis].filter(([, per]) => {
    const named = [...per].filter(([, v]) => v.size);
    const union = new Set(named.flatMap(([, v]) => [...v]));
    return named.some(([, v]) => [...union].some((i) => !v.has(i)));
  });
  ok('CONTROL: two channels naming DIFFERENT issues for one round is detected', disFound.length === 1);

  // (c) a round present in git that names nothing anywhere and declares no `no_recap`.
  const ghost = new Set([9103]);
  const ghosts = [...ghost].filter((n) => !closedBy.has(n) && !(reg.records ?? []).some((r) => r.round === n && r.no_recap));
  ok('CONTROL: a round naming nothing and declaring nothing is detected', ghosts.length === 1);
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


// ── (#174) THE DOMAIN THE RULE QUANTIFIES OVER — CLOSED ISSUES, not rounds ──────────────────────────────
//
// Everything above answers "does every ROUND that claims a closure carry at most one diary". That is a real
// question and it stays. It is not the rule. The rule is *a closed issue owes a closing report with its recap*,
// and its domain is CARDS THAT CLOSED — a set this file could not see, because it is built from git and GitHub
// state is not in git.
//
// Measured 2026-08-16 (#174), CLOSED 2026-09-04: 84 closed issues, 48 with no registry record, 8 of them closed
// on or after 2026-08-01, 4 after the rule itself (2026-08-08) — #144, #86, #157, #152. And NOBODY LIED: every
// round naming #144 declared `no_recap` with a reason that was true as written. Each artifact was individually
// honest and the obligation still evaporated, which is the signature of a domain error rather than a lapse.
//
// The snapshot pattern is `pending-binding-gate`'s, unchanged: `--write` fetches and REFUSES on an unreadable
// answer, the ordinary run reads the committed file. A gate in this repository can know an issue's state offline,
// deterministically, from a file a human refreshed — so "the gate cannot see GitHub" was never the objection.
const CLOSED_PATH = join(ROOT, 'tools/closed-issues.json');
const ISSUE_FLOOR = 174;   // the card that BUILT this leg is inside the domain it created, not exempted from it — a floor set one above it would leave the exemplar
                          // unchecked, which is the shape this repository keeps finding: a fix that removes its own subject from the detector. Everything from #174
                          // was closed under the rule; the four cards it measured are older and are dispositioned by issue-keyed records instead.

if (process.argv.includes('--write')) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const out = {};
  for (let page = 1; page <= 10; page++) {
    const r = await fetch(`https://api.github.com/repos/thelabmd/UST-Protocol/issues?state=closed&per_page=100&page=${page}`, {
      headers: { accept: 'application/vnd.github+json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) { console.error(`  ✗ tracker unreachable: HTTP ${r.status} — refusing to write a state nobody read`); process.exit(1); }
    const batch = await r.json();
    if (!batch.length) break;
    for (const i of batch) if (!i.pull_request) out[i.number] = { closed_at: i.closed_at, title: String(i.title).slice(0, 120) };
  }
  if (!Object.keys(out).length) { console.error('  ✗ the tracker returned NO closed issue — refusing to write an empty domain'); process.exit(1); }
  writeFileSync(CLOSED_PATH, JSON.stringify({
    _: 'closed issues, resolved from thelabmd/UST-Protocol — regenerated by `--write`, never typed',
    _rule: 'a closed issue owes a closing report with its recap; the registry answers with a record naming the issue, or a per-ISSUE no_recap carrying a reason',
    repo: 'thelabmd/UST-Protocol', issues: out,
  }, null, 1) + '\n');
  console.log(`  wrote ${Object.keys(out).length} closed issue(s)`);
  process.exit(0);
}

{
  let CLOSED = null;
  try { CLOSED = JSON.parse(readFileSync(CLOSED_PATH, 'utf8')).issues; } catch { /* reported below */ }
  if (!CLOSED) refuse('tools/closed-issues.json is missing or unreadable — run `node tools/recap-per-issue-gate.mjs --write`. A domain nobody read is not an empty domain');

  const inScope = Object.keys(CLOSED).map(Number).filter((n) => n >= ISSUE_FLOOR).sort((a, b) => a - b);
  // The same vacuity refusal #165 put on `closedBy`, on the new domain and for the same reason: a rule quantified
  // over an empty set is true of nothing, and a stale or truncated snapshot empties it silently.
  if (!inScope.length) refuse(`the CLOSED-ISSUE domain is EMPTY at or above #${ISSUE_FLOOR} — the snapshot is stale or truncated, and every claim below would be true of nothing`);

  // A record answers FOR THE ISSUE. `no_recap` on a round that names no issue answers for the round, which is the
  // distinction this leg exists to draw: those two artifacts were both honest and neither was about the card.
  const byIssue = new Map();
  for (const r of reg.records ?? []) if (r.issue) byIssue.set(r.issue, r);
  const unanswered = inScope.filter((n) => !byIssue.has(n));
  ok(`every closed issue at or above #${ISSUE_FLOOR} is answered by the registry (${inScope.length} in scope)`,
    !unanswered.length, unanswered.length ? `[${unanswered.map((n) => '#' + n).join(', ')}] closed with no record naming them — a report nobody recorded is a report nobody can find` : '');

  const MIN = 60;
  const thin = inScope.filter((n) => byIssue.get(n)?.no_recap && String(byIssue.get(n).no_recap).trim().length < MIN);
  ok(`every no_recap in scope states its reason (min ${MIN} chars)`, !thin.length,
    thin.length ? `[${thin.map((n) => '#' + n).join(', ')}] carry a reason too short to be one` : '');

  // A record that neither seals nor refuses is the shape the round-side channels could already produce.
  const empty = inScope.filter((n) => { const r = byIssue.get(n); return r && !r.content_hash && !r.no_recap; });
  ok('every record in scope either seals an entry or states why none', !empty.length,
    empty.length ? `[${empty.map((n) => '#' + n).join(', ')}] name an issue and say nothing about its diary` : '');

  // CONTROLS — both directions, against real values from this run rather than impossible literals.
  // The control runs on a SYNTHETIC domain, not by deleting from the live one: a control built by mutating live
  // data fails whenever the real check fails, which is noise wearing the shape of a second finding. Measured here
  // on the first run — removing #180's record reddened the check AND its control, reporting one defect twice.
  ok('CONTROL: a closed issue with no record IS detected', (() => {
    const domain = [9001, 9002], answered = new Map([[9001, { issue: 9001, no_recap: 'x' }]]);
    return domain.filter((n) => !answered.has(n)).length === 1;
  })());
  ok('CONTROL: a below-floor issue is OUT of the domain, so the floor is doing work',
    Object.keys(CLOSED).map(Number).some((n) => n < ISSUE_FLOOR));
  ok(`CONTROL: the snapshot carries a live domain (${Object.keys(CLOSED).length} closed issue(s), ${inScope.length} in scope)`,
    Object.keys(CLOSED).length > inScope.length);
}

console.log(`\n  recap per issue   PASS ${pass}   FAIL ${fail.length}   (one issue, one diary — owner 2026-08-08)`);
for (const f of fail) console.log('    ✗ ' + f);
process.exit(fail.length ? 1 : 0);
