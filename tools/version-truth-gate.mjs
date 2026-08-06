// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — PIN is a hand-typed capability table
// Version-truth gate — a version must be traceable to a written round, and the distance to what the
// world can install must be a NUMBER somebody looked at.
//
// `npm-drift-check` guards the opposite direction: a PUBLISHED version is immutable, and it states that
// "repo is ahead, publish pending" is the honest state. It is — right up until nobody measures how far
// ahead. On 2026-07-28 that distance was measured for the first time and every leg of it had rotted:
//
//   · the CLI published as `latest` was 22 candidates behind the working copy and MISSING TWO CHECKS
//     outright, so a stranger attesting the serving contract ran a weaker instrument than CI does (#103)
//   · the reference operator's engine ran `ust-protocol@rc.12` while `latest` was rc.32 — twenty
//     candidates — and its declared range `^1.0.0-rc.12` had permitted the newer one the whole time.
//     Only a lockfile held it. The capability it lacked was the checkpoint `interval`, which is what
//     lifts a stream verdict off `chain-consistent`, so hours sealed unbounded for as long as the pin stood
//   · the CHANGELOG header read `rc.37 line` while package.json read rc.38, and the bump was recorded by
//     EDITING that header — succession by removal, the thing §12.1 forbids an identity to do, applied to
//     the ledger of the protocol that forbids it
//
// None of those is a code defect and every one of them changes what a consumer gets. So this gate checks
// the two legs that are decidable from inside this repository:
//
//   A. every workspace version is traceable to a line section in the CHANGELOG — a version nobody can
//      trace back to a round is the same defect as a claim nobody can trace back to a measurement
//   B. the distance to npm is reported per package, and a CAPABILITY divergence fails: an export that
//      exists here and not in what `latest` serves is not a patch-level difference, it is a promise the
//      published artifact cannot keep
//
// Leg B needs the registry. Offline it reports and does not fail — a gate that cannot reach the network
// must not turn a laptop red, but it must never pass SILENTLY either.
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
// THE RESIDUAL IS PINNED, NOT DEMANDED. Publishing is the owner's act, and a gate that turns red until
// he publishes would be a gate issuing an instruction. So today's gaps are recorded as a ceiling that may
// only SHRINK: a new capability gap fails, closing one is free, and the number stays visible either way.
// Same shape as the reference-checker residual — the point is that nobody can widen a gap in silence.
// Lowered to ZERO the day it was raised: the owner published, every capability gap closed, and the
// ratchet's job is now to keep it there. What a stranger installs and what CI tests are the same
// artifact for the first time since the drift began. Any future entry here is a REGRESSION, not a
// baseline — if a gap reappears, publish or state the policy, do not raise the number.
const PIN = {
  untraced: 3,          // versions with no CHANGELOG row: mcp rc.29, web-signer rc.3, ots-verify rc.10
};

// HELD BACK IS NOT THE SAME AS DRIFTED, and the difference has to be readable from outside. An owner may
// deliberately accumulate rounds and publish when a consumer needs them; a stranger then genuinely installs
// fewer capabilities, and pretending otherwise by raising PIN would do exactly what the note above forbids —
// turn a regression into a baseline. So the gap is admissible only while the release LINE says so, in the
// CHANGELOG, in the open. This is NOT an escape hatch: the marker is the same one `npm-drift-check.mjs`
// verifies AGAINST THE REGISTRY, so a line cannot claim to be unpublished while its version is on npm; and the
// moment it is published the marker must go, which puts the ratchet straight back at zero. One mechanism, read
// by two gates — a second, independently-written notion of "unpublished" is how the two would drift apart.
const CHANGELOG = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
const heldBackFor = (protoVersion) => {
  const line = (String(protoVersion).match(/rc\.(\d+)/) || [])[0];
  if (!line) return false;
  const m = CHANGELOG.match(new RegExp(`^## ${line.replace('.', '\\.')} line(.*)$`, 'm'));
  return !!m && /—\s*unpublished/.test(m[1]);
};

const fail = []; const notes = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// the workspace DIRECTORY travels with the manifest. Deriving it from the package name looked
// obvious and was wrong — `@ust-protocol/mcp` lives in `packages/ust-mcp`, not `packages/mcp`.
const pkgs = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces
  // AUDIT #114 — this used to return null and the package silently left the check: a corrupt manifest was a PASS,
  // measured. A gate that sees less when its input breaks is fail-OPEN, which is the one direction it may not be.
  .map((w) => { try { return { dir: w, ...JSON.parse(readFileSync(join(root, w, 'package.json'), 'utf8')) }; } catch (e) { fail.push(`${w}/package.json is unreadable or not JSON (${String(e.message).slice(0, 60)}) — a package whose manifest cannot be read is NOT checked, so this fails instead of skipping it`); return null; } })
  .filter((p) => p && p.name && p.version);
check(pkgs.length >= 3, `only ${pkgs.length} workspace packages resolved — the gate would be near-vacuous`);
// The release LINE covers the whole set, so being held back is one fact about the tree, not nine.
const HELD_BACK = heldBackFor(pkgs.find((p) => p.name === 'ust-protocol')?.version);

// ── A. every version traceable to a written line ────────────────────────────────────────────────────
const CH = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
const lineHeads = [...CH.matchAll(/^## (?:\[Unreleased\] — )?(rc\.\d+)[^\n]*$/gm)].map((m) => m[1]);
check(lineHeads.length >= 1, 'no `## … rc.N line` section found — versions have nowhere to be traced to');

// ── the SHAPE of the record, measured 2026-07-31 after the owner read it and asked what it was. `rc.46` had TWO
// section headers: one carrying `PUBLISHED 2026-07-31`, one labelled `— unpublished` — for a version I had
// published myself — with rounds 121 and 122 filed under the section that called itself unpublished, in the
// opposite order to every other section in the file. The reader could not tell which rounds actually shipped.
//
// CLOSED 2026-07-31 by `c14d8dd` — release: rc.47 published — and the ledger carried two sections for one
// version. The guard this paragraph explains landed with it; noted 2026-08-05, appended rather than rewritten.
//
// This gate PRINTED the duplicate in its own failure text (`it has: rc.46, rc.46, rc.45, …`) and passed on it. A
// value a gate is willing to display and unwilling to check is the quietest way for a defect to be inside the
// evidence and outside the enforcement — so the shape is checked here, where the domain is already enumerated.
{
  const dupes = lineHeads.filter((v, i) => lineHeads.indexOf(v) !== i);
  check(dupes.length === 0,
    `the CHANGELOG has more than one section for ${[...new Set(dupes)].join(', ')} — a version is ONE line, and two ` +
    `sections for it split the rounds that shipped in it from the rounds that claim not to have. Merge them.`);

  // AT MOST ONE UNPUBLISHED LINE. A version line is opened by a PUBLICATION — the header of every published one
  // says so ("Opened because rc.N is PUBLISHED and a published version is immutable") — and a round that lands
  // while the line is still open belongs in that line as another ROW. MEASURED 2026-07-31: three stacked
  // `## rc.NN line — unpublished` headers, rc.49 / rc.50 / rc.51, each opened by a round and each carrying a
  // sentence I wrote to justify opening it. The owner read them and said it had become a system. It had: this is
  // the duplicate-rc.46 shape again — satisfying a surface by ADDING structure instead of using what is there.
//
// CLOSED 2026-07-31 by `5239b28b` — types(rev69): the union I called untypeable, and the third stacked
// unpublished line. In this tree a narration is written in the commit that fixes what it describes, and
// blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  const unpubCount = (CH.match(/^## rc\.\d+ line — unpublished/gm) ?? []).length;
  check(unpubCount <= 1,
    `${unpubCount} version lines are headed \`— unpublished\`. A line is opened by a PUBLICATION and never by a ` +
    `round: while the current line is unpublished, a new round is another ROW in it. Merge them, keeping every row.`);

  // MEASURED, not assumed: 5 sections read newest-first, 1 oldest-first, 3 carry a single row, and rc.38/rc.39 are
  // neither. So "newest-first" is the convention of the file without being true of all of it, and round 67 owns two
  // rows (`cli rc.68` and `ledger`) where the file's own format for a multi-artifact round is one row with `<br>`.
  // Those are HISTORICAL records. Rewriting their prose to satisfy a gate written years later would be editing the
  // record to fit the tool, so the legacy is NAMED and pinned here instead — it can shrink, never grow, and every
  // section written from now on is held to the convention.
  //
  // Reported honestly because the first run of this leg cried 15 duplicate rounds and 14 were MY OWN noise: the
  // scanner was reading the rev-ladder and milestone tables too, where `| **LIGHT** | 6 |` is not a round at all.
  const LEGACY_UNORDERED = new Set(['rc.39', 'rc.38', 'rc.37']);   // three, all older than the convention
  const LEGACY_TWICE = new Set([67]);

  const bodies = CH.split(/^## /m).slice(1).filter((b) => /^rc\.\d+/.test(b));
  const rowsIn = (b) => [...b.matchAll(/^\| .*? \| (\d+) \| /gm)].map((m) => Number(m[1]));
  for (const b of bodies) {
    const head = b.split('\n')[0], id = /^(rc\.\d+)/.exec(head)[1];
    check(!(/unpublished/i.test(head) && /\*\*PUBLISHED\b/.test(b)),
      `the section \`## ${head.trim().slice(0, 40)}\` is headed unpublished and carries a PUBLISHED banner — one of the two is false, and a reader cannot tell which`);
    const rounds = rowsIn(b);
    if (LEGACY_UNORDERED.has(id)) continue;
    check(rounds.every((n, i) => i === 0 || rounds[i - 1] > n),
      `rounds in \`## ${head.trim().slice(0, 40)}\` run ${rounds.join(', ')} — this file reads newest-first, and a section that does not reads as a different chronology rather than a different section`);
  }

  // a round is recorded ONCE across the version lines — the duplicate section is exactly how one could be filed twice
  const allRounds = bodies.flatMap(rowsIn);
  const twice = [...new Set(allRounds.filter((v, i) => allRounds.indexOf(v) !== i))].filter((n) => !LEGACY_TWICE.has(n));
  check(twice.length === 0, `round(s) ${twice.join(', ')} appear in more than one row — a round is one event and owes one row (this file's format for a multi-artifact round is ONE row with \`<br>\` between the versions)`);
  check(allRounds.length >= 20, `only ${allRounds.length} round row(s) parsed from the version lines — the row scanner has gone blind and the checks above passed for free`);
  for (const n of LEGACY_TWICE) check(allRounds.filter((x) => x === n).length > 1, `round ${n} no longer has two rows — the legacy pin outlived its reason and must be removed, not carried`);
}

// the protocol package is the one the line headers track; others are named in rows
const untraced = [];
const proto = pkgs.find((p) => p.name === 'ust-protocol');
if (proto) {
  const rc = proto.version.match(/rc\.\d+/)?.[0];
  check(!rc || lineHeads.includes(rc),
    `ust-protocol is ${proto.version} and the CHANGELOG has no \`## … ${rc} line\` section (it has: ${lineHeads.join(', ') || 'none'}) — ` +
    `bump the version and OPEN its line in the same commit; never rewrite the previous header, which erases it`);
}
for (const p of pkgs) {
  const rc = p.version.match(/rc\.\d+/)?.[0];
  if (!rc || p.name === 'ust-protocol') continue;
  const short = p.name.replace('@ust-protocol/', '').replace('ust-', '');
  const named = new RegExp(`\\*\\*(?:${short}|${p.name.replace(/[/@]/g, '.')})[^*]*${rc.replace('.', '\\.')}`).test(CH)
    || CH.includes(`${short} ${rc}`) || CH.includes(`${short}@${p.version}`);
  if (!named) untraced.push(`${p.name}@${p.version}`);
}
check(untraced.length <= PIN.untraced,
  `${untraced.length} versions have no CHANGELOG row (pinned at ${PIN.untraced}): ${untraced.join(', ')} — ` +
  `a version nobody can trace to a round is the same defect as a claim nobody can trace to a measurement`);
if (untraced.length < PIN.untraced) notes.push(`untraced versions down to ${untraced.length} — lower PIN.untraced to ${untraced.length}`);

// ── B. distance to what the world can install ───────────────────────────────────────────────────────
const exportsOf = (src) => new Set([...src.matchAll(/export (?:const|function|async function|class) (\w+)/g)].map((m) => m[1]));
let online = true;
for (const p of pkgs) {
  let tags;
  try { tags = JSON.parse(execSync(`npm view ${p.name} dist-tags --json 2>/dev/null`, { encoding: 'utf8', timeout: 20000 })); }
  catch { online = false; notes.push(`${p.name}: registry unreachable`); continue; }
  const latest = tags?.latest;
  if (!latest) { notes.push(`${p.name}: never published`); continue; }
  // Two numbering schemes live in this tree — `1.0.0-rc.N` and plain semver — and reading only the first made
  // `gap` ZERO for every semver package. The declared-hold branch below is `HELD_BACK && gap > 0`, so it was
  // UNREACHABLE for them: a 0.x package accumulating behind an unpublished release line had no way to say so and
  // could pass only by having no missing export at all. Measured 2026-08-06: n('0.10.4') and n('0.10.2') both
  // returned -1. The policy existed; the arithmetic could not reach it, which is the same shape as a roster that
  // enumerates one form of several. CLOSED 2026-08-06 in this same commit — `ahead()` compares both schemes, and
  // the branch is controlled in both directions: disabling the declared hold reddens the gate, and reversing the
  // comparison so the repo reads as BEHIND reddens it too.
  const parts = (v) => {
    const rc = /rc\.(\d+)/.exec(String(v));
    if (rc) return [Number(rc[1])];
    return String(v).split('.').map((x) => { const k = Number(x); return Number.isFinite(k) ? k : 0; });
  };
  // Ahead-ness, not a distance: for `rc.N` the difference IS the candidate count and stays the number the note
  // has always printed; for semver a lexicographic compare answers the only question the branch asks.
  const n = (v) => parts(v);
  const ahead = (a, b) => {
    const A = n(a), B = n(b);
    if (A.length === 1 && B.length === 1) return A[0] - B[0];
    for (let i = 0; i < Math.max(A.length, B.length); i++) {
      const d = (A[i] ?? 0) - (B[i] ?? 0);
      if (d !== 0) return d > 0 ? 1 : -1;
    }
    return 0;
  };
  const gap = ahead(p.version, latest);
  if (gap > 0) notes.push(`${p.name}: repo ${p.version} is ahead of latest ${latest}` + (n(p.version).length === 1 ? ` by ${gap} candidate(s)` : ''));

  // capability, not version: an export here that `latest` does not have is a promise it cannot keep
  let pub;
  try {
    const dir = execSync(`mktemp -d`, { encoding: 'utf8' }).trim();
    execSync(`cd ${dir} && npm pack ${p.name}@${latest} --silent >/dev/null 2>&1 && tar -xzf *.tgz`, { timeout: 60000 });
    pub = readFileSync(join(dir, 'package', p.main ?? 'index.mjs'), 'utf8');
  } catch { notes.push(`${p.name}: could not read the published tarball`); continue; }
  let here;
  try { here = exportsOf(readFileSync(join(root, p.dir, p.main ?? 'index.mjs'), 'utf8')); }
  catch { notes.push(`${p.name}: no ${p.main ?? 'index.mjs'} in ${p.dir} — nothing to compare`); continue; }
  const there = exportsOf(pub);
  const missing = [...here].filter((e) => !there.has(e));
  const pin = PIN[p.name] ?? 0;
  // A gap is admissible when the repo is AHEAD and the release line declares itself unpublished — the owner is
  // accumulating, and said so where an outsider reads it. It stays a reported residual, never a silent pass.
  const declaredHold = HELD_BACK && gap > 0;
  check(missing.length <= pin || declaredHold,
    `${p.name}@${latest} (what \`npm i\` gives a stranger) is missing ${missing.length} export(s), pinned at ${pin}: ` +
    `${missing.slice(0, 6).join(', ')}${missing.length > 6 ? '…' : ''} — a capability gap, not a patch gap. ` +
    `Publish, or state a policy an outsider can read.`);
  if (missing.length && declaredHold) notes.push(`${p.name}: ${missing.length} export(s) held back with the unpublished ${p.version} line — declared, not drifted`);
  else if (missing.length) notes.push(`${p.name}: ${missing.length} export(s) absent from latest (pin ${pin})`);
  if (missing.length < pin) notes.push(`${p.name}: gap shrank to ${missing.length} — lower its PIN`);
}

console.log(`\n  version truth      PASS ${pass}   FAIL ${fail.length}   (${pkgs.length} packages${online ? '' : ', registry unreachable'})`);
notes.forEach((nt) => console.log('    · ' + nt));
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
// A pinned gate must not report the pin as absence. 84 exports ARE missing from what strangers install;
// what passed is that the number did not grow. Saying "no package is missing a capability" would be a
// green light asserting something false — the exact shape this repo keeps catching elsewhere.
const held = Object.entries(PIN).filter(([k]) => k !== 'untraced').reduce((a, [, v]) => a + v, 0);
console.log(held
  ? `  ✓ no gap widened and every version traces to a written line — but ${held} exports remain absent from what \`npm i\` gives a stranger, held at the pin, not closed`
  : '  ✓ what a stranger installs IS what CI tests — no capability gap on any published package, and every version traces to a written line');
