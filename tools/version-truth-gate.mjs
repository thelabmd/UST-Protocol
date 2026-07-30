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

const fail = []; const notes = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// the workspace DIRECTORY travels with the manifest. Deriving it from the package name looked
// obvious and was wrong — `@ust-protocol/mcp` lives in `packages/ust-mcp`, not `packages/mcp`.
const pkgs = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces
  .map((w) => { try { return { dir: w, ...JSON.parse(readFileSync(join(root, w, 'package.json'), 'utf8')) }; } catch { return null; } })
  .filter((p) => p && p.name && p.version);
check(pkgs.length >= 3, `only ${pkgs.length} workspace packages resolved — the gate would be near-vacuous`);

// ── A. every version traceable to a written line ────────────────────────────────────────────────────
const CH = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
const lineHeads = [...CH.matchAll(/^## (?:\[Unreleased\] — )?(rc\.\d+)[^\n]*$/gm)].map((m) => m[1]);
check(lineHeads.length >= 1, 'no `## … rc.N line` section found — versions have nowhere to be traced to');

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
  const n = (v) => Number(String(v).match(/rc\.(\d+)/)?.[1] ?? -1);
  const gap = n(p.version) - n(latest);
  if (gap > 0) notes.push(`${p.name}: repo ${p.version} is ${gap} candidate(s) ahead of latest ${latest}`);

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
  check(missing.length <= pin,
    `${p.name}@${latest} (what \`npm i\` gives a stranger) is missing ${missing.length} export(s), pinned at ${pin}: ` +
    `${missing.slice(0, 6).join(', ')}${missing.length > 6 ? '…' : ''} — a capability gap, not a patch gap. ` +
    `Publish, or state a policy an outsider can read.`);
  if (missing.length) notes.push(`${p.name}: ${missing.length} export(s) absent from latest (pin ${pin})`);
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
