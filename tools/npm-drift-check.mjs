// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:yes — byte comparison against the PUBLISHED registry artifact
// npm-drift gate — a PUBLISHED version is immutable. The conformance version-gate keeps spec==package==vectors
// consistent INTERNALLY, but nothing stopped repo code from drifting under an already-published version label
// ("same version, different bytes" — how rc.6 gained `completeness` in-repo while npm rc.6 didn't have it).
// This closes the class: for every workspace package whose EXACT repo version exists on npm, download the
// published tarball and byte-diff every packaged file against the repo. Any difference ⇒ exit 1 with the rule:
// bump the version IN THE SAME COMMIT as the code change. An unpublished version is fine — that is the honest
// "repo is ahead, publish pending" state, visible as repo-version > npm-latest instead of invisible drift.
import { execSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const workspaces = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces;
let drift = 0, checked = 0, ahead = 0;
const pubState = new Map();   // name -> published?  (round 77: the version LINE's marker is checked against this, not hand-maintained)

const walk = (dir, base = '') => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f), rel = base ? base + '/' + f : f;
  return statSync(p).isDirectory() ? walk(p, rel) : [rel];
});

for (const ws of workspaces) {
  const pkg = JSON.parse(readFileSync(join(root, ws, 'package.json'), 'utf8'));
  const spec = `${pkg.name}@${pkg.version}`;
  let published = false;
  try { published = execSync(`npm view ${spec} version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() === pkg.version; } catch { /* 404 ⇒ not published */ }
  pubState.set(pkg.name, { published, version: pkg.version });
  if (!published) { ahead++; console.log(`  → ${spec}: not on npm — repo is ahead (publish pending), nothing to drift against`); continue; }
  checked++;
  const tmp = mkdtempSync(join(tmpdir(), 'ust-drift-'));
  try {
    // freshly-published windows: registry metadata precedes CDN tarball availability by seconds-to-minutes.
    // A transient fetch failure is NOT drift — retry, then fail CLOSED with a verdict, never a raw crash.
    let packed = false, lastErr = '';
    for (let i = 0; i < 3 && !packed; i++) {
      try { execSync(`npm pack ${spec} --silent`, { cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'] }); packed = true; }
      catch (e) { lastErr = e.message; if (i < 2) execSync('sleep 10'); }
    }
    if (!packed) { drift++; console.error(`  ✗ ${spec}: published per the registry but the tarball is UNFETCHABLE after 3 tries (propagation or outage) — cannot verify immutability, failing closed: ${lastErr.split('\n')[0]}`); continue; }
    const tgz = readdirSync(tmp).find((f) => f.endsWith('.tgz'));
    execSync(`tar xzf ${tgz}`, { cwd: tmp });
    const pubDir = join(tmp, 'package');
    const bad = [];
    for (const rel of walk(pubDir)) {
      let same = false;
      try { same = readFileSync(join(pubDir, rel)).equals(readFileSync(join(root, ws, rel))); } catch { /* missing in repo */ }
      if (!same) bad.push(rel);
    }
    if (bad.length) { drift++; console.error(`  ✗ ${spec}: repo differs from the PUBLISHED artifact of the same version — ${bad.join(', ')}\n    rule: a code change to a published package must bump its version in the same commit`); }
    else console.log(`  ✓ ${spec}: repo == published artifact`);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

// ── A DIST-TAG IS A POINTER, AND WE GATED ONLY WHAT IT POINTS AT.
// MEASURED 2026-07-30, after the owner noticed the tags looked odd: `ust-protocol@next` resolved to rc.36 — a
// version THIS REPO ITSELF deprecated as BROKEN, with a message saying it cannot be imported — and `npm i
// ust-protocol@next` duly failed with ERR_MODULE_NOT_FOUND. Worse, `npm i ust-protocol@rc` is the install command
// printed in that package's own README, and `rc` pointed at rc.22, nineteen versions and every key-handling round
// behind. Five more packages carried the same shape.
//
// CLOSED 2026-07-30 — // The tags were repointed on 2026-07-30 — registry metadata only, no republish — and each
// was verified by installing and importing it; this note was added afterwards, since the paragraph above records
// the measurement that produced the rule and not the repair. Noted 2026-08-05, appended rather than rewritten.
//
// The byte-diff above proves the ARTIFACT under a version label is immutable. It says nothing about which label a
// stranger actually resolves, and a tag is the only thing most people ever type. So: every tag of every package is
// enumerated from the registry and must point at the CURRENT published version, and never at a version we have
// disowned. A tag that should differ must say why, here, in the file.
// `latest` IS THE ONLY MAINTAINED TAG — 2026-08-08, and this is a measurement rather than a preference.
// The tags were enumerated against every consumer in the estate: not one reads `@rc` or `@next`, every
// dependent pins an exact `^1.0.0-rc.N` range, and the only code that mentioned them was this gate. A channel
// nobody reads is ceremony — and this ceremony cost NINE manual commands per release, because OIDC authorises
// `publish` and not `dist-tag`: measured as E401 in CI and again locally, so the second step of the two-step
// release could not be automated at all.
//
// The abandoned tags are left where they last pointed rather than deleted, since deleting them is the same
// manual operation that made them a burden. They are ABANDONED BY POLICY, and this gate says so on every run
// instead of failing the release over a channel with no reader. A tag that IS maintained still has to be right.
const MAINTAINED = 'latest';
const TAG_EXEMPT = {};   // `<pkg>@<tag>` → why it legitimately points elsewhere.
for (const [name, st] of pubState) {
  // A package that is not on npm has no dist-tags, and that is the honest "repo is ahead" state this gate already
  // knows how to report — not an unreadable pointer. Measured 2026-07-31 on the first genuinely unpublished package
  // in the tree: the fetch ran BEFORE the published check and failed closed on a package that simply is not there.
//
// CLOSED 2026-07-31 by `2749655b` — protocol(rc.46): a worked example taught a refusable document — and the
// fix was not the number (#101). In this tree a narration is written in the commit that fixes what it
// describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  if (!st.published) { console.log(`  → ${name}: not on npm — no dist-tags to check`); continue; }
  let tags, deprecated = {};
  try { tags = JSON.parse(execSync(`npm view ${name} dist-tags --json`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })); }
  catch (e) { drift++; console.error(`  ✗ ${name}: dist-tags UNREADABLE — a pointer that cannot be inspected cannot be trusted, failing closed: ${String(e.message).split('\n')[0]}`); continue; }
  const entries = Object.entries(tags ?? {});
  if (!entries.length) { drift++; console.error(`  ✗ ${name}: the registry reports NO dist-tags — the enumeration has gone blind and this leg would pass vacuously`); continue; }
  for (const [tag, ver] of entries) {
    const key = `${name}@${tag}`;
    // a version WE disowned must never be reachable by a name someone types
    let dep = '';
    try { dep = execSync(`npm view ${name}@${ver} deprecated`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* absent ⇒ not deprecated */ }
    if (dep) { drift++; console.error(`  ✗ ${key} → ${ver}, which is DEPRECATED: "${dep.slice(0, 90)}…" — anyone typing this tag installs a version we disowned`); continue; }
    if (tag !== MAINTAINED) { console.log(`  ℹ  ${key} → ${ver} (abandoned channel — only \`${MAINTAINED}\` is maintained)`); continue; }
    if (!st.published) { console.log(`  ℹ  ${key} → ${ver} (repo is ahead; the tag still points at a live version)`); continue; }
    if (ver === st.version) { console.log(`  ✓ ${key} → ${ver}`); continue; }
    const why = (TAG_EXEMPT[key] ?? '').trim();
    if (why.length >= 60) { console.log(`  ℹ  ${key} → ${ver}, declared: ${why.slice(0, 70)}…`); continue; }
    drift++;
    console.error(`  ✗ ${key} → ${ver} but the released version is ${st.version} — a stranger typing \`npm i ${name}@${tag}\` gets neither what we ship nor what we test. Move it, or declare in TAG_EXEMPT why it points elsewhere.`);
  }
}

// CONTROL for the leg above. The honest control would move a tag to a stale version and watch this go red — and it
// is NOT run, because for its duration a stranger typing that tag would install the wrong thing. So the mechanism is
// controlled instead, against a REAL external datum rather than a synthetic one: rc.36 is deprecated on the registry
// as BROKEN, and the detector must see it. If that probe ever comes back empty, either the deprecation was undone or
// this leg has gone blind — both are reasons to stop, and neither is silent.
{
  let dep36 = '';
  try { dep36 = execSync('npm view ust-protocol@1.0.0-rc.36 deprecated', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* leave empty ⇒ fails below */ }
  if (!dep36) { drift++; console.error('  ✗ CONTROL: ust-protocol@1.0.0-rc.36 is deprecated on npm and the probe reports nothing — the deprecation leg cannot fire, so every tag above passed for free'); }
  else console.log('  ✓ CONTROL: the deprecation probe sees a really-deprecated version');
  const mismatch = '1.0.0-rc.1' !== '1.0.0-rc.2';
  if (!mismatch) { drift++; console.error('  ✗ CONTROL: the version comparison accepts two different versions as equal'); }
}

// ── the version LINE's status marker must match the registry (round 77). A hand-written marker DRIFTS: the heading
// `## rc.38 line — published 2026-07-28` stood while rc.39 was published too and carried nothing, so the mark read
// as a distinction that did not exist. Published is the SILENT default — every line reaches it. The OPEN line is the
// one a reader must not have to guess, so it is the one that carries a mark, and the mark is answered by the
// registry this gate already queried rather than by memory.
const CL = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
const proto = pubState.get('ust-protocol');
if (!proto) { console.error('  ✗ line-marker: ust-protocol was not reached — the marker check has gone blind'); drift++; }
else {
  const line = 'rc.' + proto.version.split('-rc.')[1];
  const m = new RegExp('^## ' + line.replace('.', '\\.') + ' line(.*)$', 'm').exec(CL);
  if (!m) { console.error(`  ✗ line-marker: CHANGELOG has no '## ${line} line' heading for the working version ${proto.version}`); drift++; }
  else {
    const suffix = m[1].trim();
    const want = proto.published ? '' : '— unpublished';
    if (suffix !== want) {
      drift++;
      console.error(`  ✗ line-marker: '## ${line} line${m[1]}' but the registry says ${proto.published ? 'PUBLISHED' : 'NOT published'} — expected '## ${line} line${want ? ' ' + want : ''}'`);
      console.error('    rule: the OPEN line is marked, the published one is silent; the marker is not hand-maintained.');
    } else console.log(`  ✓ line-marker: '## ${line} line${want ? ' ' + want : ''}' matches the registry`);
  }
}

console.log(`\n${drift ? '✗ npm-drift gate FAILED' : '✓ npm-drift gate holds'} — ${checked} published checked, ${ahead} ahead-of-npm`);
process.exit(drift ? 1 : 0);
