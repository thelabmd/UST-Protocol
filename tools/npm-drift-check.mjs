// SPDX-License-Identifier: Apache-2.0
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

const walk = (dir, base = '') => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f), rel = base ? base + '/' + f : f;
  return statSync(p).isDirectory() ? walk(p, rel) : [rel];
});

for (const ws of workspaces) {
  const pkg = JSON.parse(readFileSync(join(root, ws, 'package.json'), 'utf8'));
  const spec = `${pkg.name}@${pkg.version}`;
  let published = false;
  try { published = execSync(`npm view ${spec} version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() === pkg.version; } catch { /* 404 ⇒ not published */ }
  if (!published) { ahead++; console.log(`  → ${spec}: not on npm — repo is ahead (publish pending), nothing to drift against`); continue; }
  checked++;
  const tmp = mkdtempSync(join(tmpdir(), 'ust-drift-'));
  try {
    execSync(`npm pack ${spec} --silent`, { cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'] });
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

console.log(`\n${drift ? '✗ npm-drift gate FAILED' : '✓ npm-drift gate holds'} — ${checked} published checked, ${ahead} ahead-of-npm`);
process.exit(drift ? 1 : 0);
