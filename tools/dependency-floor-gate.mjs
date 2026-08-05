// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — every floor and every sibling version is READ from the manifests and regenerated with --write; nothing here is typed
// DEPENDENCY-FLOOR GATE — what a package DECLARES it needs must be a version this tree has actually tested.
//
// MEASURED 2026-07-31, found while adding `replicationAgreement` to the core. `@ust-protocol/cli` calls it and
// declared `"ust-protocol": "^1.0.0-rc.23"`. Locally that is invisible: npm workspaces symlink the sibling, so
// every suite runs against the CURRENT core and passes. A stranger running `npm i @ust-protocol/cli` resolves the
// floor against the REGISTRY, gets whatever satisfies rc.23, and the mirror leg dies on
// `P.replicationAgreement is not a function`. Green here, broken there, and nothing in between noticed.
//
// CLOSED 2026-07-31 — in the same commit that added this gate, 2026-07-31 (round 124): all seven floors were
// raised to their sibling's current version and the `--write` path is what keeps them there — the tree measures
// clean today. Noted 2026-08-05, appended rather than rewritten.
//
// It was not one stale floor. It was ALL SEVEN cross-package floors in the tree — mcp, cli×4, diarium, operator —
// drifting for as long as versions have moved, because a floor is written once and never revisited while the
// number beside it climbs. That is the whole class: a manifest claim nobody re-derives.
//
// THE RULE, and why it is this one: a sibling's CURRENT version is the only version this tree has ever run its
// suites against. Any older floor is an untested claim about code we have not executed in that combination. So the
// floor IS the sibling's current version — not "at least", not "close enough". Raising versions then becomes the
// thing that keeps the floors true, instead of the thing that rots them.
//
// Everything here is DERIVED: the roster is the root manifest's `workspaces`, and every version and every range is
// read out of the `packages/<name>/package.json` files themselves. No package name, version or range is typed into
// this file, so it cannot drift from the tree it describes.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const J = (p) => JSON.parse(readFileSync(ROOT + p, 'utf8'));

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const WORKSPACES = J('package.json').workspaces;
const manifests = WORKSPACES.map((w) => ({ w, pkg: J(w + '/package.json') }));
const current = Object.fromEntries(manifests.map(({ pkg }) => [pkg.name, pkg.version]));

// the DOMAIN is every cross-package edge in the tree, enumerated from the manifests — never a hand-kept list,
// because a new package added tomorrow must be covered by the same rule without anyone remembering this file.
let edges = 0;
for (const { w, pkg } of manifests) {
  for (const [dep, range] of Object.entries(pkg.dependencies ?? {})) {
    if (!(dep in current)) continue;                       // a third-party range is not this gate's business
    edges++;
    check(range === '^' + current[dep],
      `${w}/package.json declares \`"${dep}": "${range}"\` and this tree only ever tested against ${current[dep]}. ` +
      `Inside the workspace npm symlinks the sibling, so every suite passes against the CURRENT code — a stranger's ` +
      `\`npm i ${pkg.name}\` resolves the DECLARED range instead and can get a sibling missing the exports this ` +
      `package calls. Set it to "^${current[dep]}" in the same change that moved the version.`);
  }
}
check(edges >= 5, `only ${edges} cross-package edge(s) enumerated — the manifest roster has gone blind and every check above passed for free`);

// `--write` raises every floor to its sibling's current version. Versions move on nearly every round; held by hand
// this gate would be a chore answered by typing a number, which is the habit it exists to end. CI runs
// `--write && git diff --exit-code`, so a floor cannot be wrong AND cannot be busywork.
if (process.argv.includes('--write')) {
  let wrote = 0;
  for (const { w, pkg } of manifests) {
    let changed = false;
    for (const [dep] of Object.entries(pkg.dependencies ?? {})) {
      if (!(dep in current) || pkg.dependencies[dep] === '^' + current[dep]) continue;
      console.log(`  ↻ ${pkg.name}: ${dep} ${pkg.dependencies[dep]} → ^${current[dep]}`);
      pkg.dependencies[dep] = '^' + current[dep];
      changed = true;
    }
    if (changed) { writeFileSync(ROOT + w + '/package.json', JSON.stringify(pkg, null, 2) + '\n'); wrote++; }
  }
  console.log(`  ✓ dependency floors written from the tree (${wrote} manifest(s) updated)`);
  process.exit(0);
}

// ── the rule must be able to FAIL, and the control RUNS it rather than reasoning about it. The first version of
// this block compared two strings and asserted they differed — which proves the decrement worked, not that the
// gate would reject the result. A control that never evaluates the rule is the vacuity this repo keeps finding.
{
  const rule = (range, dep) => range === '^' + current[dep];               // the SAME predicate the loop applies
  const [{ pkg }] = manifests.filter((m) => Object.keys(m.pkg.dependencies ?? {}).some((d) => d in current));
  const dep = Object.keys(pkg.dependencies).find((d) => d in current);
  const behind = '^' + current[dep].replace(/(\d+)$/, (n) => String(Number(n) - 1));
  check(!rule(behind, dep), `CONTROL: a floor one release behind (${behind} against ${current[dep]}) SATISFIED the rule — the rule is not discriminating and every edge above passed for free`);
  check(rule('^' + current[dep], dep), 'CONTROL: the true floor FAILED the rule — the gate would reject a correct tree, which is the opposite failure and just as bad');
}

console.log(`\n  dependency floors   PASS ${pass}   FAIL ${fail.length}   (${edges} cross-package edge(s) over ${manifests.length} manifests)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every package declares the sibling version this tree actually tested against');
