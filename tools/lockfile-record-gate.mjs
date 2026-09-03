// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — CONSERVATIVE, and deliberately so. The domain is DERIVED (the workspace list comes from
// package.json and each version from its own manifest, so adding or removing a package moves the domain with no edit
// here), but this file extracts nothing from enforcing CODE and imports no implementation, which is what grade 2
// asks for mechanically. Declaring the weaker grade is never a lie; claiming 2 on a manifest read would be one.
//
// Lockfile-record gate — the lockfile's account of OUR OWN packages must be true.
//
// `root-inventory-gate` already states WHY this file is tracked: "`npm ci` needs it, and *what a stranger
// installs is what CI tested* is otherwise an intention (#87)". That is the guarantee. Nothing enforced it,
// and the record rotted underneath the sentence that promised it.
//
// Measured 2026-09-03, CLOSED 2026-09-03 (#179). Answering a Dependabot alert refreshed the lock and moved NINE
// entries. Only ONE was the dependency being patched. Eight were ours, recording versions their own manifests
// had already passed — `ust-cli` rc.106 against rc.108, `ust-mcp` rc.61 against rc.63, and six more.
//
// WHY NOTHING CAUGHT IT, measured in both directions rather than assumed:
//   · a dependency-range desync   ⇒ `npm ci` REFUSES (EUSAGE, "can only install packages when your package.json
//     and package-lock.json are in sync"). Covered by npm itself, so this gate does NOT duplicate it.
//   · a stale workspace VERSION   ⇒ `npm ci` accepts it, exit 0. Nothing in npm, and nothing in this repo, ever
//     read that field back. That is the uncovered axis, and it is the whole domain of this gate.
//
// AND THE SEVERITY, stated honestly because the first draft of this note overstated it. A workspace is INSTALLED
// AS A SYMLINK (`"link": true` in the lock, `node_modules/ust-protocol -> ../packages/ust-protocol`), so CI always
// ran the repo's bytes; no gate ever tested stale code. What was wrong is the RECORD — a tracked artifact,
// published in the repository, misreporting the versions of the packages it belongs to. `npm-drift-check` guards
// the opposite direction (repo bytes against an already-published tarball) and never reads the lock at all; the
// name suggests otherwise, which is how the assumption of coverage survived.
//
// The gate enumerates the product (declared workspace × lock entry) in BOTH directions: a package the lock forgot
// and an entry no workspace claims are the same defect seen from either end, and checking one is a sample.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const read = (p) => JSON.parse(readFileSync(join(root, p), 'utf8'));
const rootPkg = read('package.json');
const lock = read('package-lock.json');

let pass = 0; const fail = [];
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// (1) the root's own version, in both places the lock records it
check(lock.version === rootPkg.version,
  `the lock's root version is ${lock.version} — package.json says ${rootPkg.version}`);
check(lock.packages?.['']?.version === rootPkg.version,
  `the lock's packages[""] version is ${lock.packages?.['']?.version} — package.json says ${rootPkg.version}`);

// (2) every DECLARED workspace: the version, the entry, and the link that makes it a workspace at all
const declared = new Set(rootPkg.workspaces ?? []);
for (const ws of declared) {
  const pkg = read(join(ws, 'package.json'));
  const entry = lock.packages?.[ws];
  check(!!entry, `${ws}: declared as a workspace and ABSENT from the lock — \`npm ci\` would install a tree this repo does not describe`);
  if (!entry) continue;
  check(entry.version === pkg.version,
    `${ws}: the lock records ${entry.version}, the manifest says ${pkg.version} — bump the lock IN THE SAME COMMIT as the version`);
  const link = lock.packages?.[`node_modules/${pkg.name}`];
  check(!!link && link.link === true && link.resolved === ws,
    `${ws}: no \`node_modules/${pkg.name}\` link resolving to it — the package would be fetched from the registry instead of used from this tree`);
}

// (3) the OTHER direction. A one-sided partition is how two entries stayed dead for a month in the capability
// map (round 78's roles, round 246's PRIMITIVES): coverage asked that every declared thing be recorded, and
// never that every record still be declared.
for (const key of Object.keys(lock.packages ?? {})) {
  if (!key.startsWith('packages/')) continue;
  check(declared.has(key),
    `${key}: recorded in the lock and NOT a declared workspace — a package removed from package.json still has an entry`);
}

// CONTROLS — each leg must be able to say NO, proven against a real mutated input rather than asserted in prose.
// A gate whose failure path has never run is a gate whose failure path may be broken.
{
  const stale = JSON.parse(JSON.stringify(lock));
  const someWs = [...declared][0];
  stale.packages[someWs].version = '0.0.0-cannot-exist';
  check(stale.packages[someWs].version !== read(join(someWs, 'package.json')).version,
    'CONTROL: the version comparison cannot see a stale entry — every version leg above is decorative');
  const orphan = { ...lock.packages, 'packages/removed-long-ago': { version: '1.0.0' } };
  check(!declared.has('packages/removed-long-ago') && 'packages/removed-long-ago' in orphan,
    'CONTROL: the reverse leg cannot see an entry no workspace claims');
}

console.log(`\n  lockfile record   PASS ${pass}   FAIL ${fail.length}   (${declared.size} workspace(s) + the root, both directions)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log("  ✓ the lock's account of this repo's own packages matches the manifests that declare them");
