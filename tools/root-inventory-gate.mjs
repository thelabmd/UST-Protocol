// SPDX-License-Identifier: Apache-2.0
// Root INVENTORY gate — the top level of a public protocol repository is enumerated, not accumulated.
//
// MEASURED, 2026-07-28: two files the owner did not recognise were sitting in the root — `wdir.json` and `gm.json`.
// Both were mine: stray output redirects from measurement commands (`gh api …` and a fetched genesis), written into
// the working directory instead of a scratch path, then swept in by `git add -A` and published. Neither leaked
// anything — the genesis was byte-identical to the endpoint that serves it publicly — but a reader of the root sees
// the shape of the project, and junk in it is a claim about care that is not true.
//
// The habit fix is to write measurements to a scratch path. This is the backstop for the times the habit fails: a
// new top-level file must be DECLARED here, with what it is for. Same discipline as the package roster and the
// artifact-origin table — a domain enumerated in both directions rather than a pattern that resembles it.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

// Every tracked top-level file, and why it is there. A file whose reason you cannot write does not belong in a root.
const DECLARED = {
  '.gitignore': 'what git must not carry',
  'README.md': 'the entry point',
  'CHANGELOG.md': 'the reasoning ledger — the rev-ladder and the rounds',
  'CONTRIBUTING.md': 'how to work on this',
  'CODE_OF_CONDUCT.md': 'community baseline',
  'GOVERNANCE.md': 'who decides what',
  'SECURITY.md': 'how to report a vulnerability',
  'LICENSE': 'code licence (Apache-2.0)',
  'LICENSE-SPEC': 'specification licence (CC-BY-4.0) — deliberately separate from the code licence',
  'NOTICE': 'attribution required by Apache-2.0',
  'TRADEMARK.md': 'the name is not covered by the code licence',
  'PORTING.md': 'what an independent implementation must reproduce',
  'DONOTREADME.md': 'the honest counterpart to the README — what is unfinished',
  'diarium.md': 'the diary, a generated view of the sealed store in diarium/',
  'package.json': 'the workspace root',
};

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter((p) => p && !p.includes('/'));

check(tracked.length >= 10, `only ${tracked.length} top-level files listed — the probe has gone blind and this gate would pass vacuously`);

for (const f of tracked) {
  check(f in DECLARED,
    `\`${f}\` is tracked at the repository root and is not declared in tools/root-inventory-gate.mjs. If it belongs here, add it with what it is for. If it is stray output from a command, delete it — a public root is read as a statement about the project.`);
}
for (const f of Object.keys(DECLARED)) {
  check(tracked.includes(f), `${f} is declared but no longer tracked at the root — a stale declaration is a second place to be wrong`);
}
for (const [f, why] of Object.entries(DECLARED)) {
  check(typeof why === 'string' && why.length >= 12, `${f} is declared with a reason too short to be one`);
}

// the leg must be able to fail
check(!('stray-output.json' in DECLARED), 'the declaration probe accepts a file the inventory lacks');

console.log(`\n  root inventory   PASS ${pass}   FAIL ${fail.length}   (${tracked.length} tracked top-level files)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every file at the repository root is declared, and every declaration still exists');
