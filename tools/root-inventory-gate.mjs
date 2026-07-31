// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:yes literal-ok:DECLARED s VALUES are annotations that gate nothing — the SET comes from `git ls-files`, an answer no one can fake inside this gate, and it is checked in both directions so an undeclared file and a stale declaration both fail
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
// Every tracked top-level DIRECTORY, and why it is there. Scratch has no reason, which is the point.
const DECLARED_DIRS = {
  packages: 'the published packages — the protocol, the CLI, the MCP server, the signers and connectors',
  spec: 'the specification and the formal model',
  vectors: 'conformance vectors and the executed-check manifest',
  tools: 'the gates and generators — every drift check in this repository',
  docs: 'the web verifier and the audit invitation, served from GitHub Pages',
  examples: 'sample documents, valid and tampered, referenced by the spec',
  extension: 'the "Make it UST" browser demo',
  diarium: 'the sealed diary store — one signed file per entry',
  art: 'the SOURCE artwork the CLI mascot is generated from — tools/gen-cli-mascot.mjs reads it; the package ships only the rendered text',
  releases: 'per-version release evidence — tools/release-evidence.mjs writes the signed transcript and test report here',
  '.github': 'CI workflow and the generated status panels',
};

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
  'DONOTREADME.md': 'the owner\'s joke, kept deliberately — 42 blank lines and a punchline',
  'diarium.md': 'the diary, a generated view of the sealed store in diarium/',
  'package.json': 'the workspace root',
};

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const all = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);
const tracked = all.filter((p) => !p.includes('/'));
// A DIRECTORY at the root hides everything under it from a file-only enumeration. MEASURED 2026-07-31: `.ex-tmp/`
// — scratch this repository's own gates create while they run — was committed and PUSHED to the public repo, and
// this gate passed, because `.ex-tmp/probe.ts` is not a top-level FILE. The domain was one level deep and the
// defect was one level down. Same lesson as everywhere else: enumerate the level you actually mean.
const DIRS = new Set(all.filter((p) => p.includes('/')).map((p) => p.split('/')[0]));

check(tracked.length >= 10, `only ${tracked.length} top-level files listed — the probe has gone blind and this gate would pass vacuously`);

check(DIRS.size >= 5, `only ${DIRS.size} top-level directories listed — the directory probe has gone blind`);
for (const d of DIRS) check(d in DECLARED_DIRS,
  `\`${d}/\` is tracked at the repository root and is not declared. A directory nobody wrote a reason for is how scratch reaches a PUBLIC repo: it hides its contents from a file-level check and rides in on \`git add -A\`.`);
for (const d of Object.keys(DECLARED_DIRS)) check(DIRS.has(d), `\`${d}/\` is declared and no longer tracked — remove the declaration`);
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
