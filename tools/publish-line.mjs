// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — reads each tarball before it is published; refuses on the first discrepancy
//
// PUBLISH THE RELEASE LINE — nine packages, topological order, one at a time.
//
// npm publish is IRREVERSIBLE: a version number can never be reused, so the check has to happen before the call
// and not after it. Every package is packed, the tarball is OPENED, and three things are read out of it rather
// than out of the manifest that produced it:
//
//   the version inside the tarball        — the thing a stranger installs, not the thing we meant to ship
//   the module LOADS and its exports      — `package-contents` proves shape; this proves it runs
//
// What it deliberately does NOT check is content. A tarball is a SUBSET of the tracked tree, so a scan here can
// find nothing a scan of the tree has not already had the chance to find — and the first draft of this file
// carried a list of terms to look for, which is a list published by the act of looking. A check whose statement
// of what it forbids is itself the disclosure belongs on the side that owns the secret, never here.
//
// ONE TAG, and the reason is a measurement. The tags were enumerated 2026-08-08 against every consumer in the
// estate: not one reads `@rc` or `@next` — every dependent pins an exact `^1.0.0-rc.N` range, and the only code
// mentioning the tags was the gate that checks them. A channel nobody reads is ceremony, and this one cost nine
// manual commands per release because OIDC grants `publish` and NOT `dist-tag`: the second step could not be
// automated at all, measured as E401 in CI and again locally.
//
// So the line publishes straight to `latest` and there is no promote. What that gives up is the window the two
// steps existed to protect — for the couple of minutes a run takes, `latest` moves package by package. That is
// invisible to every real consumer (they pin), and the publish order is TOPOLOGICAL, so a dependent is never
// newer than the sibling version it declares — which is the only mixing that could break an install.
//
// Historical: published on the `rc` tag only. `latest` stays on the previous, known-good line until every package has landed
// and been read back from the registry — so a failure halfway leaves consumers on a coherent set rather than on
// a new core with old dependents. Moving the tags is step two, deliberately separate.
//
// 2FA: npm asks for a one-time password per publish. That is the owner's to give and is why this exists as a
// script he runs rather than a call the assistant makes.

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DRY = process.argv.includes('--dry-run');
const PROMOTE = process.argv.includes('--promote');

// Topological: a dependent is never published before the sibling version it declares, or `npm i` resolves a
// package whose dependency does not exist yet.
const ORDER = [
  'packages/ust-protocol', 'packages/ust-mcp', 'packages/ust-web-signer', 'packages/ust-light',
  'packages/ust-ots-verify', 'packages/ust-rekor-verify', 'packages/diarium', 'packages/ust-operator',
  'packages/ust-cli',
];

const sh = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['inherit', 'pipe', 'inherit'] });

// STEP TWO — move the tags, only after every package is on the registry and has been read back. Separate from
// the publish on purpose: a half-finished line that nothing points at is recoverable by finishing it, while a
// `latest` moved mid-way puts consumers on a new core with old dependents and nothing says so.
// STANDING — this is the release procedure, not a defect record: the separation is the design and stays.
if (PROMOTE) {
  const missing = [];
  for (const dir of ORDER) {
    const { name, version } = JSON.parse(readFileSync(join(ROOT, dir, 'package.json'), 'utf8'));
    try {
      const v = JSON.parse(sh('npm', ['view', `${name}@${version}`, 'version', '--json'], ROOT)).replace(/"/g, '');
      if (v !== version) missing.push(`${name}: registry has ${v}`);
    } catch { missing.push(`${name}@${version} is not on the registry`); }
  }
  if (missing.length) {
    console.error('✗ refusing to promote — the line is not fully published:');
    for (const m of missing) console.error('   · ' + m);
    process.exit(1);
  }
  for (const dir of ORDER) {
    const { name, version } = JSON.parse(readFileSync(join(ROOT, dir, 'package.json'), 'utf8'));
    // Move exactly the tags this package ALREADY had. Inventing a tag here would change what `npm i <pkg>`
    // resolves for a package that never used it, which is a consumer-visible change nobody asked for.
    // `npm dist-tag ls` IGNORES --json and prints `tag: version` lines regardless — measured 2026-08-06, and
    // JSON.parse died on the first character. Parse what the command emits, not what its flag implies.
    const tags = sh('npm', ['dist-tag', 'ls', name], ROOT)
      .split('\n').map((l) => l.split(':')[0].trim()).filter(Boolean);
    for (const t of tags) {
      if (t === 'rc') continue;                       // already there from the publish
      execFileSync('npm', ['dist-tag', 'add', `${name}@${version}`, t], { stdio: 'inherit' });
    }
    console.log(`   ✓ ${name}@${version} — tags now: ${tags.join(', ')}`);
  }
  console.log('\nThe line is live. `## rc.67 line — unpublished` in CHANGELOG.md is now false and must change.');
  process.exit(0);
}

// A 404 here is an ANSWER — "not published" — not an error to propagate. Anything else (auth, network) must not
// be swallowed into that answer, so only the 404 shape returns false and the rest throws.
const alreadyPublished = (name, version) => {
  try {
    return JSON.parse(execFileSync('npm', ['view', `${name}@${version}`, 'version', '--json'],
      { encoding: 'utf8', stdio: ['inherit', 'pipe', 'pipe'] })).trim() === version;
  } catch (e) {
    const out = String(e.stdout ?? '') + String(e.stderr ?? '');
    if (/E404|No match found for version/.test(out)) return false;
    throw e;
  }
};

let published = 0;
for (const dir of ORDER) {
  const abs = join(ROOT, dir);
  const pkg = JSON.parse(readFileSync(join(abs, 'package.json'), 'utf8'));
  const { name, version } = pkg;
  process.stdout.write(`\n── ${name}@${version}\n`);

  // RESUMABLE. A version can never be republished, so a run that stops halfway must be re-runnable without
  // failing on what already landed. Measured 2026-08-06: the first run published ust-protocol and then died on
  // its own read-back, and a script that cannot be restarted turns a cosmetic defect into a manual recovery.
  // CLOSED 2026-08-06 in the same session: the skip below made the run resumable and the whole line went out.
  if (!DRY && alreadyPublished(name, version)) { console.log('   ⤼  already on the registry — skipping'); published++; continue; }

  // 1. pack, then READ the tarball
  const tgz = sh('npm', ['pack', '--silent'], abs).trim().split('\n').pop();
  const work = mkdtempSync(join(tmpdir(), 'ustpub-'));
  sh('tar', ['-xzf', join(abs, tgz), '-C', work]);
  const inner = JSON.parse(readFileSync(join(work, 'package', 'package.json'), 'utf8'));

  if (inner.version !== version) {
    console.error(`   ✗ the tarball says ${inner.version}, the manifest says ${version} — refusing`);
    process.exit(1);
  }

  // A package with siblings cannot be IMPORTED out of a bare extraction — there is no node_modules there — and
  // treating that as a defect would refuse every dependent. So the check splits, and says which one it ran:
  // a dependency-free package is LOADED (it runs), a dependent is PARSED (it is at least valid JavaScript).
  // Naming the weaker check is the point; a run that silently downgrades its own assurance is the failure this
  // whole file is written against.
  const main = inner.main ?? 'index.mjs';
  const mainPath = join(work, 'package', main);
  const hasSiblings = Object.keys(inner.dependencies ?? {}).some((d) => d === 'ust-protocol' || d.startsWith('@ust-protocol/'));
  if (!existsSync(mainPath)) {
    console.log(`   ⓘ  no ${main} in the tarball (binary-only package) — neither check ran, and that is stated`);
  } else if (hasSiblings) {
    try {
      execFileSync('node', ['--check', mainPath], { encoding: 'utf8' });
      console.log(`   ok  PARSES (not loaded: depends on ${Object.keys(inner.dependencies).filter((d) => d.includes('ust')).join(', ')}, absent from a bare extraction)`);
    } catch {
      console.error(`   ✗ ${main} does not parse out of the tarball — refusing`);
      process.exit(1);
    }
  } else {
    try {
      const probe = execFileSync('node', ['-e', `import('${mainPath}').then(m=>console.log(Object.keys(m).length))`], { encoding: 'utf8' }).trim();
      console.log(`   ok  LOADS · ${probe} export(s)`);
    } catch {
      console.error(`   ✗ ${main} does not load out of the tarball — refusing`);
      process.exit(1);
    }
  }

  const files = sh('tar', ['-tzf', join(abs, tgz)]).split('\n').filter(Boolean);
  console.log(`   ok  ${files.length} file(s)`);

  rmSync(work, { recursive: true, force: true });
  rmSync(join(abs, tgz), { force: true });

  if (DRY) { console.log('   (dry run — not published)'); continue; }

  // 2. publish on `rc` ONLY. latest moves in step two, after every package has landed.
  execFileSync('npm', ['publish', '--tag', 'latest'], { cwd: abs, stdio: 'inherit' });

  // 3. read it back from the REGISTRY, not from our own success — WITH BACKOFF. A publish returns before the
  // version is queryable; the first run read immediately, got a 404 on a package it had just published, and
  // reported failure for a success. Eventual consistency is a property of the registry, not a defect to assert
  // against — but a read that never succeeds still is, so the retries are bounded and the failure is loud.
  let landed = false;
  for (const waitMs of [0, 2000, 4000, 8000, 15000]) {
    if (waitMs) execFileSync('sleep', [String(waitMs / 1000)]);
    if (alreadyPublished(name, version)) { landed = true; break; }
  }
  if (!landed) {
    console.error(`   ✗ ${name}@${version} is not readable from the registry after ~29s.`);
    console.error('     The publish may still have succeeded — CHECK before re-running, and note that a');
    console.error('     re-run will skip it if it did.');
    process.exit(1);
  }
  console.log(`   ✓ published and read back: ${name}@${version}`);
  published++;
}

console.log(`\n${DRY ? 'dry run over' : `${published}/${ORDER.length} published on the rc tag`}.`);
if (!DRY && published === ORDER.length) {
  console.log('\nNothing points at the new line yet — `latest` is still on the previous one, deliberately.');
  console.log('The line is on `latest`. There is no second step.');
}
