// SPDX-License-Identifier: Apache-2.0
// Package CONTENTS gate — what `files` ships must be able to RUN, not merely to match.
//
// MEASURED 2026-07-29, and it was live in the registry: `ust-protocol@1.0.0-rc.38` and `rc.39` — the published
// `latest` — could not be imported AT ALL. `index.mjs` imports `./_clock.mjs` and re-exports `./reference-checker.mjs`,
// and neither was listed in `files`, so `npm i ust-protocol` gave a package that threw ERR_MODULE_NOT_FOUND on the
// first import. Not degraded — unusable. The reference checker, the whole L1 kernel, was absent from every install.
//
// EVERY OTHER GATE PASSED, and the reason is worth keeping: `npm-drift` byte-compares the PACKED files against the
// repo, so a file that is not packed has nothing to compare and is invisible to it; `version-truth` compares the
// EXPORT list, which it reads from the SOURCE, not from the artifact. Between them they checked that what ships is
// unchanged and that it declares the right names — and nothing checked that it loads.
//
// So this gate asks the one question the others cannot: pack each package exactly as `npm publish` would, then
// resolve every relative import inside the tarball. A file the code reaches for and the tarball lacks fails here,
// before it can reach a registry where it becomes immutable.
//
// It deliberately does NOT hit the network. A gate that installs from the registry tests yesterday's artifact and
// needs the registry to be up; this one tests the bytes about to be published, offline and deterministically.
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const workspaces = JSON.parse(readFileSync(ROOT + 'package.json', 'utf8')).workspaces;
const fail = []; let checked = 0, entries = 0;

// every `from './x'` and `import('./x')` — the two forms that make a file part of the running package
const RELATIVE = /(?:from|import)\s*\(?\s*['"](\.[^'"]*)['"]/g;

for (const ws of workspaces) {
  const pkg = JSON.parse(readFileSync(join(ROOT, ws, 'package.json'), 'utf8'));
  const tmp = mkdtempSync(join(tmpdir(), 'ust-contents-'));
  try {
    execFileSync('npm', ['pack', '--pack-destination', tmp], { cwd: join(ROOT, ws), stdio: ['ignore', 'pipe', 'pipe'] });
    const tgz = readdirSync(tmp).find((f) => f.endsWith('.tgz'));
    if (!tgz) { fail.push(`${pkg.name}: npm pack produced no tarball`); continue; }
    execFileSync('tar', ['xzf', tgz], { cwd: tmp });
    const dir = join(tmp, 'package');
    checked++;
    // walk from every packed .mjs, following relative imports transitively: a file can be packed and still reach
    // for one that is not, one hop further in.
    const seen = new Set();
    const walk = (rel) => {
      if (seen.has(rel)) return;
      seen.add(rel);
      const abs = join(dir, rel);
      if (!existsSync(abs)) {
        fail.push(`${pkg.name}@${pkg.version}: the tarball is MISSING \`${rel}\` — a packed file imports it, so \`npm i ${pkg.name}\` cannot load. Add it to "files".`);
        return;
      }
      entries++;
      if (!rel.endsWith('.mjs')) return;
      const src = readFileSync(abs, 'utf8');
      for (const m of src.matchAll(RELATIVE)) {
        const target = resolve('/' + dirname(rel), m[1]).slice(1) || m[1].replace(/^\.\//, '');
        walk(target);
      }
    };
    // RECURSIVE: a package may ship its code in a subdirectory (diarium packs `bin/`), and a top-level-only
    // listing found nothing there — the gate's own vacuity check caught that before it could pass silently.
    const listMjs = (d, base = '') => readdirSync(join(dir, d), { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? listMjs(join(d, e.name), base ? base + '/' + e.name : e.name)
                      : (e.name.endsWith('.mjs') ? [(base ? base + '/' : '') + e.name] : []));
    const packed = listMjs('.');
    if (!packed.length) fail.push(`${pkg.name}: no .mjs anywhere in the tarball — the probe would be vacuous`);
    for (const f of packed) walk(f);
  } catch (e) {
    fail.push(`${pkg.name}: could not pack or unpack — ${String(e.message).split('\n')[0]}`);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

// the probe must be able to fail: a package that packs nothing, or a run that reached no file, proves nothing
if (checked === 0) fail.push('no package was packed — the gate would pass vacuously');
if (entries === 0) fail.push('no packed file was resolved — the import walk never ran');

console.log(`\n  package contents   ${checked} package(s) packed · ${entries} file(s) resolved inside their tarballs`);
if (fail.length) { fail.forEach((f) => console.error('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every relative import of every packed file resolves INSIDE the tarball — what ships can load');
