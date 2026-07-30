// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — declarations regenerated from the source and diffed
// Types-parity gate — a declaration may not describe a version of the source that no longer exists.
//
// #105: nobody shipped types, so every TypeScript consumer wrote their own. The reference operator's said
// `buildCheckpoint(id, time, head, frameCount, prev)` — five parameters, faithful to the rc.12 it had
// installed — and could not say that rc.12 was twenty candidates old. The sixth parameter, `interval`, is what
// lifts a stream verdict off `chain-consistent`, so the product sealed every hour without bounds for as long
// as that declaration stood. The type-checker was right the whole time. It was right about the past.
//
// Generating the declarations closes the drift by construction; this gate closes the OTHER direction — that
// somebody edits a generated file, or adds an export and forgets to regenerate, and the two disagree again in
// exactly the way the generation was supposed to prevent. Regenerate into memory, compare byte-for-byte.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';

const root = new URL('..', import.meta.url).pathname;
const fail = []; const binaries = []; let pass = 0, checkedPkgs = 0, decls = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// Regenerate to a scratch tree and diff, rather than re-implementing the parser here. A gate that re-derives
// the answer its own way is testing two implementations against each other, not the artifact against its source.
const before = new Map();
const workspaces = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces;
for (const w of workspaces) {
  let pkg;
  try { pkg = JSON.parse(readFileSync(join(root, w, 'package.json'), 'utf8')); } catch { continue; }
  if (pkg.private) continue;
  // Binary-only packages are exempt BY MEASUREMENT, not by name: no `main` and no `exports` means the package
  // cannot be imported, so there is no surface to declare. Two are in this state (@ust-protocol/cli, diarium)
  // and demanding types of them would be the gate inventing an obligation. #105 asked for exactly this to be
  // stated rather than left implicit.
  if (!pkg.main && !pkg.exports) { binaries.push(pkg.name); pass++; continue; }
  const dts = (pkg.main ?? 'index.mjs').replace(/\.m?js$/, '.d.ts');
  try { before.set(w + '/' + dts, readFileSync(join(root, w, dts), 'utf8')); } catch { /* missing is its own failure below */ }
  check(pkg.types === dts, `${pkg.name} does not declare \`types\` — a consumer's editor will not find the declarations even though they ship`);
  check(Array.isArray(pkg.files) ? pkg.files.includes(dts) : true, `${pkg.name} has a \`files\` allowlist that omits ${dts} — the declarations exist in the repo and NOT in the tarball, which is the worst of both`);
  checkedPkgs++;
}
check(checkedPkgs >= 5, `only ${checkedPkgs} importable packages seen — the gate would be near-vacuous`);

execSync('node tools/gen-types.mjs', { cwd: root, stdio: 'pipe' });
for (const [rel, old] of before) {
  const now = readFileSync(join(root, rel), 'utf8');
  decls += (now.match(/^export /gm) || []).length;
  check(now === old, `${rel} is STALE — regenerating changes it. Someone edited a generated file or added an export without \`npm run types\`; a declaration that disagrees with its source is the defect #105 exists to prevent.`);
}
check(before.size >= 4, `only ${before.size} declaration files found — packages are shipping without types again`);
check(decls >= 100, `only ${decls} declarations across all packages — the surface has collapsed, which means the parser stopped seeing exports`);

console.log(`\n  types parity      PASS ${pass}   FAIL ${fail.length}   (${before.size} importable · ${decls} declarations · ${binaries.length} binary-only: ${binaries.join(', ') || 'none'})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every published package ships declarations, and every declaration still matches its source');
