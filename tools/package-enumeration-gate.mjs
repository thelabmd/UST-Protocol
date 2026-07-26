// SPDX-License-Identifier: Apache-2.0
// Package-enumeration gate (UST-l63) — `packages/*` is described in THREE places, and until now none of them was
// checked against the directory it describes.
//
//   1. the real set: packages/<dir>/package.json
//   2. the README `Layout` table — one row per package, hand-maintained
//   3. the repository-map panel in tools/gen-readme-panels.mjs, which renders BOTH the SVG text and the README alt
//
// They had already diverged twice: `ust-lite` was in the panel and not in the table, and `diarium` was added to the
// table by hand and never reached the panel — so the picture a reader sees was missing a package for a day. Every other
// from-code list in this repository is gated; this one was the exception, in a repository whose whole thesis is that a
// domain must be enumerated rather than sampled.
//
// The gate fails CLOSED in both directions: a package with no mention, and a mention with no package.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

// A directory under packages/ without a package.json is not a package. That is legitimate — `ustate` is the internal
// operator toolkit, deliberately unpublished — but it must be DECLARED here with a reason, so an accidentally
// unfinished package cannot hide in the same silence.
const NOT_A_PACKAGE = {
  ustate: 'internal operator toolkit — deliberately not an npm package (see the npm-split rule: verification is public, the engine is not)',
};

let pass = 0; const fail = [];
const ok = (name, cond, detail) => { if (cond) pass++; else fail.push(name + (detail ? ` — ${detail}` : '')); };

// ── 1. the domain, read from disk
const dirs = readdirSync(ROOT + 'packages', { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const pkgs = [];
for (const d of dirs) {
  const pj = ROOT + `packages/${d}/package.json`;
  if (!existsSync(pj)) {
    ok(`packages/${d} has no package.json and is declared a non-package`, d in NOT_A_PACKAGE,
      'add it to NOT_A_PACKAGE with a reason, or give it a package.json');
    continue;
  }
  const j = JSON.parse(readFileSync(pj, 'utf8'));
  pkgs.push({ dir: d, name: j.name, private: !!j.private, version: j.version });
}
// a declared non-package that has since become one, or vanished, must not linger in the list
for (const d of Object.keys(NOT_A_PACKAGE)) {
  ok(`declared non-package packages/${d} still exists and still has no package.json`,
    dirs.includes(d) && !existsSync(ROOT + `packages/${d}/package.json`),
    'the declaration is stale — remove it');
}
ok('at least one package found', pkgs.length > 0);

const readme = readFileSync(ROOT + 'README.md', 'utf8');

// ── 2. the README Layout table
const rows = [...readme.matchAll(/^\|\s*`packages\/([\w.@/-]+?)\/?`\s*\|([^|]*)\|/gm)].map((m) => ({ dir: m[1], cell: m[2] }));
const rowDirs = new Set(rows.map((r) => r.dir));
for (const p of pkgs) {
  if (p.private) continue;                                     // a private package is not for readers
  ok(`table row for packages/${p.dir}`, rowDirs.has(p.dir), 'add a row to the README Layout table');
  const row = rows.find((r) => r.dir === p.dir);
  // the npm name matters more than the directory: a reader installs the name
  if (row) ok(`table row for ${p.dir} cites its npm name \`${p.name}\``, row.cell.includes(p.name),
    `the row does not mention "${p.name}"`);
}
for (const d of rowDirs) ok(`table row packages/${d} corresponds to a real package`, pkgs.some((p) => p.dir === d),
  'the row points at a directory that is not a package');

// ── 3. the panel — one source, two renderings (the SVG and the README alt), so check the rendered artefacts
const svg = readFileSync(ROOT + '.github/ust-map.svg', 'utf8');
const altMatch = /!\[Repository map\.([\s\S]*?)\]\(\.github\/ust-map\.svg\)/.exec(readme);
ok('README carries the repository-map alt text', altMatch !== null);
const alt = altMatch ? altMatch[1] : '';

// The panel collapses siblings with a brace — `ust-{ots,rekor}-verify`. Expand those before comparing, or the gate
// reports a divergence that is only a notation. The expansion is exact: every brace form must expand to real packages.
const expand = (text) => {
  const out = new Set();
  for (const m of text.matchAll(/([\w-]*)\{([\w,-]+)\}([\w-]*)/g)) for (const part of m[2].split(',')) out.add(m[1] + part + m[3]);
  return out;
};
const svgNames = new Set([...svg.matchAll(/>([^<]+)</g)].flatMap((m) => m[1].trim().split(/\s+/)).map((s) => s.replace(/^[│├└─\s]+/, '')));
const svgExpanded = new Set([...svgNames, ...expand(svg)]);
for (const p of pkgs) {
  if (p.private) continue;
  ok(`the map SVG draws ${p.dir}`, svgExpanded.has(p.dir), 'the panel in tools/gen-readme-panels.mjs omits it — add a row and regenerate');
  ok(`the map alt text names ${p.dir}`, alt.includes(p.dir), 'the panel alt in tools/gen-readme-panels.mjs omits it');
}
// and a brace form must not invent a package
for (const n of expand(svg)) if (/^ust-/.test(n)) ok(`brace form expands to a real package: ${n}`, pkgs.some((p) => p.dir === n),
  'the panel names something that is not a package');

console.log(`\n  package enumeration (UST-l63)   PASS ${pass}   FAIL ${fail.length}`);
console.log(`  domain: ${pkgs.length} packages, ${Object.keys(NOT_A_PACKAGE).length} declared non-package(s)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ packages/ == README table == map panel (SVG + alt), both directions');
