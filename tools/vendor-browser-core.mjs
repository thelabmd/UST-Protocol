// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the vendored bytes are COMPARED against the package's own mapped build, file by file; nothing here is typed twice, and a divergence in either direction is named
// VENDORED BROWSER CORE — what the verifier page serves IS what npm publishes, and that is checkable.
//
// The page at the custom domain is the reference verifier, not a demonstration beside the packages. That claim
// only means something if the code a visitor runs is the code a consumer installs — otherwise "resolve the
// verifier by name" is advice the page gives and does not keep.
//
// A static page cannot import from npm, and importing from a CDN would hand the verifier to a third party — the
// one thing this page tells its reader never to accept. So the browser build is VENDORED into `docs/lib/`, and
// the equality is held here rather than promised in a README: this tool performs the bundler's own substitution
// (the package's `browser` map) and compares the result to what is committed, file by file.
//
//   --write   perform the mapping and write it into docs/lib/
//   (no arg)  compare only; a difference in EITHER direction is a failure
//
// The CI step runs both around a `git diff --exit-code`, which is this repository's idiom for "regenerate ==
// committed": the artifact cannot drift from its source without someone seeing the diff.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const PKG_DIR = join(ROOT, 'packages/ust-protocol');
const OUT_DIR = join(ROOT, 'docs/lib/ust-protocol');
const WRITE = process.argv.includes('--write');

const pkg = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8'));
const BROWSER_MAP = pkg.browser ?? {};

// The graph is WALKED, not listed — the same walk the portability gate performs, for the same reason: a list
// goes stale the day a module is added, and a vendored build missing one file fails at the first call in a page
// rather than here.
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\s[\s\S]*?from\s+'([^']+)'|(?:^|\n)\s*import\s+'([^']+)'|\bimport\(\s*'([^']+)'/g;
const seen = new Set();
const graph = [];
const foreign = [];
(function walk(rel) {
  const mapped = BROWSER_MAP['./' + rel] ? BROWSER_MAP['./' + rel].replace(/^\.\//, '') : rel;
  if (seen.has(mapped)) return;
  seen.add(mapped);
  graph.push(mapped);
  for (const m of readFileSync(join(PKG_DIR, mapped), 'utf8').matchAll(IMPORT_RE)) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (!spec) continue;
    if (spec.startsWith('.')) walk(spec.replace(/^\.\//, ''));
    else foreign.push(`${mapped} → ${spec}`);
  }
})('index.mjs');

let fail = 0;
const ok = (name, cond, detail = '') => { console.log(`  ${cond ? '✓' : '✗'} ${name}${cond || !detail ? '' : ' — ' + detail}`); if (!cond) fail++; };

ok(`the browser graph is walked from source (${graph.length} module(s): ${graph.join(', ')})`, graph.length >= 3,
  'the walk found almost nothing — every comparison below would be over an empty set');
ok('the vendored build reaches nothing outside the package', foreign.length === 0,
  `${foreign.join('; ')} — a page cannot resolve a bare specifier, and a CDN would be a third party holding the verifier`);

// The substitution the bundler performs: the mapped file takes the ORIGINAL's name, so `import './_crypto.mjs'`
// resolves to the browser implementation without a single source edit.
const wanted = new Map();
// A mapping TARGET is not served under its own name: nothing in the vendored tree imports `_crypto.browser.mjs`,
// it is imported as `_crypto.mjs`. Serving both would publish a second copy of the crypto module that no code
// path reaches — dead weight on the one surface where every served byte is part of the claim.
const TARGETS = new Set(Object.values(BROWSER_MAP).map((v) => v.replace(/^\.\//, '')));
for (const f of graph) if (!TARGETS.has(f)) wanted.set(f, readFileSync(join(PKG_DIR, f)));
for (const [from, to] of Object.entries(BROWSER_MAP)) {
  wanted.set(from.replace(/^\.\//, ''), readFileSync(join(PKG_DIR, to.replace(/^\.\//, ''))));
}

if (WRITE) {
  if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true });
  mkdirSync(OUT_DIR, { recursive: true });
  for (const [name, bytes] of wanted) writeFileSync(join(OUT_DIR, name), bytes);
  console.log(`\n  ✓ vendored ${wanted.size} file(s) into docs/lib/ust-protocol/ from the package's own browser map`);
  process.exit(0);
}

ok('the vendored build exists', existsSync(OUT_DIR), 'run `node tools/vendor-browser-core.mjs --write`');
if (existsSync(OUT_DIR)) {
  const present = readdirSync(OUT_DIR);
  for (const [name, bytes] of wanted) {
    const p = join(OUT_DIR, name);
    ok(`docs/lib/ust-protocol/${name} is byte-identical to the package's browser build`,
      existsSync(p) && Buffer.compare(readFileSync(p), bytes) === 0,
      existsSync(p) ? 'the served bytes differ from what npm publishes' : 'missing from the vendored build');
  }
  // …and the other direction. A file the mapping no longer produces would keep being SERVED, which is how a
  // retired module goes on answering requests long after the package stopped shipping it.
  const extra = present.filter((f) => !wanted.has(f));
  ok('nothing is served that the package no longer ships', extra.length === 0,
    `${extra.join(', ')} — vendored but no longer part of the browser build`);
}

// ─── CONTROLS — a comparison that cannot go red is a decoration ───────────────────────────────────────────────
// The byte comparison is the whole gate, so it is the thing that has to be shown discriminating. One flipped byte
// in a 400 KB module is the realistic drift here — a bundler substitution gone stale, a hand edit to the served
// copy — and it must not survive.
{
  const original = wanted.get('index.mjs') ?? Buffer.from('x');
  const mutated = Buffer.from(original);
  mutated[Math.floor(mutated.length / 2)] ^= 0x01;
  ok('CONTROL: one flipped byte is REJECTED by the comparison', Buffer.compare(mutated, original) !== 0,
    'the comparator answers equal for bytes that differ, so every leg above passes over anything');
  ok('CONTROL: identical bytes are accepted', Buffer.compare(Buffer.from(original), original) === 0,
    'the comparator answers unequal for identical bytes, so the gate would be red forever and tell nobody why');
  ok('CONTROL: a file the package no longer ships is DETECTED as extra',
    ['index.mjs', 'a-module-the-package-does-not-have.mjs'].filter((f) => !wanted.has(f)).length === 1,
    'the reverse leg accepts anything, so a retired module could go on being served');
}

// ─── the HOST must be able to SERVE what we vendored ──────────────────────────────────────────────────────────
// GitHub Pages runs Jekyll by default, and Jekyll silently DROPS paths beginning with `_`. Four of the six files
// here are `_crypto.mjs`, `_bytes.mjs`, `_clock.mjs`, `_sigmemo.mjs` — so the moment they were vendored, the live
// verifier began serving `index.mjs` with a 200 and every one of its imports with a 404. The module graph never
// resolved, no listener ever attached, and the page's buttons did nothing at all. Measured on the live host
// 2026-08-16, and invisible from here: every check above compares the repo to the package, and both were right.
//
// `.nojekyll` is the one byte that turns the publisher off. The check is conditional on the CAUSE rather than
// pinned to the file, so a tree that stops vendoring underscore names stops needing it and says so.
const underscored = [...wanted.keys()].filter((n) => n.startsWith('_'));
if (underscored.length) {
  ok(`the host is told not to run Jekyll — ${underscored.length} vendored file(s) begin with '_' and Jekyll drops those`,
    existsSync(join(ROOT, 'docs/.nojekyll')),
    `docs/.nojekyll is missing, so ${underscored.join(', ')} will 404 on GitHub Pages while index.mjs returns 200 — the graph fails at the first import and the page silently does nothing`);
} else {
  ok('no vendored file begins with \'_\', so Jekyll has nothing to drop here', true);
}

console.log(fail ? `\n✗ vendored browser core: ${fail} failure(s)` : `\n✓ vendored browser core: ${wanted.size} file(s) served, each byte-identical to what the package publishes`);
process.exit(fail ? 1 : 0);
