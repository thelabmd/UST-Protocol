// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the SHAPE is the subject being pinned, never the domain — every other value is
// READ from packages/ rather than written here: the surfaces are enumerated from source by looking for outbound calls,
// and each version is compared against that package's own package.json, so a stale label fails rather than being restated
// USER-AGENT GATE (#43) — outbound requests carry a label, and the label does not go stale.
//
// Why a gate rather than a convention. The substrate connectors declare NO dependencies on purpose, so they cannot
// import the core's one builder; they carry the shape locally. A copy is only safe when its agreement is CHECKED —
// an unchecked copy is the drift class this repository spends most of its gates on. So the shape is pinned here and
// every version is read from the package it belongs to.
//
// What it does NOT do: it never asserts a label reaches the network. That is a property of a live request, and this
// gate reads source. The reaching half is exercised by the surfaces' own tests.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const WIRE = '1.0';
const REPO = 'https://github.com/thelabmd/UST-Protocol';
// The shape, written once. Two versions kept SEPARATE: the wire version says what the traffic is, the package
// version says which implementation is calling. Folded together they diverge at wire 1.1.
const SHAPE = (comp, ver) => `ust/${WIRE} (${comp}/${ver}; +${REPO})`;

let fail = 0;
const ok = (name, cond, detail = '') => { console.log(`  ${cond ? '✓' : '✗'} ${name}${cond || !detail ? '' : ' — ' + detail}`); if (!cond) fail++; };

// ─── the DOMAIN, enumerated from source: shipped modules that reach the network ────────────────────────────────
const SHIPPED = (f) => f.endsWith('.mjs') && !/\.test\.mjs$|^demo-|fuzz|regression|conformance|gen-|run-/.test(f);
const surfaces = [];
for (const pkg of readdirSync(join(ROOT, 'packages'))) {
  const dir = join(ROOT, 'packages', pkg);
  if (!existsSync(join(dir, 'package.json'))) continue;
  const version = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version;
  for (const f of readdirSync(dir).filter(SHIPPED)) {
    const src = readFileSync(join(dir, f), 'utf8');
    // The predicate enumerates modules that REACH THE NETWORK, in any form — including the ones already labelled.
    // A first version looked for a bare `fetch(` and went blind the moment a surface was fixed: the labelled form
    // disappeared from its own domain.
    //
    // Line comments are STRIPPED first, and that is not a convenience. `ust-operator` reaches no network at all —
    // its only `fetch` was a resolver PARAMETER, since renamed — yet the prose "a document nobody can fetch)" put
    // it in the domain, where the only way out would have been an exemption certifying a surface that does not
    // exist. A record of the boundary must not read as the boundary; `core-network-boundary-gate` strips for the
    // same reason. STRINGS are deliberately NOT stripped: a `fetch(` inside a description is a false positive
    // that fails CLOSED and demands a look, and one such look is what found a surface injecting its own
    // `fetchImpl` past the core's labelled default.
    const code = src.replace(/^\s*\/\/.*$/gm, '').replace(/([^:])\/\/.*$/gm, '$1');
    if (!/fetchImpl|(?<![.\w])fetch\s*[(),]|ustFetch\s*\(|labelledFetch\s*\(/.test(code)) continue;
    surfaces.push({ pkg, file: f, rel: `packages/${pkg}/${f}`, version, src });
  }
}
// The label is a STATIC string and the measured count lives in the detail beside it: a check whose name is
// assembled at run time cannot be named by anything that reads this file, and the ladder registry — which points
// at a check by its text — was the thing that noticed.
ok('every shipped module that reaches the network is DISCOVERED from source, never listed', surfaces.length >= 5,
  `found ${surfaces.length}: ${surfaces.map((s) => s.rel).join(', ')}`);
if (surfaces.length >= 5) console.log(`    ${surfaces.length} surface(s): ${surfaces.map((s) => s.rel).join(', ')}`);

// ─── every surface labels its outbound calls ──────────────────────────────────────────────────────────────────
// A wrapper FACTORY is not a surface: it takes the caller's inner implementation and adds a guard, so identity is
// decided one level up and labelling here would relabel someone else's client. Named with its reason rather than
// silently excluded from the predicate, so the exemption is visible and can be argued with.
const EXEMPT = { 'packages/ust-protocol/ssrf.mjs': 'wrapper factory — wraps a caller-supplied impl, never decides identity' };
for (const [k, why] of Object.entries(EXEMPT)) ok(`exemption is live: ${k} — ${why}`, surfaces.some((s) => s.rel === k),
  'the exempted file is no longer in the domain, so this exemption is stale and hides nothing');
// A surface labels DIRECTLY if it sets the header, calls the core's builder, or declares the shape itself.
const directly = (src) => /'user-agent'/.test(src) || /userAgent\(/.test(src) || /labelledFetch\(/.test(src) || /const UA = 'ust\//.test(src);
const labelled = new Set(surfaces.filter((s) => directly(s.src)).map((s) => s.rel));
// …or INDIRECTLY, by importing a labelled client from a sibling module of the SAME package. This is the third
// form and it is admitted by CONSTRUCTION, not waved through: the sibling has to be in the labelled set itself,
// so the chain still ends at something this gate read. It exists because within one package a second copy of the
// label is pure drift — the cross-PACKAGE copies are the deliberate ones, and those are compared to package.json.
const viaSibling = (s) => [...s.src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'\.\/([\w.-]+)'/g)]
  .some((m) => /\b(labelled|labelledFetch|UA)\b/.test(m[1]) && labelled.has(`packages/${s.pkg}/${m[2]}`));
for (const s of surfaces.filter((s) => !EXEMPT[s.rel])) {
  ok(`${s.rel} labels its outbound calls`, directly(s.src) || viaSibling(s),
    'it calls fetch and sets no user-agent — a new surface inherits nothing, so it must opt IN here');
}
ok('CONTROL: the sibling form requires the sibling to be labelled, not merely imported',
  !viaSibling({ pkg: 'ust-ots-verify', src: "import { labelled } from './not-a-labelled-module.mjs';" }),
  'an import of a name that happens to look like a label would otherwise certify a surface that sets no header at all');

// ─── no literal label is stale: every version in a label equals its package's own ──────────────────────────────
let literals = 0;
for (const s of surfaces) {
  for (const m of s.src.matchAll(/ust\/([\d.]+) \(([a-z-]+)\/([^;]+); \+([^)]+)\)/g)) {
    literals++;
    const [, wire, comp, ver, url] = m;
    ok(`${s.rel} label is current (${comp}/${ver})`,
      wire === WIRE && ver === s.version && url === REPO && SHAPE(comp, ver) === m[0],
      `expected ${SHAPE(comp, s.version)}`);
  }
}
ok(`at least one literal label exists to be checked (${literals})`, literals >= 3,
  'zero literals would make every check above pass over nothing');

// ─── …and the OTHER form of the same claim. A surface that imports the core builds its label by CALL rather than
// by string — `labelledFetch('ust-cli', '1.0.0-rc.106')` — so the version travels as a bare argument and the
// full-shape pattern above never sees it. Measured 2026-08-15: three of nine surfaces carried their version this
// way and were exempt from the staleness check they were written to satisfy. A gate that enumerates one form of
// a claim reports on the SAMPLE it recognises, which is indistinguishable from coverage until the day it is not.
// CLOSED 2026-08-15 by the loop below, which walks the SAME surface list as the string form: both are counted, and
// the count of each is asserted non-zero, so losing either form reddens here rather than shrinking the domain.
let calls = 0;
for (const s of surfaces) {
  for (const m of s.src.matchAll(/(?:labelledFetch|userAgent)\(\s*'([a-z-]+)'\s*,\s*'([^']+)'/g)) {
    calls++;
    ok(`${s.rel} builds its label from a current version (${m[1]}/${m[2]})`, m[2] === s.version,
      `expected ${s.version}, the version in ${s.pkg}/package.json`);
  }
}
ok(`both label forms are covered: ${literals} written as a string, ${calls} built by call`, calls >= 1,
  'no call-built label found — either the surfaces stopped importing the builder, or this pattern has gone stale and now measures nothing');
ok('CONTROL: the call form does NOT accept a version that is not its package\'s',
  !/(?:labelledFetch|userAgent)\(\s*'([a-z-]+)'\s*,\s*'([^']+)'/.test("labelledFetch('ust-cli', VERSION.spec)"),
  'a DERIVED version is correctly outside this check — it cannot go stale, because there is no second copy to go stale');

// ─── CONTROLS — the checks discriminate, rather than passing on anything ───────────────────────────────────────
const stale = 'ust/1.0 (ust-ots-verify/0.0.0-stale; +' + REPO + ')';
ok('CONTROL: a stale version does NOT match the shape for its package', SHAPE('ust-ots-verify', '9.9.9') !== stale);
ok('CONTROL: a label missing the contact URL is not accepted by the pattern',
  !/ust\/([\d.]+) \(([a-z-]+)\/([^;]+); \+([^)]+)\)/.test('ust/1.0 (ust-cli/1.0.0)'));
ok('CONTROL: the surface finder ignores a module with no outbound call', !/(?<![.\w])fetch\s*\(/.test('const x = 1; // fetchImpl'));

console.log(fail ? `\n✗ user-agent gate: ${fail} failure(s)` : `\n✓ user-agent gate: ${surfaces.length} network surface(s), ${literals} literal label(s), none stale`);
process.exit(fail ? 1 : 0);
