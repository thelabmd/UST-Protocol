// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — renders SUPPORT.md from the same declarations the parity gate verifies against reality
//
// SUPPORT MATRIX GENERATOR — what each surface actually does, on one page.
//
// WHY IT IS GENERATED AND NOT WRITTEN. A hand-written support table is a promise, and this repository has already
// paid for one: `capability-parity` declared `ust-cli` FULL for `sign` and `build-transcript` on the strength of
// two words appearing inside ceremony internals, and no command signed a document at all (#177, round 246). The
// page below is rendered from the SAME `CAPS`/`SURFACES` declarations that gate verifies against live probes on
// every run — so a cell here is true because the gate would go red if it were not, never because someone typed it.
//
// WHAT THAT DOES AND DOES NOT BUY. It buys correspondence: the table cannot drift from the declarations. It does
// NOT buy correctness of the declarations themselves — that is the parity gate's job, and it is the reason this
// file imports nothing of its own. Two artifacts, one source, and the gate between them.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const src = readFileSync(ROOT + 'tools/capability-parity.mjs', 'utf8');

// The declarations are READ FROM THE GATE'S SOURCE rather than re-listed here. Importing it would run the gate
// (it verifies and exits), so the shapes are parsed out — and the parse is checked below, because a regex that
// silently matched nothing would render an empty table that looked like an answer.
const capIds = [...src.matchAll(/^ {2}'([a-z0-9-]+)':\s*\{ core:/gm)].map((m) => m[1]);
const surfaces = [...src.matchAll(/^ {2}'(ust-[a-z0-9-]+)':\s*\{ probe: [^,]+, full: (\[[^\]]*\]|Object\.keys\(CAPS\)), subset: \[([^\]]*)\]/gm)]
  .map((m) => ({ id: m[1], full: m[2] === 'Object.keys(CAPS)' ? 'ALL' : list(m[2]), subset: list(m[3]) }));

// THE COUNT IS CROSS-CHECKED, because under-parsing is silent and looks like an answer. Measured 2026-09-03, CLOSED 2026-09-03 by the check below
// (#178): the pattern above required `full: [ … ]`, so the core's `Object.keys(CAPS)` did not match and the page
// rendered SIX columns while the gate scored EIGHT — the page disagreeing with the file it is rendered from,
// which is the one thing it exists not to do. A cheap independent count catches that; a minimum threshold did not.
// #180 — the PROBE and the surface's own reason, parsed for the same purpose everything else here is: a surface
// whose every cell is `·` renders a row of dots, and the gate has held the sentence that says what it does since
// it was written. `ust-rfc6962-verify` is the specimen — a published RFC 6962 inclusion verifier whose declaration
// reads "it carries the `substrate-registry` membership half through `inclusionVerify`" while the page said nothing
// at all. A report that omits the reason asserts a falsehood by silence.
const ADMISSION = { exportIntersect: 'import', mcpProbe: 'named request', cliProbe: 'named request', connector: 'connector object' };
// ONE LINE PER SURFACE, then the two fields off that line. The first draft put both in a single pattern with the
// reason optional behind a LAZY quantifier — which matches the shortest thing that works, so it skipped every
// reason and reported the one surface that has one as having none. A lazy optional capture is a capture that
// never fires.
for (const line of src.split('\n')) {
  const head = /^ {2}'(ust-[a-z0-9-]+)':\s*\{ probe: ([A-Za-z]+)/.exec(line);
  if (!head) continue;
  const sf = surfaces.find((x) => x.id === head[1]);
  if (!sf) continue;
  sf.probe = head[2];
  const why = /naReason: '((?:[^'\\]|\\.)*)'/.exec(line);
  sf.naReason = why ? why[1].replace(/\\'/g, "'") : '';
}
const declared = [...src.matchAll(/^ {2}'(ust-[a-z0-9-]+)':\s*\{ probe:/gm)].map((m) => m[1]);
if (declared.length !== surfaces.length) {
  console.error(`  ✗ parsed ${surfaces.length} surface(s) but ${declared.length} are declared — missing [${declared.filter((d) => !surfaces.some((s2) => s2.id === d)).join(', ')}]. A page with fewer columns than the gate scores is a page disagreeing with its own source.`);
  process.exit(1);
}
function list(s) { return [...s.matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]); }        // capability IDs — kebab-case
// Function names are camelCase, and `list` is lowercase-only: reusing it here returned ["blinded","mmit",…]
// and rendered an EMPTY cell for the core, which is the row this table exists for. One parser, two shapes.
const idents = (s) => [...s.matchAll(/'([A-Za-z][A-Za-z0-9_]*)'/g)].map((m) => m[1]);


// #180 — CAPABILITY STATE, read from the same file for the same reason as everything else here: a count typed
// into prose is a promise, and this page exists because a promise had already gone stale once. Delivery is
// COMPUTED from the surfaces below, exactly as the gate computes it, so the two cannot disagree about a fact
// either could derive; custody and the note are declared and are read verbatim.
const stateRe = /^ {2}'([a-z0-9-]+)':\s*\['(open|key|operator|manual|sealed)'(?:,\s*(?:'((?:[^'\\]|\\.)*)'|UNBUILT))?(?:,\s*'((?:[^'\\]|\\.)*)')?\],$/gm;
const STATE = {};
for (const m of src.matchAll(stateRe)) {
  const note = m[3] !== undefined ? m[3] : (/,\s*UNBUILT/.test(m[0]) ? 'unbuilt' : '');
  STATE[m[1]] = { custody: m[2], note: note.replace(/\\'/g, "'"), via: (m[4] || '').startsWith('via ') ? (m[4] || '').slice(4).trim() : null };
}
// THE PARSE IS CROSS-CHECKED against the capability roster, because an under-parse renders an empty answer that
// reads like an answer — the defect this file already paid for once, when six surface columns rendered where the
// gate scored eight.
const unstated = capIds.filter((c) => !STATE[c]);
if (unstated.length) {
  console.error(`  ✗ parsed no state for ${unstated.length} of ${capIds.length} capabilities — the declaration shape moved: [${unstated.join(', ')}]`);
  process.exit(1);
}
const CAPS_CORE = Object.fromEntries([...src.matchAll(/^ {2}'([a-z0-9-]+)':\s*\{ core: \[([^\]]*)\]/gm)].map((m) => [m[1], idents(m[2])]));
const VERSION = JSON.parse(readFileSync(ROOT + 'package.json', 'utf8')).version;
const stance = (s, cap) => (s.full === 'ALL' || s.full.includes(cap)) ? '✅' : s.subset.includes(cap) ? '◐' : '·';
const short = (s) => s.replace('ust-', '');

// The privacy story the card was about, called out by name — a reader looking for "can I make a private
// DEAD WEIGHT, removed in round 278 and named rather than quietly deleted: `tokensFor` rendered the private-partition
// section (gone in 276), `holders` named which surface held a lagging capability (gone in 277 with the Ordering
// section), `cliHas` and `rows` predate both. Each was live when written and became unreachable when the section it
// served was removed — the generator's own instance of a record outliving its subject, which is the defect this page
// has now found in three registers and in itself.

const CUSTODY = [...(/^const CUSTODY = \[([^\]]*)\];/m.exec(src) || [, ''])[1].matchAll(/'([a-z-]+)'/g)].map((m) => m[1]);
if (CUSTODY.length < 3) { console.error('  ✗ parsed no custody vocabulary from the gate — the legend would name words nobody defined'); process.exit(1); }
const CUSTODY_MEANS = {
  open: 'safely delegable to any caller, an agent included',
  key: 'needs key material; delegable through the producer/assembler split',
  operator: 'a deployment position — what is offered, to whom, at what tier',
  manual: 'under manual control today; a state, revisable',
  sealed: 'exposing it IS the vulnerability; permanent by construction',
};
const missingMeaning = CUSTODY.filter((w) => !CUSTODY_MEANS[w]);
if (missingMeaning.length) { console.error(`  ✗ the gate defines custody [${missingMeaning.join(', ')}] and this page has no wording for them`); process.exit(1); }

const unnamed = surfaces.filter((sf) => !ADMISSION[sf.probe]);
if (unnamed.length) { console.error(`  ✗ ${unnamed.length} surface(s) use a probe this page cannot name: [${unnamed.map((sf) => sf.id + ':' + sf.probe).join(', ')}]`); process.exit(1); }
const silent = surfaces.filter((sf) => capIds.every((c) => stance(sf, c) === '·') && !sf.naReason);
if (silent.length) { console.error(`  ✗ ${silent.length} surface(s) carry no capability and no reason: [${silent.map((sf) => sf.id).join(', ')}] — a column of dots with nothing beside it says the package does nothing`); process.exit(1); }

const anySurface = (cap) => surfaces.some((sf) => sf.id !== 'ust-protocol' && (sf.full === 'ALL' || sf.full.includes(cap) || sf.subset.includes(cap)));
const delivery = (cap) => STATE[cap].via ? `via \`${STATE[cap].via}\`` : (CAPS_CORE[cap].length === 0 ? 'spec-ahead' : (anySurface(cap) ? 'shipped' : 'core-only'));
const owesNote = (cap) => delivery(cap) !== 'shipped' || ['operator', 'manual', 'sealed'].includes(STATE[cap].custody);
const asymmetry = capIds.filter((c) => anySurface(c) && !surfaces.some((sf) => sf.id === 'ust-mcp' && (sf.full === 'ALL' || sf.full.includes(c) || sf.subset.includes(c))));
const count = (d) => capIds.filter((c) => delivery(c).startsWith(d)).length;

const page = `# UST capability report

<!-- GENERATED by tools/gen-support-matrix.mjs from the declarations in tools/capability-parity.mjs — do not edit.
     Those declarations are checked against live probes by \`npm run test:parity\` on every CI run, so a cell here
     is true because the gate would go red otherwise. Regenerate: node tools/gen-support-matrix.mjs -->

Reference implementation \`${VERSION}\` · ${capIds.length} capabilities · ${count('shipped')} shipped, ${count('core-only')} core-only, ${count('via')} via another capability, ${count('spec-ahead')} spec-ahead · ${asymmetry.length} on another surface and not on \`mcp\`${asymmetry.length ? ' (' + asymmetry.map((c) => '`' + c + '`').join(', ') + ')' : ''}.

**Surface** ✅ every core export exposed · ◐ a documented reduced form · · not on this surface.
**Delivery** \`shipped\` on at least one surface · \`via X\` reachable through another capability · \`core-only\` in core, no surface · \`spec-ahead\` in the spec, not in core.
**Custody** ${CUSTODY.map((w) => '`' + w + '` ' + CUSTODY_MEANS[w]).join(' · ')}.

| capability | delivery | custody | ${surfaces.map((s) => short(s.id)).join(' | ')} |
|---|---|---|${surfaces.map(() => '---').join('|')}|
${capIds.map((c) => `| \`${c}\` | ${delivery(c)} | \`${STATE[c].custody}\` | ` + surfaces.map((s) => stance(s, c)).join(' | ') + ' |').join('\n')}

## Surfaces

A surface's ADMISSION RELATION is how a caller reaches it, and it fixes what counts as evidence that the surface
exposes a capability: an \`import\` surface is scored on its exports, a \`named request\` surface on the commands
and tools it answers, a \`connector object\` on the interface it satisfies.

| surface | admission | capabilities | what it is |
|---|---|---|---|
${surfaces.map((sf) => `| \`${short(sf.id)}\` | ${ADMISSION[sf.probe] ?? sf.probe} | ${capIds.filter((c) => stance(sf, c) !== '·').length} | ${(sf.naReason || '—').replace(/\|/g, '\\|')} |`).join('\n')}

## What would change it

Every capability that is not plain \`shipped\` + \`open\` states the condition that moves it. \`unbuilt\` means nothing
but the work itself stands in the way — the one value that carries no prose, so it cannot be rationalised.

| capability | condition |
|---|---|
${capIds.filter(owesNote).map((c) => `| \`${c}\` | ${STATE[c].note === 'unbuilt' ? '`unbuilt`' : STATE[c].note} |`).join('\n')}
`;
const path = ROOT + 'SUPPORT.md';
const before = (() => { try { return readFileSync(path, 'utf8'); } catch { return null; } })();
writeFileSync(path, page);
console.log(`\n  support matrix   ${capIds.length} capabilities × ${surfaces.length} surfaces → SUPPORT.md${before === page ? '  [already in sync]' : ''}`);
console.log('  ✓ rendered from the declarations the parity gate verifies — not from a hand-kept list');
