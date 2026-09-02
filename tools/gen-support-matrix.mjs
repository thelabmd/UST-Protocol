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
import { execFileSync } from 'node:child_process';

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
const declared = [...src.matchAll(/^ {2}'(ust-[a-z0-9-]+)':\s*\{ probe:/gm)].map((m) => m[1]);
if (declared.length !== surfaces.length) {
  console.error(`  ✗ parsed ${surfaces.length} surface(s) but ${declared.length} are declared — missing [${declared.filter((d) => !surfaces.some((s2) => s2.id === d)).join(', ')}]. A page with fewer columns than the gate scores is a page disagreeing with its own source.`);
  process.exit(1);
}
function list(s) { return [...s.matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]); }        // capability IDs — kebab-case
// Function names are camelCase, and `list` is lowercase-only: reusing it here returned ["blinded","mmit",…]
// and rendered an EMPTY cell for the core, which is the row this table exists for. One parser, two shapes.
const idents = (s) => [...s.matchAll(/'([A-Za-z][A-Za-z0-9_]*)'/g)].map((m) => m[1]);

// cli/mcp tokens per capability — read from the gate, never re-typed
const CAPS_TOKENS = {};
for (const m of src.matchAll(/^ {2}'([a-z0-9-]+)':\s*\{ core: \[[^\]]*\]([^}]*)\}/gm)) {
  const tail = m[2], one = {};
  for (const surf of ['cli', 'mcp']) {
    const arr = new RegExp(surf + ":\\s*\\[([^\\]]*)\\]").exec(tail);
    const single = new RegExp(surf + ":\\s*'([^']+)'").exec(tail);
    if (arr) one[surf] = [...arr[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
    else if (single) one[surf] = [single[1]];
  }
  CAPS_TOKENS[m[1]] = one;
}

// #178 — the agent-surface classification, read from the same file for the same reason as everything else here:
// a count typed into prose is a promise, and this page exists because a promise had already gone stale once.
const disp = [...src.matchAll(/^ {2}'([a-z0-9-]+)':\s*\['(ceremony|key-bound|lagging)'/gm)].map((m) => ({ cap: m[1], kind: m[2] }));
const ceremony = disp.filter((d) => d.kind === 'ceremony');
const keyBound = disp.filter((d) => d.kind === 'key-bound');
const lagging = disp.filter((d) => d.kind === 'lagging');
if (!keyBound.length || !lagging.length) {
  console.error('  ✗ parsed no agent-surface dispositions from the gate — the shape moved, and a page claiming "0 deferred" would read as an answer');
  process.exit(1);
}

if (capIds.length < 20 || surfaces.length < 5) {
  console.error(`  ✗ parsed ${capIds.length} capabilities and ${surfaces.length} surfaces from the gate — the declaration shapes moved, and rendering a table from a failed parse would print an empty page as if it were an answer`);
  process.exit(1);
}

const CAPS_CORE = Object.fromEntries([...src.matchAll(/^ {2}'([a-z0-9-]+)':\s*\{ core: \[([^\]]*)\]/gm)].map((m) => [m[1], idents(m[2])]));
const VERSION = JSON.parse(readFileSync(ROOT + 'package.json', 'utf8')).version;
const stance = (s, cap) => (s.full === 'ALL' || s.full.includes(cap)) ? '✅' : s.subset.includes(cap) ? '◐' : '·';
const short = (s) => s.replace('ust-', '');

// The privacy story the card was about, called out by name — a reader looking for "can I make a private
// partition and can my tool read it" should not have to infer it from a grid.
const cli = surfaces.find((s) => s.id === 'ust-cli');
// What a surface offers for a capability is RENDERED from the tokens the parity probe resolves against that
// surface — `cmd:sign` is checked to be a command, `tool:ust_seal` to be a registered tool. Writing them as prose
// is what let this page claim for five rounds that an agent could not make a private partition; a token that
// stopped resolving would fail the gate, and a token that resolves prints itself here.
const tokensFor = (cap, surface) => {
  const raw = CAPS_TOKENS[cap]?.[surface];
  return [].concat(raw ?? []).map((t) => t.replace(/^cmd:/, 'ust ').replace(/^tool:/, '').replace(/^flag:/, '--').replace(/^api:/, '').replace(/^arg:/, ''));
};
const cliHas = (cap) => !!cli && (cli.full === 'ALL' || cli.full.includes(cap) || cli.subset.includes(cap));
const rows = capIds.map((c) => `| \`${c}\` | ` + surfaces.map((s) => stance(s, c)).join(' | ') + ' |').join('\n');

const page = `# What UST supports, per surface

<!-- GENERATED by tools/gen-support-matrix.mjs from the declarations in tools/capability-parity.mjs — do not edit.
     Those declarations are checked against live probes by \`npm run test:parity\` on every CI run, so a cell here
     is true because the gate would go red otherwise. Regenerate: node tools/gen-support-matrix.mjs -->

Reference implementation \`${VERSION}\`. **✅ full** — every core export of the capability is exposed · **◐ subset**
— a documented reduced form · **·** — not on this surface, with a stated reason in \`tools/capability-parity.mjs\`.

A cell is not a promise. \`tools/capability-parity.mjs\` probes each surface for real — the CLI's dispatch table and
argument parser, the MCP tool schemas, a package's exports — and CI fails if a declaration and the probe disagree.
This page is rendered from those declarations, so it cannot drift from what the gate checks.

| capability | ${surfaces.map((s) => short(s.id)).join(' | ')} |
|---|${surfaces.map(() => '---').join('|')}|
${rows}

## Private partitions, end to end

The question the matrix answers least directly, so it is answered here. §10 gives two privacy modes and they are
per-PARTITION: one shard mixes open and closed members freely.

| | make one | read one back |
|---|---|---|
| **core** \`ust-protocol\` | ${CAPS_CORE['disclosure-produce'].map((n) => '\`' + n + '\`').join(' · ')} | \`disclosures\` + \`decKeys\` |
${surfaces.map((sf) => {
  const key = sf.id === 'ust-cli' ? 'cli' : sf.id === 'ust-mcp' ? 'mcp' : null;
  const makes = stance(sf, 'disclosure-produce'), reads = stance(sf, 'verify');
  const note = (cap) => { const t = (key ? tokensFor(cap, key) : []).map((x) => '\`' + x + '\`').join(' · '); return t ? ' ' + t : ''; };
  const cell = (st, cap) => st === '·' ? '—' : st + note(cap);
  return '| **\`' + sf.id + '\`** | ' + cell(makes, 'disclosure-produce') + ' | ' + cell(reads, 'verify') + ' |';
}).join('\n')}

Both columns are the \`disclosure-produce\` and \`verify\` stances, rendered — **not a hand-kept summary.** Measured
2026-09-03: the table that stood here WAS hand-kept, and had drifted by five rounds for \`ust-mcp\` (it said an
agent cannot make a private partition, five rounds after it could) and by seven for \`ust-light\`. A prose summary
inside a generated page is the very defect the page exists to prevent, and it happened here.

**Two channels, and they are opened by different secrets.** A \`blinded\` partition has one: the commitment, opened
by \`{nonce,value}\`. An \`encrypted\` partition has two: that commitment, plus the AEAD, opened by the key. A reader
holding only the pair has checked ONE of two, and every surface above says so rather than calling the partition
disclosed — \`disclosed\` means every channel the publisher declared was checked (§14.8).

**Producing one obliges you to keep the envelope.** \`ust sign\` generates the nonce, so \`--disclosures-out\` is
mandatory: a tool that generated it and did not hand it back would leave you holding a commitment nobody can ever
open, including you. It also refuses to invent an AEAD key — §10 leaves key management to the operator, and an
invented key is one you cannot rotate.

## The agent surface, and the rule that governs it

The agent is the protocol's **principal** audience (owner, 2026-09-02). A human at a terminal has a shell and the
package: a missing tool costs them six lines. An agent has exactly what is exposed as a tool, so the same absence
is an inconvenience on one surface and a wall on the other.

> **Any capability the protocol gives a publisher appears on the agent surface not later than on the human one.**

Every absence from \`mcp\` is classified, by one question — *would this still need a human if we trusted the agent
completely?*

**Ceremony — the act is a human decision, and stays one** (${ceremony.length}). No amount of trust in an agent removes the
person, so this classification is permanent.
${ceremony.length
  ? ceremony.map((d) => '- \`' + d.cap + '\`').join('\n')
  : `_None today, and that is a finding rather than an omission._ Ceremony is a property of an operator WORKFLOW —
the CLI walks a person through DNS, publication and confirmation — while this map is over core FUNCTIONS, which
compute artifacts that are inert until someone signs them. \`buildAuthorityCheckpoint\` computes; what needs a
person is deciding to stand behind the result. The category is real and permanent; it does not apply at this
granularity, and an entry appearing here would mean the map had grown to cover workflows.`}

**Key-bound — the key does not cross into an agent's context** (${keyBound.length}). The function holding key material stays
outside; this is not a wall, because the agent produces what is signed and assembles what comes back, and every
key-free half is on its surface. A claim here is refutable by measurement: if no function of the capability takes
key material, the gate refuses the classification.

${keyBound.map((d) => '- \`' + d.cap + '\`').join('\n')}

**Lagging — debt** (${lagging.length}). Our own unfinished work, sitting where the principal audience reaches for it. These
carry no justification, because none exists — the gate refuses one written under them. The count is pinned and
may only shrink.

${lagging.map((d) => '- \`' + d.cap + '\`' + (cliHas(d.cap) ? ' — also on the CLI' : '')).join('\n')}

${(() => { const n = lagging.filter((d) => cliHas(d.cap)).length;
  return n === 0
    ? 'None of these is on the human surface either, so the debt is uniform: nobody can reach them. The rule still binds — whichever surface receives one first, the agent surface may not receive it later.'
    : `${n} of the ${lagging.length} ${n === 1 ? 'is' : 'are'} on the human surface already, and ${n === 1 ? 'that one is' : 'those are'} the inversion the rule exists to close: reachable by a person with a terminal and by nobody with a tool.`; })()}

`;

const path = ROOT + 'SUPPORT.md';
const before = (() => { try { return readFileSync(path, 'utf8'); } catch { return null; } })();
writeFileSync(path, page);
console.log(`\n  support matrix   ${capIds.length} capabilities × ${surfaces.length} surfaces → SUPPORT.md${before === page ? '  [already in sync]' : ''}`);
console.log('  ✓ rendered from the declarations the parity gate verifies — not from a hand-kept list');
