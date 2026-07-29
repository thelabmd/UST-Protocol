#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Round RECAP renderer — the sealed diary entry, shown beside the round it belongs to.
//
// The changelog row says WHAT BECAME. The issue comment says where the ticket and reality diverged. The diary says
// what the moment was. Three authors, three different contents — and the recap block is NOT a fourth: it is the
// diary entry itself, rendered verbatim in a second place, exactly as diarium.md is a rendered view of the store.
//
// That distinction is the whole design. A hand-typed summary of a sealed entry is a paraphrase, and a paraphrase
// beside a correct content hash is worse than no hash at all — MEASURED 2026-07-29: a recap comment carried the
// right hash next to a re-worded quote, with the frame named one precision class too coarse. The hash was right;
// prose does not hash into it. The owner caught it, I did not. So this renderer exists to make typing impossible:
// the text comes from `diarium read --json`, the same one implementation of "what follows what" that renders the
// diary page, and `--check` fails if the file and the store ever disagree.
//
// WHY A BLOCKQUOTE. A diary entry opens with `## <date> · <title>`. Inserted raw into CHANGELOG.md that is an H2,
// and it would TRUNCATE the `## rc.NN line` section it sits in — every gate that enumerates rounds from those
// sections would go quietly blind, which is the vacuity class this repository keeps closing. Quoting demotes it
// without touching a byte of meaning, and the check reverses the prefix and compares to the sealed text, so
// "verbatim" is asserted rather than trusted.
//
// Usage:
//   node tools/recap-render.mjs             rewrite CHANGELOG.md
//   node tools/recap-render.mjs --check     fail if it disagrees with the store (CI)
//   node tools/recap-render.mjs --issue N   print round N's block for a GitHub comment
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MD = ROOT + 'CHANGELOG.md';
const CLI = ROOT + 'node_modules/.bin/diarium';
const REG = JSON.parse(readFileSync(ROOT + 'tools/recap-registry.json', 'utf8'));
const MIN_REASON = 60;   // a reason shorter than this is a placeholder, not a decision

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// ── the store, read through the package, never by globbing diarium/ ourselves
let docs;
try { docs = JSON.parse(execFileSync(CLI, ['read', '--depth', 'all', '--json'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })); }
catch (e) { console.error('✗ the store would not yield an order: ' + String(e.stderr || e.message).trim()); process.exit(1); }
const byHash = new Map(docs.map((d) => [P.contentHash(d), d]));

// ── which rounds EXIST, and in which version line. A round is recapped where its work is recorded.
const current = readFileSync(MD, 'utf8');
const SECTION = /^## (rc\.\d+) line.*$/gm;
const bounds = [];
for (const m of current.matchAll(SECTION)) bounds.push({ line: m[1], start: m.index });
for (const [i, b] of bounds.entries()) {
  const nextTop = current.slice(b.start + 3).search(/^## /m);
  b.end = nextTop < 0 ? current.length : b.start + 3 + nextTop;
  b.next = bounds[i + 1];
}
const roundLine = new Map();   // round -> section
for (const b of bounds)
  for (const m of current.slice(b.start, b.end).matchAll(/^\| .*? \| (\d+) \| /gm)) roundLine.set(Number(m[1]), b);

check(bounds.length > 0, 'no `## rc.NN line` section found — the renderer has gone blind and would emit nothing');
check(roundLine.size > 0, 'no round row found in any version line — the placement probe proves nothing');

// ── build every block from the SEALED bytes
const quote = (t) => t.split('\n').map((l) => (l ? '> ' + l : '>')).join('\n');
const unquote = (q) => q.split('\n').map((l) => (l === '>' ? '' : l.replace(/^> /, ''))).join('\n');

const blocks = new Map();
for (const rec of REG.records) {
  check(Number.isInteger(rec.round), `a recap record is keyed by no integer round: ${JSON.stringify(rec)}`);
  if (rec.no_recap) {
    check(String(rec.no_recap).trim().length >= MIN_REASON,
      `round ${rec.round}: no_recap is ${String(rec.no_recap).trim().length} chars — under ${MIN_REASON} is a placeholder, not a decision`);
    continue;
  }
  const d = byHash.get(rec.content_hash);
  check(!!d, `round ${rec.round} names content_hash ${String(rec.content_hash).slice(0, 22)}… and NO sealed entry in the store has it — a recap must be a view of something signed`);
  if (!d) continue;
  const text = d.state.data.entry?.value?.text;
  check(typeof text === 'string' && text.length > 0, `round ${rec.round}: the sealed entry carries no text`);
  check(roundLine.has(rec.round), `round ${rec.round} has a recap but no row in any version line — a recap belongs beside the work it recaps`);
  if (typeof text !== 'string' || !roundLine.has(rec.round)) continue;
  // the hash is RECOMPUTED from the signed bytes, never copied from the registry, so the visible proof cannot
  // drift from the document it claims to describe.
  const ch = P.contentHash(d);
  check(ch === rec.content_hash, `round ${rec.round}: the registry hash and the recomputed hash disagree`);
  blocks.set(rec.round, `#### round ${rec.round} — recap\n\n${quote(text.trim())}\n\n*Sealed \`${d.state.id.ust_id}\` · \`${ch}\` — rendered from \`diarium/\`, never typed. [The diary](diarium.md) is the source; this is a second view of it.*\n`);
}

// ── ONE issue's worth, for a comment. Same bytes, same function — that is the point of the mode existing.
const issueAt = process.argv.indexOf('--issue');
if (issueAt >= 0) {
  const r = Number(process.argv[issueAt + 1]);
  const b = blocks.get(r);
  if (!b) { console.error(`✗ round ${r} has no recap block to render`); process.exit(1); }
  console.log('## Recap\n\n' + b.split('\n').slice(2).join('\n'));
  process.exit(0);
}

// ── place them: inside the round's own section, after the table, newest first. Existing blocks are REMOVED and
// re-emitted rather than patched, so the file can never accumulate a stale one.
let out = '';
let cursor = 0;
for (const b of bounds) {
  const body = current.slice(b.start, b.end).replace(/\n#### round \d+ — recap\n[\s\S]*?(?=\n#### round \d+ — recap\n|$)/g, '\n').replace(/\n+$/, '\n');
  const mine = [...blocks.keys()].filter((r) => roundLine.get(r) === b).sort((a, z) => z - a);
  // one blank line closes the section, whether or not it gained a block — the separator belongs to the SECTION,
  // and letting the last block own it made a re-render eat the blank line the file already had.
  out += current.slice(cursor, b.start) + (body + (mine.length ? '\n' + mine.map((r) => blocks.get(r)).join('\n') : '')).replace(/\n+$/, '\n\n');
  cursor = b.end;
}
out += current.slice(cursor);

// ── the LIVE leg: from `first_recapped_round` on, every round in a version line must be DECIDED — a sealed entry
// or a written reason. Rounds below the floor predate the rule and are reported, never gated; pretending history
// complied would be the dishonesty the floor exists to avoid.
const FIRST = REG.first_recapped_round;
check(Number.isInteger(FIRST), 'first_recapped_round is not an integer — the live leg would have no floor and pass for anything');
const decided = new Set(REG.records.map((r) => r.round));
const live = [...roundLine.keys()].filter((r) => r >= FIRST).sort((a, z) => a - z);
for (const r of live)
  check(decided.has(r), `round ${r} is recorded in a version line and has NO recap and no reason for having none — the block would vanish as quietly as the habit that used to carry it`);
const below = [...roundLine.keys()].filter((r) => r < FIRST).length;

// ── the probe must be able to fail
check(!decided.has(-1), 'the decision probe accepts a round the registry lacks');
check(unquote(quote('## a\n\nb')) === '## a\n\nb', 'quoting is not reversible — "verbatim" could not be asserted');

if (process.argv.includes('--check')) {
  check(out === current, 'CHANGELOG.md does not match the sealed store — regenerate it: node tools/recap-render.mjs');
  console.log(`\n  round recaps   PASS ${pass}   FAIL ${fail.length}   (${blocks.size} block(s) from ${docs.length} sealed entries · floor ${FIRST})`);
  if (below) console.log(`  ℹ  ${below} version-line round(s) below the floor are reported, not gated — the rule starts where it was written`);
  if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
  console.log('  ✓ every recap is a verbatim view of a sealed entry, and every live round is decided');
  process.exit(0);
}

if (fail.length) { fail.forEach((f) => console.error('  ✗ ' + f)); process.exit(1); }
writeFileSync(MD, out);
console.log(`  ✓ CHANGELOG.md: ${blocks.size} recap block(s) rendered from the sealed store`);
