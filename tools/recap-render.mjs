#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — rounds enumerated from CHANGELOG; hashes recomputed from the signed bytes
// Round RECAP renderer — the sealed diary entry, rendered for the issue the round closed.
//
// The changelog row says WHAT BECAME. The issue comment says where the ticket and reality diverged. The diary says
// what the moment was. Three authors, three different contents — and the recap is NOT a fourth: it is the diary
// entry itself, rendered verbatim at the end of the closing comment, as diarium.md is a rendered view of the store.
//
// A paraphrase beside a correct content hash is worse than no hash at all — MEASURED 2026-07-29: a recap comment
// carried the right hash next to a re-worded quote, with the frame named one precision class too coarse. The hash
// was right; prose does not hash into it. So the text comes from `diarium read --json`, the same one implementation
// of "what follows what" that renders the diary page, and typing it is not possible rather than not allowed.
//
// IT DOES NOT WRITE INTO CHANGELOG.md, and that is a decision rather than an omission (round 83, owner's call). Round
// 81 put the block there on the strength of a 27 July proposal; seeing it, the owner ruled that diary entries do not
// belong in the changelog. He is right for a reason the design itself states: three authors must write DIFFERENT
// things, and a round's row and its recap sat adjacent describing one event in two registers — the only place that
// rule was broken. The entry already has a rendered home in diarium.md over the store in diarium/; the changelog was
// a third copy of the same signed bytes, and it made the anchoring 27 July warned about physical and permanent.
//
// WHAT THIS GATE CAN AND CANNOT SEE, stated so it is not mistaken for more. It checks that every live round DECIDES
// which issue receives its recap, that a named content_hash resolves to a sealed entry, that the hash it prints is
// recomputed from the signed bytes rather than copied, and that no such block is in the changelog. It CANNOT check
// that the comment was posted — these gates are offline on purpose. That step is verified by hand: fetch the comment
// back and compare it to the sealed file, which is the direction that proves something.
//
// Usage:
//   node tools/recap-render.mjs --check     registry vs store vs the live rounds (CI)
//   node tools/recap-render.mjs --issue N   print round N's recap for a GitHub comment
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
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

// ── which rounds EXIST. A round is DECIDED where its work is recorded — the version-line tables.
const CHANGELOG = readFileSync(ROOT + 'CHANGELOG.md', 'utf8');
const rounds = new Set();
for (const m of CHANGELOG.matchAll(/^## rc\.\d+ line.*$/gm)) {
  const start = m.index;
  const nextTop = CHANGELOG.slice(start + 3).search(/^## /m);
  const end = nextTop < 0 ? CHANGELOG.length : start + 3 + nextTop;
  for (const r of CHANGELOG.slice(start, end).matchAll(/^\| .*? \| (\d+) \| /gm)) rounds.add(Number(r[1]));
}
check(rounds.size > 0, 'no round row found in any version line — the round probe has gone blind and this gate would pass vacuously');

// ── build every recap from the SEALED bytes. Quoted, so a reader sees the prose is carried in from somewhere else
// and is not the comment speaking; the check reverses the prefix before comparing.
const quote = (t) => t.split('\n').map((l) => (l ? '> ' + l : '>')).join('\n');
const unquote = (q) => q.split('\n').map((l) => (l === '>' ? '' : l.replace(/^> /, ''))).join('\n');

const recaps = new Map();
for (const rec of REG.records) {
  check(Number.isInteger(rec.round), `a recap record is keyed by no integer round: ${JSON.stringify(rec)}`);
  if (rec.no_recap) {
    check(String(rec.no_recap).trim().length >= MIN_REASON,
      `round ${rec.round}: no_recap is ${String(rec.no_recap).trim().length} chars — under ${MIN_REASON} is a placeholder, not a decision`);
    continue;
  }
  // WHICH ISSUE receives it must be DECIDED, never left to the moment. Measured 2026-07-29: reading the rule as
  // round-bound rather than issue-bound, I recorded `issue: null` with a reason and posted nothing, and the owner
  // had to ask where the recap was.
  const issued = Number.isInteger(rec.issue) || String(rec._issue ?? '').trim().length >= MIN_REASON;
  check(issued, `round ${rec.round}: neither an issue number nor a reason of ${MIN_REASON}+ chars for receiving none — a recap nobody receives is a view rendered into a terminal and stopped there`);
  const d = byHash.get(rec.content_hash);
  check(!!d, `round ${rec.round} names content_hash ${String(rec.content_hash).slice(0, 22)}… and NO sealed entry in the store has it — a recap must be a view of something signed`);
  if (!d) continue;
  const text = d.state.data.entry?.value?.text;
  check(typeof text === 'string' && text.length > 0, `round ${rec.round}: the sealed entry carries no text`);
  check(rounds.has(rec.round), `round ${rec.round} has a recap but no row in any version line — a recap belongs to work that is recorded`);
  if (typeof text !== 'string') continue;
  // the hash is RECOMPUTED from the signed bytes, never copied from the registry, so the visible proof cannot
  // drift from the document it claims to describe.
  const ch = P.contentHash(d);
  check(ch === rec.content_hash, `round ${rec.round}: the registry hash and the recomputed hash disagree`);
  recaps.set(rec.round, `## Recap\n\n${quote(text.trim())}\n\n*Sealed \`${d.state.id.ust_id}\` · \`${ch}\` — rendered from \`diarium/\`, never typed. The diary is the source; this is a second view of it.*`);
}

// ── ONE round's worth, for a comment
const issueAt = process.argv.indexOf('--issue');
if (issueAt >= 0) {
  const r = Number(process.argv[issueAt + 1]);
  if (!recaps.has(r)) { console.error(`✗ round ${r} has no recap to render`); process.exit(1); }
  console.log(recaps.get(r));
  process.exit(0);
}

// ── the LIVE leg: from `first_recapped_round` on, every round in a version line must be DECIDED — a sealed entry
// or a written reason. Rounds below the floor predate the rule and are reported, never gated; pretending history
// complied would be the dishonesty the floor exists to avoid.
const FIRST = REG.first_recapped_round;
check(Number.isInteger(FIRST), 'first_recapped_round is not an integer — the live leg would have no floor and pass for anything');
const decided = new Set(REG.records.map((r) => r.round));
for (const r of [...rounds].filter((x) => x >= FIRST).sort((a, z) => a - z))
  check(decided.has(r), `round ${r} is recorded in a version line and has NO recap and no reason for having none — the decision would vanish as quietly as the habit that used to carry it`);
const below = [...rounds].filter((r) => r < FIRST).length;

// ── the diary's homes are diarium/ (the store) and diarium.md (its rendered view). The changelog is not one of
// them, and this asserts it rather than trusting that nobody re-adds the block.
check(!CHANGELOG.includes('#### round '), 'CHANGELOG.md carries a `#### round N — recap` block: diary entries do not live in the changelog (round 83). The recap is rendered for the ISSUE; diarium.md over diarium/ is the diary\'s home.');

// ── each leg must be able to FAIL
check(!decided.has(-1), 'the decision probe accepts a round the registry lacks');
check(!rounds.has(-1), 'the round probe accepts a round no version line records');
check(unquote(quote('## a\n\nb')) === '## a\n\nb', 'quoting is not reversible — "verbatim" could not be asserted');

console.log(`\n  round recaps   PASS ${pass}   FAIL ${fail.length}   (${recaps.size} recap(s) from ${docs.length} sealed entries · floor ${FIRST})`);
if (below) console.log(`  ℹ  ${below} version-line round(s) below the floor are reported, not gated — the rule starts where it was written`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every recap is a view of a sealed entry, every live round is decided, and none of it is in the changelog');
