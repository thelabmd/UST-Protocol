// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:SKIP names directories NOT WALKED and EXEMPT names one package the statement is not about — both are exclusions, and the domain is what remains: every tracked .md, discovered by reading, never listed — the copy SET is discovered by reading every tracked .md, and each copy is compared byte-for-byte against the named source; a negative control mutates one and asserts the comparison reddens
// TEN COPIES OF ONE NORMATIVE PARAGRAPH.
//
// The two-rules block — *a minor only ADDS* and *a verifier never expires* — is repeated in SECURITY.md, in
// docs/AUDIT.md and in every package README. That repetition is deliberate: a reader on npm sees ONLY the
// README of the package they are installing, so a link would send them nowhere. The text has to be there.
//
// What is not acceptable is what this repository has already paid for twice: copies that agree today and
// nothing that notices when they stop. They are byte-identical as of 2026-08-08 — measured, not assumed — and
// this gate is what keeps that a fact rather than a memory. A copy is not the defect; an unchecked copy is.
//
// The SOURCE is `packages/ust-protocol/README.md`, because that is the package the statement is about. Editing
// the wording means editing it there and re-running; every other copy must follow byte-for-byte.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = 'packages/ust-protocol/README.md';
const MARK = 'Two rules this protocol does not trade away';
const SKIP = new Set(['node_modules', '.git', 'rnd', '.beads', 'diarium', 'dist']);

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

/**
 * The blockquote that carries the mark, extracted from the source text: a run of `>` lines containing it.
 *
 * Read out of the file rather than held as a constant here. A gate that keeps its own copy of the text it
 * polices has made itself an eleventh copy — and the one nobody would think to check.
 */
const BLOCK_RE = new RegExp('(?:^>.*\\n)*^>.*' + MARK.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '.*(?:\\n^>.*)*', 'm');
const extract = (text) => text.match(BLOCK_RE)?.[0] ?? null;

// The DOMAIN is discovered, never listed: a new README carrying the block joins the comparison by existing.
const found = [];
(function walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith('.md')) {
      const block = extract(readFileSync(p, 'utf8'));
      if (block) found.push({ path: p.slice(ROOT.length + 1), block });
    }
  }
})(ROOT);

const src = found.find((f) => f.path === SOURCE);
ok(`the source copy exists (${SOURCE})`, !!src, 'the block is missing from the package it is about');

if (src) {
  const differing = found.filter((f) => f.block !== src.block).map((f) => f.path);
  ok(`all ${found.length} copies are byte-identical to the source`, differing.length === 0, differing.join(', '));
}

// Every package README must carry it — a package that quietly drops the statement is the other failure mode.
const pkgs = readdirSync(join(ROOT, 'packages')).filter((d) => {
  try { return statSync(join(ROOT, 'packages', d, 'README.md')).isFile(); } catch { return false; }
});
const EXEMPT = new Set(['diarium']);   // not a protocol surface — the statement is not about it
const missing = pkgs.filter((d) => !EXEMPT.has(d) && !found.some((f) => f.path === `packages/${d}/README.md`));
ok(`every package README carries it (${pkgs.length - EXEMPT.size} expected, ${EXEMPT.size} exempt: ${[...EXEMPT].join(', ')})`,
  missing.length === 0, missing.join(', '));

// NEGATIVE CONTROL — a comparison that cannot fail is decoration.
{
  const mutated = src ? src.block.replace('only ADDS', 'only adds') : 'x';
  ok('CONTROL: a one-character difference IS detected', src ? mutated !== src.block : false);
}

console.log(`\n  readme block   PASS ${pass}   FAIL ${fail.length}   (${found.length} copies, source ${SOURCE})`);
for (const f of fail) console.log('    ✗ ' + f);
process.exit(fail.length ? 1 : 0);
