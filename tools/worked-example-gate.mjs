// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the placeholder vocabulary is the SKELETON grammar, not the domain — the domain is every fenced json block, READ from the file and judged by the imported reference verifier
// WORKED-EXAMPLE GATE (#101) — an illustration in the specification must not assert something the specification
// forbids.
//
// §21.2 sealed an hour FLAT over 120 constituents while §13 caps breadth at 64. Every gate in this repository was
// green: the example was prose, and prose is not run. A reader implementing from it would have written a document
// the reference verifier refuses — the specification teaching a violation of itself, for as long as nobody tried it.
//
// The fix is not to check that one block. It is to make the file DECLARE, for every fenced `json` block, which of
// two things it is:
//
//   · a SKELETON — a shape with placeholders (`...`, `b64url`, `ContentHash`, `<name>`). Illustrative, not
//     runnable, and it must LOOK unrunnable so nobody mistakes it for a transcript.
//   · a WORKED EXAMPLE — marked `<!-- ust:worked-example -->` on the line before the fence. It promises to be a
//     real document, and this gate VERIFIES it against the reference checker. A promise that is checked.
//
// The teeth are in the third case: a block that PARSES, carries no placeholder, and bears no marker FAILS. That is
// the §21.2 shape exactly — something that reads like a transcript while nobody has ever run it — and the file is
// forced to say which kind it is rather than leaving a reader to guess.
//
// MEASURED 2026-07-31: 6 fenced json blocks, all skeletons, zero worked examples. So the verify leg has an empty
// domain today and a control below proves it can still fail — a gate whose domain is empty is exactly the shape
// that passes for free.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// judged by THIS TREE's checker, not by whatever `npm` happened to resolve: a gate about our specification must
// agree with the implementation the specification is being written against, or it is testing someone else's.
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SPEC = 'spec/UST-1.0.md';
const MARKER = '<!-- ust:worked-example -->';
// the SKELETON grammar: tokens that make a block visibly a shape rather than a document.
const PLACEHOLDER = /\.\.\.|…|\bb64url\b|\bContentHash\b|<[a-z_]+>|\|/i;

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// the DOMAIN is every fenced json block in the file, enumerated — never a list someone remembered to update.
const lines = readFileSync(ROOT + SPEC, 'utf8').split('\n');
const blocks = [];
for (let i = 0; i < lines.length; i++) {
  if (!lines[i].startsWith('```json')) continue;
  let j = i + 1; const body = [];
  while (j < lines.length && !lines[j].startsWith('```')) body.push(lines[j++]);
  blocks.push({ line: i + 1, body: body.join('\n'), marked: (lines[i - 1] ?? '').trim() === MARKER });
}
check(blocks.length >= 4, `only ${blocks.length} fenced json block(s) found in ${SPEC} — the scanner has gone blind and every judgement below is about nothing`);

let worked = 0, skeletons = 0;
for (const b of blocks) {
  let doc = null, parses = true;
  try { doc = JSON.parse(b.body); } catch { parses = false; }
  const placeholder = PLACEHOLDER.test(b.body);

  if (b.marked) {
    worked++;
    check(parses, `${SPEC}:${b.line} is marked a worked example and does not parse as JSON — a promise to be a real document that is not one`);
    if (!parses) continue;
    const v = P.verify(doc);
    check(P.isValid(v),
      `${SPEC}:${b.line} is marked a worked example and the REFERENCE VERIFIER refuses it (${v.error ?? v.result}) — the specification would be teaching a document it forbids, which is the §21.2 defect this gate exists for`);
    continue;
  }

  // unmarked: it must LOOK like a skeleton, or it is an unverified transcript wearing a transcript's clothes
  skeletons++;
  check(placeholder,
    `${SPEC}:${b.line} carries no placeholder and no ${MARKER} — it reads as a real document and nothing has ever run it. Mark it a worked example (and this gate will verify it) or make its placeholders visible.`);
}

console.log(`\n  worked examples   PASS ${pass}   FAIL ${fail.length}   (${blocks.length} json blocks · ${worked} verified · ${skeletons} skeletons)`);

// ── the verify leg has an EMPTY domain while no example is marked, so it must be shown able to fail. A marked
// block whose document the verifier refuses is exactly the §21.2 shape, synthesised here.
{
  const broken = { ust: '1.0', state: { id: { domain_shard: 'e.com', ust_id: 'ust:20260628.10' }, time: 'not-a-time' }, sig: 'nope' };
  const v = P.verify(broken);
  if (P.isValid(v)) { console.log('    ✗ CONTROL: the reference verifier ACCEPTED a broken document — the verify leg proves nothing'); process.exit(1); }
  const unmarked = { line: 0, body: JSON.stringify(broken), marked: false };
  if (PLACEHOLDER.test(unmarked.body)) { console.log('    ✗ CONTROL: a complete-looking document matched the skeleton grammar — the placeholder rule would excuse exactly what it must catch'); process.exit(1); }
}

if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every illustration declares what it is, and every one that claims to be a document verifies');
