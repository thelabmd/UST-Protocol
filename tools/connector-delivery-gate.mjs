// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the domain is READ from the shipped surfaces (every `combine*` assembly site), never
// a roster typed here; the delivery predicate is a symbol lookup in the call's own argument text.
//
// CONNECTOR-DELIVERY GATE (round 240) — an optional connector that is ASSEMBLED and never PASSED is invisible.
//
// Measured 2026-08-30 on the reference operator's own live document, carrying a valid inclusion proof whose hour
// root is final in Bitcoin (block 964576) — CLOSED 2026-08-30 by this gate and the five call sites it now watches:
//
//   ust verify <doc>                        → VALID:HIGH, time: unproven/unavailable
//   the same plugin set, passed by hand     → VALID:HIGH, time: anchored/verified
//
// `cmdVerify` built `inclusionVerify` with `combineInclusion(...)` two lines above the call and then handed the
// call only `substrateVerify`. The value was computed and dropped. Nothing failed: membership simply went
// unchecked, the anchor beneath the document was never bound to it, and the command printed HIGH — a downgrade
// wearing the shape of a success. The sweep that followed found the same omission at EVERY assembly site in the
// shipped surfaces: 4 sites, 5 calls, zero passing the connector. One of them was `forkchoice`, which I had
// asserted in the ticket DID pass it — it did not; the claim was refuted by reading the argument list.
//
// WHY A GATE AND NOT A TEST. The behavioural check needs a publisher, a live substrate and a network; this
// property does not. It is structural: whatever a surface assembles for a call must reach that call. So the gate
// enumerates the assembly sites FROM THE SOURCE — a new surface, or a third combinator, is in the domain the day
// it is written, without anyone remembering to add it here.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not check that the connector is USED correctly, nor that the verdict
// improves. A structural gate that claimed either would be overclaiming; the verdict half is exercised by the
// live-document measurement recorded in the changelog row.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// The SURFACES: every shipped package that consumes the core. Read from the workspace rather than listed, so a
// new consumer package joins the domain by existing.
const PKGS = readdirSync(ROOT + 'packages', { withFileTypes: true })
  .filter((d) => d.isDirectory() && d.name !== 'ust-protocol')
  .map((d) => d.name);
const FILES = [];
for (const p of PKGS) {
  for (const f of readdirSync(ROOT + 'packages/' + p)) {
    if (f.endsWith('.mjs') && !f.endsWith('.test.mjs')) FILES.push(`packages/${p}/${f}`);
  }
}

// The COMBINATORS the core exports for optional connectors, read from the core's own export list — so a third
// one (a future axis) is covered the moment it is exported, and a renamed one stops matching here rather than
// silently narrowing the domain.
const CORE = readFileSync(ROOT + 'packages/ust-protocol/index.mjs', 'utf8');
const COMBINATORS = [...CORE.matchAll(/^export function (combine[A-Za-z]+)\(/gm)].map((m) => m[1]);
check(COMBINATORS.length > 0, 'no `combine*` combinator found in the core — the domain would be empty and this gate free');

// The CONSUMERS of those connectors: the core entry points that take them through `opts`. `P.verify` is
// DELIBERATELY not here and the omission is the point — the synchronous door takes no connector, so demanding one
// there would have forced a parameter invented to satisfy a gate. Measured while writing this: including it
// produced 2 of my own 3 first failures, both on an offline branch that is correct as written.
const CALL = /\bP\.(resolveByDiscovery|forkChoice|verifyAsync)\s*\(/g;
const WINDOW = 40;   // lines; an assembly and its call live in one function body

// A call's ARGUMENTS may span several lines, and the third of my three first failures was exactly that: the
// transport object sat one line below the call and the connector read as absent. So the text under test is the
// whole call, read to its balancing parenthesis, never the line the callee's name happens to sit on.
const callText = (src, start) => {
  let depth = 0, out = '';
  for (let j = start; j < Math.min(src.length, start + WINDOW); j++) {
    out += src[j] + '\n';
    for (const ch of src[j]) { if (ch === '(') depth++; else if (ch === ')') depth--; }
    if (depth <= 0 && j > start - 1 && out.includes('(')) break;
  }
  return out;
};

let sites = 0;
for (const rel of FILES) {
  const src = readFileSync(ROOT + rel, 'utf8').split('\n');
  for (let i = 0; i < src.length; i++) {
    const asm = src[i].match(new RegExp(`const\\s+(\\w+)\\s*=.*\\b(?:${COMBINATORS.join('|')})\\s*\\(`));
    if (!asm) continue;
    const name = asm[1];
    sites++;
    // every core call within the window must carry the assembled name in its argument text
    const calls = [];
    for (let j = i + 1; j < Math.min(src.length, i + WINDOW); j++) {
      CALL.lastIndex = 0;
      if (CALL.test(src[j])) calls.push(j);
    }
    check(calls.length > 0,
      `${rel}:${i + 1} assembles \`${name}\` and no core call follows within ${WINDOW} lines — either it is dead, or the call moved out of reach of this window`);
    for (const j of calls) {
      check(callText(src, j).includes(name),
        `${rel}:${i + 1} assembles \`${name}\` but the call at ${rel}:${j + 1} does not pass it — an assembled connector that never reaches its call is silently absent, and the verdict is downgraded with no error (round 240)`);
    }
  }
}

check(sites >= 4, `only ${sites} assembly site(s) found — the domain shrank; a gate over an empty or shrunken domain passes for free`);

// NEGATIVE CONTROL — the predicate must be able to say NO, proven here rather than asserted in a comment. Two
// synthetic call texts, identical but for the delivery: one passes the assembled name, one drops it. If the
// dropped one reads as delivered, every green above is free.
{
  const good = ['const inclusionVerify = P.combineInclusion(x);', 'await P.resolveByDiscovery(doc, { a, inclusionVerify },', '  { substrateVerify });'];
  const bad = ['const inclusionVerify = P.combineInclusion(x);', 'await P.resolveByDiscovery(doc, { a },', '  { substrateVerify });'];
  check(callText(good, 1).includes('inclusionVerify'), 'CONTROL: the reader failed to see a connector that IS passed — it would report false failures');
  check(!callText(bad, 1).includes('inclusionVerify'), 'CONTROL: the reader saw a connector in a call that does NOT pass it — the check above cannot fail and every pass is free');
  // and the multi-line half, which is the shape that produced one of my own false failures
  const spread = ['const substrateVerify = P.combineSubstrates(x);', 'await P.resolveByDiscovery(doc, { a },', '  { substrateVerify, fetchImpl });'];
  check(callText(spread, 1).includes('substrateVerify'), 'CONTROL: an argument on a later line read as absent — the window does not span the whole call');
}

console.log(`\n  connector delivery   PASS ${pass}   FAIL ${fail.length}   (${sites} assembly site(s) across ${FILES.length} shipped module(s), combinators: ${COMBINATORS.join(', ')})`);
for (const f of fail) console.log('    ✗ ' + f);
if (fail.length) process.exit(1);
console.log('  ✓ every optional connector a surface assembles is passed to the call it was assembled for');
