// SPDX-License-Identifier: Apache-2.0
// Unbounded-index gate — arithmetic on a counter we do not own may not carry a ceiling.
//
// A public transparency log's index is an EXTERNAL counter. It grows without asking us, it never resets, and the
// day it crosses a boundary our arithmetic assumed is a day nobody schedules. On 2026-07-28 the reference operator's
// fresh anchor verified `final:false` while its own two-week-old anchor verified `final:true` — same connector, same
// log, same code. The log had passed 2^31 entries, and JavaScript's `>>` and `&` coerce to SIGNED 32-BIT, so the
// climb went negative halfway up: 2149645490 >> 1 = -1072660903 where the answer is 1074822745.
//
// Every gate was green throughout. Every test passed — because every test vector was recorded below the boundary.
// The verifier was not wrong about any input it had ever been shown, which is exactly what makes this class of
// defect invisible: it is CORRECT until a date, and the date is set by someone else.
//
// So this gate does not check that the arithmetic is right today. It checks that the arithmetic CANNOT carry a
// width: in the code paths that consume an externally-supplied index, fixed-width bitwise operators are forbidden
// outright and the BigInt forms are required. A future edit that reintroduces `>> 1` fails here rather than in
// three years, on a live anchor, presenting as a substrate outage.
import { readFileSync } from 'node:fs';

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const SRC = readFileSync(new URL('../packages/ust-rekor-verify/index.mjs', import.meta.url), 'utf8');
const fn = SRC.slice(SRC.indexOf('export function verifyInclusion'), SRC.indexOf('\n// Verify a Sigstore'));
check(fn.length > 200, 'verifyInclusion not found — the gate would be vacuous');

// 1. NO fixed-width bitwise operator survives on the climb. `>> 1` / `& 1` without the n suffix is the exact defect.
// comments are where the defect is DOCUMENTED — '2149645490 >> 1 = …' must not read as the defect recurring.
// Strip line comments before scanning, so the gate judges code and the record of the bug can stay verbatim.
const code = fn.split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');
const narrow = [...code.matchAll(/(?:>>=?|<<=?|&|\|)\s*(\d+)(?!n)\b/g)].map((m) => m[0].trim());
check(narrow.length === 0,
  `fixed-width bitwise arithmetic on the inclusion climb: ${narrow.join(', ')} — an index at or above 2^31 goes NEGATIVE here, and no test below that boundary can show it`);

// 2. the BigInt forms are PRESENT — absence of `>> 1` is also satisfied by deleting the climb entirely
check(/fn >>= 1n/.test(fn) && /sn >>= 1n/.test(fn), 'the climb no longer advances with BigInt shifts');
check(/\(fn & 1n\) === 1n/.test(fn), 'the parity test is no longer BigInt — `fn & 1` on a 2^31 index is where this began');
check(/BigInt\(index\)/.test(fn) && /BigInt\(treeSize\)/.test(fn), 'the index and tree size are no longer widened on entry');

// 3. a string index must be ACCEPTED, not rejected: past 2^53 a log MUST serve uint64 as a string, and a
//    `typeof index !== 'number'` guard would reinstate the same ceiling one power higher.
check(!/typeof index !== 'number'/.test(fn) && !/typeof treeSize !== 'number'/.test(fn),
  'a number-only type guard is back — that is the same ceiling at 2^53 instead of 2^31');

// 4. and it must still FAIL CLOSED on input that is not a number at all
check(/catch \{ return false; \}/.test(fn) || /catch \{ return false \}/.test(fn),
  'widening no longer fails closed — a non-numeric index must be `false`, never a host throw');

// 5. the boundary must be EXERCISED somewhere, or this gate guards a claim nothing demonstrates
const REG = readFileSync(new URL('../packages/ust-cli/regression.mjs', import.meta.url), 'utf8');
check(/2 \*\* 31|2147483648|2149645490/.test(REG),
  'no test exercises an index at or above 2^31 — the defect that shipped had 100% green gates and every vector below the boundary');

console.log(`\n  unbounded index    PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ the climb cannot carry a width — an external counter has no ceiling we may assume');
