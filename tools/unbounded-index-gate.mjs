// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the index handling extracted from every source that climbs an RFC 6962 path
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
//
// AND IT DISCOVERS ITS DOMAIN (#155). The first version of this gate named ONE file — the connector it was written
// for. The tree holds several climbs: the browser verifier is clean-room and may not import the connector, and every
// test that builds a root to check a verifier against climbs the same path itself. Those were all outside the rule,
// and the browser copy kept the 32-bit climb for sixteen days after the connector was fixed, failing every live
// anchor while the page blamed the reader's browser. A rule quantified over a class and enforced at a named instance
// is enforced nowhere else — so the subject here is DISCOVERED from the tree, and a third implementation is inside
// the rule the day it is written rather than the day somebody remembers this file exists.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };
const ROOT = new URL('..', import.meta.url).pathname;

// ── DISCOVERY. The marker is the RFC 6962 right-edge test `fn === sn`: it is what distinguishes this climb from
// every other loop, and it is present in the verifiers AND in the reference climbs the tests build roots with — a
// narrowing REFERENCE is just as fatal, since it would make a test AGREE with a narrowing verifier.
const tracked = execFileSync('git', ['ls-files', '*.mjs', '*.js', '*.ts'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter(Boolean).filter((f) => f !== 'tools/unbounded-index-gate.mjs');
const sites = tracked
  .map((f) => [f, readFileSync(new URL('../' + f, import.meta.url), 'utf8')])
  .filter(([, src]) => src.includes('fn === sn'));

// A discovery that finds one file is the defect this gate was rewritten for. The plurality is structural: the
// clean-room rule GUARANTEES a second implementation exists, so one hit means the scanner lost the tree.
check(sites.length >= 2, `discovery found ${sites.length} climb(s) — the clean-room rule guarantees at least two, so the scanner has lost its subject and this gate would pass for anything`);

for (const [name, src] of sites) {
  // comments are where the defect is DOCUMENTED — '2149645490 >> 1 = …' must not read as the defect recurring.
  // Strip line comments before scanning, so the gate judges code and the record of the bug can stay verbatim.
  const code = src.split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');

  // 1. NO fixed-width bitwise operator survives ON THE CLIMB VARIABLES. `fn >>= 1` / `(fn & 1)` is the exact defect.
  const narrow = [...code.matchAll(/\b(?:fn|sn)\b\s*(?:>>=?|<<=?|&|\|)\s*(\d+)(?!n)\b/g)].map((m) => m[0].trim());
  check(narrow.length === 0,
    `${name}: fixed-width bitwise arithmetic on the inclusion climb: ${narrow.join(', ')} — an index at or above 2^31 goes NEGATIVE here, and no test below that boundary can show it`);

  // 2. the BigInt forms are PRESENT — absence of `>> 1` is also satisfied by deleting the climb entirely
  check(/fn >>= 1n/.test(code) && /sn >>= 1n/.test(code), `${name}: the climb no longer advances with BigInt shifts`);
  check(/\(fn & 1n\) === 1n/.test(code), `${name}: the parity test is no longer BigInt — \`fn & 1\` on a 2^31 index is where this began`);

  // 3. widening must FAIL CLOSED — a non-numeric index is `false`, never a host throw
  check(/catch \{ return false/.test(code) || /catch \(/.test(code) || /^packages\/ust-(cli|protocol|operator)\//.test(name),
    `${name}: widening no longer fails closed — a non-numeric index must be a refusal, never a host throw`);
}

// 4. a string index must be ACCEPTED, not rejected: past 2^53 a log MUST serve uint64 as a string, and a
//    `typeof index !== 'number'` guard would reinstate the same ceiling one power higher.
for (const [name, src] of sites) {
  check(!/typeof index !== 'number'/.test(src) && !/typeof treeSize !== 'number'/.test(src),
    `${name}: a number-only type guard is back — that is the same ceiling at 2^53 instead of 2^31`);
}

// 5. the boundary must be EXERCISED, and by EVERY discovered verifier — a gate over a domain whose members are
//    never run is the shape that let this ship. `regression` covers the connector, `conformance` runs the connector
//    and the browser climb on the SAME paths and requires them to agree, above 2^31 and above 2^53.
const REG = readFileSync(new URL('../packages/ust-cli/regression.mjs', import.meta.url), 'utf8');
const CONF = readFileSync(new URL('../packages/ust-protocol/conformance.mjs', import.meta.url), 'utf8');
check(/2 \*\* 31|2147483648|2149645490/.test(REG),
  'no test exercises an index at or above 2^31 — the defect that shipped had 100% green gates and every vector below the boundary');
check(/2149645490/.test(CONF) && /rekorInclusion/.test(CONF) && /9007199254740993/.test(CONF),
  'conformance no longer runs the BROWSER climb against the connector above the boundary — the copy that shipped broken is the one a single-file gate cannot see');

console.log(`\n  unbounded index    PASS ${pass}   FAIL ${fail.length}   (${sites.length} climb sites discovered: ${sites.map(([f]) => f).join(', ')})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ the climb cannot carry a width — an external counter has no ceiling we may assume');
