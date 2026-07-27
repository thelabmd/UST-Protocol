// SPDX-License-Identifier: Apache-2.0
// prev-SCOPE gate — `provenance.prev` exists only inside a DECLARED sequenced stream (§11.3: "A one-off State
// outside any sequenced stream has no `prev` and is complete-strength `none`"). So a normative MUST that requires
// `prev` is satisfiable ONLY for a publisher who declared one. Stated without that scope it is not merely broad —
// it is UNSATISFIABLE, since it demands a record built from a field the publisher's stream does not have.
//
// MEASURED, 2026-07-27: §11.1's honest-gap rule read "A missing frame MUST be published as a signed gap record"
// with no scope at all. It sits in §11.1, so unlike every other prev-MUST it inherits nothing from a section
// heading. Read alone it obliges EVERY publisher, including containment-addressed ones like the notary journal
// whose verifier walks slot → hour → day and never slot → slot. That reading also contradicts the model, where the
// gap record is a condition of an EARNED property — *complete over [t₀,t₁]* holds when every grid point carries
// either a frame or a gap record — never a duty owed by all. The prose had overreached its own mathematics.
//
// Triaged honestly before reporting: a broad probe returned 15 candidates, a narrowed one 6, and exactly ONE was
// real. The other five carry their scope in their own subject ("a prev-only attestation…") or sit inside §11.3,
// whose heading IS the scope. The noise was the probe's, not the specification's.
import { readFileSync } from 'node:fs';

const lines = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8').split('\n');
const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// the section a line belongs to — the scope a MUST inherits for free
const sectionOf = (i) => { for (let k = i; k >= 0; k--) if (/^#{2,4} /.test(lines[k])) return lines[k]; return ''; };
const SCOPED_INLINE = /declared sequenced stream|within a declared|prev-only|sequenced stream \(§11\.3\)|§11\.3/i;
const SCOPED_SECTION = /Sequence completeness/i;

let musts = 0;
lines.forEach((l, i) => {
  if (!/MUST/.test(l) || !/\bprev\b/.test(l)) return;
  musts++;
  const near = lines.slice(Math.max(0, i - 2), i + 2).join(' ');
  check(SCOPED_SECTION.test(sectionOf(i)) || SCOPED_INLINE.test(near),
    `spec/UST-1.0.md:${i + 1} states a MUST requiring \`prev\` with no sequenced-stream scope — neither its section heading nor its own wording supplies one, so it obliges publishers who have no \`prev\` to give: ${l.trim().slice(0, 90)}`);
});
check(musts >= 5, `only ${musts} prev-MUSTs found — the probe has gone blind and the gate would pass vacuously`);

// the honest-gap rule specifically must carry its scope INLINE: it lives in §11.1 and inherits nothing
const gapLine = lines.findIndex((l) => /On-time or honest gap/.test(l));
check(gapLine >= 0, 'the honest-gap rule is gone from §11.1');
if (gapLine >= 0) {
  const para = lines.slice(gapLine, gapLine + 12).join(' ');
  check(/declared\s+sequenced stream \(§11\.3\)/i.test(para), 'the honest-gap MUST no longer names the declared sequenced stream it is scoped to — outside one it is unsatisfiable');
  check(/EARNED property|coarser verdict/i.test(para), 'the gap rule no longer states that the record is a condition of an earned property rather than a universal duty — the model\'s own framing');
  check(!SCOPED_SECTION.test(sectionOf(gapLine)), 'the honest-gap rule moved into §11.3; if that is deliberate the inline-scope requirement here is now redundant and should be retired, not left to pass for the wrong reason');
}

// each leg must be able to fail
check(!SCOPED_INLINE.test('a frame MUST be published as a signed gap record'), 'the inline probe accepts unscoped prose — leg would pass for anything');
check(!SCOPED_SECTION.test('### 11.1 Anchoring & honest gaps'), 'the section probe treats §11.1 as scoping — the exact confusion this gate exists to stop');

console.log(`\n  prev scope   PASS ${pass}   FAIL ${fail.length}   (${musts} prev-MUSTs)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every MUST requiring `prev` is scoped to a declared sequenced stream');
