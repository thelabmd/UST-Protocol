// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the axis list is READ from §14 of the specification, never typed here; the check is
// that the page consumes each axis from the verdict object, not that it prints a particular sentence about it.
//
// VERDICT-AXIS DISPLAY GATE (round 242) — an axis the verifier decides and the page does not show is an axis the
// reader is told nothing about.
//
// Measured 2026-08-30 on the public page — CLOSED 2026-08-30 by this gate and the Time card it watches —
// against our own published transcript whose hour root is final in Bitcoin at block 964576. The core returned:
//
//   verdict.time = { strength: "anchored", status: "verified", inclusion: true,
//                    anchorTime: "2026-08-29T13:38:38Z", assurance: "explorer-corroborated" }
//
// and the page rendered `VALID:HIGH` plus an identity block — nothing about time at all. The strings `964576` and
// `13:38:38` did not occur in the document. So a transcript anchored in Bitcoin was displayed exactly like one
// carrying no anchor, on the single surface a stranger actually visits. CLOSED 2026-08-30 by this gate and the
// Time card it watches.
//
// WORSE, AND FOUND WHILE FIXING IT: the "Proven / Not proven" lists were CONSTANTS. On that same anchored document
// the page asserted *"independently proven time — an anchor is TOP"* under **Not proven**, contradicting the very
// verdict it was rendering, and *"the no-fork witness — you asserted it"* when the witness had corroborated. A
// constant list is a claim nobody checks. Both are derived from the verdict now.
//
// WHY THE DOMAIN COMES FROM THE SPEC. §14 names the per-axis strengths. Reading them from the specification means a
// fourth axis enters this gate's domain the day it becomes normative, rather than the day somebody remembers to
// edit a list here — the failure mode this repository keeps meeting under other names.
//
// WHAT IT DOES NOT CHECK. Not the wording, not the layout, not whether the value is rendered *well*. A gate over
// prose would start defending today's sentences; this one asserts only that the page READS each axis off the
// verdict. What the reader sees is judged by the eye, and by the walkthrough that films it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const SPEC = readFileSync(ROOT + 'spec/UST-1.0.md', 'utf8');
const PAGE = readFileSync(ROOT + 'docs/index.html', 'utf8');

// §14: "Per-axis strengths (identity / time / completeness) remain below for detail."
const m = SPEC.match(/Per-axis\s*\n?\s*strengths?\s*\(([^)]+)\)/);
check(!!m, '§14 no longer states the per-axis strengths in the form this gate reads — the domain would be empty, and a gate over an empty domain passes for free');
const axes = m ? m[1].split('/').map((a) => a.trim().toLowerCase()).filter((a) => /^[a-z_]+$/.test(a)) : [];
check(axes.length >= 3, `only ${axes.length} axis name(s) parsed from §14 — expected the full set the spec enumerates`);

for (const ax of axes) {
  // the page must CONSUME the axis off the verdict object; how it labels it is not this gate's business
  const readsVerdict = new RegExp(`\\br(?:\\s*&&\\s*r)?\\.${ax}\\b`).test(PAGE);
  const readsResolution = ax === 'identity' && /resolution\.strength\b/.test(PAGE);
  check(readsVerdict || readsResolution,
    `docs/index.html never reads the \`${ax}\` axis off the verdict — §14 decides it and the page shows the reader nothing about it (round 242: this is how an anchored document looked identical to an unanchored one)`);
}

// The two derived lists: proven/unproven must be BUILT, not literal. A constant list contradicted the verdict for
// as long as it existed, so the gate refuses the shape rather than the sentence.
// `unprovenItems` CONTAINS `provenItems` as a substring, so the first draft of this check passed even with the
// positive list deleted — caught by mutating the page and watching this gate stay green. Word-boundary both.
check(/(?<![A-Za-z])provenItems\s*=/.test(PAGE) && /(?<![A-Za-z])unprovenItems\s*=/.test(PAGE),
  'the Proven / Not proven lists are no longer assembled from the verdict — a constant list is a claim nobody checks, and the last one contradicted an anchored verdict for weeks');
check(/isAnchored/.test(PAGE) && /witnessCorroborated/.test(PAGE),
  'the page no longer branches on the verdict\'s own anchored / corroborated facts when composing those lists');

// CONTROL — the axis probe must be able to say NO, proven here rather than asserted in a comment.
{
  const fake = 'function render(r){ return r.identity + r.time; }';
  const sees = (src, ax) => new RegExp(`\\br(?:\\s*&&\\s*r)?\\.${ax}\\b`).test(src);
  check(sees(fake, 'time'), 'CONTROL: the probe missed an axis that IS read — it would report false failures');
  check(!sees(fake, 'completeness'), 'CONTROL: the probe reported an axis that is NOT read — every pass above is free');
}

console.log(`\n  verdict-axis display   PASS ${pass}   FAIL ${fail.length}   (axes read from §14: ${axes.join(', ') || 'none'})`);
for (const f of fail) console.log('    ✗ ' + f);
if (fail.length) process.exit(1);
console.log('  ✓ every axis §14 decides is consumed by the page, and the tier reasoning is derived from the verdict');
