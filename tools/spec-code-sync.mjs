// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — spec regions regenerated from the code REGISTRY and diffed
// spec↔code drift gate (UST-oy8) — LAYER 2: assert the canonical REGISTRY (index.mjs) EQUALS the code's ACTUAL literal
// usage. Layer 1 (spec == REGISTRY) is `gen-spec-registry.mjs && git diff --exit-code`. Together: spec == registry ==
// code, no silent string drift. This is the check that would have caught the 2026-07-14 drifts: E-ASSURANCE (thrown,
// not registered), the VerifiedEvidence field list, and the compareEvidenceOrder return enum.
import { readFileSync } from 'node:fs';
import { REGISTRY } from '../packages/ust-protocol/index.mjs';
import { REFERENCE_CHECKER_ERROR_CODES } from '../packages/ust-protocol/reference-checker.mjs';   // round-50 P1-04 — the L1 checker's OWN error namespace

// Strip the REGISTRY declaration itself, else its own array literals ('E-…', 'ust:…') read as "usage".
const full = readFileSync(new URL('../packages/ust-protocol/index.mjs', import.meta.url), 'utf8');
const src = full.replace(/export const REGISTRY = \{[\s\S]*?\n\};/, '');
// round-50 P1-04 — the gate scanned ONLY index.mjs, so the L1 proof-checker's 54 error codes were unregistered while the gate
// claimed "spec == registry == code" over the TCB. Scan reference-checker.mjs's error literals against its OWN registered set.
const refSrc = readFileSync(new URL('../packages/ust-protocol/reference-checker.mjs', import.meta.url), 'utf8').replace(/export const REFERENCE_CHECKER_ERROR_CODES = \[[\s\S]*?\n\];/, '');

const uniq = (a) => [...new Set(a)].sort();
let fail = 0; const report = [];
const check = (name, used, declared) => {
  const U = uniq(used), D = uniq(declared);
  const undeclared = U.filter((x) => !D.includes(x));     // code uses, REGISTRY omits ⇒ the E-ASSURANCE class
  const unused = D.filter((x) => !U.includes(x));         // REGISTRY declares, code (index.mjs) never uses ⇒ dead/wrong
  if (undeclared.length || unused.length) {
    fail++;
    report.push(`  ✗ ${name}:` + (undeclared.length ? ` code uses but REGISTRY omits [${undeclared}];` : '') + (unused.length ? ` REGISTRY declares but code never uses [${unused}]` : ''));
  } else report.push(`  ✓ ${name}: ${U.length} literals — code usage == REGISTRY`);
};

// hash domain tags — first arg of H('ust:…') / Hbytes('ust:…')
check('hashDomains', [...src.matchAll(/H(?:bytes)?\(\s*['"`](ust:[a-z0-9-]+)['"`]/g)].map((m) => m[1]), REGISTRY.hashDomains);
// signed purposes — purpose: 'ust:…'
check('purposes', [...src.matchAll(/purpose:\s*['"`](ust:[a-z-]+)['"`]/g)].map((m) => m[1]), REGISTRY.purposes);
// INVALID error codes — 'E-…' in any emit context (error:/code:/new Error)
// #144 — the union, because the two sets differ in MEANING, not in drift-risk: `errorCodes` are §14 verdicts about
// a document, `resolverErrorCodes` report that this build could not decide. This check exists to stop string drift,
// so it must see every emitted literal; the split lives in the REGISTRY (and in the spec) where the meaning does.
check('errorCodes', [...src.matchAll(/['"`](E-[A-Z]+)/g)].map((m) => m[1]), [...REGISTRY.errorCodes, ...REGISTRY.resolverErrorCodes]);
// compareEvidenceOrder returns — 2026-07-14 near-miss #2
const ceo = (src.match(/export function compareEvidenceOrder[\s\S]*?\n}/) || [''])[0];
check('evidenceOrder', [...ceo.matchAll(/return\s+['"`]([a-z-]+)['"`]/g)].map((m) => m[1]), REGISTRY.evidenceOrder);
// verifiedEvidence fields — 2026-07-14 near-miss #1 (handle the `facts = {}` default inside the destructuring)
const veSig = (src.match(/function verifiedEvidence\(\{([\s\S]*?)\}\s*\)/) || [null, ''])[1];
const veFields = veSig.split(',').map((s) => s.trim().split(/[=:\s]/)[0]).filter(Boolean);
check('verifiedEvidenceFields', veFields, [...REGISTRY.verifiedEvidenceFields.required, ...REGISTRY.verifiedEvidenceFields.optional]);
// round-50 P1-04 — the L1 checker's FULL error codes (E-CONFIG-*, E-TERM-*, E-WITNESS-* …, not the `E-[A-Z]+` prefixes) vs its
// own registered set: a new/typo checker code fails until registered. Closes the "index-only" blind spot over the TCB.
check('checkerErrorCodes', [...refSrc.matchAll(/['"`](E-[A-Z][A-Z0-9-]*)/g)].map((m) => m[1]), REFERENCE_CHECKER_ERROR_CODES);
// §14 verdict results — MEASURED, and the measurement must not absorb a collision. `result:` names TWO fields in the
// core: the §14 verdict, and `forkChoice`'s answer to "which candidate is canonical". They are measured SEPARATELY
// against separate registered sets, because widening one to cover the other would let a surface print a forkchoice
// outcome as a verdict — and `forkChoice` even returns the error code `E-PREV` under that name.
// comments stripped first, and by measurement: an earlier version of THIS check read a `result: 'CANONICAL'`
// written inside the REGISTRY comment three lines above it and reported the core as drifting.
const bare = src.replace(/\/\/[^\n]*/g, '');
// forkChoice is bounded by LINES, not by a lazy `\n}` — the lazy form stopped at an inner block and leaked
// the function's own vocabulary into the verdict set.
const bl = bare.split('\n');
const fcFrom = bl.findIndex((l) => l.startsWith('export async function forkChoice'));
const fcTo = bl.findIndex((l, i) => i > fcFrom && l.startsWith('export '));
const fcBody = bl.slice(fcFrom, fcTo).join('\n');
const fcResults = [...fcBody.matchAll(/result:\s*['"`]([A-Z][A-Z_-]*)['"`]/g)].map((m) => m[1]);
check('forkChoiceResults', fcResults, REGISTRY.forkChoiceResults);
const verdictResults = [...bare.replace(fcBody, '').matchAll(/result:\s*['"`]([A-Z][A-Z_-]*)['"`]/g)].map((m) => m[1]);
check('results', verdictResults, REGISTRY.results);
// round 199 — the DISCRIMINATOR's TOTALITY, not its presence. Everything else in this file compares a SET against a
// SET; this leg compares a COUNT against a COUNT, because the defect it exists for is one return out of eleven that
// forgot the field. A set check cannot see that: with ten correct returns the string is present and the set matches.
// Enumerated over the same line-bounded `fcBody` the vocabulary check uses, so the two cannot drift apart.
{
  const returns = fcBody.split('\n').filter((l) => /return\s*\{/.test(l));
  const tagged = returns.filter((l) => new RegExp(`kind:\\s*['"\`]${REGISTRY.forkChoiceKind}['"\`]`).test(l));
  const bad = returns.length - tagged.length;
  if (bad) { fail++; report.push(`  ✗ forkChoiceKind: ${bad} of ${returns.length} \`return {\` in forkChoice omit \`kind: '${REGISTRY.forkChoiceKind}'\` — a discriminator that is absent on one path lets a fork-choice outcome be read as a §14 verdict (F.5e.2a)`); }
  else if (!returns.length) { fail++; report.push('  ✗ forkChoiceKind: the enumeration found NO returns in forkChoice — the scanner lost its subject, so this leg would pass for anything'); }
  else report.push(`  ✓ forkChoiceKind: ${tagged.length}/${returns.length} forkChoice returns carry the registered discriminator`);
}
// §11.3 completeness words, from the field the stream verdict actually sets
check('completeness', [...src.matchAll(/\bcomplete:\s*['"`]([a-z-]+)['"`]/g)].map((m) => m[1]), REGISTRY.completeness);


console.log('\n  spec-code-sync (LAYER 2 — REGISTRY == code usage):');
report.forEach((r) => console.log(r));
console.log(fail ? `\n  ✗ ${fail} set(s) drifted — fix REGISTRY (index.mjs) in the SAME change as the code that moved` : '\n  ✓ every canonical set matches actual code usage');
process.exit(fail ? 1 : 0);
