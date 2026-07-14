// SPDX-License-Identifier: Apache-2.0
// spec↔code drift gate (UST-oy8) — LAYER 2: assert the canonical REGISTRY (index.mjs) EQUALS the code's ACTUAL literal
// usage. Layer 1 (spec == REGISTRY) is `gen-spec-registry.mjs && git diff --exit-code`. Together: spec == registry ==
// code, no silent string drift. This is the check that would have caught the 2026-07-14 drifts: E-ASSURANCE (thrown,
// not registered), the VerifiedEvidence field list, and the compareEvidenceOrder return enum.
import { readFileSync } from 'node:fs';
import { REGISTRY } from '../packages/ust-protocol/index.mjs';

// Strip the REGISTRY declaration itself, else its own array literals ('E-…', 'ust:…') read as "usage".
const full = readFileSync(new URL('../packages/ust-protocol/index.mjs', import.meta.url), 'utf8');
const src = full.replace(/export const REGISTRY = \{[\s\S]*?\n\};/, '');

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
check('errorCodes', [...src.matchAll(/['"`](E-[A-Z]+)/g)].map((m) => m[1]), REGISTRY.errorCodes);
// compareEvidenceOrder returns — 2026-07-14 near-miss #2
const ceo = (src.match(/export function compareEvidenceOrder[\s\S]*?\n}/) || [''])[0];
check('evidenceOrder', [...ceo.matchAll(/return\s+['"`]([a-z-]+)['"`]/g)].map((m) => m[1]), REGISTRY.evidenceOrder);
// verifiedEvidence fields — 2026-07-14 near-miss #1 (handle the `facts = {}` default inside the destructuring)
const veSig = (src.match(/function verifiedEvidence\(\{([\s\S]*?)\}\s*\)/) || [null, ''])[1];
const veFields = veSig.split(',').map((s) => s.trim().split(/[=:\s]/)[0]).filter(Boolean);
check('verifiedEvidenceFields', veFields, [...REGISTRY.verifiedEvidenceFields.required, ...REGISTRY.verifiedEvidenceFields.optional]);

console.log('\n  spec-code-sync (LAYER 2 — REGISTRY == code usage):');
report.forEach((r) => console.log(r));
console.log(fail ? `\n  ✗ ${fail} set(s) drifted — fix REGISTRY (index.mjs) in the SAME change as the code that moved` : '\n  ✓ every canonical set matches actual code usage');
process.exit(fail ? 1 : 0);
