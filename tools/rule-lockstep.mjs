// SPDX-License-Identifier: Apache-2.0
// rule-lockstep — the §14 authority DECISION-RELATION is FROZEN (Q1, UST-y2p / spec §14+§15+§19 "never processes rules
// it doesn't have"). The 15 inference rules are a CLOSED set: RULE_CONTRACTS is the single source, REFERENCE_CHECKER_RULES
// derives from it, and every rule has a dispatch case. A 16th rule (a new RULE_CONTRACTS key) fails RED here — convergence
// is downstream of spec minimality, so the rule set cannot grow silently. Structural fail-closed already holds (decodeTerm
// rejects an unknown rule; the switch default is INVALID); this gate makes the FREEZE explicit + fail-RED, mirroring
// spec-code-sync for the error-code roster. The drift-guards meta-gate injects a 16th key and asserts this exits non-zero.
import { RULE_CONTRACTS, REFERENCE_CHECKER_RULES } from '../packages/ust-protocol/reference-checker.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const FROZEN = 15;
const keys = Object.keys(RULE_CONTRACTS);
const src = readFileSync(fileURLToPath(new URL('../packages/ust-protocol/reference-checker.mjs', import.meta.url)), 'utf8');
const caseLabels = new Set([...src.matchAll(/case '([A-Z][A-Za-z]+)':/g)].map((m) => m[1]));

let fail = 0; const F = [];
const ok = (name, cond) => { if (!cond) { F.push(name); fail++; } };

ok(`RULE_CONTRACTS cardinality === ${FROZEN} (the decision-relation is FROZEN; a 16th rule fails here)`, keys.length === FROZEN);
ok('REFERENCE_CHECKER_RULES === Object.keys(RULE_CONTRACTS) (registry parity)', REFERENCE_CHECKER_RULES.length === keys.length && REFERENCE_CHECKER_RULES.every((r, i) => r === keys[i]));
for (const k of keys) ok(`rule '${k}' has a dispatch case (contract → handler; no rule without a case)`, caseLabels.has(k));
ok(`exactly ${FROZEN} rule keys are dispatched (no rule silently un-handled)`, keys.filter((k) => caseLabels.has(k)).length === FROZEN);

if (fail) { console.log(`\n  rule-lockstep   FAIL ${fail}`); F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log(`\n  rule-lockstep   ✓ the §14 decision-relation is FROZEN: ${FROZEN} rules, RULE_CONTRACTS == REFERENCE_CHECKER_RULES, every rule dispatched`);
