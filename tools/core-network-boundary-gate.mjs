// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the reaches are DISCOVERED from the core's source; the declaration is a pin the gate holds
// Core network-boundary gate (#162) — the core reaches the network from a NAMED set, and a new reach is a decision.
//
// `ust-protocol` is the offline-decidable floor plus two deliberate exceptions: resolving a name needs the network,
// and querying a witness needs the network. Both take an injectable `fetchImpl`, so a caller may pass a stub — the
// property is NOT "the core is offline". It is that network reach is confined to a set someone chose.
//
// Nothing said so until 2026-08-14. #88 asks for the decomposition that would move these out of the core; that is a
// large change and it has been open since 2026-07-18, during which the module went from ~220 KB to 440 512 B. This
// gate is not the decomposition. It is the thing that stops the boundary eroding while the decomposition waits: a
// third reach can still be added, but not quietly, and not without editing a file called "network boundary".
//
// The gate DISCOVERS its subject rather than naming it. That distinction is the whole lesson of #155: an enforcement
// written against the instances its author had in mind passes forever on exactly those instances.
import { readFileSync } from 'node:fs';

const CORE = 'packages/ust-protocol/index.mjs';
const src = readFileSync(new URL('../' + CORE, import.meta.url), 'utf8');

// DECLARED — the reaches someone chose, with the reason each one is network-bound. Adding an entry here is the
// decision the gate exists to force; it lives in the gate rather than beside the code so that the choice and the
// code cannot arrive in one careless diff.
const DECLARED = {
  witnessNoFork: '§12.1 no-fork: the witness log is fetched from the publisher and each anchor cross-checked against its substrate. A consumer may inject `fetchImpl` to supply the bytes itself.',
  resolveByDiscovery: '§20.1 discovery: genesis, key log, cadence and witness are read from `/.well-known/`. A consumer may inject `fetchImpl` to resolve from a cache or a mirror.',
};

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// Strip line comments so prose describing the boundary is not mistaken for a breach of it (the same trap
// `unbounded-index-gate` had to close: the record of a defect must not read as the defect).
const lines = src.split('\n');
const code = lines.map((l) => l.replace(/\/\/.*$/, ''));

// DISCOVERY — every way the global `fetch` can enter the core.
const PATTERNS = [/=\s*fetch\b/, /\bawait\s+fetch\s*\(/, /\bglobalThis\.fetch\b/, /\bwindow\.fetch\b/];
// Ownership is decided by BRACE DEPTH, not by "the nearest export above". Measured while mutation-proving this
// gate: a reach placed at module scope was attributed to `deriveAssurance`, the previous export, which does not
// reach the network at all. The gate went red — correctly — while naming the wrong export, which is the defect
// class this whole round is about. Depth 0 means module scope and says so.
const reaches = [];
let depth = 0, owner = '(module scope)';
code.forEach((l, i) => {
  const m = /^export\s+(?:async\s+)?(?:function|const|class)\s+([A-Za-z_$][\w$]*)/.exec(l);
  if (m && depth === 0) owner = m[1];
  const before = depth;
  if (PATTERNS.some((p) => p.test(l))) {
    reaches.push({ line: i + 1, owner: before > 0 ? owner : '(module scope)', text: lines[i].trim().slice(0, 90) });
  }
  // strings can carry braces; this file's are balanced per line in practice, and an imbalance would only ever
  // widen ownership to `(module scope)`, which fails LOUDER rather than quieter.
  for (const ch of l) { if (ch === '{') depth++; else if (ch === '}') depth = Math.max(0, depth - 1); }
  if (depth === 0) owner = '(module scope)';
});

// vacuity: a scanner that finds nothing passes everything, and this core is known to reach twice.
check(reaches.length > 0, `no network reach found in ${CORE} — the scanner has lost its subject, and every leg below would be vacuous`);

// 1. every DISCOVERED reach is declared, and the refusal ROUTES (F.5.1e) rather than only refusing.
for (const r of reaches) {
  if (DECLARED[r.owner]) { pass++; continue; }
  fail.push(`${CORE}:${r.line} — \`${r.owner}\` reaches the network and is NOT declared in this gate.\n`
    + `      ${r.text}\n`
    + `      Declared today: ${Object.keys(DECLARED).map((k) => '`' + k + '`').join(', ')}.\n`
    + `      Either inject the transport at the call site instead, or add \`${r.owner}\` to DECLARED with the reason it must be network-bound — and expect that reason to be read.`);
}

// 2. the declaration may not ROT. A name that no longer reaches has either moved out (good — remove it here, and
//    #88 gets a step) or been renamed (and the gate is now guarding nothing under an old name).
for (const name of Object.keys(DECLARED)) {
  const found = reaches.some((r) => r.owner === name);
  check(found, `\`${name}\` is declared as a network reach and no longer reaches — it was moved, renamed or removed. Delete it from DECLARED; if it moved OUT of the core, say so in #88, which is the card that wants exactly that.`);
}

const names = [...new Set(reaches.map((r) => r.owner))].sort();
console.log(`\n  core network boundary   PASS ${pass}   FAIL ${fail.length}   (${reaches.length} reach(es) in ${names.length} export(s): ${names.join(', ')})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ the core reaches the network only where someone declared it, and every declaration still reaches');
