// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — ops and per-op fields enumerated from the reducer that enforces them
// KEY-OP CONTRACT GATE — what a surface TELLS a producer to build must be what the verifier admits.
//
// MEASURED 2026-07-29, and it had been wrong for three rounds: the MCP tool `ust_build_key_log` advertised
// `{ op:"add"|"rotate"|"revoke", pub, new_key_id?, reason?, compromised_since? }`. `rotate` was REMOVED in rev97
// (a self-authorized succession let a compromised key name its own successor), `supersedes` was added in the same
// round and `role` in round 79 — so the contract named one op the verifier refuses and omitted the two fields it
// had gained. An agent building from that description produces an entry that fails E-KEY, and agents are
// first-class publishers here.
//
// CLOSED 2026-07-29 — in the same round that added this gate, 2026-07-29 (round 84): `ust_build_key_log` now
// advertises `add|revoke|reroot` with `supersedes` and `role`, and the comparison below is what keeps it true.
// Noted 2026-08-05, appended rather than rewritten.
//
// WHY NOTHING CAUGHT IT. `retired-mechanisms-gate` exists for exactly this class and reads the SPEC and the FORMAL
// MODEL only — by design, it guards documents. `spec-code-sync` binds the canonical string sets in REGISTRY, and
// `OP_FIELDS` is not one of them: it is a function-local const in the reducer, so no gate had a reason to look at
// it. Between them the two documents were guarded and the two producer-facing contracts were not.
//
// The word is also a trap, which is why this gate does NOT grep for `rotate`. `ust rotate` is a LIVE CLI command
// and `rotateKeylog` a live export; only the key-log OP of that name is retired. A textual sweep would have to
// tell those apart and would get it wrong — so the gate enumerates the DOMAIN from the source instead: the ops and
// per-op fields the reducer actually admits, compared BOTH WAYS against every contract that describes them.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const U = (p) => readFileSync(ROOT + p, 'utf8');

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };
const set = (a) => [...new Set(a)].sort().join(', ');

// ── THE DOMAIN, from the reducer that enforces it. Comments are stripped first: a fields list quoted inside a
// note is not the rule, and reading one would let a stale comment define the contract.
const core = U('packages/ust-protocol/index.mjs').replace(/\/\/[^\n]*/g, '');
const decl = /const OP_FIELDS = [^;]+;/.exec(core);
check(!!decl, 'OP_FIELDS was not found in packages/ust-protocol/index.mjs — the gate has no domain and would pass vacuously');
const OPS = new Map();
if (decl) for (const m of decl[0].matchAll(/(\w+):\s*\[([^\]]*)\]/g))
  OPS.set(m[1], m[2].split(',').map((s) => s.trim().replace(/['"]/g, '')).filter(Boolean).filter((f) => f !== 'op'));
check(OPS.size >= 2, `OP_FIELDS yielded ${OPS.size} op(s) — the extraction has gone blind`);

// ── every surface that TELLS a producer what a key_op looks like. The roster below was TYPED, and measured
// 2026-07-30 it is complete — exactly two files in the tree describe key_op fields to a producer, and they are these
// two. A correct list is not a checked list (rounds 90 and 100 found the same thing twice): a THIRD contract added
// tomorrow would simply not be looked at. So the candidates are DERIVED and every one of them must be in the roster.
const DESCRIBES = /op:\s*"add|\{\s*op,\s*pub/;
const candidates = [
  ...readdirSync(new URL('../packages/', import.meta.url)).flatMap((pk) => {
    try { return (JSON.parse(readFileSync(new URL(`../packages/${pk}/package.json`, import.meta.url), 'utf8')).files ?? [])
      .filter((f) => f.endsWith('.mjs')).map((f) => `packages/${pk}/${f.replace(/^\.\//, '')}`); } catch { return []; }
  }),
  'spec/UST-1.0.md', 'spec/UST-1.0-formal-model.md',
  ...readdirSync(new URL('../docs/', import.meta.url)).filter((f) => f.endsWith('.mjs')).map((f) => `docs/${f}`),
].filter((f) => { try { return DESCRIBES.test(U(f)); } catch { return false; } });
check(candidates.length >= 2, `only ${candidates.length} producer-facing key_op description(s) found — the derivation has gone blind and this roster would be unchecked`);
// CONTROL — the detector must discriminate a field list from a mere mention of `key_op`.
check(DESCRIBES.test('op:"add", pub') && !DESCRIBES.test('the key_op walk rejects it'),
  'CONTROL: the contract detector does not tell a field list from prose that merely names key_op');
const CONTRACTS = [
  { id: 'ust-mcp :: ust_build_key_log', src: U('packages/ust-mcp/index.mjs'),
    rx: /key_op: \{ type: 'object', description: '([^']*)'/ },
  { id: 'spec §12.2 :: per-op field list', src: U('spec/UST-1.0.md'),
    rx: /per op \(([^)]*\}[^)]*)\)/ },
];

for (const c of CONTRACTS) {
  const m = c.rx.exec(c.src);
  check(!!m, `${c.id}: the contract text was not found — a surface that stopped matching is a surface that stopped being checked`);
  if (!m) continue;
  const text = m[1];
  // `op:"add", pub, role?` and `add: {op, pub, role?}` are the two shapes in use; both name the op and then its
  // fields, so both are read the same way — split on the op boundary, take the first token of each item.
  const found = new Map();
  for (const b of text.matchAll(/(?:op:\s*"(\w+)"([^}]*)|\b(\w+):\s*\{([^}]*))/g)) {
    const op = b[1] ?? b[3];
    const fields = (b[2] ?? b[4] ?? '').split(',')
      .map((s) => s.trim().replace(/[`"'{}]/g, '').split(/[\s?]/)[0])
      .filter((f) => f && f !== 'op');
    if (op) found.set(op, fields);
  }
  check(found.size > 0, `${c.id}: no op was parsed out of the contract text — the probe proves nothing`);
  check(set([...found.keys()]) === set([...OPS.keys()]),
    `${c.id}: advertises ops [${set([...found.keys()])}] and the reducer admits [${set([...OPS.keys()])}] — a producer told to build an op the verifier refuses builds an entry that fails E-KEY`);
  for (const [op, fields] of found) {
    if (!OPS.has(op)) continue;
    check(set(fields) === set(OPS.get(op)),
      `${c.id}: op \`${op}\` advertises fields [${set(fields)}] and the reducer admits [${set(OPS.get(op))}] — a field missing here is a capability a producer cannot discover; a field extra here is an entry that fails E-MALFORMED`);
  }
}

// every DERIVED candidate must be in the hand-written roster: a new contract fails here until it is checked
for (const c of candidates) check(CONTRACTS.some((x) => x.src === U(c)),
  `${c} describes a key_op to a producer and is NOT among the contracts this gate checks — add it, or it advertises whatever it likes`);

// the roster itself must be able to fail
check(CONTRACTS.length >= 2, 'fewer than two producer-facing contracts are enumerated — the roster has shrunk to a sample');
check(!OPS.has('rotate'), 'the reducer admits `rotate` again — rev97 removed it because a self-authorized succession let a compromised key name its own successor');

console.log(`\n  key_op contract   PASS ${pass}   FAIL ${fail.length}   (${OPS.size} ops from the reducer · ${CONTRACTS.length} producer-facing contracts, both directions)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every surface that tells a producer what to build names exactly the ops and fields the verifier admits');
