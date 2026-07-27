// SPDX-License-Identifier: Apache-2.0
// Ladder COMPLETENESS gate (#99) — the law of this repo is `math → spec → code → vector → test`, in BOTH
// directions, closed by a CHANGELOG row. Nothing enumerated the law itself, so on 2026-07-27 three rounds shipped
// with layers skipped and all 42 gates stayed green through every one of them:
//
//   rev92(d)  math ✗  spec ✗  code ✓  vector ✗  test ✓
//   rev93     math ✓  spec ✓  code ✓  vector ✗  test ✓
//   rev94     math ✓  spec ✗  code ✓  vector ✗  test ✓   ← spec and vector filled only because the owner ASKED
//
// Every artifact looked complete: green CI, a dense changelog row, a passing conformance suite.
//
// SOME SKIPS ARE LEGITIMATE, AND THAT IS THE WHOLE DESIGN. rev92's argv half genuinely has no formal-model content
// — "a verdict is a function of its argument" is what a function IS, not a theorem — and forcing model prose to
// satisfy a gate would be the patch this repo rejects. So the gate does NOT demand a reference on every layer. It
// demands a DECISION on every layer: a reference that RESOLVES, or an exclusion carrying its reason IN THE FILE.
// Same discipline already used for excluded members elsewhere: the boundary is visible rather than absent.
import { readFileSync } from 'node:fs';

const U = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const REG = JSON.parse(U('tools/ladder-registry.json'));
const MODEL = U('spec/UST-1.0-formal-model.md');
const SPEC = U('spec/UST-1.0.md');
const CHANGELOG = U('CHANGELOG.md');
const VECTORS = JSON.parse(U('vectors/conformance-vectors.json')).vectors;
const EXECUTED = new Set(JSON.parse(U('vectors/conformance-checks.json')).checks ?? JSON.parse(U('vectors/conformance-checks.json')));

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const LAYERS = ['math', 'spec', 'code', 'vector', 'test'];
const MIN_REASON = 60;   // a reason shorter than this is a placeholder, not a decision

// Each layer's reference must RESOLVE against the artifact it names — a registry of strings nobody checks is a
// second place to be wrong, which is the defect class this repo spends most of its gates on.
const RESOLVES = {
  math: (v) => MODEL.includes(v),
  spec: (v) => SPEC.includes(v),
  code: (v) => { const f = v.split(' :: ')[0].trim(); try { U(f); return true; } catch { return false; } },
  vector: (v) => VECTORS.some((x) => x.id === v),
  test: (v) => EXECUTED.has(v),
};

check(Array.isArray(REG.records) && REG.records.length > 0, 'the ladder registry is empty — the gate would be vacuous');

for (const rec of REG.records) {
  check(/^rev\d+$/.test(rec.rev || ''), `a record has no well-formed rev: ${JSON.stringify(rec.rev)}`);
  // the round it accounts for must EXIST in the ladder
  check(new RegExp(`^\\| \\*\\*${rec.rev}\\*\\*`, 'm').test(CHANGELOG), `${rec.rev} is accounted for here but has no row in the CHANGELOG ladder`);
  for (const layer of LAYERS) {
    const v = rec[layer];
    if (v === undefined || v === null) { fail.push(`${rec.rev}: layer '${layer}' is neither referenced nor excluded — an ABSENCE, which is exactly what this gate exists to stop`); continue; }
    if (typeof v === 'object') {
      const why = (v.excluded ?? '').trim();
      check(why.length >= MIN_REASON, `${rec.rev}: layer '${layer}' is excluded with a reason of ${why.length} chars — under ${MIN_REASON} is a placeholder, not a decision`);
      continue;
    }
    check(typeof v === 'string' && v.trim().length > 0, `${rec.rev}: layer '${layer}' is an empty reference`);
    check(RESOLVES[layer](v), `${rec.rev}: layer '${layer}' names "${String(v).slice(0, 70)}…" and it does NOT resolve in the artifact it points at — a registry nobody checks is a second place to be wrong`);
  }
}

// ── the RETRO baseline. 94 rows existed when this landed and they cannot be back-filled in one sitting, so the
// unaccounted count is pinned and may only ever SHRINK — the same shape as the vacuity residual pin.
const ladderRevs = [...CHANGELOG.matchAll(/^\| \*\*rev(\d+)\*\*/gm)].map((m) => 'rev' + m[1]);
const accounted = new Set(REG.records.map((r) => r.rev));
const unaccounted = ladderRevs.filter((r) => !accounted.has(r));
check(ladderRevs.length > 0, 'no rev rows found in the CHANGELOG — the retro probe has gone blind');
check(unaccounted.length <= REG.unaccounted_pin,
  `the UNACCOUNTED residual grew: ${unaccounted.length} ladder rows have no record, pinned at ${REG.unaccounted_pin}. A NEW round must be accounted for; lower the pin as old ones are back-filled, never raise it.`);
if (unaccounted.length < REG.unaccounted_pin) console.log(`  ℹ  unaccounted ${unaccounted.length} < pin ${REG.unaccounted_pin} — lower the pin in tools/ladder-registry.json`);

// ── the pin must be able to FAIL, and so must each leg.
check(REG.unaccounted_pin < ladderRevs.length, 'the pin is not below the row count — it would accept a fully unaccounted ladder');
check(!RESOLVES.vector('this-vector-does-not-exist'), 'the vector resolver accepts a name no vector carries — leg would pass for anything');
check(!RESOLVES.test('this check never ran'), 'the test resolver accepts an id the executed manifest lacks');
check(!RESOLVES.math('a sentence the formal model does not contain at all, anywhere'), 'the math resolver accepts prose the model lacks');

console.log(`\n  ladder completeness   PASS ${pass}   FAIL ${fail.length}   (${REG.records.length} accounted · ${unaccounted.length} unaccounted, pin ${REG.unaccounted_pin} · ${LAYERS.length} layers)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every accounted round decides all five layers — each reference resolves, each exclusion carries its reason');
