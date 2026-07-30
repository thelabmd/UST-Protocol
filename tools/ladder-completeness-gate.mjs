// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:LAYERS is the five-layer law itself, not a roster of instances — a wrong entry there would be a different law, not a stale list — live rounds enumerated from CHANGELOG; the retro pin bounds a CLOSED table only
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

// ── WHERE a round is recorded moved, and the gate had to move with it (round 77). The reference-checker rev-ladder
// is CLOSED at rev95, which carried rounds 1-61. The ROUND counter did not restart: round 62 onward are rows in the
// version-line tables (`## rc.NN line`), one continuous sequence — `revN` was the audited artifact's label, never the
// round number. Keying the law's accounting to a finished table meant a new round could only be accounted by
// being filed INTO that table — which is precisely the misfiling of round 76, where the gate's own demand for a
// ladder row pushed the record deeper into the wrong place instead of objecting to the place.
const VERSION_ROUNDS = (() => {                       // enumerate the DOMAIN from the file, never a sample
  const rounds = new Set();
  for (const sec of CHANGELOG.split(/^## /m)) {
    if (!/^rc\.\d+ line/.test(sec)) continue;         // version lines only — the ladder's 2nd column is also numeric
    for (const m of sec.matchAll(/^\| .+? \| (\d+) \|/gm)) rounds.add(Number(m[1]));
  }
  return rounds;
})();
check(VERSION_ROUNDS.size > 0, 'no version-line round rows found — the live probe has gone blind');

check(Array.isArray(REG.records) && REG.records.length > 0, 'the ladder registry is empty — the gate would be vacuous');

for (const rec of REG.records) {
  const isLadder = rec.rev !== undefined;
  const key = isLadder ? rec.rev : `round ${rec.round}`;
  if (isLadder) {
    check(/^rev\d+$/.test(rec.rev || ''), `a record has no well-formed rev: ${JSON.stringify(rec.rev)}`);
    // the round it accounts for must EXIST in the ladder
    check(new RegExp(`^\\| \\*\\*${rec.rev}\\*\\*`, 'm').test(CHANGELOG), `${rec.rev} is accounted for here but has no row in the CHANGELOG ladder`);
  } else {
    check(Number.isInteger(rec.round), `a record is keyed by neither a well-formed rev nor an integer round: ${JSON.stringify(rec)}`);
    check(VERSION_ROUNDS.has(rec.round), `${key} is accounted for here but has no row in any version-line table — a round is accounted where the work is RECORDED`);
  }
  for (const layer of LAYERS) {
    const v = rec[layer];
    if (v === undefined || v === null) { fail.push(`${key}: layer '${layer}' is neither referenced nor excluded — an ABSENCE, which is exactly what this gate exists to stop`); continue; }
    if (typeof v === 'object') {
      const why = (v.excluded ?? '').trim();
      check(why.length >= MIN_REASON, `${key}: layer '${layer}' is excluded with a reason of ${why.length} chars — under ${MIN_REASON} is a placeholder, not a decision`);
      continue;
    }
    check(typeof v === 'string' && v.trim().length > 0, `${key}: layer '${layer}' is an empty reference`);
    check(RESOLVES[layer](v), `${key}: layer '${layer}' names "${String(v).slice(0, 70)}…" and it does NOT resolve in the artifact it points at — a registry nobody checks is a second place to be wrong`);
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

// ── the LIVE leg (round 77). The retro pin above is a bound on a CLOSED table and can only shrink; it says nothing
// about work happening now. From `first_accounted_round` on, a version-line round MUST be accounted — no pin, no
// residual, no grace. Rounds below it predate the rule and are REPORTED rather than gated: pretending history
// complied would be the same dishonesty as a pin that silently rises.
const FIRST = REG.first_accounted_round;
const liveRounds = [...VERSION_ROUNDS].filter((r) => r >= FIRST).sort((a, b) => a - b);
const accountedRounds = new Set(REG.records.filter((r) => r.round !== undefined).map((r) => r.round));
check(Number.isInteger(FIRST), 'first_accounted_round is not an integer — the live leg would have no floor and pass for anything');
for (const r of liveRounds)
  check(accountedRounds.has(r), `round ${r} is RECORDED in a version line but has no five-layer record — the law applies to the round that shipped, not only to a closed audit arc`);
const legacyRounds = [...VERSION_ROUNDS].filter((r) => r < FIRST).length;
if (legacyRounds) console.log(`  ℹ  ${legacyRounds} version-line round(s) below the floor of ${FIRST} are reported, not gated — the rule starts where it was written, and says so`);

// ── the pin must be able to FAIL, and so must each leg.
check(REG.unaccounted_pin < ladderRevs.length, 'the pin is not below the row count — it would accept a fully unaccounted ladder');
check(liveRounds.length > 0, 'the live leg found no round at or above the floor — it would pass vacuously');
// The control below must be a DISCRIMINATION on real data, not an assertion against an impossible literal:
// `!VERSION_ROUNDS.has(-1)` was the first version of it and proved nothing, since no table can carry -1. A leg is
// shown to work by exhibiting a real row its predicate REFUSES — here a recorded round below the floor, which is
// genuinely unaccounted. If back-filling ever accounts for every legacy round this control goes silent, and the
// message says so rather than letting it rot into another free pass.
const belowFloor = [...VERSION_ROUNDS].filter((r) => r < FIRST);
const refused = belowFloor.filter((r) => !accountedRounds.has(r));
check(belowFloor.length === 0 || refused.length > 0,
  'the coverage predicate accepted every recorded round, including unaccounted ones below the floor — it does not discriminate, so the live leg would pass for anything');
check(!RESOLVES.vector('this-vector-does-not-exist'), 'the vector resolver accepts a name no vector carries — leg would pass for anything');
check(!RESOLVES.test('this check never ran'), 'the test resolver accepts an id the executed manifest lacks');
check(!RESOLVES.math('a sentence the formal model does not contain at all, anywhere'), 'the math resolver accepts prose the model lacks');

console.log(`\n  ladder completeness   PASS ${pass}   FAIL ${fail.length}   (${REG.records.length} accounted · ${unaccounted.length} unaccounted, pin ${REG.unaccounted_pin} · ${LAYERS.length} layers)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every accounted round decides all five layers — each reference resolves, each exclusion carries its reason');
