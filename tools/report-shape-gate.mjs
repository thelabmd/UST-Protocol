// SPDX-License-Identifier: Apache-2.0
// Report SHAPE gate (rev93) — what a verifier may put in a slot it could not fill, and what vocabulary it may use
// at all. Two domains, both ENUMERATED rather than sampled, because sampling is how each of these got in.
//
// What it exists for, all measured:
//   · `noFork: 'unconfirmed'` shipped under the spec's OWN `no_fork` field name while the word occurred ZERO times
//     in the spec, the formal model and the vectors. A word minted for an empty slot is unfalsifiable by
//     construction — nothing can contradict it, because it denotes nothing — and a consuming agent reading the
//     field alone takes it for a measurement that happened.
//   · the clean-room verifiers kept the `pinned`/TOFU rung that round-53 RETIRED, together with an `opts.pinnedKeys`
//     the reference does not have at all (0 mentions). That was a VERDICT divergence, not a label one: with
//     `pinnedKeys` naming other keys, the reference returned VALID:LIGHT and the clean-room INVALID E-KEY on the
//     same document — against the README's promise that two conforming verifiers agree.
//   · `docs-verifier-parity` was green throughout, because its battery compares DOCUMENTS and never varied the
//     OPTIONS. An option the second implementation reads and the reference has never heard of is unreachable by
//     any document-shaped probe.
import { readFileSync } from 'node:fs';
import * as P from '../packages/ust-protocol/index.mjs';

const U = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const CORE = U('packages/ust-protocol/index.mjs');
const WEB = U('docs/ust-verify.mjs');
const EXT = U('extension/lib/ust-verify.mjs');
const SPEC = U('spec/UST-1.0.md');
const MODEL = U('spec/UST-1.0-formal-model.md');
const VEC = U('vectors/conformance-vectors.json');

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// ── 1. the identity-strength vocabulary is DECLARED in the core, and the declaration is the domain. Read out of the
// source rather than restated here, so the gate cannot drift from the thing it guards.
const declared = CORE.match(/identity:\s*\[([^\]]+)\]/);
check(declared !== null, 'the core no longer DECLARES its identity-strength set — the gate has nothing to compare against');
const LADDER = declared ? [...declared[1].matchAll(/'([a-z-]+)'/g)].map((m) => m[1]) : [];
check(LADDER.length >= 3, `the declared ladder has ${LADDER.length} rungs — the probe has gone vacuous`);

// `consumer-override` is legal and DELIBERATELY not a rung: spec §12.1a calls it "DISTINCT from `authoritative`,
// honored only on explicit opt-in". Listed here with its reason rather than silently tolerated by a loose regex.
const NON_RUNG = { 'consumer-override': 'spec §12.1a — a raw caller override, DISTINCT from the ladder and honored only on opt-in' };
const LEGAL = new Set([...LADDER, ...Object.keys(NON_RUNG)]);

for (const [name, src] of [['core', CORE], ['docs/ust-verify.mjs', WEB], ['extension/lib/ust-verify.mjs', EXT]]) {
  // every value ASSIGNED to a strength must be in the legal set. `strength: 'unproven'` in the core is the TIME
  // coordinate, not identity — matched separately below so this probe does not silently conflate two axes.
  const assigned = new Set([...src.matchAll(/\bstrength\s*[:=]\s*'([a-z-]+)'/g)].map((m) => m[1]));
  const timeOnly = new Set(['unproven']);   // TimeStrength's floor (`{ strength: 'unproven', status: 'none' }`)
  for (const v of assigned) {
    if (timeOnly.has(v)) continue;
    check(LEGAL.has(v), `${name} emits strength '${v}', which is not in the core's declared identity set [${[...LEGAL].join(', ')}] — a retired or invented rung`);
  }
  check(assigned.size > 0, `${name}: no strength assignment found — the probe is vacuous for it`);
}

// ── 2. no verdict vocabulary may be a word the NORMATIVE CORPUS has never heard of. This is the `unconfirmed` class:
// the value looks enumerated, sits in an enumerated-looking field, and denotes nothing.
const basisValues = new Set([...CORE.matchAll(/\bnoFork:\s*'([a-z][a-z-]*)'/g)].map((m) => m[1]));
check(basisValues.size > 0, 'no no-fork basis values found in the core — the probe is vacuous');
for (const v of basisValues) {
  const known = SPEC.includes(v) || MODEL.includes(v) || VEC.includes(v);
  check(known, `the core emits no_fork basis '${v}', a word that occurs in NEITHER the spec, the formal model NOR the vectors — an invented value cannot be contradicted, and is read as a measurement that happened`);
}

// ── 3. the OPTIONS surface. Every `opts.X` a second implementation reads must be one the reference reads too, or the
// two can diverge on an input no document-shaped parity battery will ever construct.
// The reference does NOT read its options as `opts.X` — it destructures them, and `authority` alone appears 162
// times there while `opts.authority` appears zero. My first probe compared ACCESS SYNTAX and reported three defects
// that were entirely its own; the option NAME is what has to match, however each side reaches it.
const optsOf = (src) => new Set([...src.matchAll(/\bopts\.([A-Za-z_$][\w$]*)/g)].map((m) => m[1]));
const readsName = (src, name) => new RegExp(`\\b${name}\\b`).test(src);
const coreOpts = optsOf(CORE);
check(coreOpts.size > 5, `the core opts probe found only ${coreOpts.size} options — vacuous`);
for (const [name, src] of [['docs/ust-verify.mjs', WEB], ['extension/lib/ust-verify.mjs', EXT]]) {
  const read = optsOf(src);
  check(read.size > 0, `${name}: no opts read — the probe is vacuous for it`);
  for (const o of read) {
    check(coreOpts.has(o) || readsName(CORE, o), `${name} reads opts.${o} and the reference knows no such option under ANY access form — the second implementation has a lever the first has never heard of, which is exactly how a VERDICT divergence hides from a document-only parity battery (measured once: opts.pinnedKeys)`);
  }
}

// ── 4. the rev93 discipline, BEHAVIOURALLY: named floor when the measurement ran, ABSENCE when it could not.
const invalid = P.verify({ ust: '1.0', state: {}, sig: {} }, { context: 'data' });
check(invalid.result === 'INVALID' && invalid.tier === 'NONE' && 'tier' in invalid, 'an INVALID verdict must carry the NAMED floor tier NONE — a named value is what distinguishes "measured, earned nothing" from "could not measure"');
check(!('no_fork' in invalid), 'an INVALID verdict surfaces a no-fork basis it never established');

// ── 5. the pin must be able to FAIL — each leg asserted against a value the code has never had.
check(!LEGAL.has('pinned'), 'the retired `pinned` rung is back in the DECLARED set — round-53 removed it, and the model still says the ladder is 3 rungs');
check(!basisValues.has('unconfirmed'), 'the invented basis word `unconfirmed` is back');
check(!coreOpts.has('pinnedKeys'), 'the reference has grown opts.pinnedKeys — if that is deliberate, the clean-room rung must come back WITH it, never before');
check(WEB === EXT, 'the two clean-room copies have drifted apart — a fix applied to one and not the other is the defect this gate was written for');

console.log(`\n  report shape   PASS ${pass}   FAIL ${fail.length}   (ladder [${LADDER.join(', ')}] · ${basisValues.size} basis values · ${coreOpts.size} reference options)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every strength and basis value is declared or normative; no second implementation reads an option the reference lacks');
console.log('    non-rung carried in-file: ' + Object.entries(NON_RUNG).map(([k, v]) => `${k} (${v})`).join(' · '));
