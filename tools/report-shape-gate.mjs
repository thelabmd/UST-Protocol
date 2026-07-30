// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:NON_RUNG is a one-entry EXEMPTION that must cite its spec section, not the domain — deriving it from what the code emits would make the check circular — while the surfaces and the ladder are both derived
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
import { readFileSync, readdirSync } from 'node:fs';
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
// An exemption is where an invented rung would hide, so it must CITE the normative text that makes it legal — a prose
// reason can be written for anything, a section reference cannot.
for (const [k, why] of Object.entries(NON_RUNG))
  check(/§\d/.test(why) && why.length >= 40, `NON_RUNG['${k}'] must cite the spec section that makes it legal — an exemption without a citation is an invented rung with a sentence attached`);
const LEGAL = new Set([...LADDER, ...Object.keys(NON_RUNG)]);

// THE SURFACES ARE DERIVED, and the hand-typed trio was CORRECT — measured 2026-07-30, exactly three files in the
// tree assign a strength literal and they are those three. That is not a reason to keep typing them: a fourth
// implementation that starts emitting one would simply not be looked at, which is the same finding round 90 made
// about the display surfaces. The roster is every `.mjs` a package's own manifest SHIPS, plus the clean-room
// verifier and the extension's copy of it — the files that can put a rung in front of a consumer.
const STRENGTH = /\bstrength\s*[:=]\s*'([a-z-]+)'/g;
const candidates = readdirSync(new URL('../packages/', import.meta.url)).flatMap((p) => {
  try { return (JSON.parse(readFileSync(new URL(`../packages/${p}/package.json`, import.meta.url), 'utf8')).files ?? [])
    .filter((f) => f.endsWith('.mjs')).map((f) => `packages/${p}/${f.replace(/^\.\//, '')}`); } catch { return []; }
}).concat(readdirSync(new URL('../docs/', import.meta.url)).filter((f) => f.endsWith('.mjs')).map((f) => `docs/${f}`))
  .concat((() => { try { return readdirSync(new URL('../extension/lib/', import.meta.url)).filter((f) => f.endsWith('.mjs')).map((f) => `extension/lib/${f}`); } catch { return []; } })());
const SURFACES = candidates.map((f) => { try { return [f, readFileSync(new URL('../' + f, import.meta.url), 'utf8')]; } catch { return null; } })
  .filter((x) => x && STRENGTH.test(x[1]) && (STRENGTH.lastIndex = 0) === 0);
check(SURFACES.length >= 3, `only ${SURFACES.length} strength-emitting surface(s) derived — the scan has gone blind and this leg would pass vacuously`);
check(SURFACES.some(([f]) => f.endsWith('ust-protocol/index.mjs')), 'the core is not among the derived surfaces — the derivation is looking in the wrong place');
// CONTROL — the detector must discriminate, or the roster is everything or nothing.
check(/\bstrength\s*[:=]\s*'([a-z-]+)'/.test("strength: 'authoritative'") && !/\bstrength\s*[:=]\s*'([a-z-]+)'/.test('the strength of the claim'),
  'CONTROL: the strength-assignment detector does not discriminate an assignment from prose');

for (const [name, src] of SURFACES) {
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

// ── 4b. rev93 THIRD case — a filled slot the derivation refused to count. C3 neutralizes any strength whose status
// is not `verified` (it contributes the floor, never its own rung), so the label is INERT. That protects the tier;
// it does not protect the reader, who gets the earned coordinate and the discarded label side by side under the same
// word. Two enumerations, both over sets rather than examples:
//   (a) every strength the core returns carries a status, so the pair EXISTS to be shown;
//   (b) no surface renders a strength without it. `time` was already printed as `strength/status`; `identity` was
//       printed bare one line above it, so a neutralized label reached an operator with nothing beside it to say so.
// `[^;]*?` was the first shape and it was BLIND: a `detail` string containing a semicolon ("no-fork evidence; a
// served witness…") stopped the match before the statement end, so that return was not among the ones counted and
// its missing status could not be seen. Caught only by mutation-testing the leg — it reported 12 returns and 0
// defects while the defect was planted inside the 13th it could not parse.
const strengthReturns = [...CORE.matchAll(/return \{ strength: '[a-z-]+'[\s\S]*?\};/g)].map((m) => m[0]);
check(strengthReturns.length >= 12, `only ${strengthReturns.length} strength returns found — the probe is vacuous or has gone blind again`);
for (const r of strengthReturns) {
  check(/status:/.test(r), `a strength return carries no status — the pair cannot be shown, so the label is unqualifiable: ${r.slice(0, 90).replace(/\s+/g, ' ')}`);
}
for (const [name, src] of [['ust-cli', U('packages/ust-cli/index.mjs')], ['ust-mcp', U('packages/ust-mcp/index.mjs')]]) {
  // a rendered `X.strength` must have `X.status` in the SAME statement — the reader's unit is the line, not the object
  for (const m of src.matchAll(/^.*console\.log\([^\n]*\.strength[^\n]*$/gm)) {
    const line = m[0];
    check(/\.status/.test(line), `${name} renders a strength with no status in the same line — a neutralized label reaches the reader unqualified: ${line.trim().slice(0, 100)}`);
  }
}

// ── 5. the pin must be able to FAIL — each leg asserted against a value the code has never had.
check(!LEGAL.has('pinned'), 'the retired `pinned` rung is back in the DECLARED set — round-53 removed it, and the model still says the ladder is 3 rungs');
check(!basisValues.has('unconfirmed'), 'the invented basis word `unconfirmed` is back');
check(!coreOpts.has('pinnedKeys'), 'the reference has grown opts.pinnedKeys — if that is deliberate, the clean-room rung must come back WITH it, never before');
check(WEB === EXT, 'the two clean-room copies have drifted apart — a fix applied to one and not the other is the defect this gate was written for');

console.log(`\n  report shape   PASS ${pass}   FAIL ${fail.length}   (ladder [${LADDER.join(', ')}] · ${basisValues.size} basis values · ${coreOpts.size} reference options)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every strength and basis value is declared or normative; no second implementation reads an option the reference lacks');
console.log('    non-rung carried in-file: ' + Object.entries(NON_RUNG).map(([k, v]) => `${k} (${v})`).join(' · '));
