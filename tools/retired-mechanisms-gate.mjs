// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — the fingerprint LIST is history and cannot be derived from anything; but the CODE side is now zero-tolerance over a roster derived from the shipping manifests
// RETIRED-MECHANISMS GATE — an abandoned path must not walk back into the documents.
//
// WHY THIS EXISTS. The rc.37 arc abandoned two whole approaches and retired a long list of individual mechanisms:
// theorems written ahead of the code, hand-enumerated coverage, the `pinned`/TOFU identity rung, the
// `keylogHeadAnchor → attested` shortcut, the byte-transparent mirror GOAL, the injectable-child-verdict tier, the
// positioned-`H(index)` SMT terminality proof, a public `opts.__nowMs` clock, `valid_as_of` and `reason` inside signed
// claims, the domain-less computed mode, secret-url as a privacy mode. Each was removed or corrected in its own rev.
//
// The documents keep the wrong formulation ON PURPOSE — the record of a mistake is part of the evidence, and the
// convention is to leave the note standing and append a `**Correction (revNN …)**` below it. That convention is right,
// and it creates exactly one hazard: a retired mechanism READS as live text, and nothing distinguished "preserved as a
// record" from "quietly still specified". At rev88 every occurrence below was reviewed by hand and found to be either a
// corrected note or a faithful `Appendix B` history entry — no live specification of a retired mechanism remained.
//
// This gate makes that verification durable WITHOUT a heuristic. It does not try to read English and guess whether a
// mention is historical — the arc already proved (rev78) that a regex lint asserted as a guarantee is a lie. It pins the
// OCCURRENCE COUNT of each retired mechanism's fingerprint. A count that rises means new prose mentions a retired
// mechanism: maybe a legitimate new history entry, maybe a resurrection. Either way it stops being invisible and a human
// must look and re-pin. A count that falls is fine (history was consolidated) and re-pins downward.
//
// HONEST LIMITS. (a) This is a TEXTUAL guard: it catches a retired mechanism returning under its own name, not the same
// unsound idea re-worded. (b) The fingerprint list is only as complete as the changelog's own record of what was
// retired — a wrong decision the ladder never wrote down is invisible here. (c) Counting is not reading: the gate
// proves nobody added a mention silently, not that the existing mentions are correct.
import { readFileSync, readdirSync } from 'node:fs';

const spec = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8');
const model = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');

// fingerprint → occurrences reviewed at rev88 { spec, model }
const RETIRED = [
  { id: 'prove-first metatheorem ladder', rx: /M-REL|M-ERA|M-PROV|M-BYTE-INJECTIVE|M-KEY-MONOTONE/g, retiredIn: 'pivot 1 (unrealizable — theorems ahead of the code hid P0s)', spec: 0, model: 0 },
  { id: 'injectable-child-verdict tier',  rx: /injectable/g,                    retiredIn: 'rev73 (architecturally VOID)',                    spec: 0, model: 3 },
  { id: 'byte-transparent mirror GOAL',   rx: /byte-transparent/g,              retiredIn: 'rev32 (impossible for a stateful Proxy)',          spec: 0, model: 3 },
  { id: 'pinned / TOFU identity rung',    rx: /\bTOFU\b/g,                      retiredIn: 'rev83 (does not survive rotation or takeover)',    spec: 2, model: 0 },   // round 216: REV 69 names it inside Corollary F.5a.2c's negative result — the enumeration of routes to a namespace authority that were CLOSED, with TOFU's own closure cited as the reason it is not revived. A history entry in the revision list, not a live rung.
  { id: 'keylogHeadAnchor → attested',    rx: /keylogHeadAnchor/g,              retiredIn: 'rev40 (anchored head ≠ latest head)',              spec: 4, model: 1 },   // round 180: the model gained ONE mention, in F.5.1d's realization note — a history entry naming the option a blind gate roster could not see. It describes a DEFECT in a checker, not a live inference to `attested`, and the two conformance checks named in CODE_EXEMPT still hold the retirement itself. Round 216: the spec gained a FOURTH, in REV 69, citing P0-03's deletion as the precedent for the same reasoning one axis over — membership-at-anchor is not latest-head, and a pinned map root is not a current one.
  { id: 'positioned H(index) SMT',        rx: /positioned[- ]SMT|positioned\s+sparse-Merkle/g, retiredIn: 'P0-02 external audit (says nothing about length+1)', spec: 4, model: 1 },
  { id: 'public opts.__nowMs clock',      rx: /__nowMs/g,                       retiredIn: 'rev33 (caller clock flipped the verdict)',         spec: 0, model: 3 },
  { id: 'valid_as_of in a signed claim',  rx: /valid_as_of/g,                   retiredIn: 'rev44 (signer self-declared time)',                spec: 1, model: 1 },   // round 220: both mentions are the SAME history entry, cited as the reason the new name-map-root claim carries no time — the retirement invoked as precedent, never re-specified
  { id: 'domain-less computed mode',      rx: /domain-less/g,                   retiredIn: 'owner 2026-07-05 (forgeable cross-engine agreement)', spec: 4, model: 0 },
  { id: 'secret-url privacy mode',        rx: /secret[- ]url/g,                 retiredIn: 'rc.4 (a disclosure channel, out of scope)',        spec: 1, model: 0 },
  { id: 'first-wins / hash dedupe in forkChoice', rx: /first-wins|content_hash[- ]dedupe/g, retiredIn: 'rev18/19/20 (hid equivocation)',       spec: 1, model: 2 },
  // rev97 removed the key-log `rotate` OP, and round 74's sweep never added it here — measured 2026-07-29, three
  // rounds later, while it was still being advertised to agents by the MCP tool description. The fingerprint is the
  // OP FORM, not the bare word: `ust rotate` is a live CLI command and `rotateKeylog` a live export, so /rotate/
  // would churn on every unrelated edit and teach a reader to ignore this gate. Code surfaces are covered by
  // tools/keyop-contract-gate.mjs, which enumerates the domain from the reducer instead of matching text.
//
// CLOSED 2026-07-29 by `f21e7db4` — round 84: whether a key needs a role is a property of the GENESIS, not
// of the command (#109). In this tree a narration is written in the commit that fixes what it describes, and
// blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  { id: 'key-log `rotate` op',            rx: /op:\s*.?rotate/g,               retiredIn: 'rev97 (self-authorized succession named its own successor)', spec: 1, model: 2 },
  { id: 'depth-64 cap in admitDeep',      rx: /depth[- ]64/g,                   retiredIn: 'rev30 (falsely rejected a valid deep document)',   spec: 0, model: 1 },
];

// ── THE CODE SIDE, and it is where the real miss happened. Round 84: the key-log `rotate` op, removed in rev97, was
// still advertised to agents by the MCP tool description for THREE ROUNDS while this gate ran green — correctly, since
// it reads the two DOCUMENTS by design. So the same fingerprints are now checked against SHIPPED CODE, and there the
// rule is ZERO rather than a pin: a retired mechanism may be REMEMBERED in a comment (that convention is right and is
// why comments are stripped first) but it may not appear in code that runs.
//
// The roster is DERIVED, not typed: every `.mjs` each package's own manifest says it SHIPS, plus the clean-room
// verifiers we serve from docs/. A new package or a new shipped file is covered the moment it is declared.
const shipped = readdirSync(new URL('../packages/', import.meta.url)).flatMap((p) => {
  try { return (JSON.parse(readFileSync(new URL(`../packages/${p}/package.json`, import.meta.url), 'utf8')).files ?? [])
    .filter((f) => f.endsWith('.mjs')).map((f) => `packages/${p}/${f.replace(/^\.\//, '')}`); } catch { return []; }
}).concat(readdirSync(new URL('../docs/', import.meta.url)).filter((f) => /^ust-.*\.mjs$/.test(f)).map((f) => `docs/${f}`));
// AUDIT #114 — the catch used to return '' and the file was scanned as EMPTY: a retired mechanism inside an
// unreadable shipped file was a PASS, measured. An unreadable input is now a failure, because a gate that sees
// less when its input breaks is fail-OPEN.
const unreadable = [];
const bare = shipped.map((f) => {
  try { return readFileSync(new URL('../' + f, import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, ''); }
  catch (e) { unreadable.push(`${f} (${String(e.code || e.message).slice(0, 40)})`); return ''; }
}).join('\n');

// A fingerprint that matches LIVE code and is not a resurrection needs its reason here — and the reason must name what
// covers the retirement INSTEAD, or it is an excuse.
const CODE_EXEMPT = {
  'keylogHeadAnchor → attested': 'the FIELD is live and legitimate; what rev40 retired is the INFERENCE from it to `attested`, which no textual guard can express. That inference is covered by two conformance checks by name: "#40 VERIFIED keylogHeadAnchor NO LONGER earns attested" and "#40 keylogHeadAnchor WITHOUT substrateVerify → NOT attested". The fingerprint is imprecise for the code side and precise enough for the documents.',
};

const failures = [];
for (const r of RETIRED) {
  const hits = (bare.match(r.rx) || []).length;
  const why = CODE_EXEMPT[r.id];
  if (hits && !why) failures.push(`[${r.id}] appears ${hits}× in SHIPPED CODE with comments stripped — retired in ${r.retiredIn}. A retired mechanism may be remembered in a comment; it may not be present in code that runs.`);
  if (hits && why && why.length < 60) failures.push(`[${r.id}] CODE_EXEMPT reason is ${why.length} chars — under 60 is a placeholder, not a decision`);
  // an exemption may not be added SILENTLY: it must cite what covers the retirement instead — a check name, an
  // issue or a spec section. A prose reason can be written for anything; a reference cannot (round 102).
  if (hits && why && !/#\d+|§\d|"#\d|check/i.test(why)) failures.push(`[${r.id}] CODE_EXEMPT must NAME what covers the retirement instead — a check, an issue or a spec section`);
  if (!hits && why) failures.push(`[${r.id}] carries a CODE_EXEMPT and no longer appears in shipped code — remove the exemption, it now reads as a live boundary that is gone`);
}
// the code leg must be able to FAIL, and the roster must not be empty
if (unreadable.length) failures.push(`${unreadable.length} shipped file(s) could not be READ and were scanned as empty: ${unreadable.join(', ')} — a retired mechanism inside one of them would pass silently`);
if (shipped.length < 8) failures.push(`only ${shipped.length} shipped file(s) resolved from the manifests — the code roster has gone blind and this leg would pass vacuously`);
if (!/export/.test(bare)) failures.push('the stripped shipped code contains no `export` — stripping removed everything and the leg is vacuous');
if (/RETIRED_CONTROL_TOKEN_THAT_CANNOT_EXIST/.test(bare)) failures.push('the code probe matched a token that cannot exist');

for (const r of RETIRED) {
  const got = { spec: (spec.match(r.rx) || []).length, model: (model.match(r.rx) || []).length };
  for (const doc of ['spec', 'model']) {
    if (got[doc] > r[doc])
      failures.push(`[${r.id}] ${doc}: ${got[doc]} mentions, pinned ${r[doc]} — retired in ${r.retiredIn}. New prose mentions it: confirm the mention is a corrected note or a history entry, NOT a live specification, then re-pin.`);
    if (got[doc] < r[doc])
      failures.push(`[${r.id}] ${doc}: ${got[doc]} mentions, pinned ${r[doc]} — fewer than pinned. History was consolidated or a record was deleted; confirm the RECORD of the mistake is still intact, then lower the pin.`);
  }
}

if (failures.length) {
  console.error('✗ retired-mechanisms gate FAILED:');
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}
const total = RETIRED.reduce((a, r) => a + r.spec + r.model, 0);
console.log(`  ✓ code side: ${shipped.length} shipped file(s) carry NO retired mechanism with comments stripped (${Object.keys(CODE_EXEMPT).length} named exemption)`);
console.log(`✓ retired mechanisms: ${RETIRED.length} abandoned paths/mechanisms tracked, ${total} reviewed mentions pinned across spec + formal model — none can be re-specified, or newly mentioned, without a human re-pin (textual guard: catches a return under its own name, not the same idea re-worded)`);
