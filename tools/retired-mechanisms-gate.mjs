// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:no — the fingerprints and their occurrence counts are pinned by hand
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
import { readFileSync } from 'node:fs';

const spec = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8');
const model = readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8');

// fingerprint → occurrences reviewed at rev88 { spec, model }
const RETIRED = [
  { id: 'prove-first metatheorem ladder', rx: /M-REL|M-ERA|M-PROV|M-BYTE-INJECTIVE|M-KEY-MONOTONE/g, retiredIn: 'pivot 1 (unrealizable — theorems ahead of the code hid P0s)', spec: 0, model: 0 },
  { id: 'injectable-child-verdict tier',  rx: /injectable/g,                    retiredIn: 'rev73 (architecturally VOID)',                    spec: 0, model: 3 },
  { id: 'byte-transparent mirror GOAL',   rx: /byte-transparent/g,              retiredIn: 'rev32 (impossible for a stateful Proxy)',          spec: 0, model: 3 },
  { id: 'pinned / TOFU identity rung',    rx: /\bTOFU\b/g,                      retiredIn: 'rev83 (does not survive rotation or takeover)',    spec: 1, model: 0 },
  { id: 'keylogHeadAnchor → attested',    rx: /keylogHeadAnchor/g,              retiredIn: 'rev40 (anchored head ≠ latest head)',              spec: 3, model: 0 },
  { id: 'positioned H(index) SMT',        rx: /positioned[- ]SMT|positioned\s+sparse-Merkle/g, retiredIn: 'P0-02 external audit (says nothing about length+1)', spec: 4, model: 1 },
  { id: 'public opts.__nowMs clock',      rx: /__nowMs/g,                       retiredIn: 'rev33 (caller clock flipped the verdict)',         spec: 0, model: 3 },
  { id: 'valid_as_of in a signed claim',  rx: /valid_as_of/g,                   retiredIn: 'rev44 (signer self-declared time)',                spec: 0, model: 0 },
  { id: 'domain-less computed mode',      rx: /domain-less/g,                   retiredIn: 'owner 2026-07-05 (forgeable cross-engine agreement)', spec: 4, model: 0 },
  { id: 'secret-url privacy mode',        rx: /secret[- ]url/g,                 retiredIn: 'rc.4 (a disclosure channel, out of scope)',        spec: 1, model: 0 },
  { id: 'first-wins / hash dedupe in forkChoice', rx: /first-wins|content_hash[- ]dedupe/g, retiredIn: 'rev18/19/20 (hid equivocation)',       spec: 1, model: 2 },
  // rev97 removed the key-log `rotate` OP, and round 74's sweep never added it here — measured 2026-07-29, three
  // rounds later, while it was still being advertised to agents by the MCP tool description. The fingerprint is the
  // OP FORM, not the bare word: `ust rotate` is a live CLI command and `rotateKeylog` a live export, so /rotate/
  // would churn on every unrelated edit and teach a reader to ignore this gate. Code surfaces are covered by
  // tools/keyop-contract-gate.mjs, which enumerates the domain from the reducer instead of matching text.
  { id: 'key-log `rotate` op',            rx: /op:\s*.?rotate/g,               retiredIn: 'rev97 (self-authorized succession named its own successor)', spec: 1, model: 2 },
  { id: 'depth-64 cap in admitDeep',      rx: /depth[- ]64/g,                   retiredIn: 'rev30 (falsely rejected a valid deep document)',   spec: 0, model: 1 },
];

const failures = [];
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
console.log(`✓ retired mechanisms: ${RETIRED.length} abandoned paths/mechanisms tracked, ${total} reviewed mentions pinned across spec + formal model — none can be re-specified, or newly mentioned, without a human re-pin (textual guard: catches a return under its own name, not the same idea re-worded)`);
