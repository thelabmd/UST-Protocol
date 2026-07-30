// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the surface set is ENUMERATED from the tree (every file that writes to the DOM), and the premise that the terminal is not one is asserted here rather than assumed
// Display-safety gate (#73) — the human renderers must neutralize Unicode format characters before showing an
// untrusted value, and the two renderers must not drift apart.
//
// Why a gate and not just the fix: `esc` exists in TWO surfaces — the Pages verifier and the extension popup — and
// this repository has already paid a live P0 for three JS copies of one rule drifting (rev84: the clean-room web
// verifier kept returning VALID:LIGHT where the reference returned INDETERMINATE, and no gate covered it).
//
// What is asserted, all of it by EXECUTING the extracted code rather than by reading it:
//   1. both surfaces carry the neutralizer, byte-identical to each other
//   2. it neutralizes the whole \p{Cf} class, not a sample — checked against every format codepoint in the BMP
//   3. HTML escaping still happens
//   4. the emitted marker is HTML-inert for every codepoint, so neither step order can re-introduce meaning
//   5. the known deception renders harmlessly
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MIN_REASON = 60;

// ── THE DOMAIN, enumerated from the tree rather than typed. It WAS a two-entry literal, and the list happened to be
// right — measured 2026-07-30, exactly two files write to the DOM and they are exactly those two. But a correct list
// is not a checked list: a third renderer added tomorrow would be shown untrusted text with nothing objecting.
// A file may be EXEMPT, with its reason stated here, which is the difference between a known boundary and a silent one.
const DOM_WRITE = /innerHTML|insertAdjacentHTML|\.textContent\s*=/;
const EXEMPT = {};
const walk = (d) => readdirSync(ROOT + d, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(d + '/' + e.name) : (/\.(html|js|mjs)$/.test(e.name) ? [d + '/' + e.name] : []));
const renderers = ['docs', 'extension'].flatMap(walk).filter((f) => DOM_WRITE.test(readFileSync(ROOT + f, 'utf8')));
const SURFACES = renderers.filter((f) => !Object.hasOwn(EXEMPT, f));
const MARK = '// #73 display safety';

let pass = 0; const fail = [];
const ok = (name, cond) => { if (cond) pass++; else fail.push(name); };

// Pull the block out of each surface: from the marker to the end of the `const esc =` line.
const blocks = SURFACES.map((f) => {
  const src = readFileSync(ROOT + f, 'utf8');
  const i = src.indexOf(MARK);
  if (i < 0) return { f, block: null };
  const escAt = src.indexOf('const esc = ', i);
  if (escAt < 0) return { f, block: null };
  return { f, block: src.slice(i, src.indexOf('\n', escAt)) };
});

for (const b of blocks) ok(`${b.f} carries the display-safety block`, b.block !== null);
ok('at least two rendering surfaces were found — the enumeration has not gone blind', SURFACES.length >= 2);
for (const [f, why] of Object.entries(EXEMPT))
  ok(`EXEMPT ${f} states a reason of ${MIN_REASON}+ chars`, String(why).trim().length >= MIN_REASON);
// CONTROL — the detector must discriminate, or the enumeration is a list of everything or of nothing.
ok('CONTROL: the DOM-write detector fires on a synthetic writer and not on inert text',
  DOM_WRITE.test('el.innerHTML = x;') && !DOM_WRITE.test('const t = textContent + 1;'));

// ── THE PREMISE THIS GATE'S SCOPE RESTS ON, asserted rather than assumed. The terminal is a rendering surface too —
// a bidi override reverses a line in most terminals — and the CLI prints verdict details, which DO interpolate
// `domain_shard`. It is not in scope for one reason only: the core refuses a raw-Unicode `domain_shard` upstream
// (#40's A-label homograph guard) and its refusal does not echo the value, so no format character reaches a terminal
// through that path. If that guard is ever relaxed, the CLI becomes a surface and this gate must widen — so the guard
// is checked HERE, where the scope decision lives, instead of being an argument in a comment.
{
  const RLO = '\u202E';
  // built with the REAL builder so the partition hashes are right: a hand-assembled probe failed at E-CANON before
  // the shard guard was ever reached, which is the second way this leg was wrong before it was right.
  const st = P.buildState({ domain_shard: 'evil' + RLO + '.example', ust_id: 'ust:20260730.10',
    key_id: 'sha256:' + 'ab'.repeat(32), class: 'observation' },
    { generated_at: '2026-07-30T10:00:00Z', valid_from: '2026-07-30T10:00:00Z', valid_to: '2026-07-30T11:00:00Z' },
    { r: { kind: 'captured', value: { x: '1' } } });
  const v = P.verify({ ust: '1.0', state: st.state ?? st,
    sig: { alg: 'Ed25519', key_id: 'sha256:' + 'ab'.repeat(32), pub: 'A'.repeat(43), sig: 'A'.repeat(86) } }, { context: 'data' });
  // The first version of this leg asserted only `result === 'INVALID'` and was VACUOUS: the probe carries a bogus
  // signature, so it is INVALID whatever the shard guard does. Weakening the guard did not break it — the control did
  // its job on the leg its own author had just written. It now asserts the SPECIFIC refusal, so relaxing the guard
  // makes the document fail later for a different reason and this fires.
  ok('PREMISE: a raw-Unicode domain_shard is REFUSED by the A-label guard, so the terminal is not a display surface',
    v.error === 'E-MALFORMED' && /A-label/.test(String(v.detail ?? '')));
  ok('PREMISE: the refusal does not ECHO the untrusted value into a printable detail', !String(v.detail ?? '').includes(RLO));
}
if (blocks.every((b) => b.block)) {
  ok('the two surfaces are byte-identical', blocks[0].block === blocks[1].block);
}

// Execute the extracted block so what is tested is the shipped code, not a copy of it.
for (const b of blocks) {
  if (!b.block) continue;
  let esc, visCtl;
  try { ({ esc, visCtl } = new Function(`${b.block}\nreturn { esc, visCtl };`)()); } catch (e) { fail.push(`${b.f} block does not evaluate: ${e.message}`); continue; }

  // 2) the WHOLE class. Every format codepoint in the BMP must come out neutralized — a sample would let a
  //    hand-list masquerade as complete, which is the defect this file exists to prevent.
  const cf = [];
  for (let cp = 0; cp <= 0xFFFF; cp++) { const ch = String.fromCodePoint(cp); if (/\p{Cf}/u.test(ch)) cf.push(cp); }
  const leaked = cf.filter((cp) => esc(String.fromCodePoint(cp)).includes(String.fromCodePoint(cp)));
  ok(`${b.f}: all ${cf.length} \\p{Cf} codepoints neutralized (0 leak through)`, leaked.length === 0);
  if (leaked.length) fail.push(`${b.f}: leaked U+${leaked.slice(0, 5).map((c) => c.toString(16).toUpperCase()).join(', U+')}`);

  // 3) escaping still works
  ok(`${b.f}: HTML metacharacters still escaped`, esc('<a href="x">&\'') === '&lt;a href=&quot;x&quot;&gt;&amp;&#39;');

  // 4) The marker must be HTML-INERT, for EVERY codepoint it can emit — that is the property that makes the fix safe
  //    regardless of which of the two steps runs first. An earlier version of this gate asserted "neutralize precedes
  //    escape" instead; inverting the order in BOTH surfaces left it green, because the claim was not true — the two
  //    orders produce identical bytes. A check that cannot fail was replaced by one that can.
  const markers = cf.map((cp) => esc(String.fromCodePoint(cp)));
  ok(`${b.f}: every emitted marker is free of HTML metacharacters`, markers.every((m) => !/[&<>"']/.test(m)));
  ok(`${b.f}: marker shape is [U+hhhh]`, markers.every((m) => /^\[U\+[0-9A-F]{4,6}\]$/.test(m)));
  // And prove the immateriality rather than asserting it: build the other order out of the shipped pieces and compare.
  const htmlEsc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const other = (s) => visCtl(htmlEsc(s));
  const probes = ['‮<', '&‬>', '"‪\'', 'ab​c﻿d', '<script>‮</script>'];
  ok(`${b.f}: the two orders agree on every probe, so order is immaterial`, probes.every((p) => esc(p) === other(p)));

  // 5) the deception itself
  const attack = 'amount: 100‮DSU‬';
  const shown = esc(attack);
  ok(`${b.f}: the RTL-override deception is visible, not applied`,
    shown === 'amount: 100[U+202E]DSU[U+202C]' && !/[‪-‮]/.test(shown));

  // and a zero-width joiner inside a value cannot hide
  ok(`${b.f}: zero-width characters cannot hide inside a value`, esc('ab​c﻿d') === 'ab[U+200B]c[U+FEFF]d');
}

console.log(`\n  display safety (#73)   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ both human renderers neutralize the whole \\p{Cf} class before escaping, and they have not drifted');
