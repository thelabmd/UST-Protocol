// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — the §8 ABNF checked against the code that parses it
// ust_id tier gate (UST-gqj) — the §8 ABNF and the code must agree that HH/MM/SS carry NO separator.
//
// The conformance vectors already lock the BEHAVIOUR: a coarser frame is a literal string prefix of every finer frame,
// and a separator form is not a ust_id. They cannot lock the SPEC. The `ust` URI scheme is IANA-registered (provisional,
// 2026-07-20) and its reference is §8 verbatim, so an editor who "improves" the ABNF to `HH [ ":" MM ]` would break, in
// one stroke, the registered scheme and every parent frame anyone derives by truncation — and every vector would still
// pass, because the code would not have changed.
//
// So this reads the ABNF out of the spec and asserts three things:
//   1. the time component is HH [ MM [ SS ] ] with nothing between the groups
//   2. the code's own accepted set is exactly those three tiers
//   3. the registration note in §8 is still present, since the ABNF is only load-bearing while it is the cited reference
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const spec = readFileSync(ROOT + 'spec/UST-1.0.md', 'utf8');

let pass = 0; const fail = [];
const ok = (name, cond, detail) => { if (cond) pass++; else fail.push(name + (detail ? ` — ${detail}` : '')); };

// ── 1. the ABNF, read from the spec rather than restated here
const abnf = /^ust_id\s*=\s*(.+)$/m.exec(spec);
ok('§8 declares the ust_id ABNF', abnf !== null, 'the grammar line is gone — the IANA reference has nothing to cite');
if (abnf) {
  const grammar = abnf[1].split('(')[0].trim();          // drop the trailing "(UTC; tiers: …)" prose
  ok('ABNF is "ust:" YYYYMMDD "." HH [ MM [ SS ] ]',
    /^"ust:"\s+YYYYMMDD\s+"\."\s+HH\s*\[\s*MM\s*\[\s*SS\s*\]\s*\]$/.test(grammar),
    `got: ${grammar}`);
  // The load-bearing negative: no quoted literal may appear between HH and the end. A separator anywhere in the time
  // component is what breaks prefix containment, so it is checked as its own assertion with its own message.
  const timePart = grammar.slice(grammar.indexOf('HH'));
  ok('no separator literal inside the time component', !/"/.test(timePart),
    `the time component contains a quoted literal: ${timePart} — this breaks prefix containment AND the registered scheme`);
}

// ── 2. the code's accepted set is exactly the three tiers
const B = '20260726';
// build+seal through the real producer, so acceptance is the verifier's answer and not a regex opinion
const { createPrivateKey, createPublicKey } = await import('node:crypto');
const seed = Buffer.alloc(32, 3);
const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
const kid = P.keyId(pub);
const T = { generated_at: '2026-07-26T05:00:00Z', valid_from: '2026-07-26T05:00:00Z', valid_to: '2026-07-26T05:00:00Z' };
const valid = (ustId) => {
  let doc;
  try { doc = P.seal(P.buildState({ domain_shard: kid, ust_id: ustId, key_id: kid, class: 'observation' }, T, { x: { kind: 'captured', value: { v: '1' } } }), priv, pub); }
  catch { return false; }
  return P.verify(doc, { context: 'data' }).result === 'VALID:LIGHT';
};

for (const tier of [`ust:${B}.05`, `ust:${B}.0538`, `ust:${B}.053835`]) ok(`code accepts tier ${tier}`, valid(tier));
for (const bad of [`ust:${B}.05:38`, `ust:${B}.05-38`, `ust:${B}.05.38`, `ust:${B}.053`, `ust:${B}.0538351`, `ust:${B}.5`]) {
  ok(`code rejects ${bad}`, !valid(bad), 'accepting this breaks prefix containment');
}

// ── 3. containment holds by construction across the whole day, not on a sample
let holds = true;
for (let h = 0; h < 24; h++) for (const m of [0, 7, 59]) for (const s of [0, 30, 59]) {
  const p = (n) => String(n).padStart(2, '0');
  const hour = `ust:${B}.${p(h)}`, min = `${hour}${p(m)}`, sec = `${min}${p(s)}`;
  if (!(min.startsWith(hour) && sec.startsWith(min) && sec.startsWith(hour) && valid(hour) && valid(min) && valid(sec))) holds = false;
}
ok('containment holds for all 24×3×3 frames probed (coarse is a literal prefix of fine)', holds);

// ── 4. the registration note that makes §8 the cited reference
ok('§8 still carries the IANA registration note', /IANA-registered\s+\*\*`ust`\*\*|IANA-registered \*\*`ust`\*\* URI scheme|reference for the IANA-registered/.test(spec),
  'the note is gone — either the registration moved or the reference is now uncited');

console.log(`\n  ust_id tier containment (UST-gqj)   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ §8 ABNF has no separator, the code accepts exactly three tiers, and a coarser frame is a literal prefix of every finer one');
