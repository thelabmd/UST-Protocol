// SPDX-License-Identifier: Apache-2.0
// @assurance 1b canfail:no — the clean-room web verifier and the reference must agree on every vector
// docs/ VERIFIER PARITY gate (round-53/54 — UST-ybn / UST-0q7). The clean-room web verifier (docs/ust-verify.mjs, the
// zero-dependency LIGHT floor served by GitHub Pages) and the reference verifier (ust-protocol) MUST return the SAME
// verdict on every LIGHT-floor case — the README promises "two conforming verifiers agree because the verdict is a total
// deterministic function". rev83's name-form→INDETERMINATE rule ONCE diverged: it was swept into index.mjs + ust-light but
// NOT docs/ust-verify.mjs, and NO gate covered the clean-room verifier, so it silently returned VALID:LIGHT where the
// reference returned INDETERMINATE. This gate drives a battery through BOTH and fails RED on any divergence — a third
// verifier can never drift unnoticed again.
import * as P from '../packages/ust-protocol/index.mjs';
import { verify as web } from '../docs/ust-verify.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

const kp = (seedHex) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pub, key_id: P.keyId(pub) };
};
const A = kp('a1'.repeat(32));
const t = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const seal = (s) => P.seal(s, A.priv, A.pub);
const hA = 'sha256:' + 'ab'.repeat(32);
const obs = (over = {}, data) => seal(P.buildState({ domain_shard: A.key_id, ust_id: 'ust:20260715.12', key_id: A.key_id, class: 'observation', ...over }, t, data ?? { r: { kind: 'captured', value: { x: '1' } } }));
const deriv = (shard, based) => seal(P.buildState({ domain_shard: shard, ust_id: 'ust:20260715.13', key_id: A.key_id, class: 'derivation' }, t, { d: { kind: 'computed', value: { x: '1' } } }, { based_on: based, seed: P.seed(based.map((b) => b.hash)) }));
const gen = seal(P.buildGenesis({ domain_shard: 'example.com', ust_id: 'ust:20260715.10', key_id: A.key_id }, t, A.pub));
// §11.3 cadence entries — a valid one, plus the two malformed shapes the reference refuses, so BOTH verifiers must
// agree on the accept AND on each refusal (a class that is merely "known" but unpoliced is a different divergence).
const cadEntry = seal(P.buildCadenceEntry({ domain_shard: 'example.com', ust_id: 'ust:20260715.11', key_id: A.key_id }, t, 30, 'ust:20260715.12', P.contentHash(gen)));
const cadNoPrev = (() => { const d = JSON.parse(JSON.stringify(cadEntry)); delete d.state.provenance; return d; })();
const cadNoOp = (() => { const d = JSON.parse(JSON.stringify(cadEntry)); d.state.data = { r: { kind: 'captured', value: { x: '1' } } }; return d; })();
const tampered = (() => { const d = JSON.parse(JSON.stringify(obs())); d.state.data.r.value.x = '9'; return d; })();
const badSig = (() => { const d = JSON.parse(JSON.stringify(obs())); d.sig.sig = 'A'.repeat(d.sig.sig.length); return d; })();

// [name, doc, context] — the class the divergence lived in (name/key-form identity) + shape sanity + url tolerance (rev84).
const battery = [
  ['key-form observation → VALID:LIGHT', obs(), 'data'],
  ['name-form observation → INDETERMINATE', obs({ domain_shard: 'example.com' }), 'data'],
  ['name-form derivation → INDETERMINATE', deriv('example.com', [{ hash: hA }]), 'data'],
  ['key-form derivation → VALID:LIGHT', deriv(A.key_id, [{ hash: hA }]), 'data'],
  ['key-form derivation w/ based_on url (tolerated, rev84)', deriv(A.key_id, [{ hash: hA, url: 'https://mirror.example/x' }]), 'data'],
  ['name-form derivation w/ url (name rule fires)', deriv('example.com', [{ hash: hA, url: 'https://mirror.example/x' }]), 'data'],
  ['genesis name-form (exempt) → VALID:LIGHT', gen, 'key'],
  ['tampered value → INVALID', tampered, 'data'],
  ['bad signature → INVALID', badSig, 'data'],
  // §11.3 — the battery had NO cadence-class document, so the clean-room verifier omitted `cadence` from its CLASSES
  // list and returned INVALID('bad class') where the reference returned VALID:LIGHT. The gate was green throughout: a
  // battery that does not name a class cannot detect a divergence in it. Enumerate the DOMAIN of classes, not a sample.
  ['cadence entry (name-form, exempt) → VALID:LIGHT', cadEntry, 'key'],
  ['cadence entry in DATA context → INVALID (W3)', cadEntry, 'data'],
  ['cadence entry without provenance.prev → INVALID', cadNoPrev, 'key'],
  ['cadence entry without a cadence_op partition → INVALID', cadNoOp, 'key'],
];

// THE BATTERY IS A SAMPLE, AND A SAMPLE CANNOT PROVE PARITY. The comment above the cadence rows already records
// this failing once: "a battery that does not name a class cannot detect a divergence in it — enumerate the
// DOMAIN of classes, not a sample." The remedy applied then was four more hand-written rows, which names four
// more instances. It recurred one level down: nothing here named an attestation SUBTYPE, and rev84 measured
// SEVEN cells where the web verifier answered VALID:LIGHT and the reference answered E-MALFORMED — the
// pre-C2 rule, still live in the browser, in the permissive direction.
//
// So the domain is now the CORPUS: every conformance vector that carries a whole document is driven through
// both verifiers. A vector added for any reason, by anyone, becomes a parity case the same day — which is the
// only version of this gate that cannot go blind again. The hand battery stays because it holds cases the
// corpus does not (context pairs, tolerated shapes); it is now the supplement, not the population.
const V = JSON.parse(readFileSync(new URL('../vectors/conformance-vectors.json', import.meta.url), 'utf8')).vectors;
const fromCorpus = V.filter((v) => v && v.doc && v.doc.state && v.doc.sig)
  .map((v) => [`vector:${v.kind}/${v.id}`, v.doc, v.role ?? 'data']);

let fail = 0;
for (const [name, doc, context] of [...battery, ...fromCorpus]) {
  const p = P.verify(doc, { context }), w = await web(doc, { context });
  const pv = p.result || p.error || '?', wv = w.result || w.error || '?';
  const agree = pv === wv;
  if (!agree) fail++;
  if (!agree || !name.startsWith('vector:')) console.log((agree ? '  ✓ ' : '  ✗ DIVERGE ') + name + '  — ref:' + pv + '  web:' + wv);
}
// A floor, so an empty or mis-filtered corpus reads as a broken gate rather than a clean run.
const FLOOR = 20;
if (fromCorpus.length < FLOOR) { fail++; console.log(`  ✗ only ${fromCorpus.length} document-bearing vectors resolved from the corpus (floor ${FLOOR}) — the corpus leg has gone blind`); }
// CONTROL — the comparison must be able to go RED. A gate whose detector is never exercised proves nothing
// about the runs it passes, so a STUB verifier that answers VALID:LIGHT to everything is driven through the
// same loop: it must diverge from the reference on at least one enumerated case. (The first version of this
// control compared a value with itself and was true by construction — vacuous, and it would have shipped.)
{
  const stub = async () => ({ result: 'VALID:LIGHT' });
  let split = 0;
  for (const [, doc, context] of fromCorpus) {
    const p = P.verify(doc, { context }), s = await stub();
    if ((p.result || p.error) !== (s.result || s.error)) split++;
  }
  if (split === 0) { fail++; console.log('  ✗ CONTROL: an always-VALID stub agreed with the reference on every case — the comparison does not discriminate'); }
  else console.log(`  ✓ CONTROL: an always-VALID stub diverges on ${split} enumerated case(s) — the detector fires`);
}
console.log(fail
  ? `\n✗ docs-verifier-parity — ${fail} divergence(s): the clean-room web verifier disagrees with the reference`
  : `\n✓ docs-verifier-parity — clean-room web verifier agrees with the reference on all ${battery.length + fromCorpus.length} cases (${battery.length} named + ${fromCorpus.length} enumerated from the vector corpus)`);
process.exit(fail ? 1 : 0);
