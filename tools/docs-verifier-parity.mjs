// SPDX-License-Identifier: Apache-2.0
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

let fail = 0;
for (const [name, doc, context] of battery) {
  const p = P.verify(doc, { context }), w = await web(doc, { context });
  const pv = p.result || p.error || '?', wv = w.result || w.error || '?';
  const agree = pv === wv;
  if (!agree) fail++;
  console.log((agree ? '  ✓ ' : '  ✗ DIVERGE ') + name + '  — ref:' + pv + '  web:' + wv);
}
console.log(fail
  ? `\n✗ docs-verifier-parity — ${fail} divergence(s): the clean-room web verifier disagrees with the reference`
  : '\n✓ docs-verifier-parity — clean-room web verifier agrees with the reference on every case');
process.exit(fail ? 1 : 0);
