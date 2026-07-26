// SPDX-License-Identifier: Apache-2.0
// STREAM parity gate — the clean-room verifier's completeness verdict must equal the reference's, case for case.
//
// Why it exists: docs/ust-verify.mjs carried the comment "Mirrors ust-protocol.verifyStream so the two cross-check" and
// nothing cross-checked them. It returned `complete: 'proven'` — a word absent from the reference vocabulary
// (none | provisional | chain-consistent | complete) — on nothing more than chain consistency plus a matching head and
// frame_count, which is precisely what the reference calls `chain-consistent`. On a stream with a MISSING grid slot the
// reference refused completeness and NAMED the hole while the public page said "proven". A user was told a stream was
// proven while a frame was absent.
//
// The lesson is about the SHAPE of the earlier gate, not just the bug: docs-verifier-parity covered verify() only, so a
// second entry point of the same clean-room file was never compared. A parity claim must enumerate the ENTRY POINTS, not
// one of them — the same "enumerate the domain, not a sample" failure that let a missing class hide behind a green gate
// on the same day.
import * as P from '../packages/ust-protocol/index.mjs';
import { verifyStream as web } from '../docs/ust-verify.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const kp = (fill) => {
  const seed = Buffer.alloc(32, fill);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  return { priv, pub, key_id: P.keyId(pub) };
};
const A = kp(0xa1);
const D = A.key_id;                                   // key-form: both verifiers reach a verdict without discovery
const T = (ts) => ({ generated_at: ts, valid_from: ts, valid_to: ts });
const seal = (s) => P.seal(s, A.priv, A.pub);

// A stream builder: `slots` are [ust_id, timestamp] pairs, so a case can omit a grid slot on purpose.
const build = (slots, cadence, interval) => {
  const genesis = seal(P.buildGenesis({ domain_shard: D, ust_id: 'ust:20260726.08', key_id: A.key_id }, T('2026-07-26T08:00:00Z'), A.pub, 512, undefined, cadence));
  let prev = P.contentHash(genesis);
  const frames = [];
  for (const [id, ts] of slots) {
    const f = seal(P.buildState({ domain_shard: D, ust_id: id, key_id: A.key_id, class: 'observation' }, T(ts), { x: { kind: 'captured', value: { v: '1' } } }, { prev }));
    frames.push(f); prev = P.contentHash(f);
  }
  // three distinct states: NO checkpoint (null), a checkpoint WITHOUT an interval (false), one WITH an interval (object).
  // Passing {} produced {from: undefined} and canon rightly refuses undefined — my first construction, not a code defect.
  const checkpoint = interval === null ? undefined
    : seal(P.buildCheckpoint({ domain_shard: D, ust_id: 'ust:20260726.1059', key_id: A.key_id }, T('2026-07-26T10:59:00Z'), prev, frames.length, prev, interval === false ? undefined : interval));
  return { genesis, frames, checkpoint };
};

const S = (h, m) => [`ust:20260726.${h}${m}`, `2026-07-26T${h}:${m}:00Z`];
const FULL = [S('10', '00'), S('10', '01'), S('10', '02')];
const HOLE = [S('10', '00'), S('10', '02')];
const IV = { from: 'ust:20260726.1000', to: 'ust:20260726.1002' };

const cases = [
  ['no checkpoint → provisional', build(FULL, 60, null), 60],
  ['every grid slot present → complete', build(FULL, 60, IV), 60],
  ['a grid slot MISSING → chain-consistent + the hole NAMED', build(HOLE, 60, IV), 60],
  ['no cadence declared → chain-consistent (no-omission unavailable)', build(FULL, undefined, IV), null],
  ['checkpoint without an interval → chain-consistent', build(FULL, 60, false), 60],
  ['interval does not bound the set (wrong `to`) → E-PREV', build(FULL, 60, { from: 'ust:20260726.1000', to: 'ust:20260726.1005' }), 60],
  ['an off-grid frame → E-PREV', build([S('10', '00'), ['ust:20260726.100030', '2026-07-26T10:00:30Z'], S('10', '01')], 60, { from: 'ust:20260726.1000', to: 'ust:20260726.1001' }), 60],
];

const norm = (r) => JSON.stringify({ complete: r.complete, error: r.error, hole: r.hole, cadence: r.cadence });
let pass = 0; const fail = [];
const VOCAB = new Set(['none', 'provisional', 'chain-consistent', 'complete', undefined]);

for (const [name, { genesis, frames, checkpoint }, cadence] of cases) {
  const ref = P.verifyStream(frames, { genesis, checkpoint, cadenceLog: [] });
  const w = await web(frames, { genesis, checkpoint, cadence: cadence === null ? undefined : String(cadence) });
  const agree = norm(ref) === norm(w);
  const inVocab = VOCAB.has(w.complete);
  if (agree && inVocab) { pass++; continue; }
  fail.push(`${name}\n        reference: ${norm(ref)}\n        browser  : ${norm(w)}` + (inVocab ? '' : `\n        [browser used a verdict word outside the reference vocabulary: ${JSON.stringify(w.complete)}]`));
}

// the gate must be able to fail: the word that was actually shipped must be rejected by the vocabulary check
if (!VOCAB.has('proven')) pass++; else fail.push('the vocabulary check would ACCEPT "proven" — it cannot detect the drift it exists for');

console.log(`\n  stream parity   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ both stream verifiers agree case for case, and `complete` is reachable only through the signed grid');
