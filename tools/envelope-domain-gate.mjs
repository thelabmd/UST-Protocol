// SPDX-License-Identifier: Apache-2.0
// @assurance 1b canfail:yes — builds and verifies every cell of the partition-envelope product on each run
//
// ENVELOPE DOMAIN GATE (round 250) — the partition envelope is a PRODUCT, and a product must be decided cell by
// cell, not sampled.
//
// WHY IT EXISTS. Measured 2026-09-01 (#177), CLOSED 2026-09-01 by the split productions and this gate: §4.4 wrote the two private alternatives as ONE production carrying an
// unconditionally-optional `enc`, while the verifier's AEAD branch is keyed on the MODE. A partition declaring
// `privacy:"blinded"` and shipping an `enc` block therefore fell under no obligation at all — it verified
// `VALID:LIGHT` with the partition reported fully disclosed, while the ciphertext decrypted to a DIFFERENT value
// from the one the commitment binds. Two values fixed at one instant with the record accountable for one. Live in
// `ust-protocol@1.0.0-rc.72` on npm, present since rc.1, closed 2026-09-01. CLOSED by the split productions in
// §4.4 and by this gate, which re-derives the whole product every run so the next combination cannot be missed.
//
// WHY A GATE AND NOT ANOTHER VECTOR. A vector pins ONE case. This defect was not a wrong case — it was an
// UNCONSIDERED one, and the corpus had good coverage of every case anyone had thought of. The probe that found it
// enumerated the domain instead of sampling it, and enumeration is what has to run every time: a fifth partition
// kind or a third privacy mode enters this gate's product on the day it is registered, rather than on the day
// somebody remembers to write a vector for each of its combinations.
//
// WHAT IT ASSERTS, per cell of (kind × privacy × foreign-field):
//   • a field LEGAL for that shape is admitted;
//   • a field the shape does not declare is REFUSED — E-MALFORMED, before any question of authorization;
//   • and both directions are controlled, because a gate where everything is refused proves as little as one
//     where everything is admitted.
//
// WHAT IT DOES NOT ASSERT. Not the verdict of a legal document beyond admission, not the privacy semantics — those
// are the corpus's job. This gate speaks only about which SHAPES exist, which is the axis that went unwatched.
import { readFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import * as P from '../packages/ust-protocol/index.mjs';
import { verify as webVerify } from '../docs/ust-verify.mjs';   // the clean-room second verifier — see below

const V = JSON.parse(readFileSync(new URL('../vectors/conformance-vectors.json', import.meta.url), 'utf8'));
const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(V.seeds.A, 'hex')]), format: 'der', type: 'pkcs8' });
const pub = V.keypairs.A.pub_b64url, kid = V.keypairs.A.key_id;
const ID = { domain_shard: kid, ust_id: 'ust:20260901.12', key_id: kid, class: 'observation' };
const T = { generated_at: '2026-09-01T12:10:00Z', valid_from: '2026-09-01T12:00:00Z', valid_to: '2026-09-01T13:00:00Z' };
const NONCE = 'F'.repeat(22), KEY = 'G'.repeat(43);

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// ── THE PRODUCT. Bases come from the REGISTRY, never from a list here: a kind or a privacy mode registered
// tomorrow is in this product tomorrow. That is the whole difference between enumerating a domain and sampling it.
const KINDS = P.REGISTRY.partitionKinds;
const PRIVACIES = [undefined, 'blinded', 'encrypted'];

const baseFor = (kind, privacy) => {
  const value = kind === 'absence' ? { reason: 'unreachable', subject: 's' } : { x: '1' };
  if (privacy === undefined) return { kind, value };
  if (privacy === 'blinded') return P.blindPartition('p', value, { domain_shard: ID.domain_shard, ust_id: ID.ust_id, nonce: NONCE, kind }).partition;
  return P.encryptPartition('p', value, { domain_shard: ID.domain_shard, ust_id: ID.ust_id, nonce: NONCE, key_id: 'ops', key: KEY, kind }).partition;
};

// The LEGAL field set per shape IS §4.4's grammar, written once. `kind` is legal everywhere and is not a variable.
const LEGAL = {
  'undefined': ['value'],
  blinded: ['commit'],
  encrypted: ['commit', 'enc'],
};
// The foreign fields tried against every shape: the union of everything any shape legitimately carries, plus the
// two absence members, which live INSIDE `value` and must not be admitted as envelope members.
const FOREIGN = () => ({
  value: { x: '9' },
  commit: P.blindedCommit({ domain_shard: ID.domain_shard, ust_id: ID.ust_id, name: 'p', value: { x: '1' }, nonce: NONCE }),
  enc: P.encryptPartition('p', { x: '1' }, { domain_shard: ID.domain_shard, ust_id: ID.ust_id, nonce: NONCE, key_id: 'ops', key: KEY }).partition.enc,
  nonce: NONCE,
  reason: 'unreachable',
  subject: 's',
});

// BOTH verifiers are asked, and disagreement is itself a failure. This is not thoroughness for its own sake:
// measured 2026-09-01 and CLOSED 2026-09-02 by a closed envelope in that file, after the reference refused the #177 shape the clean-room verifier still ADMITTED it — 39 of 42 cells — and
// a third copy ships in the extension. A domain gate that interrogates one implementation watches one
// implementation — and the defect class here is precisely a rule that reached some surfaces and not others.
const admits = async (part) => {
  const doc = P.seal(P.buildState(ID, T, { p: part }), priv, pub);
  const one = (fn) => { try { const r = fn(); return r; } catch (e) { return { result: 'THREW', error: String(e.code || e.message).slice(0, 40) }; } };
  const ref = one(() => P.verify(doc, { context: 'data' }));
  let web; try { web = await webVerify(doc, { context: 'data' }); } catch (e) { web = { result: 'THREW', error: String(e.code || e.message).slice(0, 40) }; }
  const refOk = String(ref.result).startsWith('VALID'), webOk = String(web.result).startsWith('VALID');
  return { admitted: refOk, result: ref.result, error: ref.error, agree: refOk === webOk, web: web.result };
};

let cells = 0, admittedLegal = 0, refusedForeign = 0;
for (const kind of KINDS) {
  for (const privacy of PRIVACIES) {
    let base;
    try { base = baseFor(kind, privacy); } catch (e) { check(false, `could not construct the (${kind}, ${privacy}) base — the product cannot be enumerated: ${e.message}`); continue; }

    // POSITIVE control for the cell: the shape itself, untouched, must be admitted. Without it a build that
    // refused every private partition would satisfy every negative below for free.
    const self = await admits(base);
    check(self.admitted && self.agree, `(${kind}, ${privacy ?? 'public'}) is REFUSED in its own declared shape (${self.result} ${self.error || ''}) — the negatives below then prove nothing`);
    if (self.admitted) admittedLegal++;

    const legal = new Set(LEGAL[String(privacy)]);
    for (const [field, val] of Object.entries(FOREIGN())) {
      if (field in base || legal.has(field)) continue;                 // already part of this shape
      cells++;
      const got = await admits({ ...base, [field]: val });
      check(!got.admitted,
        `(${kind}, ${privacy ?? 'public'}) + foreign \`${field}\` is ADMITTED (${got.result}) — a member the shape does not declare falls under no obligation, so nothing ever examines it (§4.4, #177)`);
      check(got.agree,
        `(${kind}, ${privacy ?? 'public'}) + foreign \`${field}\`: the two implementations DISAGREE — reference ${got.result}, clean-room ${got.web}. A rule that reached one surface and not the other is exactly how #177 stayed open after the core was fixed.`);
      if (!got.admitted) refusedForeign++;
    }
  }
}

// ── CONTROLS. The detector must be able to speak in both directions, proven here rather than asserted above.
{
  const legalCell = await admits(baseFor(KINDS[0], 'encrypted'));
  check(legalCell.admitted, 'CONTROL: a fully legal encrypted partition is refused — every negative above would then pass for the wrong reason');
  const forged = await admits({ ...baseFor(KINDS[0], 'blinded'), enc: FOREIGN().enc });
  check(!forged.admitted, 'CONTROL: the exact #177 shape (blinded carrying enc) is admitted — this gate is not watching the thing it was written for');
}

console.log(`\n  envelope domain   PASS ${pass}   FAIL ${fail.length}   (${KINDS.length} kind(s) × ${PRIVACIES.length} privacy state(s); ${admittedLegal} declared shapes admitted, ${refusedForeign}/${cells} foreign members refused)`);
for (const f of fail) console.log('    ✗ ' + f);
if (fail.length) process.exit(1);
console.log('  ✓ every cell of the envelope product is decided: each declared shape is admitted, and no shape accepts a member it does not declare');
