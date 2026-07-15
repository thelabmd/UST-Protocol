// SPDX-License-Identifier: Apache-2.0
// ust-lite validity: prove a ust-lite document IS a valid UST document. Cross-verify BOTH directions against the
// full reference verifier, and prove byte-identity (same canon/hash/sig) — the whole point of "a lite doc verifies
// VALID:LIGHT under full UST, and lite accepts any UST doc at the LIGHT floor".
import * as lite from './index.mjs';
import * as full from '../ust-protocol/index.mjs';

let pass = 0, fail = 0; const F = [];
const ok = (id, cond) => { if (cond) pass++; else { fail++; F.push(id); } };

const kp = lite.keypair();
const id = { domain_shard: 'example.md', ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' };
const time = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const data = { temp: { kind: 'captured', value: { celsius: '21.5' } } };

// 1) lite builds+seals → the FULL verifier accepts it at LIGHT
const liteDoc = lite.seal(lite.buildState(id, time, data), kp.privateKey, kp.pub);
const fv = full.verify(liteDoc);
ok('lite doc → full.verify == VALID:LIGHT', full.isValid(fv) && fv.result === 'VALID:LIGHT');

// 2) full builds+seals → the LITE verifier accepts it at LIGHT
const fullDoc = full.seal(full.buildState(id, time, data), kp.privateKey, kp.pub);
ok('full doc → lite.verify == VALID:LIGHT', lite.verify(fullDoc).result === 'VALID:LIGHT');

// 3) BYTE-IDENTITY: same primitives ⇒ the two documents are the same bytes (Ed25519 is deterministic)
ok('lite doc == full doc (byte-identical canon/hash/sig)', JSON.stringify(liteDoc) === JSON.stringify(fullDoc));
ok('lite.contentHash == full.contentHash', lite.contentHash(liteDoc) === full.contentHash(fullDoc));

// 4) negatives — a tampered value and a bad signature must FAIL in BOTH verifiers
const tampered = JSON.parse(JSON.stringify(liteDoc)); tampered.state.data.temp.value.celsius = '99.9';
ok('tampered value → lite INVALID (E-CANON)', lite.verify(tampered).error === 'E-CANON');
ok('tampered value → full INVALID', !full.isValid(full.verify(tampered)));
const badSig = JSON.parse(JSON.stringify(liteDoc)); badSig.sig.sig = 'A'.repeat(86);
ok('forged sig → lite INVALID (E-SIG)', lite.verify(badSig).error === 'E-SIG');
const wrongKey = lite.keypair();
const impostor = lite.seal(lite.buildState(id, time, data), wrongKey.privateKey, wrongKey.pub);
ok('impostor key (key_id ≠ state.key_id) → lite INVALID', lite.verify(impostor).error === 'E-SIG');

// 5) reserved-key / shape floor
ok('unknown top-level member → INVALID', lite.verify({ ...liteDoc, evil: 1 }).error === 'E-MALFORMED');
const badId = lite.seal(lite.buildState({ ...id, ust_id: 'ust:BADSHAPE' }, time, data), kp.privateKey, kp.pub);
ok('bad ust_id shape → INVALID', lite.verify(badId).error === 'E-MALFORMED');

// 6) class↔provenance floor (§14.5/N10) — caught via MCP dogfood: ust-lite is observation-only. A class:attestation
//    doc needs constituents+root; ust-lite must REJECT it, in PARITY with full (never read VALID:LIGHT what full rejects).
let liteBuildRej = false; try { lite.buildState({ ...id, class: 'attestation' }, time, data); } catch (e) { liteBuildRej = e.code === 'E-MALFORMED'; }
ok('lite buildState rejects class:attestation (observation-only)', liteBuildRej);
const attState = { id: { ...id, class: 'attestation' }, time, data: liteDoc.state.data, hashes: liteDoc.state.hashes };
const attDoc = lite.seal(attState, kp.privateKey, kp.pub);
ok('lite.verify rejects hand-forged class:attestation w/o provenance', lite.verify(attDoc).error === 'E-MALFORMED');
ok('full.verify rejects the same doc (PARITY — no lite-only VALID)', !full.isValid(full.verify(attDoc)));

console.log(`\n  ust-lite validity vs full ust-protocol   PASS ${pass}   FAIL ${fail}`);
if (F.length) { F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ a ust-lite document IS a valid UST document — byte-identical, cross-verified both ways');
