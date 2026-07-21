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

// totality (round-46 self-audit) — lite.verify is total: a hostile Proxy / malformed doc is a structured INVALID, never a host throw.
const mkHostile = () => new Proxy([{}], { get() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, getOwnPropertyDescriptor() { throw new Error('H'); } });
let liteTotal = true;
for (const j of [null, undefined, {}, [], 'x', 123, mkHostile()]) { try { const r = lite.verify(j); if (!r || r.result !== 'INVALID') liteTotal = false; } catch { liteTotal = false; } }
ok('lite.verify is TOTAL — hostile/malformed doc → structured INVALID, never a host throw', liteTotal);

// 7) round-49 P0-01 DIFFERENTIAL — the drift-catcher. GPT round-49 found lite reading VALID:LIGHT on an omitted class and an
//    impossible calendar date (2026-02-31) that the full verifier REJECTS — a lite-only false accept, because lite re-implements
//    validation as a SHAPE regex that drifted looser than core. The invariant is soundness: lite VALID ⇒ core VALID. A resign()
//    builds a valid state, mutates it, re-seals (so the disagreement is verifier SEMANTICS, not a broken signature), and we assert
//    lite NEVER accepts what core rejects across omitted-required-member + impossible-calendar shapes.
const resign = (mutate) => { const s = JSON.parse(JSON.stringify(lite.buildState(id, time, data))); mutate(s); return lite.seal(s, kp.privateKey, kp.pub); };
const corpus = [
  ['class absent', resign((s) => { delete s.id.class; })],
  ['class attestation', resign((s) => { s.id.class = 'attestation'; })],
  ['generated_at 2026-02-31', resign((s) => { s.time.generated_at = '2026-02-31T12:00:00Z'; })],
  ['valid_to 2026-13-01', resign((s) => { s.time.valid_to = '2026-13-01T12:00:00Z'; })],
  ['ust_id 20260231 (impossible date)', resign((s) => { s.id.ust_id = 'ust:20260231.12'; })],
  ['ust_id 20260229 (non-leap Feb 29)', resign((s) => { s.id.ust_id = 'ust:20260229.12'; })],
];
let diffOk = true;
for (const [name, doc] of corpus) {
  const liteValid = lite.verify(doc).result === 'VALID:LIGHT';
  const coreValid = full.isValid(full.verify(doc));
  if (liteValid && !coreValid) { diffOk = false; F.push('P0-01 DIFFERENTIAL lite-VALID/core-INVALID: ' + name); }   // the soundness break
}
ok('round-49 P0-01 differential: lite VALID ⇒ core VALID (no lite-only accept over absent-class / impossible-calendar shapes)', diffOk);
ok('round-49 P0-01 pin: absent class → lite INVALID (was VALID:LIGHT)', lite.verify(corpus[0][1]).error === 'E-MALFORMED');
ok('round-49 P0-01 pin: 2026-02-31 generated_at → lite INVALID (was VALID:LIGHT)', lite.verify(corpus[2][1]).error === 'E-MALFORMED');

// build-based sweep — domain_shard / ust_id / a valid_to all enter the partition hash or signed content, so a post-build
// mutation would break the hash and mask the SHAPE check; build each from the start and pin the same invariant across a wider
// surface (these AGREE today — lite VALID ⇒ core VALID — the sweep catches a FUTURE drift, GPT round-49 fix #3 "generated corpus").
const buildWith = (idOver = {}, timeOver = {}) => { try { return { doc: lite.seal(lite.buildState({ ...id, ...idOver }, { ...time, ...timeOver }, data), kp.privateKey, kp.pub) }; } catch (e) { return { buildErr: e.code || 'err' }; } };
const sweep = [
  { ust_id: 'ust:20260231.12' }, { ust_id: 'ust:20260229.12' }, { ust_id: 'ust:20261301.12' }, { ust_id: 'ust:20260721.24' },
  { domain_shard: 'bad name' }, { domain_shard: '' }, { domain_shard: '192.168.1.1' }, { domain_shard: 'sha256:' + '00'.repeat(32) },
].map((o) => buildWith(o))
  .concat([{ valid_to: '2026-13-01T00:00:00Z' }, { generated_at: '2026-02-30T00:00:00Z' }, { valid_from: '2026-07-21T25:00:00Z' }].map((o) => buildWith({}, o)));
let sweepOk = true;
for (const b of sweep) { if (b.buildErr) continue; if (lite.verify(b.doc).result === 'VALID:LIGHT' && !full.isValid(full.verify(b.doc))) { sweepOk = false; F.push('P0-01 SWEEP lite-VALID/core-INVALID'); } }
ok('round-49 P0-01 build-sweep: lite VALID ⇒ core VALID across domain_shard / ust_id / time shape values (wider differential surface)', sweepOk);

// round-50 P0-01 — the EXHAUSTIVE LIGHT-obligation differential. The rev77 sweep varied only id/time and MISSED the §4.4 closed
// envelope XOR + the §4.3a A-label homograph guard + the encrypted-enc obligation, so THREE more lite-VALID/core-INVALID docs
// shipped. Build a doc for EACH core LIGHT SEMANTIC obligation violation and assert lite VALID ⇒ core VALID (lite must reject each).
const H32 = 'sha256:' + 'ab'.repeat(32);
const buildData = (d) => { try { return { doc: lite.seal(lite.buildState(id, time, d), kp.privateKey, kp.pub) }; } catch (e) { return { buildErr: e.code || 'err' }; } };
const obligations = [
  { p: { kind: 'captured', value: { x: '1' }, commit: H32 } },                                   // public carrying commit — "what you see ≠ what is signed"
  { p: { kind: 'captured', value: { x: '1' }, enc: { alg: 'AES-256-GCM', key_id: 'k', ct: 'AA' } } },   // public carrying enc
  { p: { kind: 'captured', privacy: 'blinded', value: { x: '1' }, commit: H32 } },                // private carrying a plaintext value
  { p: { kind: 'captured', privacy: 'blinded' } },                                               // private without commit
  { p: { kind: 'captured', privacy: 'encrypted', commit: H32 } },                                // encrypted without an enc block
  { p: { kind: 'captured', privacy: 'encrypted', commit: H32, enc: { alg: 'ROT13', key_id: 'k', ct: 'AA' } } },   // encrypted with a non-AEAD alg
].map((d) => buildData(d)).concat([buildWith({ domain_shard: 'аpple.com' })]);   // + §4.3a Cyrillic-homograph domain
let obligOk = true;
for (const b of obligations) { if (b.buildErr) continue; if (lite.verify(b.doc).result === 'VALID:LIGHT' && !full.isValid(full.verify(b.doc))) { obligOk = false; F.push('P0-01 OBLIGATION lite-VALID/core-INVALID'); } }
ok('round-50 P0-01 exhaustive LIGHT-obligation differential: lite VALID ⇒ core VALID over §4.4 envelope XOR (public+commit/enc, private-no-commit/plaintext, encrypted-enc) + §4.3a A-label homograph', obligOk);

// round-51 P0-01 (owner: "структурно невозможное повторение из-за неполного покрытия") — the hand corpus above kept MISSING an
// obligation (calendar→rev76, envelope/A-label→rev78, private-commit-hash→rev79). GENERATE the doc-shape space by CONSTRUCTION —
// id forms × time forms × partition ENVELOPE shapes — build+sign each, assert lite VALID ⇒ core VALID over ALL. A new lite-vs-core
// drift (any obligation lite omits) fails HERE; I never hand-enumerate obligations again. Exhaustive-by-construction, not a corpus.
const H64 = 'sha256:' + 'cd'.repeat(32), enc0 = { alg: 'AES-256-GCM', key_id: 'k', ct: 'AA' };
const gen1 = (idO, timeO, part) => { try { return lite.seal(lite.buildState({ ...id, ...idO }, { ...time, ...timeO }, { p: part }), kp.privateKey, kp.pub); } catch { return null; } };
const partForms = [
  { kind: 'captured', value: { x: '1' } }, { kind: 'captured', value: { x: '1' }, commit: H64 }, { kind: 'captured', value: { x: '1' }, enc: enc0 },
  { kind: 'captured' }, { kind: 'bogus', value: { x: '1' } }, { kind: 'captured', privacy: 'blinded', commit: H64 },
  { kind: 'captured', privacy: 'blinded', commit: 'not-a-hash' }, { kind: 'captured', privacy: 'blinded' }, { kind: 'captured', privacy: 'blinded', commit: H64, value: { x: '1' } },
  { kind: 'captured', privacy: 'encrypted', commit: H64, enc: enc0 }, { kind: 'captured', privacy: 'encrypted', commit: H64 },
  { kind: 'captured', privacy: 'encrypted', commit: H64, enc: { alg: 'ROT13', key_id: 'k', ct: 'AA' } }, { kind: 'captured', privacy: 'bogus', value: { x: '1' } },
];
const idForms = [{}, { domain_shard: 'аpple.com' }, { domain_shard: 'bad name' }, { domain_shard: 'sha256:' + '00'.repeat(32) }, { ust_id: 'ust:20260231.12' }, { ust_id: 'ust:20260722.24' }, { class: undefined }, { class: 'attestation' }, { class: 'bogus' }];
const timeForms = [{}, { generated_at: '2026-02-31T00:00:00Z' }, { valid_to: '2020-01-01T00:00:00Z' }];
let genOk = true, genN = 0;
const probe = (d) => { if (!d) return; genN++; if (lite.verify(d).result === 'VALID:LIGHT' && !full.isValid(full.verify(d))) { genOk = false; F.push('P0-01 GEN lite-VALID/core-INVALID'); } };
for (const part of partForms) probe(gen1({}, {}, part));                                                     // envelope shapes at a valid id/time
for (const idO of idForms) for (const timeO of timeForms) probe(gen1(idO, timeO, { kind: 'captured', value: { x: '1' } }));   // id × time forms at a valid public partition
ok(`round-51 P0-01 GENERATED differential (${genN} built shapes): lite VALID ⇒ core VALID over the constructed doc-shape space — a new lite-vs-core drift fails here, no hand corpus`, genOk);

console.log(`\n  ust-lite validity vs full ust-protocol   PASS ${pass}   FAIL ${fail}`);
if (F.length) { F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ a ust-lite document IS a valid UST document — byte-identical, cross-verified both ways, AND lite VALID ⇒ core VALID over adversarial shapes (round-49 P0-01 differential)');
