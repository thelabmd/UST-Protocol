// SPDX-License-Identifier: Apache-2.0
// Conformance runner (rc.2): every primitive vector + every negative class verified against ust-protocol.
// Negatives are CONSTRUCTED from the live impl (not skipped), so this is a real pass/fail. HIGH/TOP built inline.
import * as P from './index.mjs';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url)));
function kp(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubRaw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32);
  return { priv, pubB64: pubRaw.toString('base64url'), key_id: P.keyId(pubRaw.toString('base64url')) };
}
const A = kp(V.seeds.A);
const T = { generated_at: '2026-06-28T14:03:12Z', valid_from: '2026-06-28T14:00:00Z', valid_to: '2026-06-28T15:00:00Z' };
const ID = { domain_shard: 'helioradar.com', ust_id: 'ust:20260628.14', key_id: A.key_id, class: 'observation' };
const mk = (data = { sw: { kind: 'captured', value: { kp: '4.33' } } }, id = ID, time = T) => P.seal(P.buildState(id, time, data), A.priv, A.pubB64);
const clone = (d) => JSON.parse(JSON.stringify(d));

let pass = 0, fail = 0, note = 0; const fails = [];
const check = (id, ok, d) => { if (ok) pass++; else { fail++; fails.push(id + (d ? ' — ' + d : '')); } };
const noted = (id, m) => { note++; };

// ─── 1. primitive vectors from the deterministic suite ───
for (const v of V.vectors) {
  switch (v.kind) {
    case 'canon': check(v.id, P.canon(v.input) === v.expect_canon); break;
    case 'canon-reject': {
      if (v.id.includes('ts-')) {                                        // timestamp is a §14.5 SHAPE reject, not §6 canon
        const bad = clone(mk()); bad.state.time.generated_at = v.id.includes('fractional') ? '2026-06-28T14:03:09.500Z' : '2026-06-28T14:03:09+00:00';
        check(v.id, P.verify(bad, { context: 'data' }).error === 'E-MALFORMED'); break;
      }
      if (v.id.includes('dupkey')) { check(v.id, P.verifyJson('{"a":"1","a":"2"}').error === 'E-CANON', 'verifyJson raw-bytes dup detection (F7 closed)'); break; }
      let input = v.input;
      if (!input && v.id.includes('nonNFC')) input = { note: 'e' + String.fromCharCode(0x301) };   // decomposed e + combining acute (NOT NFC)
      let threw = false; try { P.canon(input); } catch (e) { threw = e.code === 'E-CANON'; }
      check(v.id, threw, 'expected E-CANON'); break;
    }
    case 'hash': check(v.id, P.H(v.tag, P.canon(v.input)) === v.expect); break;
    case 'key_id': check(v.id, P.keyId(v.pub_b64url) === v.expect); break;
    case 'commit': check(v.id, P.H('ust:shard', P.canon(v.input)) === v.expect); break;
    case 'seed': check(v.id, P.seed(v.input) === v.expect); break;
    case 'merkle-root': check(v.id, P.merkleRoot(v.input) === v.expect); break;
    case 'signature': { const ok = P.edVerifyStrict(v.pub_b64url, v.signed_content, v.sig); check(v.id, (ok && v.expect === 'VALID') || (!ok && v.expect === 'E-SIG')); break; }
    case 'malleability-reject': check(v.id, P.edVerifyStrict(v.pub_b64url, v.signed_content, v.sig_malleable) === false, 'strict verifier MUST reject non-canonical S'); break;
    case 'version-reject': { const b = clone(mk()); b.ust = v.id.includes('major') ? '2.0' : '1.9'; check(v.id, P.verify(b).error === 'E-MALFORMED'); break; }
    case 'bijection-reject': { const b = clone(mk()); if (v.id.includes('missing')) b.state.data.extra = { kind: 'captured', value: { x: '1' } }; else b.state.hashes.ghost = 'sha256:' + '00'.repeat(32); check(v.id, P.verify(b, { context: 'data' }).error === 'E-MALFORMED'); break; }
    case 'document-negative': check(v.id, P.verify(v.doc, { context: 'data' }).result === 'INVALID'); break;
    default: noted(v.id, 'kind ' + v.kind + ' not exercised');
  }
}

// ─── 2. valid round-trip (new uniform preimage) + producer check ───
check('valid-roundtrip', P.verify(mk(), { context: 'data' }).result === 'VALID:LIGHT');
check('producer-seal-verifies', P.verify(mk({ a: { kind: 'captured', value: { x: '1' } }, b: { kind: 'computed', value: { y: '2' } } }), { context: 'data' }).result === 'VALID:LIGHT');

// ─── 3. rc.2 negatives — audit findings + Gemini-B ───
check('#1 stream-mixed-authority→E-AUTHORITY', (() => {
  const G = kp('bb'.repeat(32)), gen = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.10', key_id: G.key_id }, T, G.pubB64), G.priv, G.pubB64);
  const f0 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1001', key_id: A.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '1' } } }, { prev: P.contentHash(gen) }), A.priv, A.pubB64);
  const evil = P.seal(P.buildState({ domain_shard: 'evil.com', ust_id: 'ust:20260628.1002', key_id: A.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '2' } } }, { prev: P.contentHash(f0) }), A.priv, A.pubB64);
  return P.verifyStream([f0, evil], { genesis: gen }).error === 'E-AUTHORITY';
})());
check('#2 reserved-partition-name→E-MALFORMED', P.verify(mk({ ust_id: { kind: 'captured', value: { x: '1' } } }), { context: 'data' }).error === 'E-MALFORMED');
check('#2 no-collision (different ust_id → different hash)', P.partitionHash({ domain_shard: 'a', ust_id: 'ust:20260628.01', name: 'x', value: { v: '1' } }) !== P.partitionHash({ domain_shard: 'a', ust_id: 'ust:20260628.02', name: 'x', value: { v: '1' } }));
check('#3 unknown-top-level→E-MALFORMED', (() => { const b = clone(mk()); b.summary = 'unsigned-evil'; return P.verify(b, { context: 'data' }).error === 'E-MALFORMED'; })());
check('#4 unknown-kind→E-MALFORMED', P.verify(mk({ r: { kind: 'observation', value: { x: '1' } } }), { context: 'data' }).error === 'E-MALFORMED');
check('#5 anchor-bad-dir→fail-closed', (() => { const r = P.verifyAnchor('sha256:' + 'ab'.repeat(32), { root: 'sha256:' + 'cd'.repeat(32), path: [{ dir: 'BOGUS', hash: 'sha256:' + 'ef'.repeat(32) }] }); return r.inclusion === false && r.error === 'E-ANCHOR'; })());
check('#5 anchor-missing-path→no-throw', (() => { try { P.verifyAnchor('sha256:' + 'ab'.repeat(32), { root: 'sha256:' + 'cd'.repeat(32) }); return true; } catch { return false; } })());
check('#6 sig-alg-none→E-SIG', (() => { const b = clone(mk()); b.sig.alg = 'none'; return P.verify(b, { context: 'data' }).error === 'E-SIG'; })());
check('B leap-second→E-MALFORMED', P.verify(mk({ r: { kind: 'captured', value: { x: '1' } } }, ID, { generated_at: '2026-12-31T23:59:60Z', valid_from: '2026-12-31T23:00:00Z', valid_to: '2027-01-01T00:00:00Z' }), { context: 'data' }).error === 'E-MALFORMED');
// G1 (Gemini 3.1) — pinned identity (§3.1 TOFU) + Y3 name epistemics (publisher only when authoritative)
check('G1 pinned in-set→strength pinned', (r => r.result === 'VALID:LIGHT' && r.identity.strength === 'pinned' && r.publisher === undefined && r.publisher_claimed === 'helioradar.com')(P.verify(mk(), { context: 'data', pinnedKeys: [A.key_id] })));
check('G1 pinned not-in-set→E-KEY', P.verify(mk(), { context: 'data', pinnedKeys: ['sha256:' + '00'.repeat(32)] }).error === 'E-KEY');
check('G1 Y3 LIGHT→publisher_claimed (not publisher)', (r => r.publisher === undefined && r.publisher_claimed === 'helioradar.com' && r.identity.strength === 'self-asserted')(P.verify(mk(), { context: 'data' })));

// ── ChatGPT 5.5 Max audit — F1–F8 (all closed structurally) ──
{
  const G = kp('bb'.repeat(32)), K = kp('cc'.repeat(32)), E = kp('ee'.repeat(32)), signG = (s) => P.seal(s, G.priv, G.pubB64);
  const gen = signG(P.buildGenesis({ domain_shard: 'v.com', ust_id: 'ust:20260628.10', key_id: G.key_id }, T, G.pubB64));
  // F1 — new_key_id alias: entry adds K but claims new_key_id=E; doc signed by E must NOT be authoritative
  const alias = signG(P.buildKeyLogEntry({ domain_shard: 'v.com', ust_id: 'ust:20260628.1001', key_id: G.key_id }, T, { op: 'add', pub: K.pubB64, new_key_id: E.key_id }, P.contentHash(gen)));
  const docE = P.seal(P.buildState({ domain_shard: 'v.com', ust_id: 'ust:20260628.11', key_id: E.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '1' } } }), E.priv, E.pubB64);
  check('F1 keylog new_key_id alias→E-KEY', P.verify(docE, { genesis: gen, keylog: [alias], noForkConfirmed: true, context: 'data' }).error === 'E-KEY');
}
// F2 — stream checkpoint WITHOUT genesis → not proven
{
  const a0 = P.seal(P.buildState({ domain_shard: 'x.com', ust_id: 'ust:20260628.2001', key_id: A.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '1' } } }), A.priv, A.pubB64);
  const a1 = P.seal(P.buildState({ domain_shard: 'x.com', ust_id: 'ust:20260628.2002', key_id: A.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '2' } } }, { prev: P.contentHash(a0) }), A.priv, A.pubB64);
  const h = P.contentHash(a1), cp = P.seal(P.buildCheckpoint({ domain_shard: 'x.com', ust_id: 'ust:20260628.2003', key_id: A.key_id }, T, h, 2, h), A.priv, A.pubB64);
  check('F2 stream checkpoint w/o genesis→not proven', P.verifyStream([a0, a1], { checkpoint: cp }).complete !== 'proven');
}
check('F3 embedded bad proof→E-ANCHOR', (() => { const b = clone(mk()); b.proof = { root: 'sha256:' + '00'.repeat(32), path: [], anchor: { substrate: 'bitcoin-ots' } }; return P.verify(b, { context: 'data' }).error === 'E-ANCHOR'; })());
check('F4 derivation no-provenance→E-MALFORMED', P.verify(mk({ r: { kind: 'computed', value: { x: '1' } } }, { ...ID, class: 'derivation' }), { context: 'data' }).error === 'E-MALFORMED');
check('F4 observation w/ root→E-MALFORMED', (() => { const st = P.buildState(ID, T, { r: { kind: 'captured', value: { x: '1' } } }); st.provenance = { constituents: ['sha256:' + '11'.repeat(32)], root: 'sha256:' + '99'.repeat(32) }; return P.verify(P.seal(st, A.priv, A.pubB64), { context: 'data' }).error === 'E-MALFORMED'; })());
check('F5 encrypted w/o enc→E-MALFORMED', (() => { const st = { id: ID, time: T, data: { e: { kind: 'captured', privacy: 'encrypted', commit: 'sha256:' + 'cd'.repeat(32) } }, hashes: { e: P.partitionHash({ commit: 'sha256:' + 'cd'.repeat(32) }) } }; return P.verify(P.seal(st, A.priv, A.pubB64), { context: 'data' }).error === 'E-MALFORMED'; })());
check('F6 non-NFC member name→E-CANON', (() => { try { P.canon({ ['e' + String.fromCharCode(0x301)]: '1' }); return false; } catch (e) { return e.code === 'E-CANON'; } })());
check('F7 raw duplicate-key→E-CANON', P.verifyJson('{"ust":"0.0","ust":"1.0","state":{},"sig":{}}').error === 'E-CANON');
check('F8 impossible ust_id→E-MALFORMED', P.verify(mk({ r: { kind: 'captured', value: { x: '1' } } }, { ...ID, ust_id: 'ust:20261340.99' }), { context: 'data' }).error === 'E-MALFORMED');

// ─── 4. HIGH (genesis + keylog → authoritative) + TOP (stream proven, anchor inclusion) inline ───
{
  const G = kp('cc'.repeat(32)), K = kp('dd'.repeat(32)), signG = (s) => P.seal(s, G.priv, G.pubB64);
  const gen = signG(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.19', key_id: G.key_id }, T, G.pubB64));
  const add = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1901', key_id: G.key_id }, T, { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));
  const docK = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.20', key_id: K.key_id, class: 'observation' }, T, { sw: { kind: 'captured', value: { kp: '5' } } }), K.priv, K.pubB64);
  check('HIGH genesis VALID+self-signed', P.verify(gen).result === 'VALID:LIGHT' && gen.sig.key_id === gen.state.id.key_id);
  check('HIGH resolve→authoritative', (r => r.result === 'VALID:HIGH' && r.identity?.strength === 'authoritative')(P.verify(docK, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data' })));
  check('G1 Y3 authoritative→publisher (not claimed)', (r => r.publisher === 'noosphere.md' && r.publisher_claimed === undefined)(P.verify(docK, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data' })));
  // TOP stream (single authority) + checkpoint → proven
  const s0 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2001', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '1' } } }, { prev: P.contentHash(gen) }), G.priv, G.pubB64);
  const s1 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2002', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '2' } } }, { prev: P.contentHash(s0) }), G.priv, G.pubB64);
  const head = P.contentHash(s1);
  const cp = signG(P.buildCheckpoint({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2003', key_id: G.key_id }, T, head, 2, head));
  check('TOP stream+checkpoint→proven', P.verifyStream([s0, s1], { genesis: gen, checkpoint: cp }).complete === 'proven');
  // TOP anchor inclusion (2-leaf tree, audit path)
  const leaf = P.contentHash(s0), other = P.contentHash(s1);
  const sorted = [leaf, other].slice().sort();
  const root = P.merkleRoot(sorted);
  const sib = sorted[0] === leaf ? sorted[1] : sorted[0];
  const dir = sorted[0] === leaf ? 'R' : 'L';
  const proof = { root, path: [{ dir, hash: P.Hbytes('ust:leaf', Buffer.from(sib, 'utf8')) }], anchor: { substrate: 'bitcoin-ots', status: 'pending' } };
  check('TOP anchor inclusion', P.verifyAnchor(leaf, proof).inclusion === true);
  // TOP tier via verify(): authoritative identity + an embedded, substrate-final anchor ⇒ VALID:TOP
  const dch = P.contentHash(docK);
  const topProof = { root: P.Hbytes('ust:leaf', Buffer.from(dch, 'utf8')), path: [], anchor: { substrate: 'bitcoin-ots' } };
  const topR = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data', substrateVerify: () => ({ final: true, time: '2027-01-01T00:00:00Z' }) });
  check('TOP authoritative+anchored→VALID:TOP', topR.result === 'VALID:TOP');
  check('TOP verdict still carries completeness: not_evaluated (range property)', topR.completeness === 'not_evaluated');
  check('tier ladder distinct: LIGHT vs TOP', P.verify(mk(), { context: 'data' }).result === 'VALID:LIGHT' && topR.tier === 'TOP');
  // rc.6 N9 — a document cannot postdate its own anchor: substrate time BEFORE generated_at ⇒ E-ANCHOR.
  const n9 = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data', substrateVerify: () => ({ final: true, time: '2020-01-01T00:00:00Z' }) });
  check('N9 generated_at after anchorTime → E-ANCHOR', n9.error === 'E-ANCHOR');
  // rc.6 M-05 — the anchor availability STATUS is carried through (substrate unreachable ⇒ status unavailable, doc stays LIGHT-time-unproven).
  const un = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data', substrateVerify: () => null });
  check('anchor substrate unreachable → time.status unavailable (not flattened)', P.isValid(un) && un.time.status === 'unavailable' && un.time.strength === 'unproven');
  // rc.9 (11th audit 7.1/B): revocation boundary U==C is INVALID; a non-strict-Z compromised_since is E-MALFORMED.
  const C = '2026-06-28T15:00:00Z';
  const rev = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1902', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: C }, P.contentHash(add)));
  check('revocation boundary U == C → E-KEY (X1: VALID only if U < C)', P.resolveAuthority(docK, { genesis: gen, keylog: [add, rev], anchorTime: C }).error === 'E-KEY');
  check('revocation U < C → pre-compromise accepted', P.resolveAuthority(docK, { genesis: gen, keylog: [add, rev], anchorTime: '2026-06-28T14:59:59Z' }).strength === 'authoritative');
  const revBad = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1903', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: '2026-06-28T15:00:00.5Z' }, P.contentHash(add)));
  check('fractional compromised_since → E-MALFORMED (strict-Z, §12.2)', P.resolveAuthority(docK, { genesis: gen, keylog: [add, revBad], anchorTime: C }).error === 'E-MALFORMED');
}

// ─── rc.6 — the OBLIGATIONS TABLE (§14a): every commitment-bearing member recomputed; semantic consistency;
//     typed identity; MTI registry; honest provenance report. One check per obligation (audit E regression).
{
  const obsA = mk(); const hA = P.contentHash(obsA);
  const stBadSeed = P.buildState({ ...ID, class: 'derivation' }, T, { d: { kind: 'computed', value: { x: '1' } } },
    { based_on: [{ hash: hA }], seed: P.seed(['sha256:' + 'ab'.repeat(32)]) });
  check('E-SEED derivation seed mismatch → INVALID', P.verify(P.seal(stBadSeed, A.priv, A.pubB64), { context: 'data' }).error === 'E-SEED');
  const goodDeriv = P.seal(P.buildDerivation(ID, T, { d: { kind: 'computed', value: { x: '1' } } }, [{ hash: hA }]), A.priv, A.pubB64);
  const rd = P.verify(goodDeriv, { context: 'data' });
  check('correct seed → VALID + depth-0 reports referents unverified', rd.result === 'VALID:LIGHT' && rd.provenance.depth === 0 && rd.provenance.referents === 'unverified');
  const rw = P.verify(goodDeriv, { context: 'data', provenanceDepth: 1, resolveRef: (h) => (h === hA ? obsA : null) });
  check('depth-1 walk resolves referent → referents verified', rw.provenance.depth >= 1 && rw.provenance.referents === 'verified');
  const rp = P.verify(goodDeriv, { context: 'data', provenanceDepth: 1, resolveRef: () => null });
  check('depth-1 unresolvable referent → partial (availability ≠ failure)', P.isValid(rp) && rp.provenance.referents === 'partial');
  const rz = P.verify(goodDeriv, { context: 'data', provenanceDepth: 1, resolveRef: () => mk({ zz: { kind: 'captured', value: { q: '9' } } }) });
  check('resolver returning a DIFFERENT document → INVALID', rz.error === 'E-MALFORMED');
  // §9.4/§13 boundary pins (rc.8, 10th audit): duplicate refs are a SHAPE error; the key-log ceiling is E-BOUNDS.
  const stDup = P.buildState({ ...ID, class: 'derivation' }, T, { d: { kind: 'computed', value: { x: '1' } } },
    { based_on: [{ hash: hA }, { hash: hA }], seed: P.seed([hA, hA]) });
  check('duplicate hash in based_on → E-MALFORMED (§9.4)', P.verify(P.seal(stDup, A.priv, A.pubB64), { context: 'data' }).error === 'E-MALFORMED');
  check('duplicate hash in constituents → E-MALFORMED (§9.4)', P.verify(P.seal(P.buildAttestation(ID, T, {}, [hA, hA]), A.priv, A.pubB64), { context: 'data' }).error === 'E-MALFORMED');
  const gen257 = P.seal(P.buildGenesis({ domain_shard: ID.domain_shard, ust_id: ID.ust_id, key_id: A.key_id }, T, A.pubB64), A.priv, A.pubB64);
  check('key-log > 256 → E-BOUNDS at resolution, log never truncates (§13 N8)', P.resolveAuthority(mk(), { genesis: gen257, keylog: Array.from({ length: 257 }, () => mk()) }).error === 'E-BOUNDS');
  // rc.9 edge pass (11th audit): full reserved-name registry · coexistence · verified-node budget · long/emoji names
  check('partition named "kind" → E-MALFORMED (§17 full registry)', P.verify(mk({ kind: { kind: 'captured', value: { x: '1' } } }), { context: 'data' }).error === 'E-MALFORMED');
  check('partition named "prev" → E-MALFORMED (§17 full registry)', P.verify(mk({ prev: { kind: 'captured', value: { x: '1' } } }), { context: 'data' }).error === 'E-MALFORMED');
  check('2000-unit partition name → VALID (full-length sort, §6)', P.isValid(P.verify(mk({ ['n'.repeat(2000)]: { kind: 'captured', value: { x: '1' } } }), { context: 'data' })));
  check('emoji partition name → VALID (NFC-stable)', P.isValid(P.verify(mk({ '🌞': { kind: 'captured', value: { x: '1' } } }), { context: 'data' })));
  const coexist = P.buildState({ ...ID, class: 'derivation' }, T, { d: { kind: 'computed', value: { x: '1' } } },
    { based_on: [{ hash: hA }], seed: P.seed([hA]), constituents: [hA], root: P.merkleRoot([hA]) });
  check('based_on+seed AND constituents+root coexist, both verified → VALID (§9.4)', P.isValid(P.verify(P.seal(coexist, A.priv, A.pubB64), { context: 'data' })));
  const coexistBad = P.buildState({ ...ID, class: 'derivation' }, T, { d: { kind: 'computed', value: { x: '1' } } },
    { based_on: [{ hash: hA }], seed: P.seed([hA]), constituents: [hA], root: 'sha256:' + 'ee'.repeat(32) });
  check('coexistence: wrong root still E-ROOT (one never waives the other)', P.verify(P.seal(coexistBad, A.priv, A.pubB64), { context: 'data' }).error === 'E-ROOT');
  const five = Array.from({ length: 5 }, (_, i) => mk({ ['v' + i]: { kind: 'captured', value: { x: String(i) } } })); const fiveMap = new Map(five.map((d) => [P.contentHash(d), d]));
  const wideDeriv = P.seal(P.buildDerivation(ID, T, { d: { kind: 'computed', value: { x: '1' } } }, [...fiveMap.keys()].map((h) => ({ hash: h }))), A.priv, A.pubB64);
  check('verified-node budget exceeded → E-BOUNDS whole walk (§13 P4)', P.verify(wideDeriv, { context: 'data', provenanceDepth: 1, resolveRef: (h) => fiveMap.get(h), refBudget: 2 }).error === 'E-BOUNDS');
  const wideOk = P.verify(wideDeriv, { context: 'data', provenanceDepth: 1, resolveRef: (h) => fiveMap.get(h) });
  check('default budget (256) suffices → referents verified', P.isValid(wideOk) && wideOk.provenance.referents === 'verified');
  check('ust_id Feb-31 → INVALID (real calendar)', P.verify(mk(undefined, { ...ID, ust_id: 'ust:20260231.09' }), { context: 'data' }).error === 'E-MALFORMED');
  check('generated_at Feb-30 → INVALID (real calendar)', P.verify(mk(undefined, ID, { ...T, generated_at: '2026-02-30T10:00:00Z' }), { context: 'data' }).error === 'E-MALFORMED');
  const noKind = P.seal(P.buildState(ID, T, { p: { privacy: 'blinded', commit: 'sha256:' + 'cd'.repeat(32) } }), A.priv, A.pubB64);
  check('private partition without kind → INVALID (closed per-mode schema)', P.verify(noKind, { context: 'data' }).error === 'E-MALFORMED');
  const rsc = P.verify(mk(undefined, { ...ID, domain_shard: A.key_id }), { context: 'data' });
  check('key-form shard == key_id → VALID + identity.mode key (self-certifying)', rsc.result === 'VALID:LIGHT' && rsc.identity.mode === 'key');
  check('name shard → identity.mode name', P.verify(mk(), { context: 'data' }).identity.mode === 'name');
  check('key-form shard != key_id → INVALID', P.verify(mk(undefined, { ...ID, domain_shard: 'sha256:' + '12'.repeat(32) }), { context: 'data' }).error === 'E-MALFORMED');
  const nonce = 'n-' + 'a'.repeat(16);
  const commit = P.blindedCommit({ domain_shard: ID.domain_shard, ust_id: ID.ust_id, name: 'e', value: { v: '1' }, nonce });
  const encDoc = P.seal(P.buildState(ID, T, { e: { kind: 'captured', privacy: 'encrypted', commit, enc: { alg: 'XChaCha20-Poly1305', key_id: 'k1', ct: 'AAAA' } } }), A.priv, A.pubB64);
  const re = P.verify(encDoc, { context: 'data', disclosures: { e: { nonce, value: { v: '1' } } }, decKeys: { k1: 'AAAA' } });
  check('OPTIONAL AEAD not implemented → INDETERMINATE(unsupported_alg)', re.result === 'INDETERMINATE' && re.reason === 'unsupported_alg');
  // P1-2: the result ALWAYS carries an explicit completeness field; a single-document verify never evaluates it.
  check('completeness field explicit: not_evaluated on doc verify', P.verify(mk(), { context: 'data' }).completeness === 'not_evaluated');
  const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
  check('version gate: package.json == VERSION.spec', pkg.version === P.VERSION.spec);
  check('version gate: vectors tagged with the same rc', V.version.includes(P.VERSION.spec.slice(P.VERSION.spec.indexOf('rc'))));
  // rc.12 residual (14th round): the spec HEADER drifted to rc.6 while the body carried rc.11/12 —
  // one-version-source now ENFORCED end-to-end: header must name the exact current rc.
  const specText = readFileSync(new URL('../../spec/UST-1.0.md', import.meta.url), 'utf8');
  check('version gate: spec release header == VERSION.spec', specText.includes('`' + P.VERSION.spec + '`'));
  // bundled-drift gate: the extension MUST carry the exact clean-room bytes (twice-in-one-day lesson).
  const cleanRoom = readFileSync(new URL('../../docs/ust-verify.mjs', import.meta.url), 'utf8');
  const bundled = readFileSync(new URL('../../extension/lib/ust-verify.mjs', import.meta.url), 'utf8');
  check('bundle gate: extension clean-room is byte-identical to docs/ust-verify.mjs', bundled === cleanRoom);
}

// ─── verifier PARITY (I4 across OUR OWN two verifiers) — the 2026-07-12 probe found the
//     clean-room admitting >64 partitions the reference rejects; these pin parity on the edges.
{
  const { verify: cleanRoom } = await import('../../docs/ust-verify.mjs');
  const mkN = (n, id = { ...ID, ust_id: 'ust:20260628.15' }) => {
    const data = {};
    for (let i = 0; i < n; i++) data['p' + i] = { kind: 'captured', value: { x: String(i) } };
    return P.seal(P.buildState(id, T, data, undefined, { maxPartitions: 4096 }), A.priv, A.pubB64);
  };
  const d64 = mkN(64), d65 = mkN(65);
  const r64 = P.verify(d64, { context: 'data' }), c64 = await cleanRoom(d64, { context: 'data' });
  const r65 = P.verify(d65, { context: 'data' }), c65 = await cleanRoom(d65, { context: 'data' });
  check('parity: 64 partitions VALID in BOTH verifiers', P.isValid(r64) && P.isValid(c64));
  // ─── §13 capacity ladder (rc.10): floor 64 · genesis-declared ≤ 4096 · INDETERMINATE without genesis ───
  check('ladder: 65 name-form NO genesis → INDETERMINATE(unavailable) in BOTH', r65.result === 'INDETERMINATE' && r65.reason === 'unavailable' && c65.result === 'INDETERMINATE' && c65.reason === 'unavailable');
  const d65k = mkN(65, { domain_shard: A.key_id, ust_id: 'ust:20260628.15', key_id: A.key_id, class: 'observation' });
  check('ladder: 65 KEY-form → E-BOUNDS (no ceremony can exist)', P.verify(d65k, { context: 'data' }).error === 'E-BOUNDS' && (await cleanRoom(d65k, { context: 'data' })).error === 'E-BOUNDS');
  const genCap = (mp, mb) => P.seal(P.buildGenesis({ domain_shard: ID.domain_shard, ust_id: 'ust:20260628.01', key_id: A.key_id }, T, A.pubB64, mp, mb), A.priv, A.pubB64);
  // rc.12 P0-4: capacity = TRUSTED GRANT via opts.capacity; a raw self-signed genesis is a
  // self-issued budget and NO LONGER expands anything.
  check('grant: 65 + capacity{128} → ADMITTED VALID:LIGHT', P.verify(d65, { context: 'data', capacity: { maxPartitions: 128 } }).result === 'VALID:LIGHT');
  check('grant: 65 + capacity{64} → E-BOUNDS (over granted)', P.verify(d65, { context: 'data', capacity: { maxPartitions: 64 } }).error === 'E-BOUNDS');
  const d1000 = mkN(1000);
  check('grant: 1024 granted — 1000 partitions ADMITTED (default ≠ ceiling)', P.verify(d1000, { context: 'data', capacity: { maxPartitions: 1024 } }).result === 'VALID:LIGHT');
  check('P0-4 pinned: raw self-signed genesis ALONE no longer expands → INDETERMINATE', P.verify(d65, { context: 'data', genesis: genCap(128) }).result === 'INDETERMINATE');
  const auth = P.resolveAuthority(mk(), { genesis: genCap(512, 4_000_000), keylog: [], noForkConfirmed: true });
  check('resolveAuthority surfaces the ceremony capacity (grant flows FROM resolution)', auth.capacity?.maxPartitions === 512 && auth.capacity?.maxTranscriptBytes === 4_000_000 && auth.strength === 'authoritative');
  const fake4097 = { state: { data: Object.fromEntries(Array.from({ length: 4097 }, (_, i) => ['p' + i, '1'])) } };
  check('ABS: 4097 partitions → structural E-BOUNDS precheck', P.checkBounds(fake4097) === 'partitions > 4096');
  let guardThrew = false; try { P.buildState(ID, T, Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['p' + i, { kind: 'captured', value: { x: '1' } }]))); } catch (e) { guardThrew = e.code === 'E-BOUNDS'; }
  check('producer guard: buildState 65 without {maxPartitions} THROWS E-BOUNDS', guardThrew);
  // ─── §13 SIZE ladder (rc.11): floor 1 MiB · genesis-declared ≤ 64 MiB · pre-parse INDETERMINATE ───
  const bigVal = 'x'.repeat(1_200_000);
  const mkBig = (id = { ...ID, ust_id: 'ust:20260628.16' }, opts = { maxTranscriptBytes: 4_000_000 }) =>
    P.seal(P.buildState(id, T, { blob: { kind: 'captured', value: { x: bigVal } } }, undefined, opts), A.priv, A.pubB64);
  const dBig = mkBig();
  const rBigNo = P.verify(dBig, { context: 'data' });
  check('size: >floor name-form NO grant → INDETERMINATE(unavailable)', rBigNo.result === 'INDETERMINATE' && rBigNo.reason === 'unavailable');
  const cBigNo = await cleanRoom(dBig, { context: 'data' });
  check('size parity: clean-room >floor name-form → INDETERMINATE', cBigNo.result === 'INDETERMINATE');
  check('size: >floor + capacity grant → ADMITTED VALID:LIGHT', P.verify(dBig, { context: 'data', capacity: { maxTranscriptBytes: 4_000_000 } }).result === 'VALID:LIGHT');
  check('size: >floor + grant smaller than doc → E-BOUNDS', P.verify(dBig, { context: 'data', capacity: { maxTranscriptBytes: 1_048_576 } }).error === 'E-BOUNDS');
  const dBigK = mkBig({ domain_shard: A.key_id, ust_id: 'ust:20260628.16', key_id: A.key_id, class: 'observation' });
  check('size: >floor KEY-form → E-BOUNDS (no ceremony can exist)', P.verify(dBigK, { context: 'data' }).error === 'E-BOUNDS');
  // rc.12 P0-1: UTF-8 vs UTF-16 parity — Cyrillic doc (700k units = 1.4M bytes) must agree in BOTH
  const cyr = P.seal(P.buildState({ ...ID, ust_id: 'ust:20260628.17' }, T, { txt: { kind: 'captured', value: { body: 'ж'.repeat(700_000) } } }, undefined, { maxTranscriptBytes: 4_000_000 }), A.priv, A.pubB64);
  const rCyr = P.verify(cyr, { context: 'data' }), cCyr = await cleanRoom(cyr, { context: 'data' });
  check('P0-1 pinned: Cyrillic 1.4 MB UTF-8 — SAME verdict in both verifiers (UTF-8 metric)', rCyr.result === 'INDETERMINATE' && cCyr.result === 'INDETERMINATE');
  // rc.12 P0-3: formatting can never flip a verdict — pretty-printed raw > floor, canonical ≤ floor ⇒ VALID
  const small = mk();
  const pretty = JSON.stringify(small, null, 8) + ' '.repeat(1_200_000);
  check('P0-3 pinned: transport whitespace never flips the verdict (canonical metric)', P.verifyJson(pretty, { context: 'data' }).result === 'VALID:LIGHT');
  // rc.12 P0-2/P1-7: transport admission is resource_limit, decided on BYTES before decode
  const rTrans = P.verifyJson(Buffer.alloc(67_108_865, 120));
  check('transport: over-budget Buffer → INDETERMINATE(resource_limit) BEFORE decode', rTrans.result === 'INDETERMINATE' && rTrans.reason === 'resource_limit');
  // rc.12 capability ceiling: protocol-valid but beyond THIS verifier
  const rCapb = P.verify(mk(), { context: 'data', maxSupportedBytes: 100 });
  check('capability: valid doc beyond verifier budget → INDETERMINATE(resource_limit)', rCapb.result === 'INDETERMINATE' && rCapb.reason === 'resource_limit');
  // rc.12 P1-6: ACCURATE producer guard — hashes map counted (old {id,time,data}+512 missed it)
  const manyData = Object.fromEntries(Array.from({ length: 4000 }, (_, i) => ['p' + i, { kind: 'captured', value: { v: 'x'.repeat(180) } }]));
  let hashGuard = false; try { P.buildState(ID, T, manyData, undefined, { maxPartitions: 4096 }); } catch (e) { hashGuard = e.code === 'E-BOUNDS'; }
  check('P1-6 pinned: 4000×180B — hashes map pushes over floor, guard THROWS (accurate metric)', hashGuard);
  let sizeGuard = false; try { P.buildState(ID, T, { b: { kind: 'captured', value: { x: bigVal } } }); } catch (e) { sizeGuard = e.code === 'E-BOUNDS'; }
  check('producer guard: 1.2 MiB without {maxTranscriptBytes} THROWS E-BOUNDS', sizeGuard);
  const good = mk(); const rg = P.verify(good, { context: 'data' }); const cg = await cleanRoom(good, { context: 'data' });
  check('parity: identical verdict+hash on a valid doc', rg.result === cg.result && rg.content_hash === cg.content_hash);
}

console.log('\n════════════════════════════════════════════');
// ─── rc.13: discovery-driven resolution + SSRF guard (owner: a verifier that resolves BY NAME must not
//     let an untrusted document point it at an internal address). The guard is a protocol-law boundary.
{
  const pub = ['noosphere.md', 'example.com', 'a.b.co.uk', 'x.london'];
  const priv = ['localhost', '127.0.0.1', '169.254.169.254', '192.168.1.1', 'foo.internal', 'x.local',
    'y.onion', '::1', 'fd00::1', 'host:8080', 'nohostonly', 'a..b.com', 'http://x.com', 'x.com/p', 'user@x.com'];
  check('ssrf guard: public DNS names pass', pub.every(P.isPublicDnsShard));
  check('ssrf guard: IPs/localhost/internal/ports/paths refused', priv.every((s) => !P.isPublicDnsShard(s)));

  // resolveByDiscovery: an internal-address document NEVER makes a network call (fetchImpl asserts none)
  let touched = 0;
  const spyFetch = async () => { touched++; return { ok: false, status: 0, text: async () => '' }; };
  const evilId = { ...ID, domain_shard: '169.254.169.254', ust_id: 'ust:20260628.15' };
  const evil = P.seal(P.buildState(evilId, T, { p: { kind: 'captured', value: { x: '1' } } }), A.priv, A.pubB64);
  const r1 = await P.resolveByDiscovery(evil, { context: 'data' }, { fetchImpl: spyFetch });
  check('resolveByDiscovery: SSRF target never fetched', touched === 0 && !!r1.resolution?.skipped);

  // offline forbids the network even for a public name
  const okId = { ...ID, domain_shard: 'noosphere.md', ust_id: 'ust:20260628.15' };
  const okDoc = P.seal(P.buildState(okId, T, { p: { kind: 'captured', value: { x: '1' } } }), A.priv, A.pubB64);
  const r2 = await P.resolveByDiscovery(okDoc, { context: 'data', offline: true }, { fetchImpl: spyFetch });
  check('resolveByDiscovery: offline makes zero network calls', touched === 0 && r2.resolution === null);

  // a public-name LIGHT document IS worth resolving (a small slot still wants its publisher) — fetch fires
  touched = 0;
  const r3 = await P.resolveByDiscovery(okDoc, { context: 'data' }, { fetchImpl: spyFetch });
  check('resolveByDiscovery: public LIGHT resolves (fetch fires, honest error on failure)', touched > 0 && !!r3.resolution?.error);
}

// ─── rc.14: witness auto-query (§12.1 M2, #68) — no-fork becomes EVIDENCE, so HIGH is the honest default.
{
  const rootW = kp('bb'.repeat(32)), opW = kp('cc'.repeat(32));
  const gen = P.seal(P.buildGenesis({ domain_shard: 'wit-test.example', ust_id: 'ust:20260713.14', key_id: rootW.key_id }, T, rootW.pubB64, 256), rootW.priv, rootW.pubB64);
  const kl0 = P.seal(P.buildKeyLogEntry({ domain_shard: 'wit-test.example', ust_id: 'ust:20260713.14', key_id: rootW.key_id }, T, { op: 'add', pub: opW.pubB64, new_key_id: opW.key_id }, P.contentHash(gen)), rootW.priv, rootW.pubB64);
  const gHash = P.contentHash(gen);
  const data = {}; for (let i = 0; i < 146; i++) data['s' + i] = { kind: 'captured', value: { v: String(i) } };
  const doc = P.seal(P.buildState({ domain_shard: 'wit-test.example', ust_id: 'ust:20260713.140030', key_id: opW.key_id, class: 'observation' }, T, data, undefined, { maxPartitions: 256 }), opW.priv, opW.pubB64);
  const anchorOf = (h) => ({ root: P.Hbytes('ust:leaf', Buffer.from(h, 'utf8')), path: [], anchor: { substrate: 'bitcoin-ots', block_height: 900000 } });
  const wlog = (entries, active) => ({ domain_shard: 'wit-test.example', active, genesis_log: entries });
  const mk = (log, extra = {}) => async (u) => {
    u = String(u);
    if (u.endsWith('/.well-known/ust-genesis')) return { ok: true, text: async () => JSON.stringify(gen) };
    if (u.endsWith('/.well-known/ust-keylog')) return { ok: true, text: async () => JSON.stringify([kl0]) };
    if (u.endsWith('/.well-known/ust-witness')) return log ? { ok: true, text: async () => JSON.stringify(log) } : { ok: false, status: 404, text: async () => '' };
    return { ok: false, status: 404, text: async () => '' };
  };
  const final = () => ({ final: true, time: '2026-07-13T14:05:00Z' });

  const okLog = wlog([{ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) }], gHash);
  const r1 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: final });
  check('witness-confirmed lifts to HIGH automatically', r1.verdict.result === 'VALID:HIGH' && r1.resolution.noFork === 'witness-confirmed' && r1.verdict.publisher === 'wit-test.example');

  const r2 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(null), substrateVerify: final });
  check('witness unreachable = LIGHT + HIGH pending (never forged, W1)', r2.verdict.result === 'VALID:LIGHT' && r2.resolution.noFork.startsWith('HIGH pending'));

  const forkLog = wlog([{ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) }, { content_hash: 'sha256:' + 'ab'.repeat(32), superseded_by: null, anchor: anchorOf('sha256:' + 'ab'.repeat(32)) }], gHash);
  const r3 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(forkLog), substrateVerify: final });
  check('two anchored active genesis = fork = E-GENESIS', r3.verdict.result === 'INVALID' && r3.verdict.error === 'E-GENESIS');

  const r4 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: () => ({ final: false }) });
  check('anchor not final (Bitcoin pending) = no HIGH, honest pending', r4.verdict.result === 'VALID:LIGHT' && r4.resolution.noFork.startsWith('HIGH pending'));

  const r5 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog) });   // no substrateVerify
  check('no substrate cross-check = never witness-confirmed (anchor unproven)', r5.verdict.result === 'VALID:LIGHT');

  const r6 = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true }, { fetchImpl: mk(null) });
  check('explicit --no-fork-confirmed still overrides (air-gap) without witness', r6.verdict.result === 'VALID:HIGH');
}

// ─── rc.15: combineSubstrates — heterogeneous witness substrates (#68). A verifier may speak several
// anchor dialects (Bitcoin, Rekor, …) via plugins; each returns null for a substrate it does not handle,
// the router tries them in order. One QUESTION, many dialects — §17 registry is the shared vocabulary.
{
  const bitcoinOnly = async (anchor) => (anchor.substrate === 'bitcoin-ots' ? { final: true, time: 'btc' } : null);
  const rekorOnly = async (anchor) => (anchor.substrate === 'rekor' ? { final: true, time: 'rekor' } : null);
  const router = P.combineSubstrates([bitcoinOnly, rekorOnly]);
  check('router delegates by substrate: bitcoin', (await router({ substrate: 'bitcoin-ots' }, 'sha256:x')).time === 'btc');
  check('router delegates by substrate: rekor', (await router({ substrate: 'rekor' }, 'sha256:x')).time === 'rekor');
  check('router returns null for an unknown substrate (→ INDETERMINATE, honest)', (await router({ substrate: 'dogecoin' }, 'sha256:x')) === null);
  check('router order: first non-null wins', (await P.combineSubstrates([async () => null, rekorOnly])({ substrate: 'rekor' }, 'x')).time === 'rekor');
}

// ─── rc.16 web parity: the browser clean-room verifier auto-queries the witness too (#68), so all three
// surfaces (cli/mcp/web) reach VALID:HIGH the same way. Source-pin the witness half + its RFC6962 fix.
{
  const resolve = readFileSync(new URL('../../docs/ust-resolve.mjs', import.meta.url), 'utf8');
  check('web resolver auto-queries the witness', resolve.includes('export async function witnessNoFork') && resolve.includes('rekorInclusion'));
  check('web witness has the RFC6962 right-edge shift', resolve.includes('fn === sn || (fn & 1) === 1') && resolve.includes('while (fn !== 0'));
  check('web witness confirmed = automatic HIGH (no checkbox)', readFileSync(new URL('../../docs/index.html', import.meta.url), 'utf8').includes("witness.status === 'confirmed'"));
}

console.log('  ust-protocol ' + P.VERSION.spec + ' conformance vs ' + V.version);
console.log('  PASS ' + pass + '   FAIL ' + fail + '   NOTES ' + note);
if (fails.length) { console.log('\n  FAILURES:'); fails.forEach(f => console.log('    ✗ ' + f)); }
else console.log('  ✓ all exercised checks pass (primitives + 6 findings + Gemini-B + HIGH + TOP)');
