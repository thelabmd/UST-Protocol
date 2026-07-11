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
}

console.log('\n════════════════════════════════════════════');
console.log('  ust-protocol ' + P.VERSION.spec + ' conformance vs ' + V.version);
console.log('  PASS ' + pass + '   FAIL ' + fail + '   NOTES ' + note);
if (fails.length) { console.log('\n  FAILURES:'); fails.forEach(f => console.log('    ✗ ' + f)); }
else console.log('  ✓ all exercised checks pass (primitives + 6 findings + Gemini-B + HIGH + TOP)');
