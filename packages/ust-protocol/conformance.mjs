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
// P0-2 — `authoritative` name-authority is EARNED from a verified NO-FORK EVIDENCE (a typed claim signed by a witness
// the CONSUMER trusts), never from a raw `noForkConfirmed` boolean (that is only a `consumer-override`). `nfe(genesis)`
// mints a consumer-trusted witness's evidence bound to this domain + active genesis, to reach authoritative in tests.
const W = kp('bb'.repeat(32));
const nfe = (genesis) => ({ noForkEvidence: P.buildNoForkEvidence({ domain_shard: genesis.state.id.domain_shard, active_genesis: P.contentHash(genesis) }, W.priv, W.pubB64), trustRoots: { [W.key_id]: W.pubB64 } });
// round-17 P0-02 — the proven anchor upper bound U reaches K_n(t) ONLY through the verified anchor seam (a raw
// resolveAuthority anchorTime no longer forges U). Supply U by verifying an anchored copy of the doc (a trivial
// self-consistent inclusion proof: empty path ⇒ root = H_leaf(content_hash)) with a mock substrate returning `time:U`.
const atU = (doc, genesis, keylog, U, opts = {}) => {
  const proof = { root: P.Hbytes('ust:leaf', Buffer.from(P.contentHash(doc), 'utf8')), path: [], anchor: { substrate: 'test-anchor' } };
  return P.verify({ ...doc, proof }, { genesis, keylog, ...nfe(genesis), substrateVerify: () => ({ final: true, time: U }), context: 'data', ...opts });
};

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
    // #75 language-neutral encoder vectors (a second implementation runs the SAME cases)
    case 'utf8-reject': check(v.id, P.verifyJson(Buffer.from(v.input_hex, 'hex')).error === v.expect_error); break;
    case 'b64url': check(v.id, (P.strictB64url(v.value, v.bytes) !== null) === v.expect); break;
    case 'cadence': check(v.id, P.parseCadenceInt(v.value) === v.expect); break;
    // #75 ROOT 2 — the key-log state machine as a language-neutral vector: run resolveKeys over embedded signed docs.
    case 'keylog-state': { const r = P.resolveKeys(v.genesis, v.keylog); check(v.id, v.expect.error ? r.error === v.expect.error : (!r.error && r.active.size === v.expect.active_count && r.validKeys.size === v.expect.all_count)); break; }
    // #75 ROOT 1 — K_n(t): authority resolved at a PROVEN anchor time (lower bound premature · upper bound X1).
    case 'authority-at-time': { const r = atU(v.doc, v.genesis, v.keylog, v.anchor_time); const id = r.identity || {}; check(v.id, v.expect.error ? (r.result === 'INVALID' && new RegExp(v.expect.error).test(r.error || '')) : (id.strength === v.expect.strength && id.status === v.expect.status)); break; }
    // #75 ROOT 3 (math-derived, no manifest) — composition authority: forkChoice/verifyStream resolve per-frame
    // authority (impersonation) + grid equality (off-grid), all language-neutral.
    case 'stream-authority': case 'stream-grid': { const r = P.verifyStream(v.frames, { genesis: v.genesis, checkpoint: v.checkpoint }); check(v.id, v.expect.error ? r.error === v.expect.error : r.complete === v.expect.complete); break; }
    case 'fork-choice': { const sv = (a, root) => v.anchored_roots.includes(root) ? { final: true, time: '2027-01-01T00:00:00Z' } : null; const r = await P.forkChoice(v.candidates, { genesis: v.genesis, ...nfe(v.genesis), substrateVerify: sv }); check(v.id, r.result === v.expect.result); break; }
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
  check('HIGH resolve→authoritative', (r => r.result === 'VALID:HIGH' && r.identity?.strength === 'authoritative')(P.verify(docK, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data' })));
  check('G1 Y3 authoritative→publisher (not claimed)', (r => r.publisher === 'noosphere.md' && r.publisher_claimed === undefined)(P.verify(docK, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data' })));
  // TOP stream (single authority) + checkpoint → proven
  const s0 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2001', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '1' } } }, { prev: P.contentHash(gen) }), G.priv, G.pubB64);
  const s1 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2002', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n: '2' } } }, { prev: P.contentHash(s0) }), G.priv, G.pubB64);
  const head = P.contentHash(s1);
  const cp = signG(P.buildCheckpoint({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2003', key_id: G.key_id }, T, head, 2, head));
  check('TOP stream+checkpoint→chain-consistent (no-deletion; complete needs signed cadence, #69 C)', P.verifyStream([s0, s1], { genesis: gen, checkpoint: cp }).complete === 'chain-consistent');
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
  const topR = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data', substrateVerify: () => ({ final: true, time: '2027-01-01T00:00:00Z' }) });
  check('TOP authoritative+anchored→VALID:TOP', topR.result === 'VALID:TOP');
  // #71 — a substrate's ASSURANCE basis flows into the verdict's time field (TOP names its trust model honestly)
  const topA = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data', substrateVerify: () => ({ final: true, time: '2027-01-01T00:00:00Z', assurance: 'explorer-corroborated' }) });
  check('#71 substrate assurance surfaces in the TOP verdict (explorer-corroborated ≠ trustless)', topA.result === 'VALID:TOP' && topA.time.assurance === 'explorer-corroborated');
  check('TOP verdict still carries completeness: not_evaluated (range property)', topR.completeness === 'not_evaluated');
  check('tier ladder distinct: LIGHT vs TOP', P.verify(mk(), { context: 'data' }).result === 'VALID:LIGHT' && topR.tier === 'TOP');
  // UST-9op surface #1 — bind the LATTICE projection to the LIVE §14 verify path, not only the rewritten inlineTier
  // oracle. On REAL verify() outputs across the whole tier ladder, the emitted tier MUST equal projectTier of the
  // emitted AssuranceState, and result MUST be 'VALID:'+tier. If verify ever recomputes the tier independently
  // (the transcription drift the audit worried about), this breaks; inlineTier stays as the INDEPENDENT oracle.
  const liveLadder = [
    P.verify(mk(), { context: 'data' }),                                            // LIGHT
    P.verify(docK, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data' }),  // HIGH
    topR,                                                                            // TOP
  ];
  check('LATTICE (6c) LIVE verify tier == projectTier(emitted assurance) across LIGHT/HIGH/TOP (single source, no transcription gap)',
    liveLadder.every((v) => v.assurance && P.projectTier(v.assurance) === v.tier && v.result === 'VALID:' + v.tier)
    && new Set(liveLadder.map((v) => v.tier)).size === 3);
  // rc.6 N9 — a document cannot postdate its own anchor: substrate time BEFORE generated_at ⇒ E-ANCHOR.
  const n9 = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data', substrateVerify: () => ({ final: true, time: '2020-01-01T00:00:00Z' }) });
  check('N9 generated_at after anchorTime → E-ANCHOR', n9.error === 'E-ANCHOR');
  // rc.6 M-05 — the anchor availability STATUS is carried through (substrate unreachable ⇒ status unavailable, doc stays LIGHT-time-unproven).
  const un = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, context: 'data', substrateVerify: () => null });
  check('anchor substrate unreachable → time.status unavailable (not flattened)', P.isValid(un) && un.time.status === 'unavailable' && un.time.strength === 'unproven');
  // rc.9 (11th audit 7.1/B): revocation boundary U==C is INVALID; a non-strict-Z compromised_since is E-MALFORMED.
  const C = '2026-06-28T15:00:00Z';
  const rev = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1902', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: C }, P.contentHash(add)));
  check('revocation boundary U == C → E-KEY (X1: VALID only if U < C)', (r => r.result === 'INVALID' && /E-KEY/.test(r.error || ''))(atU(docK, gen, [add, rev], C)));
  // round-16 P1-01 — the compromise estimate C can taint EARLIER signatures but NEVER lengthen the active window past
  // the revoke transition R (F.5e). Here R = the revoke entry time (14:03:12); a doc at U=14:59:59 (R < U < C) is AFTER
  // the key left the active set ⇒ EXPIRED, not suspect. (rev12 used C alone as the upper bound — the reversed bug.)
  check('revocation R < U < C (after the revoke transition) → expired, not suspect (round-16 P1-01)', (r => (r.identity || {}).strength === 'self-asserted' && (r.identity || {}).status === 'expired')(atU(docK, gen, [add, rev], '2026-06-28T14:59:59Z')));
  // realistic pre-compromise (U < C ≤ R, inside the active window): add@14:04, revoke(compromised, C=14:40)@14:50, doc anchored@14:20 → authoritative/suspect (C is a publisher estimate).
  const teC = (g) => ({ generated_at: g, valid_from: g, valid_to: '2026-06-28T15:00:00Z' });
  const addE = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1921', key_id: G.key_id }, teC('2026-06-28T14:04:00Z'), { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));
  const revE = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1922', key_id: G.key_id }, teC('2026-06-28T14:50:00Z'), { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: '2026-06-28T14:40:00Z' }, P.contentHash(addE)));
  check('revocation U < C ≤ R (provably pre-compromise, in the active window) → authoritative/suspect', (r => (r.identity || {}).strength === 'authoritative' && (r.identity || {}).status === 'suspect')(atU(docK, gen, [addE, revE], '2026-06-28T14:20:00Z')));
  const revBad = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1903', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: '2026-06-28T15:00:00.5Z' }, P.contentHash(add)));
  check('fractional compromised_since → E-MALFORMED (strict-Z, §12.2)', P.resolveAuthority(docK, { genesis: gen, keylog: [add, revBad], anchorTime: C }).error === 'E-MALFORMED');
  // round-15 P1-01 — compromised_since must be a REAL calendar instant: "9999-99-99T99:99:99Z" matches the regex but is
  // not a date; the string-compare U ≥ C then always failed, silently downgrading the E-KEY containment to suspect.
  const revFake = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1905', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: '9999-99-99T99:99:99Z' }, P.contentHash(add)));
  check('P1-01 compromised_since "9999-99-99T99:99:99Z" (shape-valid, not a real time) → E-MALFORMED', P.resolveKeys(gen, [add, revFake]).error === 'E-MALFORMED');
  // round-15 P0-03 — the single-domain key-log invariant lives IN the reducer (not only the NameBound caller): resolveAuthority
  // consumes resolveKeys directly, so a foreign-domain class:key entry must be rejected by the reducer itself.
  const foreignAdd = signG(P.buildKeyLogEntry({ domain_shard: 'evil.example', ust_id: 'ust:20260628.1904', key_id: G.key_id }, T, { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));
  check('P0-03 resolveKeys rejects a foreign-domain key-log entry (reducer is a TCB unit, sound in isolation)', P.resolveKeys(gen, [foreignAdd]).error === 'E-KEY');
  // round-15 P0-02 — a key's lifetime is a SET of authorization windows (two-sided K_n(t)). add→retire→re-add→retire: a doc
  // anchored in the FIRST retired GAP must be EXPIRED. Scalar first/last collapsed the two windows → the gap doc wrongly passed.
  const Tt = (g) => ({ generated_at: g, valid_from: g, valid_to: '2026-06-28T15:00:00Z' });
  const kAdd1 = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1911', key_id: G.key_id }, Tt('2026-06-28T14:04:00Z'), { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));   // AFTER the genesis (14:03:12) — the key-log timeline is nondecreasing (round-16 P1-02)
  const kRet1 = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1912', key_id: G.key_id }, Tt('2026-06-28T14:10:00Z'), { op: 'revoke', pub: K.pubB64, reason: 'retired' }, P.contentHash(kAdd1)));
  const kAdd2 = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1913', key_id: G.key_id }, Tt('2026-06-28T14:20:00Z'), { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(kRet1)));
  const kRet2 = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1914', key_id: G.key_id }, Tt('2026-06-28T14:30:00Z'), { op: 'revoke', pub: K.pubB64, reason: 'retired' }, P.contentHash(kAdd2)));
  check('P0-02 doc anchored in a retired GAP (add→retire→re-add→retire) → expired, not authoritative (interval collapse closed)', (r => r.status === 'expired' && r.strength === 'self-asserted')(P.resolveAuthority(docK, { genesis: gen, keylog: [kAdd1, kRet1, kAdd2, kRet2], ...nfe(gen), anchorTime: '2026-06-28T14:15:00Z' })));
  check('P0-02 doc anchored AFTER the re-add (second window) → still authoritative (the fix does not over-reject)', (r => r.strength === 'authoritative')(P.resolveAuthority(docK, { genesis: gen, keylog: [kAdd1, kRet1, kAdd2], ...nfe(gen), anchorTime: '2026-06-28T14:25:00Z' })));
  // round-16 P0-01 — a key that has LEFT the active set + a doc with NO proven U cannot be authoritative (window
  // membership undecidable ⇒ fail closed); and verify() feeds K_n(t) ONLY the proven anchor, never a raw opts.anchorTime
  // (a forged early string once made a post-retirement doc VALID:HIGH while the honest late U rejected it).
  const kRetOnly = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1915', key_id: G.key_id }, Tt('2026-06-28T14:10:00Z'), { op: 'revoke', pub: K.pubB64, reason: 'retired' }, P.contentHash(kAdd1)));
  check('P0-01 retired key + UNANCHORED doc → NOT authoritative (fail-closed, K_n needs a proven U)', (r => r.strength !== 'authoritative' && r.status === 'expired')(P.resolveAuthority(docK, { genesis: gen, keylog: [kAdd1, kRetOnly], ...nfe(gen) })));
  check('P0-01 verify() ignores a forged raw opts.anchorTime (early) on a retired key → not VALID:HIGH', P.verify(docK, { genesis: gen, keylog: [kAdd1, kRetOnly], ...nfe(gen), requireAuthoritative: true, anchorTime: '2026-06-28T14:05:00Z', context: 'data' }).result !== 'VALID:HIGH');
  // round-16 P1-02 — the key-log timeline is NONDECREASING along the prev-chain: an entry claiming an EARLIER
  // generated_at than a prior entry inverts the intervals and is rejected (M-KEY-INTERVAL), never silently ordered.
  const kBack = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1916', key_id: G.key_id }, Tt('2026-06-28T14:02:00Z'), { op: 'revoke', pub: K.pubB64, reason: 'retired' }, P.contentHash(kAdd1)));
  check('P1-02 non-monotone key-log timeline (entry predates a prior entry) → E-MALFORMED', P.resolveKeys(gen, [kAdd1, kBack]).error === 'E-MALFORMED');
  // round-17 P0-02 — a RAW anchorTime string to the EXPORTED resolver never becomes U (only the verified anchor seam mints
  // it): a post-retirement doc stays fail-closed, not authoritative. The proven path (verify + anchor) is atU above.
  check('P0-02 raw anchorTime string to resolveAuthority → no proven U → retired key NOT authoritative', (r => r.strength !== 'authoritative')(P.resolveAuthority(docK, { genesis: gen, keylog: [kAdd1, kRetOnly], ...nfe(gen), anchorTime: '2026-06-28T14:05:00Z' })));
  // round-17 P1-02 — the exported resolvers are TOTAL: a malformed input is a STRUCTURED reject, never a host throw.
  check('P1-02 resolveKeys(gen, non-array keylog) → E-MALFORMED, no throw', (() => { try { return P.resolveKeys(gen, { length: 0 }).error === 'E-MALFORMED'; } catch { return false; } })());
  check('P1-02 resolveAuthority(null doc) → E-MALFORMED, no throw', (() => { try { return P.resolveAuthority(null, { genesis: gen, keylog: [] }).error === 'E-MALFORMED'; } catch { return false; } })());
  check('P1-02 resolveAuthority(doc, non-array keylog) → structured error, no throw', (() => { try { return !!P.resolveAuthority(docK, { genesis: gen, keylog: { length: 0 } }).error; } catch { return false; } })());
  // round-17 P1-01 — an untyped substrate receipt cannot mint TimeStrength=anchored: final must be Boolean true AND carry a real RFC3339-Z instant.
  const anchoredDoc = (d) => ({ ...d, proof: { root: P.Hbytes('ust:leaf', Buffer.from(P.contentHash(d), 'utf8')), path: [], anchor: { substrate: 'test' } } });
  check('P1-01 substrate {final:"yes"} (non-Boolean) → NOT anchored (not VALID:TOP)', P.verify(anchoredDoc(docK), { genesis: gen, keylog: [kAdd1], ...nfe(gen), substrateVerify: () => ({ final: 'yes', time: '2026-06-28T16:00:00Z' }), context: 'data' }).result !== 'VALID:TOP');
  check('P1-01 substrate {final:true, time:{}} (non-RFC3339 time) → NOT anchored (not VALID:TOP)', P.verify(anchoredDoc(docK), { genesis: gen, keylog: [kAdd1], ...nfe(gen), substrateVerify: () => ({ final: true, time: {} }), context: 'data' }).result !== 'VALID:TOP');
  // ─── #45 F.5b DOWNGRADE RESISTANCE — requireAnchored is the symmetric floor to requireAuthoritative. Stripping
  //     the anchor can only LOWER the tier; a TOP-needing consumer REJECTS, never silently accepts a lower tier.
  const anchorSV = () => ({ final: true, time: '2027-01-01T00:00:00Z' });
  check('#45 requireAnchored: TOP doc passes the TOP floor', P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data', requireAnchored: true, substrateVerify: anchorSV }).result === 'VALID:TOP');
  check('#45 requireAnchored: proof STRIPPED (authoritative HIGH) → E-ANCHOR (downgrade rejected)', P.verify(docK, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data', requireAnchored: true }).error === 'E-ANCHOR');
  check('#45 control: same stripped doc, NO floor → VALID:HIGH (default surfaces the earned tier)', P.verify(docK, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data' }).result === 'VALID:HIGH');
  check('#45 requireAnchored: proof present but substrate unreachable → INDETERMINATE (retry, not forgery)', P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], ...nfe(gen), context: 'data', requireAnchored: true, substrateVerify: () => null }).result === 'INDETERMINATE');
  check('#45 requireAnchored: self-asserted (LIGHT) doc → E-GENESIS (name axis fails first)', P.verify(mk(), { requireAnchored: true, context: 'data' }).error === 'E-GENESIS');
  // ─── #45 F.5c FORK-CHOICE — canonical = anchor-included. One ust_id, distinct content_hashes (dual-writer race).
  const leafRoot = (d) => ({ root: P.Hbytes('ust:leaf', Buffer.from(P.contentHash(d), 'utf8')), path: [], anchor: { substrate: 'bitcoin-ots' } });
  const slot = (n) => P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.2015', key_id: K.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { n } } }), K.priv, K.pubB64);
  const f1 = slot('1'), f2 = slot('2');
  const fp1 = leafRoot(f1), fp2 = leafRoot(f2);
  const cand1 = { ...f1, proof: fp1 }, cand2 = { ...f2, proof: fp2 };
  const fbase = { genesis: gen, keylog: [add], ...nfe(gen), context: 'data' };
  const only1 = (a, root) => root === fp1.root ? anchorSV() : null;
  const fcWin = await P.forkChoice([cand1, cand2], { ...fbase, substrateVerify: only1 });
  check('#45 forkChoice: one anchor-included → CANONICAL picks it', fcWin.result === 'CANONICAL' && fcWin.content_hash === P.contentHash(f1));
  check('#45 forkChoice: the out-raced doc is a recorded loser (VALID, not anchored)', fcWin.losers.length === 1 && fcWin.losers[0].content_hash === P.contentHash(f2));
  check('#45 forkChoice: determinism — reversed input order → SAME canonical', (await P.forkChoice([cand2, cand1], { ...fbase, substrateVerify: only1 })).content_hash === fcWin.content_hash);
  check('#45 forkChoice: neither anchored → INDETERMINATE (no guessed winner)', (await P.forkChoice([cand1, cand2], { ...fbase, substrateVerify: () => null })).result === 'INDETERMINATE');
  check('#45 forkChoice: both anchored, one authority, distinct hash → E-PREV (equivocation)', (await P.forkChoice([cand1, cand2], { ...fbase, substrateVerify: anchorSV })).result === 'E-PREV');
  check('#45 forkChoice: mixed ust_ids → E-MALFORMED (fork-choice is per-slot)', (await P.forkChoice([cand1, { ...docK, proof: topProof }], { ...fbase, substrateVerify: anchorSV })).result === 'E-MALFORMED');
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
  const gcap = genCap(512, 4_000_000);
  const auth = P.resolveAuthority(mk(), { genesis: gcap, keylog: [], ...nfe(gcap) });
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

// ─── #69 Theme D — the key-log is AUTHORITY input and MUST cross the SAME raw-byte boundary as the main
//     verify path (I4). A duplicate member in a discovered key-log entry is E-CANON, never a silent LIGHT.
{
  const Gd = kp('d1'.repeat(32)), Kd = kp('d2'.repeat(32));
  const genD = P.seal(P.buildGenesis({ domain_shard: 'rawbyte.example', ust_id: 'ust:20260713.10', key_id: Gd.key_id }, T, Gd.pubB64), Gd.priv, Gd.pubB64);
  const addD = P.seal(P.buildKeyLogEntry({ domain_shard: 'rawbyte.example', ust_id: 'ust:20260713.1001', key_id: Gd.key_id }, T, { op: 'add', pub: Kd.pubB64, new_key_id: Kd.key_id }, P.contentHash(genD)), Gd.priv, Gd.pubB64);
  const docD = P.seal(P.buildState({ domain_shard: 'rawbyte.example', ust_id: 'ust:20260713.1010', key_id: Kd.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '1' } } }), Kd.priv, Kd.pubB64);
  const genRaw = JSON.stringify(genD);
  const mockD = (klRaw) => async (u) => String(u).endsWith('/ust-genesis') ? { ok: true, text: async () => genRaw }
    : String(u).endsWith('/ust-keylog') ? { ok: true, text: async () => klRaw }
    : { ok: false, status: 404, text: async () => '' };   // witness 404 → HIGH pending, but D is decided first
  const dupKl = '[' + JSON.stringify(addD).replace('{', '{"ust":"1.0",') + ']';   // JSON.parse would collapse the dup
  const rDup = await P.resolveByDiscovery(docD, { context: 'data' }, { fetchImpl: mockD(dupKl) });
  check('#69 D: dup-key discovered key-log → E-CANON (not a silent LIGHT)', /E-CANON/.test(rDup.resolution?.error || ''));
  const rClean = await P.resolveByDiscovery(docD, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: mockD(JSON.stringify([addD])) });
  check('#69 D: clean key-log + honored override still resolves VALID:HIGH (honest path intact)', rClean.verdict.result === 'VALID:HIGH');
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
  // #69 B / F.5a — the publisher's OWN served list is CORROBORATION, not independent no-fork: HIGH, but strength
  // `corroborated` (never `authoritative`), and the name stays `publisher_claimed` (not the definitive `publisher`).
  check('witness served-list → HIGH but CORROBORATED not authoritative (#69 B)', r1.verdict.result === 'VALID:HIGH' && r1.verdict.identity.strength === 'corroborated' && r1.verdict.no_fork === 'served-list' && r1.verdict.publisher_claimed === 'wit-test.example' && r1.verdict.publisher === undefined);
  // P0-2 — a raw air-gap assertion is NOT independent evidence: it is a `consumer-override`. It reaches the name-
  // authoritative TIER only when the consumer CONSCIOUSLY honors it (acceptConsumerOverride), and the verdict stays
  // transparent (independently_verified:false) — it never silently claims independent `authoritative`.
  const r1b = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: mk(okLog), substrateVerify: final });
  check('caller air-gap override (honored) → HIGH, strength consumer-override + not independently verified (#69 B / P0-2)', r1b.verdict.result === 'VALID:HIGH' && r1b.verdict.identity.strength === 'consumer-override' && r1b.verdict.identity.independently_verified === false && r1b.verdict.publisher === 'wit-test.example');
  // and WITHOUT the conscious opt-in, the raw override never earns authority — the overclaim is closed.
  const r1c = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true }, { fetchImpl: mk(null), substrateVerify: final });
  check('P0-2: raw noForkConfirmed alone → consumer-override, NOT authoritative (overclaim closed)', r1c.verdict.identity.strength === 'consumer-override' && r1c.verdict.identity.independently_verified === false && r1c.verdict.result === 'VALID:LIGHT' && r1c.verdict.publisher === undefined);

  const r2 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(null), substrateVerify: final });
  check('witness unreachable = LIGHT + HIGH pending (never forged, W1)', r2.verdict.result === 'VALID:LIGHT' && r2.resolution.noFork.startsWith('HIGH pending'));

  const forkLog = wlog([{ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) }, { content_hash: 'sha256:' + 'ab'.repeat(32), superseded_by: null, anchor: anchorOf('sha256:' + 'ab'.repeat(32)) }], gHash);
  const r3 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(forkLog), substrateVerify: final });
  check('two anchored active genesis = fork = E-GENESIS', r3.verdict.result === 'INVALID' && r3.verdict.error === 'E-GENESIS');

  const r4 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: () => ({ final: false }) });
  check('anchor not final (Bitcoin pending) = no HIGH, honest pending', r4.verdict.result === 'VALID:LIGHT' && r4.resolution.noFork.startsWith('HIGH pending'));

  const r5 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog) });   // no substrateVerify
  check('no substrate cross-check = never witness-confirmed (anchor unproven)', r5.verdict.result === 'VALID:LIGHT');

  const r6 = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: mk(null) });
  check('explicit --no-fork-confirmed (honored) still overrides (air-gap) without witness → HIGH', r6.verdict.result === 'VALID:HIGH');
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

// ─── #69 C (#70) — completeness against the SIGNED cadence grid: no-deletion (`chain-consistent`) is re-earned
//     to no-omission (`complete`) only when the expected grid is covered; the cadence is signed (genesis),
//     never a free per-checkpoint choice, so a publisher cannot claim a coarser grid to hide a slot. C2: a
//     checkpoint and a gap are distinct SUBTYPES (data.checkpoint XOR data.gap), no longer a shape collision.
{
  const C = kp('c1'.repeat(32)); const dom = 'stream.example', signC = (s) => P.seal(s, C.priv, C.pubB64);
  const Tc = { generated_at: '2026-06-28T14:29:00Z', valid_from: '2026-06-28T14:29:00Z', valid_to: '2026-06-28T14:30:00Z' };
  const gen = signC(P.buildGenesis({ domain_shard: dom, ust_id: 'ust:20260628.1429', key_id: C.key_id }, Tc, C.pubB64, undefined, undefined, 30)); // 30s cadence
  const genNo = signC(P.buildGenesis({ domain_shard: dom, ust_id: 'ust:20260628.1429', key_id: C.key_id }, Tc, C.pubB64));                        // no cadence
  const gH = P.contentHash(gen);
  const fr = (uid, prev) => signC(P.buildState({ domain_shard: dom, ust_id: uid, key_id: C.key_id, class: 'observation' }, Tc, { r: { kind: 'captured', value: { x: '1' } } }, { prev }));
  const gp = (uid, prev) => signC(P.buildGap({ domain_shard: dom, ust_id: uid, key_id: C.key_id }, Tc, prev, 'src-down'));
  const cp = (head, n, prev) => signC(P.buildCheckpoint({ domain_shard: dom, ust_id: 'ust:20260628.143001', key_id: C.key_id }, Tc, head, n, prev, { from: 'ust:20260628.142900', to: 'ust:20260628.143000' }));
  // C2 — checkpoint vs gap are now distinct subtypes; a bare prev-only attestation (neither) is E-MALFORMED
  const bare = signC(P.buildState({ domain_shard: dom, ust_id: 'ust:20260628.1430', key_id: C.key_id, class: 'attestation' }, Tc, { note: { kind: 'computed', value: { x: '1' } } }, { prev: gH }));
  check('#70 C2: bare prev-only attestation → E-MALFORMED (checkpoint/gap collision closed)', P.verify(bare, { context: 'data' }).error === 'E-MALFORMED');
  check('#70 C2: a signed gap record is VALID (data.gap subtype)', P.verify(gp('ust:20260628.142930', gH), { context: 'data' }).result === 'VALID:LIGHT');
  // (1) full grid → complete
  const f0 = fr('ust:20260628.142900', gH), f1 = fr('ust:20260628.142930', P.contentHash(f0)), f2 = fr('ust:20260628.143000', P.contentHash(f1));
  check('#70 full grid + signed cadence → complete (no-omission)', P.verifyStream([f0, f1, f2], { genesis: gen, checkpoint: cp(P.contentHash(f2), 3, P.contentHash(f2)) }).complete === 'complete');
  // (2) omitted slot, NO gap → chain-consistent (the honest ceiling), hole named
  const g0 = fr('ust:20260628.142900', gH), g2 = fr('ust:20260628.143000', P.contentHash(g0));
  const r2 = P.verifyStream([g0, g2], { genesis: gen, checkpoint: cp(P.contentHash(g2), 2, P.contentHash(g2)) });
  check('#70 omitted slot, no gap → chain-consistent + names the hole', r2.complete === 'chain-consistent' && r2.hole === 'ust:20260628.142930');
  // (3) omission covered by a signed gap → complete
  const h0 = fr('ust:20260628.142900', gH), hg = gp('ust:20260628.142930', P.contentHash(h0)), h2 = fr('ust:20260628.143000', P.contentHash(hg));
  check('#70 omission covered by a signed gap → complete', P.verifyStream([h0, hg, h2], { genesis: gen, checkpoint: cp(P.contentHash(h2), 3, P.contentHash(h2)) }).complete === 'complete');
  // (4) no SIGNED cadence → the grid is undecidable → chain-consistent, NEVER complete (anti-lie: the cadence
  //     is signed in the genesis, not a caller/per-checkpoint choice, so a coarser grid cannot be claimed).
  const nH = P.contentHash(genNo), n0 = fr('ust:20260628.142900', nH), n1 = fr('ust:20260628.142930', P.contentHash(n0)), n2 = fr('ust:20260628.143000', P.contentHash(n1));
  check('#70 no signed cadence → chain-consistent (grid undecidable, never complete)', P.verifyStream([n0, n1, n2], { genesis: genNo, checkpoint: cp(P.contentHash(n2), 3, P.contentHash(n2)) }).complete === 'chain-consistent');
  check('#70 ustGrid computes the expected slots (30s over a minute = 3)', P.ustGrid('ust:20260628.142900', 'ust:20260628.143000', 30).length === 3);

  const cpI = (head, n, prev, from, to) => signC(P.buildCheckpoint({ domain_shard: dom, ust_id: 'ust:20260628.143501', key_id: C.key_id }, Tc, head, n, prev, { from, to }));
  // rc.20-audit P0 — chronological grid ORDER: a chain valid by prev but reordered in TIME must be E-PREV.
  const z0 = fr('ust:20260628.142900', gH), z1 = fr('ust:20260628.143000', P.contentHash(z0)), z2 = fr('ust:20260628.142930', P.contentHash(z1));
  check('audit P0: reordered stream (chain ok, ust_id not monotonic) → E-PREV', P.verifyStream([z0, z1, z2], { genesis: gen }).error === 'E-PREV');
  // rc.20-audit P0 — checkpoint interval must BOUND the frames: a frame past `to` → E-PREV (not silently complete).
  const y0 = fr('ust:20260628.142900', gH), y1 = fr('ust:20260628.142930', P.contentHash(y0)), y2 = fr('ust:20260628.143000', P.contentHash(y1));
  check('audit P0: frame outside checkpoint [from,to] → E-PREV', P.verifyStream([y0, y1, y2], { genesis: gen, checkpoint: cpI(P.contentHash(y2), 3, P.contentHash(y2), 'ust:20260628.142900', 'ust:20260628.142930') }).error === 'E-PREV');
  // continuity — a cadence change never invalidates old data: an OLD interval verifies `complete` under the OLD
  // cadence; an interval CROSSING the change → chain-consistent (split at the boundary), not an error, not invalid.
  const ce = signC(P.buildCadenceEntry({ domain_shard: dom, ust_id: 'ust:20260628.1429', key_id: C.key_id }, Tc, 60, 'ust:20260628.143000', gH));
  const o0 = fr('ust:20260628.142900', gH), o1 = fr('ust:20260628.142930', P.contentHash(o0));
  check('continuity: old interval verifies complete under the OLD (pre-change) cadence', P.verifyStream([o0, o1], { genesis: gen, checkpoint: cpI(P.contentHash(o1), 2, P.contentHash(o1), 'ust:20260628.142900', 'ust:20260628.142930'), cadenceLog: [ce] }).complete === 'complete');
  const x0 = fr('ust:20260628.142900', gH), x1 = fr('ust:20260628.142930', P.contentHash(x0)), x2 = fr('ust:20260628.143000', P.contentHash(x1));
  check('continuity: interval crossing a cadence change → chain-consistent (split), never invalid', P.verifyStream([x0, x1, x2], { genesis: gen, checkpoint: cpI(P.contentHash(x2), 3, P.contentHash(x2), 'ust:20260628.142900', 'ust:20260628.143000'), cadenceLog: [ce] }).complete === 'chain-consistent');
  check('cadence entry is a valid class:cadence transcript (key context) but E-MALFORMED in data context (W3)', (() => { const v = P.verify(ce, { context: 'key' }); const d = P.verify(ce, { context: 'data' }); return v.result === 'VALID:LIGHT' && d.error === 'E-MALFORMED'; })());
  // audit P0 (cadence authority) — a cadence entry signed by an UNAUTHORIZED key (LIGHT-valid, same domain, real
  // prev) must be REJECTED, not accepted; else a transport/caller could change the grid and hide holes.
  { const EV = kp('e7'.repeat(32)); const evilCad = P.seal(P.buildCadenceEntry({ domain_shard: dom, ust_id: 'ust:20260628.1429', key_id: EV.key_id }, Tc, 60, 'ust:20260628.143000', gH), EV.priv, EV.pubB64);
    check('audit P0: cadence entry by an UNAUTHORIZED key → E-KEY (not a silent grid change)', P.resolveCadence(gen, [evilCad], 'ust:20260628.143000', { keylog: [] }).error === 'E-KEY');
    check('audit P0: verifyStream with an unauthorized cadence-log → error, never complete', P.verifyStream([o0, o1], { genesis: gen, checkpoint: cpI(P.contentHash(o1), 2, P.contentHash(o1), 'ust:20260628.142900', 'ust:20260628.142930'), cadenceLog: [evilCad] }).error === 'E-KEY'); }
  check('cadence by the GENESIS key is authorized without a key-log (self-signed authority)', P.resolveCadence(gen, [ce], 'ust:20260628.143000').cadence === 60);
  // rc.20-audit P1 — no `mapInclusion:true` boolean shortcut to authoritative (would be an unverified proof).
  check('audit P1: mapInclusion:true does NOT grant authoritative (no map verifier yet)', P.resolveAuthority(gen, { genesis: gen, keylog: [], mapInclusion: true }).strength !== 'authoritative');
}

// ─── #44 AGENT-SAFETY — throw-on-non-VALID (control flow, not an advisory field) + machine-structured verdict.
{
  const goodDoc = mk();
  const tampered = clone(goodDoc); tampered.state.data.sw.value.kp = '9.9';   // recomputed partition hash mismatches
  check('#44 verifyOrThrow returns the verdict for a VALID doc', P.verifyOrThrow(goodDoc).result === 'VALID:LIGHT');
  check('#44 verifyOrThrow THROWS UstInvalid on a tampered doc', (() => { try { P.verifyOrThrow(tampered); return false; } catch (e) { return e instanceof P.UstInvalid && e.code === 'E-CANON' && e.verdict?.error === 'E-CANON'; } })());
  check('#44 INDETERMINATE throws UstIndeterminate, NOT UstInvalid (retry ≠ reject)', (() => { const r = P.verify(goodDoc, { maxSupportedBytes: 1 }); if (r.result !== 'INDETERMINATE') return false; try { P.assertValid(r); return false; } catch (e) { return e instanceof P.UstIndeterminate && !(e instanceof P.UstInvalid); } })());
  check('#44 assertValid composes with verifyAsync (async verdict)', (await (async () => P.assertValid(await P.verifyAsync(goodDoc)).result === 'VALID:LIGHT')()));
  // machine-structured failure: obligation + expected/actual, no string parsing
  const vc = P.verify(tampered);
  check('#44 partition mismatch → obligation §4.4 + partition + expected≠actual', vc.error === 'E-CANON' && vc.obligation === '§4.4 partition-hash' && vc.partition === 'sw' && /^sha256:/.test(vc.expected) && /^sha256:/.test(vc.actual) && vc.expected !== vc.actual);
  const badSig = clone(goodDoc); badSig.sig.sig = badSig.sig.sig.slice(0, -4) + 'AAAA';
  check('#44 bad signature → obligation §14.2 whole-state-signature', (r => r.error === 'E-SIG' && r.obligation === '§14.2 whole-state-signature')(P.verify(badSig)));
  // §9.4 recompute obligations carry structured expected/actual too
  const obsX = mk(); const hX = P.contentHash(obsX);
  const badRoot = P.buildState({ ...ID, class: 'attestation' }, T, { a: { kind: 'computed', value: { x: '1' } } });
  badRoot.provenance = { constituents: [hX], root: 'sha256:' + '99'.repeat(32) };
  check('#44 E-ROOT → obligation §9.4 attestation-root + expected/actual', (r => r.error === 'E-ROOT' && r.obligation === '§9.4 attestation-root' && r.actual === P.merkleRoot([hX]) && r.expected !== r.actual)(P.verify(P.seal(badRoot, A.priv, A.pubB64), { context: 'data' })));
  check('#44 human fields preserved beside machine fields (error+detail intact)', typeof vc.detail === 'string' && vc.detail.includes('sw'));
}

// ─── #40 IDENTITY HARDENING — IDN/homograph A-label guard (§4.3a) + key-log freshness (§12.2a). ───
{
  const G = kp('bb'.repeat(32)), K = kp('cc'.repeat(32));
  const signG = (st) => P.seal(st, G.priv, G.pubB64);
  // Hole 1: a homograph name-form domain_shard (Cyrillic а, U+0430) must be E-MALFORMED, never a deceptive publisher.
  const homo = 'а' + 'pple.com';
  const genH = signG(P.buildGenesis({ domain_shard: homo, ust_id: 'ust:20260628.10', key_id: G.key_id }, T, G.pubB64));
  check('#40 homograph name-form domain_shard → E-MALFORMED (obligation §4.3a A-label)', (r => r.error === 'E-MALFORMED' && r.obligation === '§4.3a name-form A-label')(P.verify(genH, { context: 'key' })));
  check('#40 punycode A-label (xn--…) still VALID (guard blocks glyphs, not IDN)', P.verify(P.seal(P.buildState({ domain_shard: 'xn--80ak6aa92e.com', ust_id: 'ust:20260628.12', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '1' } } }), G.priv, G.pubB64), { context: 'data' }).result.startsWith('VALID'));
  // Hole 2: key-log freshness — a stale cache must REPORT freshness, and requireFreshKeylog floors on it.
  const dom = 'noosphere.md';
  const gen = signG(P.buildGenesis({ domain_shard: dom, ust_id: 'ust:20260628.19', key_id: G.key_id }, T, G.pubB64));
  const add = signG(P.buildKeyLogEntry({ domain_shard: dom, ust_id: 'ust:20260628.1901', key_id: G.key_id }, T, { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));
  const revoke = signG(P.buildKeyLogEntry({ domain_shard: dom, ust_id: 'ust:20260628.1902', key_id: G.key_id }, T, { op: 'revoke', pub: K.pubB64, reason: 'compromised', compromised_since: '2026-06-28T14:30:00Z' }, P.contentHash(add)));
  const docK = P.seal(P.buildState({ domain_shard: dom, ust_id: 'ust:20260628.20', key_id: K.key_id, class: 'observation' }, T, { sw: { kind: 'captured', value: { kp: '5' } } }), K.priv, K.pubB64);
  const Aft = '2026-06-28T14:45:00Z';
  check('#40 fresh log [add,revoke] → E-KEY (revocation still bites)', (r => r.result === 'INVALID' && /E-KEY/.test(r.error || ''))(atU(docK, gen, [add, revoke], Aft)));
  check('#40 stale cache [add] REPORTS freshness:unverified (no longer silent)', (r => r.strength === 'authoritative' && r.freshness === 'unverified')(P.resolveAuthority(docK, { genesis: gen, keylog: [add], ...nfe(gen), anchorTime: Aft })));
  check('#40 requireFreshKeylog on a stale cache → INDETERMINATE stale_keylog', (r => r.result === 'INDETERMINATE' && r.reason === 'stale_keylog')(P.verify(docK, { genesis: gen, keylog: [add], noForkConfirmed: true, requireFreshKeylog: true, anchorTime: Aft, context: 'data' })));
  // rc.28 AUDIT FIX — a raw self-computed head hash proves nothing (derivable from a stale log): NOT attested.
  const headProof = { root: P.Hbytes('ust:leaf', Buffer.from(P.contentHash(add), 'utf8')), path: [], anchor: { substrate: 'bitcoin-ots' } };
  check('#40 keylogHeadAnchor WITHOUT substrateVerify → NOT attested (overclaim closed)', P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkConfirmed: true, anchorTime: Aft, keylogHeadAnchor: headProof }).freshness !== 'attested');
  check('#40 VERIFIED keylogHeadAnchor NO LONGER earns attested — legacy shortcut removed (UST-0ol Phase 3, P0-03: anchored head ≠ latest head; strong freshness only via checkpoint derivation)', P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkConfirmed: true, anchorTime: Aft, keylogHeadAnchor: headProof, substrateVerify: () => ({ final: true, time: '2027-01-01T00:00:00Z' }) }).freshness !== 'attested');
  // round-16 P0-02 — a RAW keylogFreshAsOf (a string, OR an unbranded look-alike object) can NEVER mint `fresh`:
  // freshness is EARNED from an authenticated fetch (F.5d), not a caller assertion. It stays `unverified`, so
  // requireFreshKeylog still floors to INDETERMINATE — a caller string cannot lift the FreshnessStrength axis.
  check('#40/P0-02 raw string keylogFreshAsOf → freshness:unverified (never minted from a caller string)', P.resolveAuthority(docK, { genesis: gen, keylog: [add], ...nfe(gen), anchorTime: Aft, keylogFreshAsOf: '2026-06-28T15:00:00Z' }).freshness === 'unverified');
  check('#40/P0-02 unbranded look-alike freshness object → unverified (not in VERIFIED_FRESH)', P.resolveAuthority(docK, { genesis: gen, keylog: [add], ...nfe(gen), anchorTime: Aft, keylogFreshAsOf: { observed_at: '2026-06-28T15:00:00Z', domain: dom, active_genesis: P.contentHash(gen) } }).freshness === 'unverified');
  // the EARNED path — resolveByDiscovery actually fetched /.well-known/ust-keylog ⇒ mints a VERIFIED_FRESH token ⇒ fresh.
  const freshMock = (u) => { const p = new URL(u).pathname; const body = p.endsWith('ust-genesis') ? JSON.stringify(gen) : p.endsWith('ust-keylog') ? JSON.stringify([add]) : null; return Promise.resolve(body === null ? { ok: false, status: 404 } : { ok: true, text: () => Promise.resolve(body) }); };
  const rFresh = await P.resolveByDiscovery(docK, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: freshMock });
  check('#40/P0-02 resolveByDiscovery key-log fetch → freshness:fresh (EARNED, branded token)', rFresh.verdict?.identity?.freshness === 'fresh');
  // round-17 P1-03 — authority discovery has a BYTE CEILING (F.9/§13): an oversize key-log body is rejected by size,
  // before it is fully accumulated / duplicate-scanned / parsed.
  const bigBody = '"' + '0'.repeat(1 << 22) + '"';   // > the 2 MiB DISCOVERY_MAX_BYTES ceiling
  const bigMock = (u) => Promise.resolve({ ok: true, text: () => Promise.resolve(bigBody) });   // an oversize authority-discovery body (the genesis fetch, whose error is surfaced, not swallowed)
  const rBig = await P.resolveByDiscovery(docK, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: bigMock });
  check('P1-03 oversize discovery body → rejected by the §13 byte ceiling (before scan/parse)', /ceiling|§13/.test(JSON.stringify(rBig.resolution || {})));
  // round-17 P0-01 — verifyAsync verifies an IMMUTABLE SNAPSHOT: mutating the live document during the substrate await
  // must not swap the verdict target (the receipt for root A cannot be reused for a substituted document B).
  const aDoc = { ...docK, proof: { root: P.Hbytes('ust:leaf', Buffer.from(P.contentHash(docK), 'utf8')), path: [], anchor: { substrate: 'test' } } };
  const origCH = P.contentHash(aDoc);
  const mutSub = async () => { aDoc.proof.root = 'sha256:' + 'ff'.repeat(32); aDoc.state = { ...aDoc.state, id: { ...aDoc.state.id, ust_id: 'ust:20260628.99' } }; return { final: true, time: '2026-06-28T16:00:00Z' }; };
  const rTocc = await P.verifyAsync(aDoc, { genesis: gen, keylog: [add], ...nfe(gen), substrateVerify: mutSub, context: 'data' });
  check('P0-01 verifyAsync verifies an immutable snapshot (a live mutation during the await cannot swap the verdict target)', rTocc.content_hash === origCH);
  // ─── P0-2 (audit) — NAME NO-FORK EVIDENCE reclassification (UST-0l5). `authoritative` name-authority is EARNED
  //     from a verified, CONSUMER-trusted witness statement bound to this domain + active genesis; a raw
  //     `noForkConfirmed` boolean is only a transparent `consumer-override`, never silently authoritative.
  {
    const active = P.contentHash(gen);
    const good = P.buildNoForkEvidence({ domain_shard: docK.state.id.domain_shard, active_genesis: active }, W.priv, W.pubB64);
    const roots = { [W.key_id]: W.pubB64 };
    const rEv = P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkEvidence: good, trustRoots: roots });
    check('P0-2: verified noForkEvidence → authoritative + independently_verified + basis + witness_id',
      rEv.strength === 'authoritative' && rEv.independently_verified === true && rEv.basis === 'accepted-external-witness' && rEv.witness_id === W.key_id);
    const rRaw = P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkConfirmed: true });
    check('P0-2: raw noForkConfirmed → consumer-override (NOT authoritative), independently_verified:false',
      rRaw.strength === 'consumer-override' && rRaw.independently_verified === false);
    check('P0-2: witness NOT in the consumer trustRoots → not accepted (independence is consumer-owned)',
      P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkEvidence: good, trustRoots: {} }).strength !== 'authoritative');
    const tampered = JSON.parse(JSON.stringify(good)); tampered.claim.active_genesis = 'sha256:' + '00'.repeat(32);
    check('P0-2: tampered no-fork claim (not bound to this active genesis) → NOT authoritative',
      P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkEvidence: tampered, trustRoots: roots }).strength !== 'authoritative');
    const selfDom = { claim: { ...good.claim, trust_domain: 'independent-7' }, issuer_id: W.key_id, sig: good.sig };
    check('P0-2: self-declared trust_domain inside the signed claim → rejected (verifyNoForkEvidence)',
      P.verifyNoForkEvidence(selfDom, { domain_shard: docK.state.id.domain_shard, active_genesis: active, trustRoots: roots }).ok === false);
    const wrongGen = P.buildNoForkEvidence({ domain_shard: docK.state.id.domain_shard, active_genesis: 'sha256:' + 'ab'.repeat(32) }, W.priv, W.pubB64);
    check('P0-2: no-fork evidence not bound to this active genesis (cross-epoch replay) → NOT authoritative',
      P.resolveAuthority(docK, { genesis: gen, keylog: [add], noForkEvidence: wrongGen, trustRoots: roots }).strength !== 'authoritative');
  }
}

// ─── #41 CROSS-LANGUAGE CANON ARBITER — the vectors ARE the contract; guard that the edge-case set stays present
//     (key sort · nested · array-vs-key · object-in-array · escaping · control · BMP + astral Unicode · empties).
{
  const canonV = V.vectors.filter((x) => x.kind === 'canon');
  check('#41 canon arbiter covers the cross-language edge cases (≥ 11 canon vectors)', canonV.length >= 11);
  // the non-ASCII trap explicitly pinned: UTF-8 kept literal, NOT \u-escaped (where most JSON libs diverge)
  check('#41 non-ASCII stays literal UTF-8 in canon (not \\u-escaped)', (v => v && P.canon(v.input) === v.expect_canon && !v.expect_canon.includes('\\u'))(canonV.find((x) => x.id === 'canon-10-unicode-astral-not-escaped')));
}

// ─── #76 Phase A — CONNECTOR EVIDENCE ALGEBRA. Facts-only evidence, core-derived class (transparency-log ≠ non-
//     membership), `compareEvidenceOrder` as a PROOF RELATION, quorum by DISTINCT consumer-resolved trust domains.
{
  const ev = (proof_kind, facts, source_id = 's') => P.verifiedEvidence({ proof_kind, subject: 'ust:x', source_id, facts });
  check('PhA facts-only: connector self-declaring assurance → E-EVIDENCE', (() => { try { P.verifiedEvidence({ proof_kind: 'k', subject: 'x', source_id: 's', facts: { assurance: 'attested' } }); return false; } catch (e) { return e.code === 'E-EVIDENCE'; } })());
  check('PhA facts-only: connector self-declaring trust_domain → E-EVIDENCE', (() => { try { P.verifiedEvidence({ proof_kind: 'k', subject: 'x', source_id: 's', facts: { trust_domain: 'me' } }); return false; } catch (e) { return e.code === 'E-EVIDENCE'; } })());
  check('PhA class: transparency-log → append-only (NOT non-membership)', P.evidenceClass('transparency-log') === 'append-only-inclusion+consistency');
  check('PhA class: authenticated-map → keyed non-membership', P.evidenceClass('authenticated-map') === 'keyed-membership+non-membership');
  check('PhA class: unknown proof-kind → opaque', P.evidenceClass('made-up') === 'opaque');
  const btc = (h) => ev('pow-header-chain', { substrate: 'bitcoin', position: String(h) });
  check('PhA order: same substrate a.pos>b.pos → proven-after', P.compareEvidenceOrder(btc(900), btc(800)) === 'proven-after');
  check('PhA order: same substrate a.pos<b.pos → not-after', P.compareEvidenceOrder(btc(800), btc(900)) === 'not-after');
  check('PhA order: a.not_before ≥ b.not_after → proven-after', P.compareEvidenceOrder(ev('t', { not_before: '2027-01-02T00:00:00Z' }), ev('t', { not_after: '2027-01-01T00:00:00Z' })) === 'proven-after');
  check('PhA order: b.not_before ≥ a.not_after → not-after', P.compareEvidenceOrder(ev('t', { not_after: '2027-01-01T00:00:00Z' }), ev('t', { not_before: '2027-01-02T00:00:00Z' })) === 'not-after');
  check('PhA order: two not_after upper bounds alone → unproven', P.compareEvidenceOrder(ev('t', { not_after: '2027-01-02T00:00:00Z' }), ev('t', { not_after: '2027-01-01T00:00:00Z' })) === 'unproven');
  check('PhA order: cross-substrate positions → unproven', P.compareEvidenceOrder(ev('t', { substrate: 'bitcoin', position: '900' }), ev('t', { substrate: 'rekor', position: '5' })) === 'unproven');
  const domains = { a1: 'op-a', a2: 'op-a', b1: 'op-b', c1: 'op-c' };
  check('PhA quorum: two sources in one domain → count 1', P.quorumTrustDomains([ev('k', {}, 'a1'), ev('k', {}, 'a2')], { domains }).count === 1);
  check('PhA quorum: three domains → count 3, threshold 2 met', (q => q.count === 3 && q.met === true)(P.quorumTrustDomains([ev('k', {}, 'a1'), ev('k', {}, 'b1'), ev('k', {}, 'c1')], { domains, threshold: 2 })));
  check('PhA quorum: source not in consumer config → not counted', P.quorumTrustDomains([ev('k', {}, 'a1'), ev('k', {}, 'unknown')], { domains }).count === 1);
  check('PhA quorum: self-declared trust_domain on evidence ignored (only consumer config counts)', P.quorumTrustDomains([{ source_id: 'x', facts: { trust_domain: 'fake' } }], { domains }).count === 0);
}

// ─── #76/#77 AUTHORITY CHECKPOINT — three-layer object + NON-CIRCULAR in-band authority state machine. genesis
//     authorizes C₀; Cₙ₋₁ authorizes Cₙ; a checkpoint never authorizes itself. Signer resolved from PRIOR state first.
{
  const K0 = kp('01'.repeat(32)), K1 = kp('02'.repeat(32)), K2 = kp('03'.repeat(32)), KX = kp('0f'.repeat(32));
  const gAuth = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + 'bb'.repeat(32), EP = P.genesisEpoch(AG);   // M2: epoch canonical for the fixture's active_genesis
  const KL = (l, tag) => ({ length: String(l), root: 'sha256:' + (tag + '0').repeat(32).slice(0, 64), head: 'sha256:' + (tag + '1').repeat(32).slice(0, 64) });
  const bc = (seq, prev, cur, nxt, D = 'noosphere.md', ep = EP) => P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: ep, sequence: seq, previous_checkpoint: prev, active_genesis: AG, current_key_id: cur.key_id, ...(nxt ? { next_key_id: nxt.k.key_id, next_pub: nxt.k.pubB64, effective_sequence: nxt.at } : {}), keylog: KL(5, 'c') });   // K5: constant data key-log across the chain (append-only-consistent; these tests exercise AUTHORITY rotation, not key-log growth)
  const C0 = P.sealAuthorityCheckpoint(bc('0', null, K0, { k: K1, at: '1' }), K0.priv, K0.pubB64); const id0 = P.authorityCheckpointId(C0);
  const C1 = P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), K1.priv, K1.pubB64); const id1 = P.authorityCheckpointId(C1);
  const C2 = P.sealAuthorityCheckpoint(bc('2', id1, K2, null), K2.priv, K2.pubB64);

  check('AC valid genesis-rooted chain C0→C1→C2 (in-band rotation) → VALID', (r => r.result === 'VALID' && r.head === P.authorityCheckpointId(C2) && r.length === '3')(P.verifyAuthorityCheckpointChain([C0, C1, C2], { genesisAuthority: gAuth })));
  check('AC cold verifier, no genesis/pinned authority → INDETERMINATE(authority_unresolved)', (r => r.result === 'INDETERMINATE' && r.reason === 'authority_unresolved')(P.verifyAuthorityCheckpointChain([C0, C1, C2], {})));
  // pinned prior: the pin carries the authority IN FORCE for the NEXT checkpoint (K2, what C1 committed), not C1's signer
  const pinC1 = { scope_id: P.authorityScopeId(AG), checkpoint_id: id1, sequence: '1', authority_for_next: { key_id: K2.key_id, pub: K2.pubB64 }, keylog_size: '5', keylog_root: KL(5, 'c').root, keylog_head: KL(5, 'c').head };   // K5: full PinnedCheckpointState (scope-bound)
  check('AC pinned prior C1 → verify only the C1→C2 transition → VALID', (r => r.result === 'VALID')(P.verifyAuthorityCheckpointChain([C2], { pinnedPrior: pinC1 })));
  // signer NOT authorized by the prior checkpoint
  check('AC Cₙ signed by a key not authorized by Cₙ₋₁ → INVALID(E-AUTHORITY)', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), KX.priv, KX.pubB64)], { genesisAuthority: gAuth })));
  // retroactive self-authorization: C1 signed by ITS OWN declared next key (K2), not the prior-authorized K1
  check('AC checkpoint signed by its own declared next key → INVALID (no retroactive self-auth)', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('1', id0, K1, { k: K2, at: '2' }), K2.priv, K2.pubB64)], { genesisAuthority: gAuth })));
  // carried current_key_id ≠ the prior-authorized signer (diagnostic field must not resolve authority)
  check('AC carried current_key_id ≠ prior-authorized signer → INVALID(E-AUTHORITY)', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('1', id0, KX, { k: K2, at: '2' }), K1.priv, K1.pubB64)], { genesisAuthority: gAuth })));
  // linkage + sequence
  check('AC previous_checkpoint ≠ prior id → INVALID(E-PREV)', (r => r.error === 'E-PREV')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('1', 'sha256:' + 'ee'.repeat(32), K1, null), K1.priv, K1.pubB64)], { genesisAuthority: gAuth })));
  check('AC sequence skip (0→2) → INVALID(E-SEQ)', (r => r.error === 'E-SEQ')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('2', id0, K1, null), K1.priv, K1.pubB64)], { genesisAuthority: gAuth })));
  // rotation exactness
  check('AC keyId(next_pub) ≠ next_key_id → INVALID(E-KEY)', (r => r.error === 'E-KEY')(P.verifyAuthorityCheckpointChain([P.sealAuthorityCheckpoint({ ...bc('0', null, K0, { k: K1, at: '1' }), checkpoint_authority: { current_key_id: K0.key_id, next_key_id: K2.key_id, next_pub: K1.pubB64, effective_sequence: '1' } }, K0.priv, K0.pubB64)], { genesisAuthority: gAuth })));
  check('AC effective_sequence ≠ seq+1 → INVALID(E-SEQ)', (r => r.error === 'E-SEQ')(P.verifyAuthorityCheckpointChain([P.sealAuthorityCheckpoint(bc('0', null, K0, { k: K1, at: '5' }), K0.priv, K0.pubB64)], { genesisAuthority: gAuth })));
  check('AC partial rotation (next_key_id without next_pub) → INVALID(E-MALFORMED)', (r => r.error === 'E-MALFORMED')(P.verifyAuthorityCheckpointChain([P.sealAuthorityCheckpoint({ ...bc('0', null, K0, null), checkpoint_authority: { current_key_id: K0.key_id, next_key_id: K1.key_id } }, K0.priv, K0.pubB64)], { genesisAuthority: gAuth })));
  // three-layer id: external evidence is NOT part of checkpoint_id (same checkpoint, two anchor receipts ⇒ same id)
  check('AC checkpoint_id excludes attached external evidence (stable id)', P.authorityCheckpointId({ ...C2, anchor: { substrate: 'bitcoin-ots', receipt: 'a' } }) === P.authorityCheckpointId({ ...C2, anchor: { substrate: 'rekor', receipt: 'b' } }));
  // tampered body ⇒ signature no longer matches the preimage
  const C2t = { body: { ...C2.body, checkpoint_authority: { ...C2.body.checkpoint_authority, current_key_id: 'sha256:' + '00'.repeat(32) } }, sig: C2.sig };   // tamper current_key_id: passes shape/epoch/scope/append-only, breaks ONLY the signature preimage → E-AUTHORITY (active_genesis→scope, keylog→append-only would trip first)
  check('AC tampered body (sig over the pre-tamper preimage) → INVALID(E-AUTHORITY)', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C2t], { pinnedPrior: pinC1 })));
  // domain must not change within one chain
  check('AC domain_shard changes within the chain → INVALID(E-MALFORMED)', (r => r.error === 'E-MALFORMED')(P.verifyAuthorityCheckpointChain([C0, P.sealAuthorityCheckpoint(bc('1', id0, K1, null, 'evil.example'), K1.priv, K1.pubB64)], { genesisAuthority: gAuth })));
}

// ─── P1-04 — checkpoint-authority root RESOLVED from the signed genesis, not a raw caller pin ───────────────────
{
  const K0 = kp('31'.repeat(32)), D = 'noosphere.md';
  const genCA = P.seal(P.buildGenesis({ domain_shard: D, ust_id: 'ust:20260701.00', key_id: K0.key_id }, T, K0.pubB64, undefined, undefined, undefined, { key_id: K0.key_id, pub: K0.pubB64 }), K0.priv, K0.pubB64);
  const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: P.genesisEpoch(P.contentHash(genCA)), sequence: '0', active_genesis: P.contentHash(genCA), current_key_id: K0.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), K0.priv, K0.pubB64);
  check('P1-04 roots RESOLVED from the signed genesis → authority_root:"genesis"', (r => r.result === 'VALID' && r.authority_root === 'genesis')(P.verifyAuthorityCheckpointChain([C0], { genesis: genCA })));
  check('P1-04 raw genesisAuthority pin → authority_root:"consumer-pin" (not silently genesis-authorized)', (r => r.result === 'VALID' && r.authority_root === 'consumer-pin')(P.verifyAuthorityCheckpointChain([C0], { genesisAuthority: { key_id: K0.key_id, pub: K0.pubB64 } })));
  check('P1-04 resolveCheckpointRoots rejects a checkpoint_authority key_id ≠ keyId(pub)', P.resolveCheckpointRoots(P.seal(P.buildGenesis({ domain_shard: D, ust_id: 'ust:20260701.01', key_id: K0.key_id }, T, K0.pubB64, undefined, undefined, undefined, { key_id: 'sha256:' + '99'.repeat(32), pub: K0.pubB64 }), K0.priv, K0.pubB64))?.genesisAuthority === undefined);
  // M2 (rc.35 refactor) — the verifyGenesis seam derives the canonical scope; the publisher never chooses domain/epoch/scope.
  check('M2/K2 verifiedGenesisContext derives scope_id = H("ust:authority-scope", contentHash(g)) — binds the whole genesis', (c => c && c.genesis_epoch === P.genesisEpoch(P.contentHash(genCA)) && c.scope_id === P.authorityScopeId(P.contentHash(genCA)) && c.scope_id === P.H('ust:authority-scope', c.active_genesis) && c.domain === D && c.checkpoint_authority.key_id === K0.key_id)(P.verifiedGenesisContext(genCA)));
  check('M2 verifiedGenesisContext rejects an unsigned genesis → null (P0-2 carried)', P.verifiedGenesisContext({ state: { id: { class: 'genesis' }, data: { genesis: { value: {} } } } }) === null);
  // C1 (UST-6vj) — downstream takes the CONTEXT: one verified derivation carries scope + authority + recovery.
  const ctx = P.verifiedGenesisContext(genCA);
  check('C1 chain rooted in a VerifiedAuthorityContext → VALID (authority_root verified-context)', (r => r.result === 'VALID' && r.authority_root === 'verified-context')(P.verifyAuthorityCheckpointChain([C0], { context: ctx })));
  check('C1 context-rooted C₀ bound to the context scope: foreign active_genesis → INVALID(E-GENESIS)', (r => r.result === 'INVALID' && r.error === 'E-GENESIS')((() => {
    const AGx = 'sha256:' + '77'.repeat(32);
    const Cx = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: P.genesisEpoch(AGx), sequence: '0', active_genesis: AGx, current_key_id: K0.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), K0.priv, K0.pubB64);
    return P.verifyAuthorityCheckpointChain([Cx], { context: ctx });
  })()));
  // K3 — the context MUST be a branded GenesisHandle. A caller-shaped look-alike (round-3 P0-1 forge) is rejected.
  check('K3 forged context (caller-shaped {scope_id, checkpoint_authority}) → INVALID(E-AUTHORITY), not verified-context', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0], { context: { scope_id: ctx.scope_id, active_genesis: ctx.active_genesis, domain: D, genesis_epoch: ctx.genesis_epoch, checkpoint_authority: { key_id: K0.key_id, pub: K0.pubB64 } } })));
  check('K3 the genuine context IS a branded handle (isVerifiedHandle true); the look-alike is not', P.isVerifiedHandle('genesis', ctx) === true && P.isVerifiedHandle('genesis', { ...ctx }) === false);
  check('K3 a VALID chain mints a branded CheckpointChainHandle (pin) carrying the scoped snapshot', (r => P.isVerifiedHandle('chain', r.pin) && r.pin.scope_id === P.authorityScopeId(P.contentHash(genCA)) && r.pin.checkpoint_id === r.head)(P.verifyAuthorityCheckpointChain([C0], { context: ctx })));

  // ── K4 (UST-znh) — verifyAuthorityBundle: the ONE public entrypoint. Caller hands RAW inputs + config; the kernel
  //    builds every branded handle itself (genesis → context → chain → freshness → assurance). Corroborated path.
  const KCk = kp('64'.repeat(32));
  const connK = { [KCk.key_id]: { pub: KCk.pubB64, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } };
  const klk = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
  const C0k = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: P.genesisEpoch(P.contentHash(genCA)), sequence: '0', active_genesis: P.contentHash(genCA), current_key_id: K0.key_id, keylog: { root: klk.root, length: klk.length, head: klk.head } }), K0.priv, K0.pubB64);
  const headK = P.authorityCheckpointId(C0k);
  const rcptK = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: P.contentHash(genCA), subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KCk.priv, KCk.pubB64);
  const bundleIn = { genesis: genCA, checkpoints: [C0k], target: { active_genesis: P.contentHash(genCA), domain_shard: D, subject: 'ust:target', anchor: rcptK('ust:target', 800) }, commitment: rcptK(headK, 900), terminality: { headProof: klk.headProof, successorProof: klk.successorProof } };
  const cfg = { trust: { connectors: connK } };
  // K4 is now PROVER ∘ check_C (Closed Proof Kernel): the verdict comes SOLELY from the reference checker; D1 shape
  // (base + anti-equivocation basis), trust from config only, no producer-stack verdict honored.
  check('K4/CPK verifyAuthorityBundle (prover∘check_C) → VALID corroborated, scope_id, support carries order, proof_hash', (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated' && r.scope_id === P.authorityScopeId(P.contentHash(genCA)) && !r.anti_equivocation.quorum && !r.anti_equivocation.map && r.support.includes('order') && typeof r.proof_hash === 'string')(P.verifyAuthorityBundle(bundleIn, cfg)));
  check('K4 bundle without genesis → INDETERMINATE(authority_unresolved) — an authority bundle roots in a verified genesis', (r => r.result === 'INDETERMINATE' && r.reason === 'authority_unresolved')(P.verifyAuthorityBundle({ ...bundleIn, genesis: undefined }, cfg)));
  check('K4 bundle with an UNVERIFIED genesis (not self-signed) → INVALID (check_C rejects at the Genesis rule)', (r => r.result === 'INVALID' && /Genesis/.test(r.reason))(P.verifyAuthorityBundle({ ...bundleIn, genesis: { state: { id: { class: 'genesis' } }, sig: {} } }, cfg)));
  check('K4 bundle output is frozen (single public verdict, no post-hoc mutation)', (() => { const r = P.verifyAuthorityBundle(bundleIn, cfg); try { r.keylog_freshness = 'attested'; } catch {} return Object.isFrozen(r) && r.keylog_freshness !== 'attested'; })());
  // K4 + K1: attested only via explicit experimental policy; default stable caps at corroborated.
  const Wq = kp('71'.repeat(32));   // a consumer-admitted witness (trust lives in CONFIG, never inputs — round-4 P0-02)
  const uniqK = { attestations: [P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: P.genesisEpoch(P.contentHash(genCA)), sequence: '0', checkpoint: headK }, Wq.priv, Wq.pubB64)] };
  const cfgQ = { trust: { connectors: connK, witnesses: { [Wq.key_id]: Wq.pubB64 }, domains: { [Wq.key_id]: 'op-a' }, uniqueness_threshold: 1 } };
  // D1: a witness quorum yields the QUORUM basis (witness-attested), NEVER the scalar `attested`; the legacy scalar stays
  // corroborated; and the quorum basis lives ONLY in anti_equivocation, never in evidence support (carriers disjoint, M-SEP).
  check('K4/D1 witness quorum → anti_equivocation.quorum set, label witness-attested, legacy stays corroborated; support carries NO quorum', (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated' && r.anti_equivocation.quorum && r.anti_equivocation.quorum.domains.length === 1 && !r.anti_equivocation.map && r.label === 'witness-attested' && r.legacy_freshness === 'corroborated' && !r.support.includes('quorum'))(P.verifyAuthorityBundle({ ...bundleIn, uniqueness: uniqK }, cfgQ)));
  // D1/P0-02: an attacker's witnesses that are NOT in config are not counted — no quorum basis appears.
  check('K4/P0-02 attacker attestations (∉ config witnesses) → no quorum basis (self-supplied trust rejected)', (r => r.result === 'INDETERMINATE' || (r.result === 'VALID' && !r.anti_equivocation.quorum))(P.verifyAuthorityBundle({ ...bundleIn, uniqueness: uniqK }, cfg)));

  // K7 — the assembler is a Horn least-fixed-point: rungs derive from atoms, with a premise trace (calculus §7).
  check('K7 provePredicates → Horn closure: IdentityAuthoritative ← name-bound ∧ active-genesis-unique (with trace)', (g => { const r = P.deriveAssurance(g); return r.derivation.some((t) => t.rule === 'IdentityAuthoritative' && t.premises.includes('active-genesis-unique')) && r.provenAtoms.includes('name-bound'); })(P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' } })));
  check('K7 no-upward-forge: without checkpoint-unique, FreshnessAttested is NOT in the closure', (g => !P.deriveAssurance(g).derivation.some((t) => t.rule === 'FreshnessAttested'))(P.provePredicates({ identity: { status: 'verified', strength: 'corroborated' }, freshness: { result: 'VALID', keylog_freshness: 'corroborated' } })));
  check('K7 TierTOP ← integrity-valid ∧ IdentityAuthoritative ∧ time-anchored (composite rule fires)', (g => P.deriveAssurance(g).derivation.some((t) => t.rule === 'TierTOP'))(P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' }, anchor: { inclusion: true, time: 'anchored' } })));
}

// ─── #76 Phase B — publisher-checkpoint CORROBORATED freshness (authorized chain × head∈root × proven-after target).
//     Closes the P0-05 stale-prefix overclaim: earns `corroborated`, NEVER `attested` (no independent anti-equivocation).
{
  const K0 = kp('21'.repeat(32)), KX = kp('2f'.repeat(32));
  const gAuth = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + '22'.repeat(32), EP = P.genesisEpoch(AG), D = 'noosphere.md';
  const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);         // strict terminality: head at position L-1 + no successor
  const keylog = { length: kl.length, root: kl.root, head: kl.head }, term = { headProof: kl.headProof, successorProof: kl.successorProof };
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), K0.priv, K0.pubB64);
  const headId = P.authorityCheckpointId(C0);
  const KC = kp('61'.repeat(32));                                            // the consumer-admitted connector (M3)
  const connectors = { [KC.key_id]: { pub: KC.pubB64, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain', 'rfc3161-tsa'] } };
  const trust = { connectors };
  const rcpt = (subj, facts, kind = 'pow-header-chain') => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: subj, proof_kind: kind, facts, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pubB64);
  const btc = (pos, subj) => rcpt(subj, { substrate: 'bitcoin', position: String(pos) });
  const commit = btc(900, headId);
  const target = { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: btc(800, 'ust:target') };
  const F = (opts) => P.deriveCheckpointFreshness([C0], { genesisAuthority: gAuth, trust, ...opts });

  check('PhB all conjuncts (authorized × head∈root × proven-after) → corroborated', (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated' && r.head === headId)(F({ target, commitment: commit, terminality: term })));
  check('PhB CEILING: corroborated carries anti_equivocation:unverified and is NEVER attested', (r => r.keylog_freshness === 'corroborated' && r.anti_equivocation === 'unverified' && r.keylog_freshness !== 'attested')(F({ target, commitment: commit, terminality: term })));
  check('PhB commitment NOT proven-after target → INDETERMINATE(order_unproven)', (r => r.result === 'INDETERMINATE' && r.reason === 'order_unproven')(F({ target, commitment: btc(700, headId), terminality: term })));
  check('PhB two not_after upper bounds → unproven → order_unproven', (r => r.reason === 'order_unproven')(F({ target: { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: rcpt('ust:target', { not_after: '2027-01-01T00:00:00Z' }, 'rfc3161-tsa') }, commitment: rcpt(headId, { not_after: '2027-02-01T00:00:00Z' }, 'rfc3161-tsa'), terminality: term })));
  check('PhB terminality missing → INDETERMINATE(terminality_unproven)', (r => r.reason === 'terminality_unproven')(F({ target, commitment: commit })));
  check('PhB commitment not bound to checkpoint id → INDETERMINATE(evidence_unverified)', (r => r.result === 'INDETERMINATE' && r.reason === 'evidence_unverified')(F({ target, commitment: btc(900, 'sha256:' + '00'.repeat(32)), terminality: term })));
  check('PhB unauthorized chain (wrong signer) → INVALID, freshness unverified', (r => r.result === 'INVALID' && r.keylog_freshness === 'unverified')(P.deriveCheckpointFreshness([P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), KX.priv, KX.pubB64)], { genesisAuthority: gAuth, target, commitment: commit, terminality: term })));
  check('PhB checkpoint active_genesis ≠ target → INVALID(E-GENESIS)', (r => r.result === 'INVALID' && r.error === 'E-GENESIS')(F({ target: { active_genesis: 'sha256:' + '99'.repeat(32), domain_shard: D, anchor: btc(800, 'ust:target') }, commitment: commit, terminality: term })));
  check('PhB cold verifier (no root) → INDETERMINATE(authority_unresolved)', (r => r.reason === 'authority_unresolved')(P.deriveCheckpointFreshness([C0], { target, commitment: commit, terminality: term })));

  // ── M3 (UST-6vj C2) — THE EVIDENCE SEAM: provenance is verified, not assumed. VerifyEvidence_C = 7 ordered checks;
  //    only its image carries capability; the caller-minted look-alike (rc.35 round-2 forge) earns nothing.
  const scope = { domain_shard: D, active_genesis: AG, genesis_epoch: EP };
  const vr = (r, o = {}) => P.verifyEvidenceReceipt(r, { subject: r?.claim?.subject, scope, connectors, ...o });
  check('M3 receipt: admitted connector receipt → VerifiedEvidence (verified_facts, consumer trust_domain, basis admitted-connector-receipt)',
    (r => r.result === 'VALID' && r.evidence.basis === 'admitted-connector-receipt' && r.evidence.trust_domain === 'btc-watch' && r.evidence.verified_facts.position === '900' && r.evidence.subject_id === headId && r.evidence.issuer_id === KC.key_id)(vr(commit)));
  check('M3 receipt: tampered claim (sig over the pre-tamper preimage) → INVALID(E-EVIDENCE)',
    (r => r.result === 'INVALID' && r.error === 'E-EVIDENCE')(vr({ ...commit, claim: { ...commit.claim, facts: { substrate: 'bitcoin', position: '999999' } } })));
  check('M3 receipt: facts self-declaring assurance/trust_domain/capability → INVALID(E-EVIDENCE) at build AND verify',
    (() => { try { P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: 'x', proof_kind: 'k', facts: { assurance: 'attested' }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pubB64); return false; } catch (e) {
      const forged = { ...commit, claim: { ...commit.claim, facts: { ...commit.claim.facts, capability: 'time' } } };
      return e.code === 'E-EVIDENCE' && vr(forged).result === 'INVALID'; } })());
  check('M3 receipt: non-canonical genesis_epoch → INVALID(E-EVIDENCE) (M2 hygiene is uniform)',
    (r => r.result === 'INVALID' && r.error === 'E-EVIDENCE')(vr({ ...commit, claim: { ...commit.claim, genesis_epoch: 'sha256:' + 'ee'.repeat(32) } })));
  check('M3 admission: issuer not in consumer connectors → INDETERMINATE(evidence_unverified)',
    (r => r.result === 'INDETERMINATE' && r.reason === 'evidence_unverified')(vr(commit, { connectors: {} })));
  check('M3 admission: proof_kind outside allowed_proof_kinds → INDETERMINATE(evidence_unverified) (B4: a content connector never contributes order/time)',
    (r => r.result === 'INDETERMINATE' && r.reason === 'evidence_unverified')(vr(commit, { connectors: { [KC.key_id]: { pub: KC.pubB64, allowed_proof_kinds: ['content-addressed'] } } })));
  check('M3 binding: receipt subject ≠ required subject → evidence_unverified',
    (r => r.reason === 'evidence_unverified')(vr(commit, { subject: 'sha256:' + '00'.repeat(32) })));
  check('M3 binding: receipt scope ≠ authority scope → evidence_unverified',
    (r => r.reason === 'evidence_unverified')(vr(commit, { scope: { ...scope, active_genesis: 'sha256:' + '99'.repeat(32) } })));
  check('M3 forge: a caller-minted evidence object cannot earn corroborated (freshness → evidence_unverified)',
    (r => r.result === 'INDETERMINATE' && r.reason === 'evidence_unverified' && r.keylog_freshness === 'unverified')(F({ target, commitment: P.verifiedEvidence({ proof_kind: 'pow-header-chain', subject: headId, source_id: 'btc', facts: { substrate: 'bitcoin', position: '900' } }), terminality: term })));
  check('M3 forge: a look-alike VerifiedEvidence (correct fields, no provenance) earns nothing',
    (r => r.reason === 'evidence_unverified')(F({ target, commitment: { evidence_id: 'sha256:' + '11'.repeat(32), authority_scope_id: P.authorityScopeId(AG), subject_id: headId, proof_kind: 'pow-header-chain', verified_facts: { substrate: 'bitcoin', position: '900' }, issuer_id: KC.key_id, trust_domain: 'btc-watch', basis: 'admitted-connector-receipt' }, terminality: term })));
  check('M3 token: a core-verified VerifiedEvidence token is accepted without re-verification (WeakSet witness)',
    (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated')(F({ target: { ...target, anchor: vr(target.anchor).evidence }, commitment: vr(commit).evidence, terminality: term })));
  check('M3 token: a verified token bound to a DIFFERENT subject is rejected at admission',
    (r => r.reason === 'evidence_unverified')(F({ target, commitment: vr(btc(900, 'sha256:' + '77'.repeat(32)), { subject: 'sha256:' + '77'.repeat(32) }).evidence, terminality: term })));
  check('M3 id: evidenceReceiptId is stable over {claim, sig} only', P.evidenceReceiptId(commit) === P.evidenceReceiptId({ claim: commit.claim, sig: commit.sig, extra: 'ignored' }));
}

// ─── #76 Phase C — `attested` via INDEPENDENT anti-equivocation (accepted-witness-quorum). attested = corroborated ∧
//     independent-uniqueness; witnesses sign the BYTE-IDENTICAL typed claim; independence = DISTINCT consumer-resolved domains.
{
  const K0 = kp('31'.repeat(32)), KX = kp('3f'.repeat(32)), Wa = kp('41'.repeat(32)), Wb = kp('42'.repeat(32)), Wc = kp('43'.repeat(32));
  const gAuth = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + '66'.repeat(32), EP = P.genesisEpoch(AG), D = 'noosphere.md';
  const kl = P.buildKeylogCommitment(['sha256:' + 'cd'.repeat(32)]), keylog = { length: kl.length, root: kl.root, head: kl.head }, term = { headProof: kl.headProof, successorProof: kl.successorProof };
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), K0.priv, K0.pubB64);
  const headId = P.authorityCheckpointId(C0);
  const KC = kp('62'.repeat(32));                                            // consumer-admitted connector (M3)
  const trust = { connectors: { [KC.key_id]: { pub: KC.pubB64, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } } };
  const btc = (pos, subj) => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pubB64);
  const commit = btc(900, headId), target = { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: btc(800, 'ust:target') };
  const domains = { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b', [Wc.key_id]: 'op-a' };   // Wa & Wc share a domain; Wb is distinct
  const trustRoots = { [Wa.key_id]: Wa.pubB64, [Wb.key_id]: Wb.pubB64, [Wc.key_id]: Wc.pubB64 };
  const ua = (W, extra) => P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, ...extra }, W.priv, W.pubB64);
  const uOpts = (atts) => ({ attestations: atts, trustRoots, domains, threshold: 2 });
  const F = (uniq) => P.deriveCheckpointFreshness([C0], { genesisAuthority: gAuth, target, commitment: commit, terminality: term, trust, uniqueness: uniq, allowExperimentalAttested: true });   // K1: these test the EXPERIMENTAL attested path
  const VU = (atts) => P.verifyCheckpointUniqueness(atts, { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots, domains, threshold: 2 });

  // K1 ship-gate (UST-znh) — the STABLE verifier does not EMIT attested; the proof still holds but the rung is capped.
  check('K1 stable path (no opt-in): a would-be attested checkpoint is capped at corroborated, attested_withheld named', (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated' && r.attested_withheld === 'experimental-gate' && r.anti_equivocation === 'attested')(P.deriveCheckpointFreshness([C0], { genesisAuthority: gAuth, target, commitment: commit, terminality: term, trust, uniqueness: uOpts([ua(Wa), ua(Wb)]) })));
  check('PhC 2 witnesses, DISTINCT domains → attested (accepted-witness-quorum), anti_equivocation attested', (r => r.result === 'VALID' && r.keylog_freshness === 'attested' && r.basis === 'accepted-witness-quorum' && r.anti_equivocation === 'attested' && r.trust_domains.length === 2)(F(uOpts([ua(Wa), ua(Wb)]))));
  check('PhC 2 witnesses, SAME domain → quorum not met → stays corroborated', (r => r.keylog_freshness === 'corroborated')(F(uOpts([ua(Wa), ua(Wc)]))));
  check('PhC uniqueness on an UNAUTHORIZED checkpoint → INVALID, never attested', (r => r.result === 'INVALID' && r.keylog_freshness !== 'attested')(P.deriveCheckpointFreshness([P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), KX.priv, KX.pubB64)], { genesisAuthority: gAuth, target, commitment: commit, terminality: term, uniqueness: uOpts([ua(Wa), ua(Wb)]) })));
  check('PhC bare observation (wrong purpose) is NOT uniqueness → not admitted', VU([{ claim: { purpose: 'ust:observed', domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }, issuer_id: Wa.key_id, sig: { alg: 'Ed25519', key_id: Wa.key_id, pub: Wa.pubB64, sig: 'x' } }, ua(Wb)]).attested === false);
  check('PhC witnesses signing NON-identical claims → mismatches dropped → quorum not met', VU([ua(Wa, { observed_map_root: 'sha256:' + 'a1'.repeat(32) }), ua(Wb, { observed_map_root: 'sha256:' + 'b2'.repeat(32) })]).attested === false);
  check('PhC witness NOT in consumer trustRoots → not admitted', P.verifyCheckpointUniqueness([ua(Wa), ua(Wb)], { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots: { [Wa.key_id]: Wa.pubB64 }, domains, threshold: 2 }).attested === false);
  check('PhC self-declared trust_domain inside the claim → rejected', VU([{ claim: { ...P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }), trust_domain: 'independent-7' }, issuer_id: Wa.key_id, sig: ua(Wa).sig }, ua(Wb)]).attested === false);
  check('PhC uniqueness for a DIFFERENT checkpoint → not admitted (binding)', VU([P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: 'sha256:' + '00'.repeat(32) }, Wa.priv, Wa.pubB64), ua(Wb)]).attested === false);

  // ── M5 (UST-6vj) — ONE QUORUM ALGEBRA: admit → group → count → adjudicate; uniqueness and recovery are instances.
  const Wd = kp('44'.repeat(32));
  const roots4 = { ...trustRoots, [Wd.key_id]: Wd.pubB64 }, doms4 = { ...domains, [Wd.key_id]: 'op-d' };
  const VU4 = (atts) => P.verifyCheckpointUniqueness(atts, { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots: roots4, domains: doms4, threshold: 2 });
  check('M5 quorum-poison closed: an UNAUTHENTICATED first claim-variant cannot suppress the honest quorum (group AFTER admission)',
    (r => r.attested === true)(VU4([{ claim: P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, as_of: '2026-01-01T00:00:00Z' }), issuer_id: Wa.key_id, sig: { alg: 'Ed25519', key_id: Wa.key_id, pub: Wa.pubB64, sig: 'AA' } }, ua(Wa), ua(Wb)])));
  check('M5 conflict determinism: two RIVAL claims each reaching quorum → conflict, never first-wins',
    (r => r.attested === false && r.conflict === true)(VU4([ua(Wa), ua(Wb), P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, observed_map_root: 'sha256:' + 'aa'.repeat(32) }, Wc.priv, Wc.pubB64), P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, observed_map_root: 'sha256:' + 'aa'.repeat(32) }, Wd.priv, Wd.pubB64)])));
  check('M5 conflict is order-independent (reversed array → same conflict)',
    (r => r.attested === false && r.conflict === true)(VU4([P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, observed_map_root: 'sha256:' + 'aa'.repeat(32) }, Wd.priv, Wd.pubB64), P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, observed_map_root: 'sha256:' + 'aa'.repeat(32) }, Wc.priv, Wc.pubB64), ua(Wb), ua(Wa)])));
  check('M5 ValidThreshold uniform: quorumTrustDomains threshold 0 → met:false (never satisfied)',
    (r => r.met === false)(P.quorumTrustDomains([{ source_id: 'a' }], { domains: { a: 'op-a' }, threshold: 0 })));
  check('M5 total: a malformed recovery leaf (canon-throwing) admits nothing and never throws',
    (() => { try { return P.verifyCheckpointRecovery([{ claim: { purpose: 'ust:checkpoint-authority-recovery', domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: headId, effective_sequence: '1', replacement_authority: { key_id: Wa.key_id, pub: Wa.pubB64 }, junk: undefined }, issuer_id: Wa.key_id, sig: { sig: 'AA', pub: Wa.pubB64 } }], { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: headId, effective_sequence: '1', recoveryKeys: roots4, threshold: 2 }).recovered === false; } catch { return false; } })());
}

// ─── #76/#42 AUTHENTICATED-MAP UNIQUENESS — independent (non-publisher) non-membership via a sparse Merkle map. Same
//     predicates as the witness quorum, different basis; TWO typed key spaces (checkpoint→attested, name→authoritative).
{
  const K0 = kp('51'.repeat(32)), KX = kp('5f'.repeat(32));
  const gAuth = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + '88'.repeat(32), EP = P.genesisEpoch(AG), D = 'noosphere.md';
  const kl = P.buildKeylogCommitment(['sha256:' + 'de'.repeat(32)]), keylog = { length: kl.length, root: kl.root, head: kl.head }, term = { headProof: kl.headProof, successorProof: kl.successorProof };
  const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), K0.priv, K0.pubB64);
  const headId = P.authorityCheckpointId(C0);
  const KC = kp('63'.repeat(32));                                            // consumer-admitted connector (M3)
  const connectors = { [KC.key_id]: { pub: KC.pubB64, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain'] } };
  const btc = (pos, subj) => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pubB64);
  const target = { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: btc(800, 'ust:target') };
  const cpLeaf = P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId });
  const cmap = P.buildVerifiableMap([cpLeaf, P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '1', checkpoint: 'sha256:' + 'ab'.repeat(32) })]);
  const cproof = cmap.prove(cpLeaf.key);
  const Fmap = (uniq) => P.deriveCheckpointFreshness([C0], { genesisAuthority: gAuth, target, commitment: btc(900, headId), terminality: term, uniqueness: uniq, trust: { connectors, mapRoots: uniq?.map ? [uniq.map.mapRoot] : [] }, allowExperimentalAttested: true });   // K1: experimental attested path; consumer admits the root it holds

  check('#42 checkpoint-map inclusion → attested (basis authenticated-map-uniqueness)', (r => r.keylog_freshness === 'attested' && r.basis === 'authenticated-map-uniqueness' && r.map_root === cmap.root)(Fmap({ map: { proof: cproof, mapRoot: cmap.root } })));
  const rivalMap = P.buildVerifiableMap([P.checkpointMapLeaf({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: 'sha256:' + '99'.repeat(32) })]);
  check('#42 map shows a RIVAL at the same sequence → not attested → stays corroborated', (r => r.keylog_freshness === 'corroborated')(Fmap({ map: { proof: rivalMap.prove(cpLeaf.key), mapRoot: rivalMap.root } })));
  check('#42 map uniqueness on an UNAUTHORIZED chain → INVALID, never attested', (r => r.result === 'INVALID' && r.keylog_freshness !== 'attested')(P.deriveCheckpointFreshness([P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: K0.key_id, keylog }), KX.priv, KX.pubB64)], { genesisAuthority: gAuth, target, commitment: btc(900, headId), terminality: term, uniqueness: { map: { proof: cproof, mapRoot: cmap.root } } })));

  const G = kp('cc'.repeat(32)), K = kp('dd'.repeat(32)), signG = (s) => P.seal(s, G.priv, G.pubB64);
  const gen = signG(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.19', key_id: G.key_id }, T, G.pubB64));
  const add = signG(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.1901', key_id: G.key_id }, T, { op: 'add', pub: K.pubB64, new_key_id: K.key_id }, P.contentHash(gen)));
  const docK = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260628.20', key_id: K.key_id, class: 'observation' }, T, { sw: { kind: 'captured', value: { kp: '5' } } }), K.priv, K.pubB64);
  const nLeaf = P.nameMapLeaf({ domain_shard: 'noosphere.md', active_genesis: P.contentHash(gen) });
  const nmap = P.buildVerifiableMap([nLeaf]), nproof = nmap.prove(nLeaf.key), emptyMap = P.buildVerifiableMap([]);
  check('#42 name-map inclusion → identity authoritative (independently_verified, basis map)', (r => r.strength === 'authoritative' && r.independently_verified === true && r.basis === 'authenticated-map-uniqueness')(P.resolveAuthority(docK, { genesis: gen, keylog: [add], nameMap: { proof: nproof, mapRoot: nmap.root }, trust: { mapRoots: [nmap.root] } })));
  check('#42 name-map absent (empty map non-membership) → NOT authoritative', (r => r.strength !== 'authoritative')(P.resolveAuthority(docK, { genesis: gen, keylog: [add], nameMap: { proof: emptyMap.prove(nLeaf.key), mapRoot: emptyMap.root }, trust: { mapRoots: [emptyMap.root] } })));
  check('#42 name-map inclusion via verify() composes to VALID:HIGH (authoritative name)', P.verify(docK, { genesis: gen, keylog: [add], nameMap: { proof: nproof, mapRoot: nmap.root }, trust: { mapRoots: [nmap.root] }, context: 'data' }).result === 'VALID:HIGH');
  check('#42 typed key spaces: a name-map proof is rejected as a checkpoint-map proof (no collision)', P.verifyCheckpointMapUniqueness(nproof, { domain_shard: 'noosphere.md', genesis_epoch: EP, sequence: '0', checkpoint: headId, mapRoot: nmap.root }).attested === false);
  check('#42 SMT non-membership: absent key → proven non-membership (absent:true), not authoritative', (r => r.authoritative === false && r.absent === true)(P.verifyActiveGenesisUniqueness(emptyMap.prove(nLeaf.key), { domain_shard: 'noosphere.md', active_genesis: P.contentHash(gen), mapRoot: emptyMap.root })));
  check('#42 SMT rival-value-bound is NOT non-membership (absent falsy) — distinct from an absent key', (r => r.authoritative === false && !r.absent)(P.verifyActiveGenesisUniqueness(nproof, { domain_shard: 'noosphere.md', active_genesis: 'sha256:' + '00'.repeat(32), mapRoot: nmap.root })));
}

// ─── #76 §1.7 CHECKPOINT RECOVERY — genesis-authorized 2-of-3 multisig re-authorizes the checkpoint authority after
//     key loss, WITHOUT bypassing checkpoint validation. Dormant emergency mechanism, not a normal rotation.
{
  const K0 = kp('61'.repeat(32)), K1 = kp('62'.repeat(32)), KR = kp('6a'.repeat(32)), KR2 = kp('6b'.repeat(32));
  const R1 = kp('71'.repeat(32)), R2 = kp('72'.repeat(32)), R3 = kp('73'.repeat(32)), RX = kp('7f'.repeat(32));
  const gAuth = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + '99'.repeat(32), EP = P.genesisEpoch(AG), D = 'noosphere.md';
  const KL = { length: '1', root: 'sha256:' + 'c0'.repeat(32), head: 'sha256:' + 'd0'.repeat(32) };
  const bc = (seq, prev, cur, nxt) => P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: seq, previous_checkpoint: prev, active_genesis: AG, current_key_id: cur.key_id, ...(nxt ? { next_key_id: nxt.k.key_id, next_pub: nxt.k.pubB64, effective_sequence: nxt.at } : {}), keylog: KL });
  const C0 = P.sealAuthorityCheckpoint(bc('0', null, K0, { k: K1, at: '1' }), K0.priv, K0.pubB64); const id0 = P.authorityCheckpointId(C0);
  const rKeys = { [R1.key_id]: R1.pubB64, [R2.key_id]: R2.pubB64, [R3.key_id]: R3.pubB64 };
  const rf = (repl, seq = '1', last = id0) => ({ domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: last, replacement_key_id: repl.key_id, replacement_pub: repl.pubB64, reason: 'lost', effective_sequence: seq });
  const stmt = (fields, W) => P.buildRecoveryStatement(fields, W.priv, W.pubB64);
  const C1r = P.sealAuthorityCheckpoint(bc('1', id0, KR, null), KR.priv, KR.pubB64);          // C1 signed by the RECOVERED replacement KR
  const chain = (recs, threshold = 2, c1 = C1r) => P.verifyAuthorityCheckpointChain([C0, c1], { genesisAuthority: gAuth, recoveries: { '1': recs }, recoveryKeys: rKeys, recoveryThreshold: threshold });
  const VR = (recs, over = {}) => P.verifyCheckpointRecovery(recs, { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: id0, effective_sequence: '1', recoveryKeys: rKeys, threshold: 2, ...over });

  check('RECOVERY 2-of-3 (lost key K1) authorizes replacement KR → chain VALID', chain([stmt(rf(KR), R1), stmt(rf(KR), R2)]).result === 'VALID');
  check('RECOVERY 1-of-3 (below threshold) → chain INVALID(E-AUTHORITY)', (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(chain([stmt(rf(KR), R1)])));
  check('RECOVERY same signer twice → counts once → quorum not met', VR([stmt(rf(KR), R1), stmt(rf(KR), R1)]).recovered === false);
  check('RECOVERY conflicting replacements (non-identical claims) → no quorum (must agree on ONE)', VR([stmt(rf(KR), R1), stmt(rf(KR2), R2)]).recovered === false);
  check('RECOVERY signer NOT in the genesis recovery set → not counted', VR([stmt(rf(KR), R1), stmt(rf(KR), RX)]).recovered === false);
  check('RECOVERY replacement key_id ≠ keyId(pub) → not recovered', VR([{ claim: { ...P.checkpointRecoveryClaim(rf(KR)), replacement_authority: { key_id: K1.key_id, pub: KR.pubB64 } }, issuer_id: R1.key_id, sig: stmt(rf(KR), R1).sig }, stmt(rf(KR), R2)]).recovered === false);
  check('RECOVERY effective_sequence ≠ last+1 → not recovered (only the next checkpoint)', VR([stmt(rf(KR, '2'), R1), stmt(rf(KR, '2'), R2)]).recovered === false);
  check('RECOVERY stale last_accepted_checkpoint → not recovered (bound to the prior)', VR([stmt(rf(KR, '1', 'sha256:' + 'ee'.repeat(32)), R1), stmt(rf(KR, '1', 'sha256:' + 'ee'.repeat(32)), R2)]).recovered === false);
  check('RECOVERY valid 2-of-3 → replacement_authority + threshold + 2 signers', (r => r.recovered === true && r.replacement_authority.key_id === KR.key_id && r.threshold === '2' && r.signers.length === 2)(VR([stmt(rf(KR), R1), stmt(rf(KR), R2)])));
  // recovery re-authorizes the SIGNER only — it does NOT bypass the rest of checkpoint validation
  const C1bad = P.sealAuthorityCheckpoint({ ...bc('1', id0, KR, null), checkpoint_authority: { current_key_id: KR.key_id, next_key_id: K1.key_id } }, KR.priv, KR.pubB64);
  check('RECOVERY does NOT bypass checkpoint validation (recovered signer, but malformed rotation → E-MALFORMED)', (r => r.result === 'INVALID' && r.error === 'E-MALFORMED')(chain([stmt(rf(KR), R1), stmt(rf(KR), R2)], 2, C1bad)));
}

// ─── #76 (audit-8) GENESIS-EPOCH TRANSITION — a new epoch must NOT silently reset; it needs an A→B transition signed
//     by epoch A's authority. Epoch B's C₀ binds A's final checkpoint + the transition's initial sequence.
{
  const KA0 = kp('a0'.repeat(32)), KB0 = kp('b0'.repeat(32)), KX = kp('af'.repeat(32));
  const D = 'noosphere.md', AGA = 'sha256:' + 'a2'.repeat(32), AGB = 'sha256:' + 'b2'.repeat(32), EPA = P.genesisEpoch(AGA), EPB = P.genesisEpoch(AGB);
  const KL = { length: '1', root: 'sha256:' + 'c0'.repeat(32), head: 'sha256:' + 'd0'.repeat(32) };
  const C0a = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPA, sequence: '0', active_genesis: AGA, current_key_id: KA0.key_id, keylog: KL }), KA0.priv, KA0.pubB64);
  const idA = P.authorityCheckpointId(C0a), gA = { key_id: KA0.key_id, pub: KA0.pubB64 };
  const etf = (over = {}) => ({ domain_shard: D, from_genesis_epoch: EPA, from_final_checkpoint: idA, to_active_genesis: AGB, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pubB64, to_initial_sequence: '0', ...over });
  const et = P.buildEpochTransition(etf(), KA0.priv, KA0.pubB64);
  const c0b = (over = {}) => P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPB, sequence: '0', previous_epoch_final_checkpoint: idA, active_genesis: AGB, current_key_id: KB0.key_id, keylog: KL, ...over }), (over._signer || KB0).priv, (over._signer || KB0).pubB64);
  const C0b = c0b();
  const chain = (c1, ets) => P.verifyAuthorityCheckpointChain([C0a, c1], { genesisAuthority: gA, epochTransitions: ets });
  const VE = (stmt, over = {}) => P.verifyEpochTransition(stmt, { domain_shard: D, from_genesis_epoch: EPA, from_final_checkpoint: idA, fromAuthority: gA, ...over });

  check('EPOCH A→B with authenticated transition → chain VALID (initial seq 0)', (r => r.result === 'VALID' && r.sequence === '0')(chain(C0b, { [EPB]: et })));
  check('EPOCH silent reset (no transition supplied) → INVALID(E-MALFORMED)', (r => r.result === 'INVALID' && r.error === 'E-MALFORMED')(chain(C0b, undefined)));
  check('EPOCH transition NOT signed by epoch A authority → INVALID(E-MALFORMED)', (r => r.error === 'E-MALFORMED')(chain(C0b, { [EPB]: P.buildEpochTransition(etf(), KX.priv, KX.pubB64) })));
  check('EPOCH B C₀ does not bind the prior-epoch final checkpoint → INVALID(E-PREV)', (r => r.error === 'E-PREV')(chain(c0b({ previous_epoch_final_checkpoint: 'sha256:' + 'ee'.repeat(32) }), { [EPB]: et })));
  check('EPOCH B C₀ sequence ≠ transition to_initial_sequence → INVALID(E-SEQ)', (r => r.error === 'E-SEQ')(P.verifyAuthorityCheckpointChain([C0a, P.sealAuthorityCheckpoint({ ...P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPB, sequence: '5', previous_epoch_final_checkpoint: idA, active_genesis: AGB, current_key_id: KB0.key_id, keylog: KL }) }, KB0.priv, KB0.pubB64)], { genesisAuthority: gA, epochTransitions: { [EPB]: P.buildEpochTransition(etf({ to_initial_sequence: '0' }), KA0.priv, KA0.pubB64) } })));
  check('EPOCH verifyEpochTransition valid → to_checkpoint_authority + to_initial_sequence', (r => r.ok === true && r.to_checkpoint_authority.key_id === KB0.key_id && r.to_initial_sequence === '0')(VE(et)));
  check('EPOCH transition bound to wrong from_final_checkpoint → not ok', VE(et, { from_final_checkpoint: 'sha256:' + '00'.repeat(32) }).ok === false);
  check('EPOCH transition to_checkpoint_authority malformed (key_id ≠ keyId(pub)) → not ok', VE(P.buildEpochTransition({ ...etf(), to_key_id: KA0.key_id }, KA0.priv, KA0.pubB64)).ok === false);
  // M4.4 — the destination is a VERIFIED genesis, never a free label.
  check('M4.4 transition without to_active_genesis → not ok (no free epoch label)', VE(P.buildEpochTransition({ domain_shard: D, from_genesis_epoch: EPA, from_final_checkpoint: idA, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pubB64, to_initial_sequence: '0' }, KA0.priv, KA0.pubB64)).ok === false);
  check('M4.4 transition with a NON-canonical to_genesis_epoch → not ok (M2 hygiene uniform)', VE(P.buildEpochTransition(etf({ to_genesis_epoch: 'sha256:' + 'ee'.repeat(32) }), KA0.priv, KA0.pubB64)).ok === false);
  check('M4.4 transition bound to a DIFFERENT destination genesis than the checkpoint lives in → INVALID (no cross-genesis seeding)', (r => r.result === 'INVALID')((() => {
    const AGC = 'sha256:' + 'c2'.repeat(32);                                            // the transition hands authority to genesis C; the epoch-B checkpoint cannot ride it
    const etC = P.buildEpochTransition(etf({ to_active_genesis: AGC, to_genesis_epoch: P.genesisEpoch(AGC) }), KA0.priv, KA0.pubB64);
    return P.verifyAuthorityCheckpointChain([C0a, C0b], { genesisAuthority: gA, epochTransitions: { [EPB]: etC, [P.genesisEpoch(AGC)]: etC } });
  })()));                                                                              // M2 (canonical epoch both sides) makes b.active_genesis === et.to_active_genesis derivable; the explicit E-GENESIS check in the chain verifier remains as the hash-collision belt
}

// ─── M4.2 (UST-6vj) CHAIN-CONSISTENT KEY LOG — append-only ACROSS same-epoch checkpoints. Closes keylog-rewind: a
//     signed rewind was two INDIVIDUALLY-terminal snapshots (C₀ commits length 10, C₁ commits length 4) that the
//     per-checkpoint terminality check could never relate. Monotone length + equal-length-identical-snapshot are
//     unconditional; the FULL prefix-extension proof is the consumer-supplied key-log entry vector (≤ 256, §13).
{
  const K0 = kp('71'.repeat(32));
  const gA = { key_id: K0.key_id, pub: K0.pubB64 };
  const AG = 'sha256:' + '72'.repeat(32), EP = P.genesisEpoch(AG), D = 'noosphere.md';
  const e = (n) => 'sha256:' + n.toString(16).padStart(2, '0').repeat(32);
  const E = [e(0x01), e(0x02), e(0x03)];                                               // the ONE honest entry vector
  const kc = (n) => P.buildKeylogCommitment(E.slice(0, n));
  const cp = (seq, prevId, kl, over = {}) => P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EP, sequence: seq, ...(prevId ? { previous_checkpoint: prevId } : {}), active_genesis: AG, current_key_id: K0.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head }, ...over }), K0.priv, K0.pubB64);
  const C0 = cp('0', null, kc(2)), id0 = P.authorityCheckpointId(C0);

  check('M4.2 keylog grows across checkpoints (2→3) with the prefix witness → VALID', (r => r.result === 'VALID')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, kc(3))], { genesisAuthority: gA, keylogEntries: E })));
  check('K5 growth WITHOUT the prefix witness → INDETERMINATE(chain_consistency_unproven) (round-3 P0-3)', (r => r.result === 'INDETERMINATE' && r.reason === 'chain_consistency_unproven')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, kc(3))], { genesisAuthority: gA })));
  check('M4.2 keylog REWIND (length 2→1) → INVALID(E-COMMIT) — a signed rewind is caught without any proof', (r => r.result === 'INVALID' && r.error === 'E-COMMIT')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, kc(1))], { genesisAuthority: gA })));
  check('M4.2 equal-length keylog with a DIFFERENT root/head → INVALID(E-COMMIT) — same-length history rewrite', (r => r.result === 'INVALID' && r.error === 'E-COMMIT')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, P.buildKeylogCommitment([e(0x01), e(0x0f)]))], { genesisAuthority: gA })));
  check('M4.2 prefix-extension witness: every checkpoint is a prefix of the supplied entry vector → VALID', (r => r.result === 'VALID')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, kc(3))], { genesisAuthority: gA, keylogEntries: E })));
  check('M4.2 prefix-extension witness: a checkpoint whose keylog is NOT a prefix of the vector → INVALID(E-COMMIT)', (r => r.result === 'INVALID' && r.error === 'E-COMMIT')((() => {
    const rogue = P.buildKeylogCommitment([e(0x01), e(0x0f), e(0x03)]);                // same length 3, middle entry rewritten
    return P.verifyAuthorityCheckpointChain([C0, cp('1', id0, rogue)], { genesisAuthority: gA, keylogEntries: [e(0x01), e(0x0f), e(0x03)] });
  })()));                                                                              // the WITNESS is the rewritten vector: C0 (honest prefix of E) no longer matches it
  check('M4.2 witness longer than the checkpoint keylog is fine; checkpoint longer than the witness → INVALID(E-COMMIT)', (r => r.result === 'INVALID' && r.error === 'E-COMMIT')(P.verifyAuthorityCheckpointChain([C0, cp('1', id0, kc(3))], { genesisAuthority: gA, keylogEntries: E.slice(0, 2) })));
  check('M4.2 keylogEntries over the §13 ceiling (257) → INVALID(E-BOUNDS) before any Merkle work', (r => r.result === 'INVALID' && r.error === 'E-BOUNDS')(P.verifyAuthorityCheckpointChain([C0], { genesisAuthority: gA, keylogEntries: Array.from({ length: 257 }, () => e(0x01)) })));
}

// ─── #77 STRICT KEY-LOG TERMINALITY — head = LAST entry (position L-1) AND no successor at L. Strictly stronger than
//     the earlier `head ∈ root`: a hidden successor (a lying length) is CAUGHT, which bare membership could not.
{
  const e0 = 'sha256:' + '01'.repeat(32), e1 = 'sha256:' + '02'.repeat(32);
  const kl1 = P.buildKeylogCommitment([e0]);
  check('TERM honest length-1 log (head at pos0, nothing at pos1) → terminal', P.verifyKeylogTerminality({ root: kl1.root, length: kl1.length, head: kl1.head }, kl1).terminal === true);
  const kl2 = P.buildKeylogCommitment([e0, e1]);
  check('TERM honest length-2 log (head at pos1, nothing at pos2) → terminal', P.verifyKeylogTerminality({ root: kl2.root, length: kl2.length, head: kl2.head }, kl2).terminal === true);
  const lie = P.verifyKeylogTerminality({ root: kl2.root, length: '1', head: e0 }, { headProof: kl2.prove(0) });   // present a length-2 log as length-1, hiding e1
  check('TERM strict catches a HIDDEN SUCCESSOR (length lies) → not terminal (depth-mismatch or right subtree not empty)', lie.terminal === false && /beyond|right subtree|proof depth/.test(lie.detail));   // P0-5: an under-depth proof for the lied length is now caught earlier by the depth check
  check('TERM wrong head at position L-1 → not terminal', P.verifyKeylogTerminality({ root: kl1.root, length: '1', head: 'sha256:' + '99'.repeat(32) }, kl1).terminal === false);
}

// ─── #78/M1 ASSURANCE PRODUCT-LATTICE — the formal-model F.5.0 realized as RUNNING property checks (math ⇒ code
//     ⇒ vector). M1.1: STRENGTH = four chains (2×4×4×2 = 64); capability SUPPORT is a separate Boolean lattice
//     (P(Caps), ⊆) — not a fifth coordinate. Exhaustive; deterministic, no sampling for pairwise laws.
{
  const AX = P.ASSURANCE_AXES, keys = Object.keys(AX);
  const all = []; (function rec(i, acc) { if (i === keys.length) return all.push({ ...acc }); for (const v of AX[keys[i]]) rec(i + 1, { ...acc, [keys[i]]: v }); })(0, {});
  const eq = (a, b) => keys.every((k) => a[k] === b[k]);
  check('LATTICE product = 64 states (2×4×4×2) — strength only, support is not a coordinate (M1.1)', all.length === 64);

  // (1) every axis a TOTAL order (all pairs comparable); (2) the product a PARTIAL order (reflexive + antisymmetric)
  let totalOK = true; for (const ax of keys) for (const x of AX[ax]) for (const y of AX[ax]) if (!(P.axisRank(ax, x) <= P.axisRank(ax, y) || P.axisRank(ax, y) <= P.axisRank(ax, x))) totalOK = false;
  check('LATTICE (1) every axis is a total order', totalOK);
  let refl = true, antisym = true; for (const a of all) { if (!P.assuranceLE(a, a)) refl = false; for (const b of all) if (P.assuranceLE(a, b) && P.assuranceLE(b, a) && !eq(a, b)) antisym = false; }
  check('LATTICE (2) product order reflexive + antisymmetric', refl && antisym);

  // (3) LATTICE laws pairwise (64²): meet a lower bound, join an upper bound, both commutative + absorptive
  let latOK = true; for (const a of all) for (const b of all) {
    const m = P.meetAssurance(a, b), j = P.joinAssurance(a, b);
    if (!(P.assuranceLE(m, a) && P.assuranceLE(m, b) && P.assuranceLE(a, j) && P.assuranceLE(b, j))) latOK = false;
    if (!(eq(m, P.meetAssurance(b, a)) && eq(j, P.joinAssurance(b, a)))) latOK = false;                 // commutative
    if (!(eq(P.meetAssurance(a, j), a) && eq(P.joinAssurance(a, m), a))) latOK = false;                 // absorption
  }
  check('LATTICE (3) meet=glb, join=lub, commutative + absorption (64² pairs)', latOK);

  // (4) A_id ⊥ A_fresh — the axes strengthen INDEPENDENTLY (gap 1/3): id-up/fresh-fixed vs fresh-up/id-fixed is INCOMPARABLE
  const idUp = { integrity: 'valid', identity: 'authoritative', freshness: 'unverified', time: 'unproven' };
  const frUp = { integrity: 'valid', identity: 'self-asserted', freshness: 'attested', time: 'unproven' };
  check('LATTICE (4) A_id / A_fresh product-incomparability (M1.4 — no ⊥): id-up vs fresh-up incomparable', !P.assuranceLE(idUp, frUp) && !P.assuranceLE(frUp, idUp));

  // (5) projectTier MONOTONE over every comparable pair (64²): a ≤ b ⇒ tier(a) ≤ tier(b)
  let monoOK = true; for (const a of all) for (const b of all) if (P.assuranceLE(a, b) && !(P.TIER_RANK[P.projectTier(a)] <= P.TIER_RANK[P.projectTier(b)])) monoOK = false;
  check('LATTICE (5) projectTier is monotone (order-preserving)', monoOK);

  // (6) the projection AGREES with the realized §14 tier (authoritative∧anchored⇒TOP; name-bound⇒HIGH) — NO 2nd truth
  const inlineTier = (id, time) => (id === 'authoritative' && time === 'anchored') ? 'TOP' : (id === 'corroborated' || id === 'authoritative') ? 'HIGH' : 'LIGHT';
  let agreeOK = true; for (const id of AX.identity) for (const time of AX.time) if (P.projectTier({ integrity: 'valid', identity: id, freshness: 'unverified', time }) !== inlineTier(id, time)) agreeOK = false;
  check('LATTICE (6) projectTier agrees with the realized §14 tier (identity+time)', agreeOK);
  check('LATTICE (6b) integrity floor unmet ⇒ NONE (INVALID upstream)', P.projectTier({ integrity: 'invalid', identity: 'authoritative', freshness: 'attested', time: 'anchored' }) === 'NONE');

  // (7) capAssurance = the ℐ_C CAPPED term (F.5b downgrade-resistance): downgrade-only (cap ≤ proven), idempotent, no-ceiling ⇒ identity
  const top = { integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' };
  let capOK = true; for (const a of all) { const c = P.capAssurance(a, { identity: 'pinned', freshness: 'fresh' }); if (!P.assuranceLE(c, a) || !eq(P.capAssurance(c, { identity: 'pinned', freshness: 'fresh' }), c)) capOK = false; }
  check('LATTICE (7a) capAssurance downgrade-only (cap ≤ proven) + idempotent', capOK);
  check('LATTICE (7b) no ceiling ⇒ unchanged', eq(P.capAssurance(top, null), top));
  const capped = P.capAssurance(top, { identity: 'self-asserted', freshness: 'corroborated' });
  check('LATTICE (7c) proven-TOP capped by no-trust-roots/no-domains ⇒ tier drops to LIGHT', P.projectTier(capped) === 'LIGHT' && capped.identity === 'self-asserted' && capped.freshness === 'corroborated');

  // (8) fail-closed: a missing/out-of-range axis ⇒ E-ASSURANCE (never a guessed state)
  let threw = ''; try { P.assuranceState({ integrity: 'valid', identity: 'authoritative', freshness: 'attested' }); } catch (e) { threw = e.code; }
  let threw2 = ''; try { P.assuranceState({ integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'sometime' }); } catch (e) { threw2 = e.code; }
  check('LATTICE (8) missing/out-of-range axis ⇒ E-ASSURANCE (fail-closed)', threw === 'E-ASSURANCE' && threw2 === 'E-ASSURANCE');

  // M1.1 — capability SUPPORT: a separate Boolean lattice (P(Caps), ⊆), single-sourced, |Caps| = 8
  check('M1.1 EVIDENCE_CAPS_UNIVERSE: |Caps| = 8, single-sourced from EVIDENCE_CAPS (support ≠ strength coordinate)', P.EVIDENCE_CAPS_UNIVERSE.length === 8 && ['pow-header-chain', 'transparency-log', 'authenticated-map', 'content-addressed', 'rfc3161-tsa'].every((k) => P.evidenceCaps(k).every((c) => P.EVIDENCE_CAPS_UNIVERSE.includes(c))));
  check('M1.1 support is ⊆-ordered, not a chain: transparency-log vs authenticated-map caps are incomparable sets', (() => { const a = P.evidenceCaps('transparency-log'), b = P.evidenceCaps('authenticated-map'); return !a.every((c) => b.includes(c)) && !b.every((c) => a.includes(c)); })());

  // ── C3/K3 — deriveAssurance: THE one assembler, takes ONLY a branded PredicateGraph. provePredicates maps seam
  //    verdicts → atoms; deriveAssurance projects. Strength from SEAM VERDICTS, support from image(VerifyEvidence_C).
  const DA = (v) => P.deriveAssurance(P.provePredicates(v));
  check('K3 deriveAssurance REJECTS a caller-shaped object (not a PredicateGraph) → E-ASSURANCE (round-3 P0-4 closed)',
    (r => r.error === 'E-ASSURANCE')(P.deriveAssurance({ identity: { status: 'verified', strength: 'authoritative' }, freshness: { result: 'VALID', keylog_freshness: 'attested' }, anchor: { inclusion: true, time: 'anchored' } })));
  check('K3 provePredicates output is a branded handle a caller cannot forge (isVerifiedHandle true; a look-alike false)',
    P.isVerifiedHandle('predicate-graph', P.provePredicates({})) === true && P.isVerifiedHandle('predicate-graph', { atoms: {}, support: [] }) === false);
  check('C3 a bare strength LABEL without a verified status earns nothing (no caller labels)',
    (r => r.strength.identity === 'self-asserted' && r.tier === 'LIGHT')(DA({ identity: { strength: 'authoritative' } })));
  check('C3 the identity seam verdict maps by fixed rules (authoritative/verified → authoritative)',
    (r => r.strength.identity === 'authoritative' && r.tier === 'HIGH')(DA({ identity: { strength: 'authoritative', status: 'verified' } })));
  check('C3 suspect status never name-binds (mirrors §14)',
    (r => r.strength.identity === 'self-asserted')(DA({ identity: { strength: 'authoritative', status: 'suspect' } })));
  check('C3 freshness rung only from a VALID freshness verdict, never a label',
    (() => { const lie = DA({ identity: { strength: 'corroborated', status: 'verified' }, freshness: { keylog_freshness: 'attested' } });
      const ok = DA({ identity: { strength: 'corroborated', status: 'verified' }, freshness: { result: 'VALID', keylog_freshness: 'attested' } });
      return lie.strength.freshness === 'unverified' && ok.strength.freshness === 'attested'; })());
  check('C3 anchored time requires inclusion === true AND time === anchored from the anchor seam',
    (() => { const no = DA({ identity: { strength: 'authoritative', status: 'verified' }, anchor: { inclusion: false, time: 'anchored' } });
      const yes = DA({ identity: { strength: 'authoritative', status: 'verified' }, anchor: { inclusion: true, time: 'anchored' } });
      return no.strength.time === 'unproven' && no.tier === 'HIGH' && yes.strength.time === 'anchored' && yes.tier === 'TOP'; })());
  check('C3 support: only image(VerifyEvidence_C) contributes capabilities — a minted look-alike contributes none (B3)',
    (r => r.support.length === 0)(DA({ identity: { strength: 'self-asserted', status: 'verified' }, evidence: [{ proof_kind: 'pow-header-chain', verified_facts: {}, basis: 'admitted-connector-receipt' }] })));
  check('C3 deriveAssurance output is frozen (pure value, no post-hoc mutation)',
    (() => { const r = DA({}); try { r.tier = 'TOP'; } catch {} try { r.strength.identity = 'authoritative'; } catch {} return r.tier !== 'TOP' && Object.isFrozen(r) && r.strength.identity === 'self-asserted'; })());

  // ── V1 (UST-sul, M1.2) — Reach_C CONFINEMENT: over the FULL verdict grid, the assembler emits ONLY tuples whose
  //    every coordinate is earned by ITS OWN seam predicate — and each coordinate is a function of ITS verdict alone
  //    (changing another verdict never moves it). This is the evidence→assurance transition the rc.35 "256 abstract
  //    combinations" check never exercised.
  {
    const ids = [undefined, { strength: 'authoritative' }, { strength: 'authoritative', status: 'verified' },
      { strength: 'authoritative', status: 'suspect' }, { strength: 'corroborated', status: 'verified' },
      { strength: 'pinned', status: 'verified' }, { strength: 'self-asserted', status: 'verified' },
      { strength: 'consumer-override', status: 'verified' }, { strength: 'corroborated', status: 'unavailable' },
      { strength: 'corroborated', status: 'verified', freshness: 'fresh' }, { strength: 'authoritative', status: 'verified', freshness: 'fresh' }];
    const frs = [undefined, { result: 'VALID', keylog_freshness: 'corroborated' }, { result: 'VALID', keylog_freshness: 'attested' },
      { result: 'INDETERMINATE', keylog_freshness: 'corroborated' }, { keylog_freshness: 'attested' }, { result: 'VALID', keylog_freshness: 'unverified' }];
    const ans = [undefined, { inclusion: true, time: 'anchored' }, { inclusion: false, time: 'anchored' }, { inclusion: true, time: 'unproven' }];
    // the INDEPENDENT per-coordinate rules (restated here, not shared with the implementation)
    const expId = (id) => id?.status !== 'verified' ? 'self-asserted' : ['authoritative', 'corroborated', 'pinned'].includes(id.strength) ? (id.strength === 'authoritative' ? 'authoritative' : id.strength) : 'self-asserted';
    const expFr = (fr, id) => (fr?.result === 'VALID' && ['corroborated', 'attested'].includes(fr.keylog_freshness)) ? fr.keylog_freshness : (id?.freshness === 'fresh' ? 'fresh' : 'unverified');
    const expTm = (an) => an?.inclusion === true && an?.time === 'anchored' ? 'anchored' : 'unproven';
    let confined = true, coordinateLocal = true;
    for (const id of ids) for (const fr of frs) for (const an of ans) {
      const r = P.deriveAssurance(P.provePredicates({ identity: id, freshness: fr, anchor: an }));
      if (r.strength.identity !== expId(id) || r.strength.freshness !== expFr(fr, id) || r.strength.time !== expTm(an) || r.strength.integrity !== 'valid') confined = false;
      if (r.tier !== P.projectTier(r.strength)) confined = false;                       // the report never carries a tier its own strength does not project
    }
    for (const id of ids) {                                                             // identity is a function of the identity verdict ALONE
      const base = P.deriveAssurance(P.provePredicates({ identity: id })).strength.identity;
      for (const fr of frs) for (const an of ans) if (P.deriveAssurance(P.provePredicates({ identity: id, freshness: fr, anchor: an })).strength.identity !== base) coordinateLocal = false;
    }
    check('V1 Reach_C confinement: 264-combination verdict grid — every coordinate earned by its own predicate, tier = projection', confined);
    check('V1 Reach_C per-coordinate locality: a coordinate is a function of ITS verdict alone (no cross-coordinate lift)', coordinateLocal);
  }
}

// ─── #39 negative / absence observation — the notary's other half ──────────────────────────────────────
{
  const abs = P.seal(P.buildAbsence({ ...ID, ust_id: 'ust:20260628.1401' }, T, 'noaa_swpc', 'unreachable', { subject: 'GOES-18' }), A.priv, A.pubB64);
  check('#39 buildAbsence → VALID:LIGHT', P.verify(abs, { context: 'data' }).result === 'VALID:LIGHT');
  check('#39 absence is machine-distinguishable (kind + reason)', abs.state.data.noaa_swpc.kind === 'absence' && abs.state.data.noaa_swpc.value.reason === 'unreachable');
  check('#39 captured ≠ absence (a normal reading is not a negative)', mk().state.data.sw.kind === 'captured');
  const noReason = P.seal(P.buildState({ ...ID, ust_id: 'ust:20260628.1402' }, T, { x: { kind: 'absence', value: {} } }), A.priv, A.pubB64);
  check('#39 public absence WITHOUT reason → E-MALFORMED', P.verify(noReason, { context: 'data' }).error === 'E-MALFORMED');
  const window = { from: 'ust:20260628.10', to: 'ust:20260628.12' };
  const cover = { from: 'ust:20260628.10', to: 'ust:20260628.13' };   // interval as verifyStream RETURNS it (verified)
  const observedFrames = [{ state: { id: { ust_id: 'ust:20260628.10' }, data: { q: { kind: 'captured', value: { v: '1' } } } } }, { state: { id: { ust_id: 'ust:20260628.11' }, data: { q: { kind: 'captured', value: { v: '2' } } } } }];
  const blindFrames = [{ state: { id: { ust_id: 'ust:20260628.11' }, data: { q: { kind: 'absence', value: { reason: 'unreachable' } } } } }];   // publisher blind at a covered slot
  check('#39 complete + observed frames ⇒ completeness-backed', P.noEventBacking(window, { complete: 'complete', interval: cover }, observedFrames) === 'completeness-backed');
  check('#39 complete + BLIND (unreachable) covered slot ⇒ observation-gap (self-audit #2: blind ≠ no-event)', P.noEventBacking(window, { complete: 'complete', interval: cover }, blindFrames) === 'observation-gap');
  check('#39 complete but NO frames ⇒ observation-unchecked (cannot confirm observation)', P.noEventBacking(window, { complete: 'complete', interval: cover }) === 'observation-unchecked');
  check('#39 chain-consistent covering interval ⇒ no-deletion-only (omission still possible)', P.noEventBacking(window, { complete: 'chain-consistent', interval: cover }, observedFrames) === 'no-deletion-only');
  check('#39 provisional stream ⇒ publisher-asserted', P.noEventBacking(window, { complete: 'provisional', interval: cover }, observedFrames) === 'publisher-asserted');
  check('#39 verified interval does NOT contain the window ⇒ publisher-asserted', P.noEventBacking(window, { complete: 'complete', interval: { from: 'ust:20260628.10', to: 'ust:20260628.11' } }, observedFrames) === 'publisher-asserted');
  check('#39 completeness WITHOUT a verified interval ⇒ publisher-asserted (no spoofable checkpoint)', P.noEventBacking(window, { complete: 'complete' }, observedFrames) === 'publisher-asserted');
  check('#39 no window ⇒ not-applicable', P.noEventBacking({}, { complete: 'complete', interval: cover }, observedFrames) === 'not-applicable');
}

console.log('  ust-protocol ' + P.VERSION.spec + ' conformance vs ' + V.version);
console.log('  PASS ' + pass + '   FAIL ' + fail + '   NOTES ' + note);
if (fails.length) { console.log('\n  FAILURES:'); fails.forEach(f => console.log('    ✗ ' + f)); }
else console.log('  ✓ all exercised checks pass (primitives + 6 findings + Gemini-B + HIGH + TOP)');
process.exit(fail ? 1 : 0);                                              // fail-closed for CI / `npm test`
