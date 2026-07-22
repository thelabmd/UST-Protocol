// SPDX-License-Identifier: Apache-2.0
// Conformance runner (rc.2): every primitive vector + every negative class verified against ust-protocol.
// Negatives are CONSTRUCTED from the live impl (not skipped), so this is a real pass/fail. HIGH/TOP built inline.
import * as P from './index.mjs';
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createHash, sign } from 'node:crypto';
import { __setWitnessClockForConformance, witnessNow } from './_clock.mjs';   // rev33/36 R4 — the witness clock is verifier-owned in an INTERNAL module; the harness drives it deterministically HERE (not through public opts), then restores
const withWitnessClock = async (clock, body) => { __setWitnessClockForConformance(clock); try { return await body(); } finally { __setWitnessClockForConformance(); } };
// round-51 (owner sweep: eliminate drift-prone hand-lists) — the R47 roster's MAY-THROW exemption was a SECOND hand-list beside
// the R31 CLASS map (surface|exempt). They agreed, but nothing LOCKED them: a future drift could exempt a real surface from the
// runtime-namespace totality net. Define it ONCE here (used by R47) and cross-check it below against CLASS — MAY_THROW(n) ⟺
// CLASS[n] !== 'surface', so the two can no longer diverge. (Totality itself is already guaranteed by R34's surface×BATTERY.)
const MAY_THROW_TOTALITY = (n) => /^(build|seal|make)/.test(n) || /(Claim|Leaf|Id|Epoch)$/.test(n) || /^Ust[A-Z]/.test(n)
  || ['canon', 'H', 'Hbytes', 'keyId', 'merkleRoot', 'partitionHash', 'contentHash', 'signedContent', 'admitUtf8', 'anyLoneSurrogate', 'ustGrid', 'blindPartition', 'blindedCommit', 'seed', 'axisRank', 'evidenceCaps', 'admitDeep', 'isValid', 'verifiedEvidence'].includes(n)
  || ['verifyOrThrow', 'assertValid'].includes(n);

const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url)));
function kp(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubRaw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32);
  return { priv, pubB64: pubRaw.toString('base64url'), key_id: P.keyId(pubRaw.toString('base64url')) };
}
const A = kp(V.seeds.A);
const T = { generated_at: '2026-06-28T14:03:12Z', valid_from: '2026-06-28T14:00:00Z', valid_to: '2026-06-28T15:00:00Z' };
const ID = { domain_shard: A.key_id, ust_id: 'ust:20260628.14', key_id: A.key_id, class: 'observation' };   // round-53 — key-form (= key_id): a self-asserted LIGHT doc identifies by its KEY, not a name-form domain claim (UST-ybn); name-form requires HIGH binding
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

let pass = 0, fail = 0, note = 0; const fails = []; const executed = [];
const check = (id, ok, d) => { executed.push(id); if (ok) pass++; else { fail++; fails.push(id + (d ? ' — ' + d : '')); } };   // round-28 P1-03 — record EVERY executed check id for the executed-manifest the lockstep gate consumes (not source-substring)
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
// G1 — round-53 (UST-ybn): the `pinned`/TOFU rung was REMOVED; LIGHT identity = the KEY (key-form domain_shard = key_id).
check('G1 key-form self-asserted → VALID:LIGHT (identity = key, no domain claim, publisher undefined)', (r => r.result === 'VALID:LIGHT' && r.identity.strength === 'self-asserted' && r.publisher === undefined)(P.verify(mk(), { context: 'data' })));
check('G1 name-form domain_shard, no binding → INDETERMINATE (cannot confirm the domain — unified rule)', (r => r.result === 'INDETERMINATE' && r.reason === 'unavailable')(P.verify(mk({ r: { kind: 'captured', value: { x: '1' } } }, { domain_shard: 'helioradar.com', ust_id: 'ust:20260628.14', key_id: A.key_id, class: 'observation' }), { context: 'data' })));

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
  const un = P.verify({ ...docK, proof: topProof }, { genesis: gen, keylog: [add], noForkConfirmed: true, acceptConsumerOverride: true, context: 'data', substrateVerify: () => null });
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
  check('key-form shard → identity.mode key (round-53: mk is key-form; a name-form doc without binding is INDETERMINATE)', P.verify(mk(), { context: 'data' }).identity.mode === 'key');
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
  const d65n = mkN(65, { domain_shard: 'helioradar.com', ust_id: 'ust:20260628.14', key_id: A.key_id, class: 'observation' });
  const r65n = P.verify(d65n, { context: 'data' }), c65n = await cleanRoom(d65n, { context: 'data' });
  check('ladder: 65 name-form NO binding → INDETERMINATE(unavailable) in BOTH (cannot confirm the domain — round-53 UST-ybn)', r65n.result === 'INDETERMINATE' && r65n.reason === 'unavailable' && c65n.result === 'INDETERMINATE' && c65n.reason === 'unavailable');
  const d65k = mkN(65, { domain_shard: A.key_id, ust_id: 'ust:20260628.15', key_id: A.key_id, class: 'observation' });
  check('ladder: 65 KEY-form → E-BOUNDS (no ceremony can exist)', P.verify(d65k, { context: 'data' }).error === 'E-BOUNDS' && (await cleanRoom(d65k, { context: 'data' })).error === 'E-BOUNDS');
  const genCap = (mp, mb) => P.seal(P.buildGenesis({ domain_shard: ID.domain_shard, ust_id: 'ust:20260628.01', key_id: A.key_id }, T, A.pubB64, mp, mb), A.priv, A.pubB64);
  // rc.12 P0-4: capacity = TRUSTED GRANT via opts.capacity; a raw self-signed genesis is a
  // self-issued budget and NO LONGER expands anything.
  // round-53 (UST-ybn): capacity > 64 is a HIGH-only feature — only a genesis (name-form, name-bound) can DECLARE a larger
  // capacity; a bare key (key-form LIGHT floor) is capped at 64 and cannot declare more (E-BOUNDS). So >64 ⇒ HIGH, never LIGHT.
  check('grant: 65 key-form (LIGHT floor) → E-BOUNDS (a bare key cannot declare capacity > 64)', P.verify(d65, { context: 'data', capacity: { maxPartitions: 128 } }).error === 'E-BOUNDS');
  check('grant: 65 + capacity{64} → E-BOUNDS (over granted)', P.verify(d65, { context: 'data', capacity: { maxPartitions: 64 } }).error === 'E-BOUNDS');
  const d1000 = mkN(1000);
  check('grant: 1000 partitions key-form → E-BOUNDS (capacity > floor is HIGH-only; a bare key is capped at 64 — round-53)', P.verify(d1000, { context: 'data', capacity: { maxPartitions: 1024 } }).error === 'E-BOUNDS');
  check('P0-4: a raw self-signed genesis does NOT expand a key-form doc → E-BOUNDS (capacity is HIGH-only; a bare key is capped at 64 — round-53)', P.verify(d65, { context: 'data', genesis: genCap(128) }).error === 'E-BOUNDS');
  const gcap = genCap(512, 4_000_000);
  const auth = P.resolveAuthority(mk(), { genesis: gcap, keylog: [], ...nfe(gcap) });
  check('resolveAuthority surfaces the ceremony capacity (grant flows FROM resolution)', auth.capacity?.maxPartitions === 512 && auth.capacity?.maxTranscriptBytes === 4_000_000 && auth.strength === 'authoritative');
  const fake4097 = { state: { data: Object.fromEntries(Array.from({ length: 4097 }, (_, i) => ['p' + i, '1'])) } };
  check('ABS: 4097 partitions → structural E-BOUNDS precheck', P.checkBounds(fake4097) === 'partitions > 4096');
  let guardThrew = false; try { P.buildState(ID, T, Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['p' + i, { kind: 'captured', value: { x: '1' } }]))); } catch (e) { guardThrew = e.code === 'E-BOUNDS'; }
  check('producer guard: buildState 65 without {maxPartitions} THROWS E-BOUNDS', guardThrew);
  // ─── §13 SIZE ladder (rc.11): floor 1 MiB · genesis-declared ≤ 64 MiB · pre-parse INDETERMINATE ───
  const bigVal = 'x'.repeat(1_200_000);
  const mkBig = (id = { domain_shard: 'helioradar.com', ust_id: 'ust:20260628.16', key_id: A.key_id, class: 'observation' }, opts = { maxTranscriptBytes: 4_000_000 }) =>   // round-53 — name-form: exercises the name-form → INDETERMINATE path
    P.seal(P.buildState(id, T, { blob: { kind: 'captured', value: { x: bigVal } } }, undefined, opts), A.priv, A.pubB64);
  const dBig = mkBig();
  const rBigNo = P.verify(dBig, { context: 'data' });
  check('size: >floor name-form NO grant → INDETERMINATE(unavailable)', rBigNo.result === 'INDETERMINATE' && rBigNo.reason === 'unavailable');
  const cBigNo = await cleanRoom(dBig, { context: 'data' });
  check('size parity: clean-room >floor name-form → INDETERMINATE', cBigNo.result === 'INDETERMINATE');
  check('size: >floor name-form + capacity grant → still INDETERMINATE (name unbound; capacity is HIGH-only — round-53)', P.verify(dBig, { context: 'data', capacity: { maxTranscriptBytes: 4_000_000 } }).result === 'INDETERMINATE');
  const dBigK = mkBig({ domain_shard: A.key_id, ust_id: 'ust:20260628.16', key_id: A.key_id, class: 'observation' });
  check('size: >floor KEY-form → E-BOUNDS (no ceremony can exist)', P.verify(dBigK, { context: 'data' }).error === 'E-BOUNDS');
  // rc.12 P0-1: UTF-8 vs UTF-16 parity — Cyrillic doc (700k units = 1.4M bytes) must agree in BOTH
  const cyr = P.seal(P.buildState({ domain_shard: 'helioradar.com', ust_id: 'ust:20260628.17', key_id: A.key_id, class: 'observation' }, T, { txt: { kind: 'captured', value: { body: 'ж'.repeat(700_000) } } }, undefined, { maxTranscriptBytes: 4_000_000 }), A.priv, A.pubB64);
  const rCyr = P.verify(cyr, { context: 'data' }), cCyr = await cleanRoom(cyr, { context: 'data' });
  check('P0-1 pinned: Cyrillic 1.4 MB UTF-8 — SAME verdict in both verifiers (UTF-8 metric)', rCyr.result === 'INDETERMINATE' && cCyr.result === 'INDETERMINATE');
  // rc.12 P0-3: formatting can never flip a verdict — pretty-printed raw > floor, canonical ≤ floor ⇒ VALID
  const small = mk();
  const pretty = JSON.stringify(small, null, 8) + ' '.repeat(1_200_000);
  check('P0-3 pinned: transport whitespace never flips the verdict (canonical metric)', P.verifyJson(pretty, { context: 'data' }).result === 'VALID:LIGHT');
  // rc.12 P0-2/P1-7: transport admission is resource_limit, decided on BYTES before decode
  const rTrans = P.verifyJson(Buffer.alloc(67_108_865, 120));
  check('transport: over-budget Buffer → INDETERMINATE(resource_limit) BEFORE decode', rTrans.result === 'INDETERMINATE' && rTrans.reason === 'resource_limit');
  // round-49 P1-02 — the transport measurement is read through the INTRINSIC byteLength (snapshotBinary), not a caller-overridable
  // property: a Uint8Array SUBCLASS whose own `byteLength` getter reports 1 (intrinsic 2008) must NOT bypass maxInputBytes.
  const forgedLen = (() => { class Evil extends Uint8Array { get byteLength() { return 1; } }; const e = new Evil(2008); return P.verifyJson(e, { maxInputBytes: 64 }); })();
  check('round-49 P1-02: a Uint8Array subclass with a forged byteLength getter cannot bypass the transport budget — measured by the intrinsic snapshot (resource_limit on the REAL 2008 B, not the forged 1 B)', forgedLen.result === 'INDETERMINATE' && forgedLen.reason === 'resource_limit');
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
  check('ssrf PORTABLE LEXICAL floor: isPublicDnsShard rejects each of these ' + priv.length + ' IP-literal/localhost/internal/port/path forms (the browser-safe floor; the Node resolve-time guard + IPv4-mapped-IPv6 normalization is covered separately in ssrf.test.mjs — round-49 P1-03: this label is the lexical list, not the full guard)', priv.every((s) => !P.isPublicDnsShard(s)));

  // resolveByDiscovery: an internal-address document NEVER makes a network call (fetchImpl asserts none)
  let touched = 0;
  const spyFetch = async () => { touched++; return { ok: false, status: 0, text: async () => '' }; };
  const evilId = { ...ID, domain_shard: '169.254.169.254', ust_id: 'ust:20260628.15' };
  const evil = P.seal(P.buildState(evilId, T, { p: { kind: 'captured', value: { x: '1' } } }), A.priv, A.pubB64);
  const r1 = await P.resolveByDiscovery(evil, { context: 'data' }, { fetchImpl: spyFetch });
  check('resolveByDiscovery: a document whose domain_shard is a literal internal IP (169.254.169.254) is SKIPPED — no fetch attempted (round-49 P1-03: one representative internal-literal case; the full resolve-time private-address refusal is exercised in ssrf.test.mjs)', touched === 0 && !!r1.resolution?.skipped);

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
  // round-18 P0-02 — the witness genesisAnchored path uses the SAME closed substrate decoder as verifyAnchor: an untyped
  // receipt {final:"yes"} (no real time) can no longer confirm the served genesis → NOT corroborated (F.5.0/C3, one core).
  const r18p02 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: () => ({ final: 'yes' }) });
  check('round-18 P0-02 untyped witness substrate {final:"yes"} → witness NOT confirmed (no served-list corroboration)', r18p02.verdict.no_fork !== 'served-list');
  // round-26 P1-03 / L4 (rev27 E) — F.9 ρ_v.time belongs to the verifier THROUGH the public entry: resolveByDiscovery
  //   now threads the consumer's maxWitnessOpMs into witnessNoFork (rev23 wired it only at the leaf → unreachable). A
  //   tight budget + a never-settling substrate resource-limits the witness (two canon-distinct anchors: the whole-op
  //   deadline trips on the 2nd leaf, deterministic), so the tier does NOT upgrade to a served-list HIGH after the budget.
  const leafRoot = P.Hbytes('ust:leaf', Buffer.from(gHash, 'utf8'));
  // rev33 R4 — deterministic budget exhaustion driven by the VERIFIER-OWNED clock (set via the internal _clock module,
  //   NOT a public opts field): consulting the leaf's substrate advances the module clock past the whole-op deadline, so
  //   the tier does NOT upgrade to served-list HIGH after the budget. No timer race; no caller-writable time surface.
  let bSpent = false; const bNow = () => (bSpent ? 1_000_000 : 1000); const bSV = () => { bSpent = true; return { final: false }; };
  const budgetAnchors = [{ root: leafRoot, path: [], anchor: { substrate: 'bitcoin-ots', block_height: 900001 } }];
  const budgetLog = wlog([{ content_hash: gHash, superseded_by: null, anchors: budgetAnchors }], gHash);
  const rBudget = await withWitnessClock(bNow, () => P.resolveByDiscovery(doc, { context: 'data', maxWitnessOpMs: 50 }, { fetchImpl: mk(budgetLog), substrateVerify: bSV }));
  check('round-26 P1-03/L4 resolveByDiscovery THREADS the consumer witness budget (maxWitnessOpMs) through the PUBLIC entry → a tight budget resource-limits the witness, no false served-list HIGH (F.9 ρ_v)',
    rBudget.verdict.no_fork !== 'served-list');
  // rev33 R4 (round-29 P0-02) — the clock is NOT caller-writable: a hostile non-monotonic `__nowMs` passed in the PUBLIC
  //   opts is DEAD (never read), so it cannot expand the leaf timeout and mint a served-list HIGH. Same document, same
  //   tight budget, an adversarial clock in opts → the SAME resource-limited verdict as without it.
  let eSpent = false; const eNow = () => (eSpent ? 1_000_000 : 1000); const eSV = () => { eSpent = true; return { final: false }; };
  let ecalls = 0; const evilClock = () => { ecalls++; return ecalls === 1 ? 1000 : 0; };   // non-monotonic: would REWIND the deadline to grant the slow connector time — IF it were read
  const rEvil = await withWitnessClock(eNow, () => P.resolveByDiscovery(doc, { context: 'data', maxWitnessOpMs: 50, __nowMs: evilClock }, { fetchImpl: mk(budgetLog), substrateVerify: eSV }));
  check('R4 CLOCK-OWNED: a hostile __nowMs in public opts is DEAD (never read) — it cannot expand the witness budget or flip resource_limit into a served-list HIGH (round-29 P0-02; ρ_v belongs to the verifier)',
    ecalls === 0 && rEvil.verdict.no_fork !== 'served-list');
  // rev36 R4 (round-30 P1-01) — the witness budget is measured against a MONOTONIC ELAPSED source (performance.now), not a
  //   wall clock behind a non-decreasing wrapper. The rev33 wrapper FROZE on a backward step and DISABLED the whole-op
  //   budget; performance.now cannot go backward (immune to NTP/wall-clock correction), so it needs no wrapper and cannot
  //   freeze. Assert the production clock (no injection) is non-decreasing across many reads.
  { __setWitnessClockForConformance(); let prev = -Infinity, monotone = true; for (let i = 0; i < 2000; i++) { const t = witnessNow(); if (typeof t !== 'number' || t < prev) monotone = false; prev = t; }
    check('R4 MONOTONIC: the witness budget clock is a monotonic ELAPSED source (performance.now), non-decreasing across reads — a wall-clock/NTP rollback cannot rewind the deadline and disable the whole-op budget (round-30 P1-01; not a wall clock with a wrapper)', monotone); }
  // round-18 P0-01 — forkChoice returns the IMMUTABLE snapshot: a live mutation during the substrate await cannot make the returned canonical object differ from its proven content_hash (F.5c: canonical = the dᵢ with content_hash(dᵢ) ∈ F_t). Genesis-key-signed doc ⇒ authoritative with no key-log.
  const gkDoc = P.seal(P.buildState({ domain_shard: 'wit-test.example', ust_id: 'ust:20260713.150000', key_id: rootW.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { v: 'A' } } }), rootW.priv, rootW.pubB64);
  const fcCand = { ...gkDoc, proof: anchorOf(P.contentHash(gkDoc)) };
  const mutSub = async () => { fcCand.state = { ...fcCand.state, data: { r: { kind: 'captured', value: { v: 'SWAP' } } } }; return { final: true, time: '2026-07-13T14:05:00Z' }; };
  const fc = await P.forkChoice([fcCand], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: mutSub });
  check('round-18 P0-01 forkChoice canonical object == its proven content_hash (immutable snapshot)', fc.result === 'CANONICAL' && P.contentHash(fc.canonical) === fc.content_hash);
  // round-18 P0-03 — an oversize (present-but-unreadable) key-log body → INDETERMINATE(resource_limit), NEVER keylog=[] (which would erase a real retirement and false-accept). F.9.
  const bigKl = '[' + '"' + '0'.repeat(9 << 20) + '"' + ']';   // > the 8 MiB KEYLOG_MAX_BYTES budget
  const mkBig = async (u) => { u = String(u); if (u.endsWith('/.well-known/ust-genesis')) return { ok: true, text: async () => JSON.stringify(gen) }; if (u.endsWith('/.well-known/ust-keylog')) return { ok: true, text: async () => bigKl }; return { ok: false, status: 404, text: async () => '' }; };
  const rBig = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: mkBig });
  check('round-18 P0-03 oversize key-log → resource_limit INDETERMINATE, never keylog=[] (no false HIGH)', rBig.verdict.result !== 'VALID:HIGH' && /resource_limit|E-RESOURCE/.test(JSON.stringify(rBig.resolution || {})));
  // round-18 P1-01 — null options/transport are TOTAL on the exported resolvers (a default param only catches undefined).
  let p1ok = true; try { await P.verifyAsync(doc, null); await P.resolveByDiscovery(doc, null); await P.resolveByDiscovery(doc, {}, null); P.resolveAuthority(doc, null); P.verifyAnchor(P.contentHash(doc), { root: 'x', path: [] }, null); } catch { p1ok = false; }
  check('round-18 P1-01 null options/transport (5 exports) → no host throw (total)', p1ok);
  // round-18 P1-02 — invalid UTF-8 in a discovery body is REJECTED, never replacement-decoded to U+FFFD (I4/M-BYTE).
  const badMk = async () => ({ ok: true, headers: { get: () => null }, body: { getReader: () => { let s = false; return { read: async () => (s ? { done: true } : (s = true, { done: false, value: new Uint8Array([0x7b, 0xff, 0x7d]) })), cancel: async () => {} }; } } });
  const rBad = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: badMk });
  check('round-18 P1-02 invalid-UTF-8 discovery body → rejected (no U+FFFD replacement)', rBad.verdict.result !== 'VALID:HIGH' && /UTF-8|fetch failed/.test(JSON.stringify(rBad.resolution || {})));

  // ─── round-19 (rev16) — narrower structural/domain bypasses of the rev15 remediations ───────────────────────────
  // P0-01 — forkChoice SNAPSHOTS every candidate BEFORE any read; a snapshot failure is E-MALFORMED, NEVER a live-object
  // fallback, and the ust_id grouping reads the snapshot (not a lying accessor). (F.5c: canonical = the dᵢ with hash ∈ F_t.)
  const c19 = { ...gkDoc, proof: anchorOf(P.contentHash(gkDoc)) };
  const thrower = { ...c19 }; Object.defineProperty(thrower, 'toJSON', { enumerable: false, configurable: true, value() { throw new Error('one-shot clone fail'); } });
  let r19SubCalled = false;
  const r19a = await P.forkChoice([thrower], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: () => { r19SubCalled = true; return { final: true, time: '2026-07-13T14:05:00Z' }; } });
  check('round-19 P0-01 forkChoice throwing-toJSON candidate → E-MALFORMED, substrate NEVER called (no live-object fallback)', r19a.result === 'E-MALFORMED' && r19SubCalled === false);
  const slotCand = { ...c19, state: { ...c19.state, id: { ...c19.state.id } } }; const realSlot = c19.state.id.ust_id; let slotReads = 0;
  Object.defineProperty(slotCand.state.id, 'ust_id', { enumerable: true, configurable: true, get() { slotReads++; return slotReads === 1 ? 'ust:20990101.000000' : realSlot; } });
  const r19b = await P.forkChoice([slotCand], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: async () => ({ final: true, time: '2026-07-13T14:05:00Z' }) });
  check('round-19 P0-01 forkChoice ust_id accessor lies once → NOT canonical (snapshot froze the first read)', r19b.result !== 'CANONICAL');
  // P0-02 — the substrate seam is a CLOSED TYPED verdict decoded from OWN data: a prototype look-alike earns nothing;
  // and (contra "reject extra fields") a legitimate `assurance` on a plain receipt SURVIVES.
  const protoReceipt = Object.create({ final: true, time: '2026-07-13T14:05:00Z' });
  const r19p02 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: () => protoReceipt });
  check('round-19 P0-02 prototype look-alike substrate → witness NOT confirmed (own-data only, F.5.0/C3)', r19p02.verdict.no_fork !== 'served-list');
  const r19asr = P.verifyAnchor(P.contentHash(gkDoc), anchorOf(P.contentHash(gkDoc)), { substrateVerify: () => ({ final: true, time: '2026-07-13T14:05:00Z', assurance: 'explorer-corroborated' }) });
  check('round-19 P0-02 legit plain receipt + assurance → anchored, assurance PRESERVED (closed-ADT ≠ reject-extra-fields)', r19asr.time === 'anchored' && r19asr.assurance === 'explorer-corroborated');
  const r19acc = P.verifyAnchor(P.contentHash(gkDoc), anchorOf(P.contentHash(gkDoc)), { substrateVerify: () => ({ get final() { return true; }, time: '2026-07-13T14:05:00Z' }) });
  check('round-19 P0-02 accessor `final` getter → earns nothing (unproven, not anchored)', r19acc.time === 'unproven');
  // P1-01 — discovery has ONE Unicode domain with the byte checker: a leading BOM (byte boundary) and a lone surrogate
  // (parsed tree) no longer upgrade a document.
  const bomBytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(gen), 'utf8')]);
  const bomMk = async (u) => { u = String(u); if (u.endsWith('/.well-known/ust-genesis')) return { ok: true, headers: { get: () => null }, body: { getReader() { let s = false; return { read: async () => s ? { done: true } : (s = true, { done: false, value: new Uint8Array(bomBytes) }), cancel: async () => {} }; } } }; if (u.endsWith('/.well-known/ust-witness')) return { ok: true, text: async () => JSON.stringify(okLog) }; return { ok: false, status: 404, text: async () => '' }; };
  const rBom = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: bomMk, substrateVerify: final });
  check('round-19 P1-01 discovery genesis with a leading UTF-8 BOM → NOT upgraded (rejected, byte-checker domain)', rBom.verdict.result !== 'VALID:HIGH' && /BOM/.test(JSON.stringify(rBom.resolution || {})));
  check('round-19 P1-01 verifyJson BOM bytes → E-CANON (same domain as the byte checker E-BOM)', P.verifyJson(new Uint8Array(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(doc), 'utf8')]))).error === 'E-CANON');
  check('round-19 P1-01 verifyJson lone-surrogate escape → E-CANON (not a Unicode scalar)', P.verifyJson('{"ust":"1.0","state":{"x":"\\ud800"}}').error === 'E-CANON');
  // P1-02 — DEFENSIVE boundary totality (hardening; the §14 math domain is BYTES). A hostile accessor/Proxy arg on any
  // exported boundary maps to a structured E-MALFORMED, never a host throw.
  const hostile = () => new Proxy({}, { get() { throw new Error('h'); }, ownKeys() { throw new Error('h'); }, getOwnPropertyDescriptor() { throw new Error('h'); } });
  const arrH = new Proxy([], { get(t, k) { if (k === 'length') throw new Error('h'); return t[k]; } });
  let p19ok = false, p19throw = false;
  try {
    const a1 = P.resolveAuthority(doc, hostile()); const a2 = P.resolveKeys(gen, arrH); const a3 = await P.forkChoice([hostile()], {}); const a4 = await P.verifyAsync(doc, hostile()); const a5 = await P.resolveByDiscovery(doc, {}, hostile());
    p19ok = a1.error === 'E-MALFORMED' && a2.error === 'E-MALFORMED' && a3.result === 'E-MALFORMED' && a4.result === 'E-MALFORMED' && a5.verdict.result === 'E-MALFORMED';
  } catch { p19throw = true; }
  check('round-19 P1-02 hostile accessor/Proxy args (5 boundaries) → structured E-MALFORMED, never a host throw', p19ok && !p19throw);
  // P0-2 — a raw air-gap assertion is NOT independent evidence: it is a `consumer-override`. It reaches the name-
  // authoritative TIER only when the consumer CONSCIOUSLY honors it (acceptConsumerOverride), and the verdict stays
  // transparent (independently_verified:false) — it never silently claims independent `authoritative`.
  const r1b = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true, acceptConsumerOverride: true }, { fetchImpl: mk(okLog), substrateVerify: final });
  check('caller air-gap override (honored) → HIGH, strength consumer-override + not independently verified (#69 B / P0-2)', r1b.verdict.result === 'VALID:HIGH' && r1b.verdict.identity.strength === 'consumer-override' && r1b.verdict.identity.independently_verified === false && r1b.verdict.publisher === 'wit-test.example');
  // and WITHOUT the conscious opt-in, the raw override never earns authority — the overclaim is closed.
  const r1c = await P.resolveByDiscovery(doc, { context: 'data', noForkConfirmed: true }, { fetchImpl: mk(null), substrateVerify: final });
  check('P0-2: raw noForkConfirmed alone on a name-form doc without binding → INDETERMINATE (cannot confirm the domain; a raw override earns no authority — round-53 UST-ybn unified rule)', r1c.verdict.result === 'INDETERMINATE' && r1c.verdict.reason === 'unavailable');

  const r2 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(null), substrateVerify: final });
  check('witness unreachable on a name-form doc → INDETERMINATE (cannot confirm the domain; never forged — round-53 UST-ybn)', r2.verdict.result === 'INDETERMINATE' && r2.verdict.reason === 'unavailable');

  const forkLog = wlog([{ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) }, { content_hash: 'sha256:' + 'ab'.repeat(32), superseded_by: null, anchor: anchorOf('sha256:' + 'ab'.repeat(32)) }], gHash);
  const r3 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(forkLog), substrateVerify: final });
  check('two anchored active genesis = fork = E-GENESIS', r3.verdict.result === 'INVALID' && r3.verdict.error === 'E-GENESIS');

  // ─── round-20 (rev17) — resolver/discovery integration bypasses of the rev16 fixes ──────────────────────────────
  // P0-01 — the witness is AUTHORITY input, so it crosses the SAME raw-byte duplicate-member boundary as genesis/key-log.
  // A duplicate `genesis_log` collapses under JS last-wins parsing; a fork-bearing occurrence hidden behind an innocent
  // one must NOT earn `corroborated` (model: corroborated = "exactly one active anchored binding"; I4 byte determinism).
  const fMember = JSON.stringify({ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) });
  const rivalM = JSON.stringify({ content_hash: 'sha256:' + 'cd'.repeat(32), superseded_by: null, anchor: anchorOf('sha256:' + 'cd'.repeat(32)) });
  const dupWitnessRaw = `{"domain_shard":"wit-test.example","genesis_log":[${fMember},${rivalM}],"genesis_log":[${fMember}]}`;   // two genesis_log members: first has a rival, second is clean
  const mkDup = async (u) => { u = String(u); if (u.endsWith('/.well-known/ust-genesis')) return { ok: true, text: async () => JSON.stringify(gen) }; if (u.endsWith('/.well-known/ust-witness')) return { ok: true, text: async () => dupWitnessRaw }; return { ok: false, status: 404, text: async () => '' }; };
  const r20a = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mkDup, substrateVerify: final });
  check('round-20 P0-01 duplicate genesis_log in witness → NOT corroborated (raw dup-key boundary; a hidden fork cannot earn HIGH)', r20a.verdict.result !== 'VALID:HIGH' && r20a.verdict.identity?.strength !== 'corroborated');
  // P1-01 — a normal JSON-parsed opts whose sole own key is "__proto__" must NOT install inherited authority config.
  const protoOpts = JSON.parse('{"__proto__":{"noForkConfirmed":true,"acceptConsumerOverride":true}}');
  const r20b = P.resolveAuthority(doc, protoOpts);
  check('round-20 P1-01 JSON __proto__ opts → inherited config NOT admitted (null-proto admission; ℐ_C own-field only)', r20b.strength !== 'authoritative' && r20b.strength !== 'corroborated' && r20b.strength !== 'consumer-override');
  // P1-02 — a witness with more distinct active roots than the F.9 structural budget is refused BEFORE any connector
  // fan-out (resource_limit), never a HIGH — a body under the byte ceiling cannot amplify into unbounded substrate calls.
  const manyRoots = Array.from({ length: 40 }, (_, i) => ({ content_hash: 'sha256:' + String(i).padStart(64, '0'), superseded_by: null, anchor: anchorOf('sha256:' + String(i).padStart(64, '0')) }));
  const mkMany = async (u) => { u = String(u); if (u.endsWith('/.well-known/ust-genesis')) return { ok: true, text: async () => JSON.stringify(gen) }; if (u.endsWith('/.well-known/ust-witness')) return { ok: true, text: async () => JSON.stringify({ domain_shard: 'wit-test.example', genesis_log: manyRoots }) }; return { ok: false, status: 404, text: async () => '' }; };
  let fanCalls = 0; const countSub = async (a, r) => { fanCalls++; return { final: true, time: '2026-07-13T14:05:00Z' }; };
  const r20c = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mkMany, substrateVerify: countSub });
  check('round-20 P1-02 witness with 40 distinct active roots → resource_limit, ZERO substrate fan-out (F.9 W-budget)', fanCalls === 0 && r20c.verdict.result !== 'VALID:HIGH');
  // P2-01 — forkChoice now admits opts (rev16 missed it): a hostile Proxy opts is a structured reject, not a host throw.
  let fcThrew = false, fcRes;
  try { fcRes = await P.forkChoice([doc], new Proxy({}, { ownKeys() { throw new Error('h'); }, get() { throw new Error('h'); }, getOwnPropertyDescriptor() { throw new Error('h'); } })); } catch { fcThrew = true; }
  check('round-20 P2-01 forkChoice hostile opts Proxy → structured E-MALFORMED, never a host throw', !fcThrew && fcRes.result === 'E-MALFORMED');

  // ─── round-21 (rev18) — the round-20 witness fan-out fix was LOSSY: it DISCARDED rival evidence, then minted HIGH ─────
  // P0-01 — a rival root split across entries (one without an anchor, one WITH) must UNION its anchor evidence, not
  // first-wins drop it (F.5a: the served list is a MEASURABLE input, not a lossy projection). rival IS anchored ⇒ fork.
  const gHashB = 'sha256:' + 'cd'.repeat(32);
  const splitLog = wlog([
    { content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) },
    { content_hash: gHashB, superseded_by: null },                                     // rival, first occurrence: NO anchor
    { content_hash: gHashB, superseded_by: null, anchor: anchorOf(gHashB) },           // SAME rival, WITH anchor (rev17 dropped this)
  ], gHash);
  const r21a = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(splitLog), substrateVerify: final });
  check('round-21 P0-01 rival anchor split across entries → UNIONed → fork, never false corroborated HIGH', r21a.verdict.result !== 'VALID:HIGH');
  const shadowLog = wlog([
    { content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) },
    { content_hash: gHashB, superseded_by: null, anchors: [], anchor: anchorOf(gHashB) },   // empty plural must NOT shadow the valid singular
  ], gHash);
  const r21b = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(shadowLog), substrateVerify: final });
  check('round-21 P0-01 anchors:[] does not shadow a valid singular anchor (union both) → fork, never false HIGH', r21b.verdict.result !== 'VALID:HIGH');
  // P0-02 — a genesis carrying more anchors than the budget is REFUSED (resource_limit), never truncated to hide a late valid one.
  const nineAnchors = Array.from({ length: 9 }, (_, i) => anchorOf('sha256:' + String(i).padStart(64, 'a')));
  const bigAnchorLog = wlog([{ content_hash: gHash, superseded_by: null, anchors: nineAnchors }], gHash);
  const r21c = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(bigAnchorLog), substrateVerify: final });
  check('round-21 P0-02 over-budget anchors/genesis → resource_limit refuse (never truncate) → NOT HIGH', r21c.verdict.result !== 'VALID:HIGH' && /resource_limit/.test(JSON.stringify(r21c.resolution || {})));
  // P1-01 — a connector that throws is UNAVAILABLE evidence, not a host exception escaping the verifier.
  const throwLog = wlog([{ content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) }], gHash);
  let r21threw = false, r21tres;
  try { r21tres = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(throwLog), substrateVerify: () => { throw new Error('connector parser failure'); } }); } catch { r21threw = true; }
  check('round-21 P1-01 witness connector throw → structured result, never a host exception', !r21threw && !!r21tres.verdict.result);
  // P1-02 — forkChoice over the candidate budget is refused, never a fan-out of N verifications.
  const manyCands = Array.from({ length: 100 }, () => ({ ...gkDoc, proof: anchorOf(P.contentHash(gkDoc)) }));
  const r21fc = await P.forkChoice(manyCands, { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: final });
  check('round-21 P1-02 forkChoice over candidate budget → INDETERMINATE resource_limit (no N-way fan-out)', r21fc.result === 'INDETERMINATE' && /resource_limit/.test(JSON.stringify(r21fc)));
  // P2-01 — an over-budget witness is machine-readably INDETERMINATE(resource_limit), surfaced through the resolution.
  const bigWit = wlog(Array.from({ length: 300 }, (_, i) => ({ content_hash: 'sha256:' + String(i).padStart(64, '0'), superseded_by: null, anchor: anchorOf('sha256:' + String(i).padStart(64, '0')) })), gHash);
  const r21p2 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(bigWit), substrateVerify: final });
  check('round-21 P2-01 over-budget witness → machine-readable resource_limit in the resolution', /resource_limit/.test(JSON.stringify(r21p2.resolution || {})));
  // rev19 (round-22 self-catch) — the rev18 P1-02 forkChoice content_hash dedupe was itself LOSSY: content_hash covers
  // the STATE, not the `proof`, so a snapshot with a valid proof behind one with an invalid proof (same content_hash) was
  // dropped — hiding anchor-inclusion (the same lossy-projection class the witness fix closed). No dedupe now; the budget
  // caps the work. A valid proof in a later same-state candidate must still be seen.
  const badProof = { root: 'sha256:' + '00'.repeat(32), path: [], anchor: { substrate: 'bitcoin-ots' } };
  const withBad = { ...gkDoc, proof: badProof };
  const withGood = { ...gkDoc, proof: anchorOf(P.contentHash(gkDoc)) };
  const rDedupe = await P.forkChoice([withBad, withGood], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: final });
  check('rev19 forkChoice does NOT content_hash-dedupe away a valid proof (same state, later valid proof still seen) → CANONICAL', rDedupe.result === 'CANONICAL' && P.contentHash(rDedupe.canonical) === P.contentHash(gkDoc));

  // ─── round-22 (rev20) — the rev18/rev19 witness UNION + forkChoice fix were STILL lossy/non-deterministic ─────────────
  // P0-01 — status is reconciled AFTER grouping by content_hash: a hash listed BOTH active and superseded is contradictory
  // (a rival cannot be quietly 'superseded' on one record to erase its anchor from the active count) → fail closed.
  const conflictLog = wlog([
    { content_hash: gHash, superseded_by: null, anchor: anchorOf(gHash) },
    { content_hash: gHashB, superseded_by: null },                                       // rival, active, no anchor
    { content_hash: gHashB, superseded_by: 'sha256:' + 'ff'.repeat(32), anchor: anchorOf(gHashB) },   // SAME rival, superseded, WITH a valid anchor
  ], gHash);
  const r22a = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(conflictLog), substrateVerify: final });
  check('round-22 P0-01 rival listed active AND superseded (anchor on the superseded record) → fail closed, never false HIGH', r22a.verdict.result !== 'VALID:HIGH');
  // P1-01 — forkChoice returns a DETERMINISTIC full document for equal-state / different-valid-proof candidates (F.5c).
  const pA = anchorOf(P.contentHash(gkDoc)); const pB = { ...anchorOf(P.contentHash(gkDoc)), anchor: { substrate: 'test2' } };
  const cA = { ...gkDoc, proof: pA }, cB = { ...gkDoc, proof: pB };
  const svBoth = async (a, root) => root === pA.root ? { final: true, time: '2026-07-13T14:05:00Z' } : null;
  const fAB = await P.forkChoice([cA, cB], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: svBoth });
  const fBA = await P.forkChoice([cB, cA], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: svBoth });
  check('round-22 P1-01 forkChoice same set, reversed order → byte-identical full output (F.5c: canonical is set-determined)', JSON.stringify(fAB) === JSON.stringify(fBA));
  // round-23 P1-03/04 — the order key is TOTAL even when canon(doc) THROWS (a proof carrying a numeric diagnostic that
  // canon rejects but verifyAnchor accepts). rev20 fell back to arrival order here; rev21 uses JSON.stringify (total).
  const rootN = anchorOf(P.contentHash(gkDoc)).root;
  const pN = (n) => ({ root: rootN, path: [], anchor: { substrate: 'test', block: n } });   // numeric extra → canon(doc) throws
  const svN = async (a, root) => root === rootN ? { final: true, time: '2026-07-13T14:05:00Z' } : null;
  const gnAB = await P.forkChoice([{ ...gkDoc, proof: pN(900001) }, { ...gkDoc, proof: pN(900002) }], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: svN });
  const gnBA = await P.forkChoice([{ ...gkDoc, proof: pN(900002) }, { ...gkDoc, proof: pN(900001) }], { genesis: gen, keylog: [], ...nfe(gen), substrateVerify: svN });
  check('round-23 P1-03 forkChoice total order even when canon(doc) throws (numeric proof extra) → byte-identical output', JSON.stringify(gnAB) === JSON.stringify(gnBA) && gnAB.result === 'CANONICAL');
  // P1-02 — combineSubstrates isolates a throwing plugin so a later valid plugin still verifies the anchor.
  const combined = P.combineSubstrates([() => { throw new Error('plugin down'); }, async () => ({ final: true, time: '2026-07-13T14:05:00Z' })]);
  const r22c = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: combined });
  check('round-22 P1-02 combineSubstrates: a throwing plugin does not shadow a later valid one → HIGH still reachable', r22c.verdict.result === 'VALID:HIGH');
  // P2-01 — byte-identical duplicate proofs are SET-UNIONed (deduped) before the structural cap, not counted against it.
  const dupAnchor = anchorOf(gHash);
  const dupProofsLog = wlog([{ content_hash: gHash, superseded_by: null, anchors: Array.from({ length: 9 }, () => dupAnchor) }], gHash);
  const r22d = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(dupProofsLog), substrateVerify: final });
  check('round-22 P2-01 nine byte-identical proofs → set-unioned to one, under the cap → HIGH (not a false resource_limit)', r22d.verdict.result === 'VALID:HIGH');

  const r4 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog), substrateVerify: () => ({ final: false }) });
  check('anchor not final (Bitcoin pending), name-form → INDETERMINATE (no HIGH — cannot confirm the domain; honest pending — round-53)', r4.verdict.result === 'INDETERMINATE');

  const r5 = await P.resolveByDiscovery(doc, { context: 'data' }, { fetchImpl: mk(okLog) });   // no substrateVerify
  check('no substrate cross-check, name-form → INDETERMINATE (never witness-confirmed; cannot confirm the domain — round-53)', r5.verdict.result === 'INDETERMINATE');

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
  check('#70 C2: a signed gap record is a valid subtype (not E-MALFORMED) — name-form → INDETERMINATE, never a collision error (round-53)', P.verify(gp('ust:20260628.142930', gH), { context: 'data' }).result === 'INDETERMINATE');
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
  check('#40 punycode A-label (xn--…) passes the glyph guard → INDETERMINATE not E-MALFORMED (a valid A-label, just name-unbound — round-53)', P.verify(P.seal(P.buildState({ domain_shard: 'xn--80ak6aa92e.com', ust_id: 'ust:20260628.12', key_id: G.key_id, class: 'observation' }, T, { r: { kind: 'captured', value: { x: '1' } } }), G.priv, G.pubB64), { context: 'data' }).result === 'INDETERMINATE');
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
  const iv = (clock_id, not_before, not_after) => ev('rfc3161-tsa', { clock_id, not_before, not_after });   // a well-formed same-clock interval (kernel FACTS_SCHEMA: clock_id + BOTH real-calendar bounds)
  check('PhA order: a.not_before ≥ b.not_after → proven-after', P.compareEvidenceOrder(iv('c1', '2027-01-02T00:00:00Z', '2027-01-03T00:00:00Z'), iv('c1', '2026-12-31T00:00:00Z', '2027-01-01T00:00:00Z')) === 'proven-after');
  check('PhA order: b.not_before ≥ a.not_after → not-after', P.compareEvidenceOrder(iv('c1', '2026-12-31T00:00:00Z', '2027-01-01T00:00:00Z'), iv('c1', '2027-01-02T00:00:00Z', '2027-01-03T00:00:00Z')) === 'not-after');
  check('PhA order: overlapping intervals prove neither → unproven', P.compareEvidenceOrder(iv('c1', '2027-01-01T00:00:00Z', '2027-01-03T00:00:00Z'), iv('c1', '2027-01-02T00:00:00Z', '2027-01-04T00:00:00Z')) === 'unproven');
  check('PhA order: cross-substrate positions → unproven', P.compareEvidenceOrder(ev('pow-header-chain', { substrate: 'bitcoin', position: '900' }), ev('pow-header-chain', { substrate: 'litecoin', position: '5' })) === 'unproven');
  // round-32 P0-01 — the public order path mirrors the reference KERNEL's orderSemantic (ORDER_COORD/FACTS_SCHEMA), so
  // the two independent derivations agree: a cross-kind tag, a non-calendar instant, an inverted interval, or a
  // cross-clock pair mints NO temporal-order predicate (the corroborated-freshness forge).
  check('R32 order cross-kind: transparency-log wearing pow facts {substrate,position} → unproven (its coord is log_id/index)', P.compareEvidenceOrder(ev('transparency-log', { substrate: 'bitcoin', position: '900' }), ev('pow-header-chain', { substrate: 'bitcoin', position: '800' })) === 'unproven');
  check('R32 order transparency-log legit {log_id,index} orders within one log', P.compareEvidenceOrder(ev('transparency-log', { log_id: 'rekor', index: '900' }), ev('transparency-log', { log_id: 'rekor', index: '800' })) === 'proven-after');
  check('R32 order non-calendar: rfc3161-tsa not_before 9999-99-99T99:99:99Z (shape-valid, calendar-invalid) → unproven', P.compareEvidenceOrder(iv('c1', '9999-99-99T99:99:99Z', '2027-01-01T00:00:00Z'), iv('c1', '2026-01-01T00:00:00Z', '2026-07-01T00:00:00Z')) === 'unproven');
  check('R32 order inverted-interval: rfc3161-tsa not_before > not_after in one receipt → unproven', P.compareEvidenceOrder(iv('c1', '2099-01-01T00:00:00Z', '2020-01-01T00:00:00Z'), iv('c1', '2020-01-01T00:00:00Z', '2021-01-01T00:00:00Z')) === 'unproven');
  check('R32 order cross-clock: two intervals on different clocks prove nothing → unproven', P.compareEvidenceOrder(iv('c1', '2027-02-01T00:00:00Z', '2027-03-01T00:00:00Z'), iv('c2', '2020-01-01T00:00:00Z', '2021-01-01T00:00:00Z')) === 'unproven');
  check('R32 order calendar-valid still holds: real same-clock instants compare chronologically', P.compareEvidenceOrder(iv('c1', '2027-02-28T23:59:59Z', '2027-03-01T00:00:00Z'), iv('c1', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z')) === 'proven-after');
  // round-32 P2-01 — the Horn explanatory trace must AGREE with the canonical projectTier over the whole grid: a
  check('R32 Horn≡projectTier: every identity×time cell — max Horn Tier == projectTier', (() => {
    const RANK = { LIGHT: 1, HIGH: 2, TOP: 3 };
    const IDS = [{ spec: {}, id: 'self-asserted' },   // round-53 — `pinned` rung removed; identity states = self-asserted / corroborated / authoritative ("every cell")
      { spec: { status: 'verified', strength: 'corroborated' }, id: 'corroborated' }, { spec: { status: 'verified', strength: 'authoritative' }, id: 'authoritative' }];
    for (const { spec, id } of IDS) for (const time of ['unproven', 'anchored']) {
      const g = P.provePredicates({ identity: spec, anchor: time === 'anchored' ? { inclusion: true, time: 'anchored' } : undefined });
      let best = 'NONE', r = 0;
      for (const t of g.derivation) if (/^Tier/.test(t.rule) && RANK[t.rule.slice(4)] > r) { r = RANK[t.rule.slice(4)]; best = t.rule.slice(4); }
      if (best !== P.projectTier({ integrity: 'valid', identity: id, freshness: 'unverified', time })) return false;
    }
    return true;
  })());
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
  check('M2/D verifiedGenesisContext: a getter on the genesis (TOCTOU) cannot mint a context whose scope ≠ the verified genesis → null (round-26 D — snapshot once)',
    (() => { const evil = JSON.parse(JSON.stringify(genCA)); let n = 0; Object.defineProperty(evil.state.id, 'domain_shard', { enumerable: true, get() { return ++n === 1 ? D : 'evil.com'; } }); return P.verifiedGenesisContext(evil) === null; })());
  // C1 (UST-6vj) — downstream takes the CONTEXT: one verified derivation carries scope + authority + recovery.
  const ctx = P.verifiedGenesisContext(genCA);
  check('C1 chain rooted in a VerifiedAuthorityContext → VALID (authority_root verified-context)', (r => r.result === 'VALID' && r.authority_root === 'verified-context')(P.verifyAuthorityCheckpointChain([C0], { context: ctx })));
  check('C1 context-rooted C₀ bound to the context scope: foreign active_genesis → INVALID(E-GENESIS)', (r => r.result === 'INVALID' && r.error === 'E-GENESIS')((() => {
    const AGx = 'sha256:' + '77'.repeat(32);
    const Cx = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: P.genesisEpoch(AGx), sequence: '0', active_genesis: AGx, current_key_id: K0.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), K0.priv, K0.pubB64);
    return P.verifyAuthorityCheckpointChain([Cx], { context: ctx });
  })()));
  // round-26 P0-01/P0-02 (rev25, L1/L2) — the ADVERSARIAL closure of M2 "never raw fields" / F.5l "recovery immutable":
  //   under a branded context, a raw authority-root field ALONGSIDE it is rejected (it cannot substitute the root the
  //   context fixes) — never accepted while still reporting verified-context. This is what the positive C1 never tested.
  check('C1/L1 a raw pinnedPrior alongside a branded context → INVALID(E-AUTHORITY) — the context is the SOLE root (never raw fields, M2; round-26 P0-01)',
    (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0], { context: ctx, pinnedPrior: { scope_id: 'sha256:' + '44'.repeat(32), checkpoint_id: 'sha256:' + '44'.repeat(32), sequence: '9', authority_for_next: { key_id: K0.key_id, pub: K0.pubB64 }, keylog_size: '1', keylog_root: 'sha256:' + '44'.repeat(32), keylog_head: 'sha256:' + '44'.repeat(32) } })));
  check('C1/L2 raw recoveryKeys/recoveryThreshold alongside a branded context → INVALID(E-AUTHORITY) — recovery is genesis-fixed, never injected from a call argument (F.5l; round-26 P0-02)',
    (r => r.result === 'INVALID' && r.error === 'E-AUTHORITY')(P.verifyAuthorityCheckpointChain([C0], { context: ctx, recoveryKeys: { [K0.key_id]: K0.pubB64 }, recoveryThreshold: '1' })));
  // round-27 P0-02 — the WHOLE (chain, config) authority graph crosses the admitDeep boundary: a getter on a checkpoint
  //   body (sign a no-rotation body, then mint an attacker rotation on the re-read) is not an inert record → E-MALFORMED,
  //   never a VALID takeover. rev24 put the snapshot on the evidence/genesis entries but NOT the chain verifier (P0-02).
  check('round-27 P0-02 a getter on a checkpoint body cannot sign one body and mint another → INVALID(E-MALFORMED) (the chain crosses the snapshot boundary)',
    (() => { const evil = { ...C0, body: { ...C0.body } }; let n = 0; const realCA = C0.body.checkpoint_authority;
      Object.defineProperty(evil.body, 'checkpoint_authority', { enumerable: true, get() { n++; return realCA; } });   // an accessor at ANY depth of the chain → not inert
      const r = P.verifyAuthorityCheckpointChain([evil], { context: ctx });
      return r.error === 'E-MALFORMED' && n === 0; })());   // rejected at the snapshot boundary — the getter never fires
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
  //    round-25 P0-01: provePredicates returns the UNBRANDED graph (the pure mapper), so read its derivation/provenAtoms
  //    directly — deriveAssurance now blesses ONLY a TCB-sealed graph and would reject this synthetic one (that is the fix).
  check('K7 provePredicates → Horn closure: IdentityAuthoritative ← name-bound ∧ active-genesis-unique (with trace)', (g => g.derivation.some((t) => t.rule === 'IdentityAuthoritative' && t.premises.includes('active-genesis-unique')) && g.provenAtoms.includes('name-bound'))(P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' } })));
  check('K7 no-upward-forge: without checkpoint-unique, FreshnessAttested is NOT in the closure', (g => !g.derivation.some((t) => t.rule === 'FreshnessAttested'))(P.provePredicates({ identity: { status: 'verified', strength: 'corroborated' }, freshness: { result: 'VALID', keylog_freshness: 'corroborated' } })));
  check('K7 TierTOP ← integrity-valid ∧ IdentityAuthoritative ∧ time-anchored (composite rule fires)', (g => g.derivation.some((t) => t.rule === 'TierTOP'))(P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' }, anchor: { inclusion: true, time: 'anchored' } })));
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
  const connectors = { [KC.key_id]: { pub: KC.pubB64, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain', 'rfc3161-tsa', 'transparency-log'] } };
  const trust = { connectors };
  const rcpt = (subj, facts, kind = 'pow-header-chain') => P.buildEvidenceReceipt({ domain_shard: D, active_genesis: AG, subject: subj, proof_kind: kind, facts, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pubB64);
  const btc = (pos, subj) => rcpt(subj, { substrate: 'bitcoin', position: String(pos) });
  const commit = btc(900, headId);
  const target = { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: btc(800, 'ust:target') };
  const F = (opts) => P.deriveCheckpointFreshness([C0], { genesisAuthority: gAuth, trust, ...opts });

  check('PhB all conjuncts (authorized × head∈root × proven-after) → corroborated', (r => r.result === 'VALID' && r.keylog_freshness === 'corroborated' && r.head === headId)(F({ target, commitment: commit, terminality: term })));
  check('PhB CEILING: corroborated carries anti_equivocation:unverified and is NEVER attested', (r => r.keylog_freshness === 'corroborated' && r.anti_equivocation === 'unverified' && r.keylog_freshness !== 'attested')(F({ target, commitment: commit, terminality: term })));
  check('PhB commitment NOT proven-after target → INDETERMINATE(order_unproven)', (r => r.result === 'INDETERMINATE' && r.reason === 'order_unproven')(F({ target, commitment: btc(700, headId), terminality: term })));
  check('PhB overlapping same-clock intervals prove neither → order_unproven (round-33: rfc3161-tsa facts are CLOSED — clock_id + both real-calendar bounds)', (r => r.reason === 'order_unproven')(F({ target: { active_genesis: AG, domain_shard: D, subject: 'ust:target', anchor: rcpt('ust:target', { clock_id: 'c1', not_before: '2027-01-01T00:00:00Z', not_after: '2027-01-03T00:00:00Z' }, 'rfc3161-tsa') }, commitment: rcpt(headId, { clock_id: 'c1', not_before: '2027-01-02T00:00:00Z', not_after: '2027-01-04T00:00:00Z' }, 'rfc3161-tsa'), terminality: term })));
  check('PhB terminality missing → INDETERMINATE(terminality_unproven)', (r => r.reason === 'terminality_unproven')(F({ target, commitment: commit })));
  // round-33 P0-01/02 — the PUBLIC receipt admission applies the kernel's CLOSED typed ADT (a receipt the kernel would
  // reject can no longer mint a branded VerifiedEvidence handle) and reads issuer_id from the ADMITTED snapshot only.
  const scR33 = { domain_shard: D, active_genesis: AG, genesis_epoch: P.genesisEpoch(AG) };
  const signRcR33 = (claim, issuer = KC.key_id) => { const sg = sign(null, Buffer.from(P.canon({ purpose: 'ust:evidence-receipt-signature', claim }), 'utf8'), KC.priv).toString('base64url'); return { claim, issuer_id: issuer, sig: { alg: 'Ed25519', key_id: KC.key_id, pub: KC.pubB64, sig: sg } }; };
  const tlR33 = (over = {}) => ({ version: '1', purpose: 'ust:evidence-receipt', domain_shard: D, active_genesis: AG, genesis_epoch: P.genesisEpoch(AG), subject: 'ust:target', proof_kind: 'transparency-log', facts: { log_id: 'rekor', index: '900' }, issued_at: '2026-01-01T00:00:00Z', ...over });
  const vrR33 = (rc) => P.verifyEvidenceReceipt(rc, { subject: 'ust:target', scope: scR33, connectors });
  check('R33 P0-01 signed transparency-log receipt with an EXTRA facts field → INVALID (closed per-kind facts, kernel-aligned)', vrR33(signRcR33(tlR33({ facts: { log_id: 'rekor', index: '900', extra: 'x' } }))).result === 'INVALID');
  check('R33 P0-01 shape-valid IMPOSSIBLE issued_at 9999-99-99T99:99:99Z → INVALID (real calendar, not just regex)', vrR33(signRcR33(tlR33({ issued_at: '9999-99-99T99:99:99Z' }))).result === 'INVALID');
  check('R33 P0-01 unregistered proof_kind → INVALID (closed kind registry, own-key)', vrR33(signRcR33(tlR33({ proof_kind: 'made-up', facts: {} }))).result === 'INVALID');
  check('R33 P0-01 EXTRA claim field → INVALID (exact claim keys)', vrR33(signRcR33({ ...tlR33(), rogue: 'x' })).result === 'INVALID');
  check('R33 P0-01 EXTRA envelope field → INVALID (envelope exactly { claim, issuer_id, sig })', vrR33({ ...signRcR33(tlR33()), rogue: 'x' }).result === 'INVALID');
  check('R33 P0-01 wrong per-kind facts (pow {substrate,position} worn by a transparency-log) → INVALID', vrR33(signRcR33(tlR33({ facts: { substrate: 'bitcoin', position: '900' } }))).result === 'INVALID');
  check('R33 P0-01 a well-typed transparency-log receipt is STILL VALID (kernel-aligned, no over-reject)', vrR33(signRcR33(tlR33())).result === 'VALID');
  check('R33 P0-02 issuer_id two-face Proxy → INVALID; issuer_id read from the ADMITTED snapshot R, never a raw re-read', (() => {
    let reads = 0; const base = signRcR33(tlR33());
    const px = new Proxy(base, { get(t, k, r) { if (k === 'issuer_id') { reads++; return reads === 1 ? 'sha256:' + '00'.repeat(32) : KC.key_id; } return Reflect.get(t, k, r); } });
    return vrR33(px).result === 'INVALID' && reads <= 1;   // the fixed check reads R.issuer_id (frozen face-1), so the raw second face is never consulted
  })());
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
  // round-26 P0-03 / L3 (rev24 D) — the ADVERSARIAL closure the model asserted but never tested: a genuine
  //   EvidenceHandle's verified_facts EQUAL the signature-verified facts. A live getter on facts (return the signed
  //   value during verify, an unsigned value during handle construction) is a getter-TOCTOU; admitDeep snapshots ONCE
  //   at entry, so a getter-bearing receipt is not an inert record → INVALID, never a branded handle with unsigned facts.
  check('M3/D getter-TOCTOU on receipt facts cannot mint an EvidenceHandle whose facts ≠ the signed facts → INVALID (round-26 P0-03, L3 closed)',
    (() => { const ef = { substrate: 'bitcoin' }; let n = 0; Object.defineProperty(ef, 'position', { enumerable: true, get() { return ++n === 1 ? '900' : '999999'; } });
      const r = P.verifyEvidenceReceipt({ ...commit, claim: { ...commit.claim, facts: ef } }, { subject: commit.claim.subject, scope, connectors });
      return r.result === 'INVALID' && r.error === 'E-EVIDENCE' && !P.isVerifiedHandle('evidence', r.evidence); })());
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
  check('R34 P0-03 a uniqueness claim with an EXTRA signed field (observed_map_root ∉ the closed VOTE_CLAIM) is DROPPED → quorum not met', VU([{ claim: { ...P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }), observed_map_root: 'sha256:' + 'a1'.repeat(32) }, issuer_id: Wa.key_id, sig: ua(Wa).sig }, ua(Wb)]).attested === false);
  check('PhC witness NOT in consumer trustRoots → not admitted', P.verifyCheckpointUniqueness([ua(Wa), ua(Wb)], { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots: { [Wa.key_id]: Wa.pubB64 }, domains, threshold: 2 }).attested === false);
  check('PhC self-declared trust_domain inside the claim → rejected', VU([{ claim: { ...P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId }), trust_domain: 'independent-7' }, issuer_id: Wa.key_id, sig: ua(Wa).sig }, ua(Wb)]).attested === false);
  // ─── round-23 (rev21) — the quorum evidence surface had the SAME class as witness/forkChoice, never applied to it ────
  // P0-01 — two issuers mapped to structurally-equal OBJECT trust-domains must NOT count as two independent voters (a Set
  // of objects counts by identity → a fake quorum). Only NFC strings are admitted domains.
  check('round-23 P0-01 object trust-domains (structurally equal) do not fake independence → attested:false', P.verifyCheckpointUniqueness([ua(Wa), ua(Wb)], { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots, domains: { [Wa.key_id]: { name: 'same' }, [Wb.key_id]: { name: 'same' } }, threshold: 2 }).attested === false);
  // P1-01 — the quorum full output is set-determined (voters/tags sorted in the M5 core), not arrival-order.
  check('round-23 P1-01 quorum full output is order-independent (voters/tags sorted)', JSON.stringify(VU([ua(Wa), ua(Wb)])) === JSON.stringify(VU([ua(Wb), ua(Wa)])) && VU([ua(Wa), ua(Wb)]).attested === true);
  // P1-02 — null / non-record config is total on the exported quorum surfaces (structured, never a host throw).
  check('round-23 P1-02 quorum functions total for null config (no host throw)', (() => { try { P.verifyCheckpointUniqueness([], null); P.verifyCheckpointRecovery([], null); P.quorumTrustDomains([], null); return true; } catch { return false; } })());
  // ─── round-24 (rev22) — the recurring classes on the surfaces they had never reached ────────────────────────────────
  // P0-03 — a lone UTF-16 surrogate trust-domain is OUTSIDE the §6 scalar domain and must not count as an independent domain.
  check('round-24 P0-03 lone-surrogate trust-domains → NOT two independent voters → attested:false', P.verifyCheckpointUniqueness([ua(Wa), ua(Wb)], { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots, domains: { [Wa.key_id]: '\uD800', [Wb.key_id]: '\uD801' }, threshold: 2 }).attested === false);
  // round-25 P1-01 — CanonicalSeq: a coercible array `["0"]` signed sequence (String(["0"])==="0" fools JS ==) is NOT a
  //    canonical sequence; isSeq runs BEFORE the signature, so the claim is dropped and cannot join the uniqueness quorum.
  check('round-25 P1-01 a coercible array sequence `["0"]` is dropped (not admitted to the uniqueness quorum)', VU([{ claim: { purpose: 'ust:checkpoint-uniqueness-attestation', domain_shard: D, genesis_epoch: EP, sequence: ['0'], checkpoint: headId }, issuer_id: Wa.key_id, sig: { alg: 'Ed25519', key_id: Wa.key_id, pub: Wa.pubB64, sig: 'AA' } }, ua(Wb)]).attested === false);
  // P1-01 — null-total across ALL the public proof surfaces (the round-23 quorum fix + this sweep + the self-audit pair).
  check('round-24 P1-01 nine public proof surfaces total for null config (no host throw)', (() => { try { P.verifyNoForkEvidence({}, null); P.verifyEvidenceReceipt({}, null); P.verifyEpochTransition({}, null); P.verifyAuthorityCheckpointChain([], null); P.verifyCheckpointMapUniqueness({}, null); P.verifyActiveGenesisUniqueness({}, null); P.verifyKeylogTerminality(null, {}); P.deriveCheckpointFreshness([], null); P.verifyStream([{}], null); return true; } catch { return false; } })());
  // round-26 L5 (rev24 C) — I4 totality on the boundaries the rev23 grid missed: a null TRAILING arg (not just null
  //   config) on the public data/verify boundary returns structured, never a host throw (resolveCadence 4th arg,
  //   verifyJson opts). These drive the PUBLIC entry, per the audit-plan Definition-of-Done.
  check('round-26 L5 malformed non-null on trailing args: resolveCadence and verifyJson accept a null trailing arg and return structured (no host throw)',
    (() => { try { const a = P.resolveCadence({}, [], 'ust:20260719.03', null); const b = P.verifyJson('{}', null); return typeof a === 'object' && typeof b === 'object'; } catch { return false; } })());
  // round-26 B (rev26) — CanonicalSeq at the LAST unswept signed scalars (Merkle index + key-log length): a coercible
  //   array `["1"]` (String/BigInt of it collapses to the canonical value) is NOT a canonical sequence → not terminal.
  check('round-26 B key-log terminality: a coercible array Merkle index / length does not decode (isSeq before String/BigInt)',
    (() => { const kl = P.buildKeylogCommitment(['sha256:' + '22'.repeat(32), 'sha256:' + '33'.repeat(32)]);
      const ok = P.verifyKeylogTerminality({ root: kl.root, length: kl.length, head: kl.head }, kl.headProof).terminal === true;
      const idx = P.verifyKeylogTerminality({ root: kl.root, length: kl.length, head: kl.head }, { ...kl.headProof, index: [kl.headProof.index] }).terminal === false;
      const len = P.verifyKeylogTerminality({ root: kl.root, length: [kl.length], head: kl.head }, kl.headProof).terminal === false;
      return ok && idx && len; })());
  // round-25 P1-02 — MALFORMED NON-NULL totality (I4): the null matrix was closed in round-24; round-25 sweeps ordinary
  //    non-null junk that still reached a host operation. A numeric-extra claim (canon throws), a null proof deref, a null
  //    seam arg, and a non-binary verifyJson input all now return STRUCTURED verdicts, never a host TypeError/E-CANON.
  check('round-25 P1-02 malformed non-null across verify*/prove* surfaces returns structured, never a host throw', (() => { try {
    P.verifyNoForkEvidence({ claim: { purpose: 'ust:name-no-fork', domain_shard: 'noosphere.md', active_genesis: 'sha256:' + '00'.repeat(32), x: 1 }, issuer_id: 'z', sig: { sig: 'y', pub: 'p' } }, { domain_shard: 'noosphere.md', active_genesis: 'sha256:' + '00'.repeat(32), trustRoots: { z: 'p' } });
    P.verifyKeylogTerminality({ root: 'sha256:' + 'ab'.repeat(32), length: '1', head: 'x' }, null);
    P.provePredicates(null); P.provePredicates(42); P.verifyJson([1, 2, 3]); return true; } catch { return false; } })());
  check('round-25 P1-02 verifyJson(non-binary) → structured E-MALFORMED (not a host ERR_INVALID_ARG_TYPE)', P.verifyJson({ a: 'b' }).error === 'E-MALFORMED' && P.verifyJson(123).error === 'E-MALFORMED');
  // round-25 P0-04 — the TCB structural registries are DEEP-frozen: a nested axis/domain array cannot be mutated to change
  //    projectTier ranks or the canonical string sets in-process (history-independent verdict).
  check('round-25 P0-04 exported TCB registries are deep-frozen (nested arrays immutable)', Object.isFrozen(P.ASSURANCE_AXES) && Object.isFrozen(P.ASSURANCE_AXES.identity) && Object.isFrozen(P.REGISTRY) && Object.isFrozen(P.REGISTRY.hashDomains) && P.REGISTRY.assuranceAxes === P.ASSURANCE_AXES);
  // round-25 Div2 (F.9) — the T_v coordinate of ρ_v: the whole-operation witness budget is min(reference default,
  //    consumer maxWitnessOpMs). The consumer can only TIGHTEN; over-budget is INDETERMINATE(resource_limit) naming the
  //    effective budget — a refusal, never a truncation and never a verdict about the data. (These are the FIRST witness
  //    budget vectors: round-24 P1-04 shipped without one — the vector-in-same-commit rule now enforced retroactively.)
  {
    const AGW = 'sha256:' + 'ab'.repeat(32), shard = 'w.example';
    const wRoot = P.Hbytes('ust:leaf', Buffer.from(AGW, 'utf8'));                       // single-leaf inclusion so anchoredByProofs reaches the substrate call
    const wp = (n) => ({ root: wRoot, path: [], anchor: { substrate: 'test-anchor', n } });
    // rev33 R4 — budget exhaustion is DETERMINISTIC via the VERIFIER-OWNED module clock (set through the internal _clock
    //   module, NOT a public opts field). Consulting a leaf's substrate advances that clock past the whole-op deadline, so
    //   resource_limit trips with ZERO timer race — this KILLS the recurring round-27/28 CI flake at the root (the substrate
    //   resolves AT ONCE, no real setTimeout in play) WITHOUT exposing any caller-writable time surface (round-29 P0-02).
    const spentClock = () => { let spent = false; return { now: () => (spent ? 1_000_000 : 1000), sv: () => { spent = true; return { final: false }; } }; };
    const log = JSON.stringify({ domain_shard: shard, genesis_log: [{ content_hash: AGW, anchors: [wp('1'), wp('2')] }] });
    const fetchW = async () => ({ ok: true, headers: { get: () => undefined }, arrayBuffer: async () => new TextEncoder().encode(log).buffer });
    const fastSV = () => ({ final: true, time: '2027-01-01T00:00:00Z' });
    const c1 = spentClock();
    const capped = await withWitnessClock(c1.now, () => P.witnessNoFork(shard, AGW, { fetchImpl: fetchW, substrateVerify: c1.sv, maxWitnessOpMs: 50 }));
    check('F.9 T_v realization: the whole-operation witness budget is min(reference default, consumer deadline) — a tighter consumer deadline trips INDETERMINATE(resource_limit) naming the effective budget',
      capped.status === 'indeterminate' && capped.reason === 'resource_limit' && capped.detail.includes('50 ms whole-operation budget'));
    check('F.9 T_v control: the same witness with no consumer cap verifies (confirmed) — the cap lowers decisibility, never flips a verdict',
      (await P.witnessNoFork(shard, AGW, { fetchImpl: fetchW, substrateVerify: fastSV })).status === 'confirmed');
    // round-27 P2-01 — typed policy admission: an INVALID maxWitnessOpMs (0 / -1 / NaN / Infinity / fractional) is REFUSED
    //   (resource_limit), never silently expanded to the 30 s default (which admitted a slow connector and returned confirmed).
    let allRefused = true;
    for (const bad of [0, -1, NaN, Infinity, 1.5]) {
      const r = await P.witnessNoFork(shard, AGW, { fetchImpl: fetchW, substrateVerify: fastSV, maxWitnessOpMs: bad });
      if (!(r.status === 'indeterminate' && r.reason === 'resource_limit')) allRefused = false;
    }
    check('round-27 P2-01 invalid maxWitnessOpMs (0/-1/NaN/Infinity/fractional) is REFUSED (resource_limit), never expanded to the reference default', allRefused);
    // round-27 P1-01 — a budget exhausted on the FINAL/only leaf is INDETERMINATE(resource_limit), not 'pending': the
    //   deadline is checked AFTER every awaited leaf, not only before (a single never-settling anchor + a tight budget).
    const oneAnchorLog = JSON.stringify({ domain_shard: shard, genesis_log: [{ content_hash: AGW, anchor: wp('1') }] });
    const fetch1 = async () => ({ ok: true, headers: { get: () => undefined }, arrayBuffer: async () => new TextEncoder().encode(oneAnchorLog).buffer });
    const c2 = spentClock();
    const lastLeaf = await withWitnessClock(c2.now, () => P.witnessNoFork(shard, AGW, { fetchImpl: fetch1, substrateVerify: c2.sv, maxWitnessOpMs: 50 }));   // the ONLY leaf's substrate consult spends the budget → the post-await deadline check returns resource_limit (never falls through to 'pending')
    check('round-27 P1-01 a budget exhausted on the FINAL leaf → INDETERMINATE(resource_limit), never reported as pending',
      lastLeaf.status === 'indeterminate' && lastLeaf.reason === 'resource_limit');
  }
  // P1-03 — evidenceCaps returns a FROZEN copy: a caller cannot mutate the checker's capability vocabulary.
  check('round-24 P1-03 evidenceCaps is a frozen copy (mutation cannot make check_C history-dependent)', (() => { const a = P.evidenceCaps('pow-header-chain'); try { a.push('forged'); } catch {} return Object.isFrozen(a) && !P.evidenceCaps('pow-header-chain').includes('forged'); })());
  check('PhC uniqueness for a DIFFERENT checkpoint → not admitted (binding)', VU([P.buildUniquenessAttestation({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: 'sha256:' + '00'.repeat(32) }, Wa.priv, Wa.pubB64), ua(Wb)]).attested === false);

  // ── M5 (UST-6vj) — ONE QUORUM ALGEBRA: admit → group → count → adjudicate; uniqueness and recovery are instances.
  const Wd = kp('44'.repeat(32));
  const roots4 = { ...trustRoots, [Wd.key_id]: Wd.pubB64 }, doms4 = { ...domains, [Wd.key_id]: 'op-d' };
  const VU4 = (atts) => P.verifyCheckpointUniqueness(atts, { domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, trustRoots: roots4, domains: doms4, threshold: 2 });
  check('M5 quorum-poison closed: an UNAUTHENTICATED first claim-variant cannot suppress the honest quorum (group AFTER admission)',
    (r => r.attested === true)(VU4([{ claim: P.checkpointUniquenessClaim({ domain_shard: D, genesis_epoch: EP, sequence: '0', checkpoint: headId, as_of: '2026-01-01T00:00:00Z' }), issuer_id: Wa.key_id, sig: { alg: 'Ed25519', key_id: Wa.key_id, pub: Wa.pubB64, sig: 'AA' } }, ua(Wa), ua(Wb)])));
  // round-34 P0-03 — M5 conflict determinism moved to the RECOVERY block: with the closed VOTE_CLAIM + binding, every
  // admitted uniqueness attestation for one checkpoint is BYTE-IDENTICAL, so a uniqueness quorum can never split into
  // two rival groups. Conflict is real only where the payload can differ (recovery: rival replacement authorities).
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
  const R1 = kp('71'.repeat(32)), R2 = kp('72'.repeat(32)), R3 = kp('73'.repeat(32)), R4 = kp('74'.repeat(32)), RX = kp('7f'.repeat(32));
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
  // round-34 P0-03 — M5 conflict determinism now lives HERE (recovery has a differing PAYLOAD; uniqueness cannot conflict
  // under the closed VOTE_CLAIM). Two RIVAL replacements each reaching the 2-of-4 quorum → conflict, order-independent.
  { const rKeys4 = { ...rKeys, [R4.key_id]: R4.pubB64 }; const VRc = (recs) => P.verifyCheckpointRecovery(recs, { domain_shard: D, genesis_epoch: EP, last_accepted_checkpoint: id0, effective_sequence: '1', recoveryKeys: rKeys4, threshold: 2 });
    check('M5 conflict determinism: two RIVAL claims each reaching quorum → conflict, never first-wins', (r => r.recovered === false && r.conflict === true)(VRc([stmt(rf(KR), R1), stmt(rf(KR), R2), stmt(rf(KR2), R3), stmt(rf(KR2), R4)])));
    check('M5 conflict is order-independent (reversed array → same conflict)', (r => r.recovered === false && r.conflict === true)(VRc([stmt(rf(KR2), R4), stmt(rf(KR2), R3), stmt(rf(KR), R2), stmt(rf(KR), R1)]))); }
  // round-34 P0-01/P0-02 — the public authority verifiers apply the kernel's closed typed ADT + strict Pub32 to every
  // signed witness, so a witness the kernel rejects (non-canonical Pub32 authority, unsigned extra sig field) roots/mints nothing.
  { const T2 = { generated_at: '2026-06-28T14:03:12Z', valid_from: '2026-06-28T14:00:00Z', valid_to: '2026-06-28T15:00:00Z' };
    const gk = kp('81'.repeat(32)), D2 = 'noosphere.md';
    const gen2 = P.seal(P.buildGenesis({ domain_shard: D2, ust_id: 'ust:20260701.00', key_id: gk.key_id }, T2, gk.pubB64, undefined, undefined, undefined, { key_id: gk.key_id, pub: gk.pubB64 }), gk.priv, gk.pubB64);
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', raw = Buffer.from(gk.pubB64, 'base64url'); let alias = null;
    for (const ch of alpha) { const c = gk.pubB64.slice(0, -1) + ch; try { const b = Buffer.from(c, 'base64url'); if (b.length === 32 && b.equals(raw) && b.toString('base64url') !== c) { alias = c; break; } } catch { /* not base64url */ } }
    check('R34 P0-01 a non-canonical Pub32 alias maps to the SAME key (keyId) but is not canonical', alias !== null && P.keyId(alias) === gk.key_id);
    const genBad = P.seal(P.buildGenesis({ domain_shard: D2, ust_id: 'ust:20260701.00', key_id: gk.key_id }, T2, gk.pubB64, undefined, undefined, undefined, { key_id: gk.key_id, pub: alias }), gk.priv, gk.pubB64);
    check('R34 P0-01 a genesis authority carrying a non-canonical Pub32 alias roots NO authority (strict Pub32 before keyId)', !P.resolveCheckpointRoots(genBad)?.genesisAuthority);
    const kl2 = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]), ctx2 = P.verifiedGenesisContext(gen2);
    const cp2 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D2, genesis_epoch: P.genesisEpoch(P.contentHash(gen2)), sequence: '0', active_genesis: P.contentHash(gen2), current_key_id: gk.key_id, keylog: { root: kl2.root, length: kl2.length, head: kl2.head } }), gk.priv, gk.pubB64);
    check('R34 P0-02 a checkpoint witness with an unsigned EXTRA sig field → INVALID (closed { body, sig } — no checkpoint-id malleability)', (r => r.result === 'INVALID' && r.error === 'E-MALFORMED')(P.verifyAuthorityCheckpointChain([{ ...cp2, sig: { ...cp2.sig, extra: 'unsigned-malleability' } }], { context: ctx2 })));
    check('R34 P0-02 the genuine checkpoint is STILL VALID (kernel-aligned, no over-reject)', P.verifyAuthorityCheckpointChain([cp2], { context: ctx2 }).result === 'VALID'); }
  // round-35 P0-01/03 — the ONE admitSigner choke-point: EVERY signed authority witness binds issuer_id === sig.key_id
  // === keyId(pub) over an EXACT Ed25519 wrapper. A foreign sig.key_id / alg:RSA / extra wrapper or envelope field admits nothing.
  { const W1 = kp('92'.repeat(32)), W2 = kp('93'.repeat(32)), D3 = 'noosphere.md', EP3 = P.genesisEpoch('sha256:' + '33'.repeat(32)), CK3 = 'sha256:' + 'bb'.repeat(32), AG3 = 'sha256:' + 'aa'.repeat(32), foreign = 'sha256:' + 'cc'.repeat(32);
    const ua3 = (W) => P.buildUniquenessAttestation({ domain_shard: D3, genesis_epoch: EP3, sequence: '0', checkpoint: CK3 }, W.priv, W.pubB64);
    const fk = (att) => ({ ...att, sig: { ...att.sig, key_id: foreign } });   // swap sig.key_id to a foreign valid hash (issuer_id + sig.pub stay genuine)
    const uCfg = { domain_shard: D3, genesis_epoch: EP3, sequence: '0', checkpoint: CK3, trustRoots: { [W1.key_id]: W1.pubB64, [W2.key_id]: W2.pubB64 }, domains: { [W1.key_id]: 'op-a', [W2.key_id]: 'op-b' }, threshold: 2 };
    check('R35 P0-01 uniqueness sig.key_id ≠ issuer (admitSigner binds issuer===key_id===keyId(pub)) → NOT attested', P.verifyCheckpointUniqueness([fk(ua3(W1)), fk(ua3(W2))], uCfg).attested === false);
    check('R35 P0-01 the genuine uniqueness quorum is STILL attested (no over-reject)', P.verifyCheckpointUniqueness([ua3(W1), ua3(W2)], uCfg).attested === true);
    const nf = P.buildNoForkEvidence({ domain_shard: D3, active_genesis: AG3 }, W1.priv, W1.pubB64), nfCfg = { domain_shard: D3, active_genesis: AG3, trustRoots: { [W1.key_id]: W1.pubB64 } };
    check('R35 P0-03 no-fork GENUINE witness → ok (now in the closed-ADT sweep)', P.verifyNoForkEvidence(nf, nfCfg).ok === true);
    check('R35 P0-03 no-fork open sig (alg:RSA + foreign key_id + extra wrapper field) → ok:false', P.verifyNoForkEvidence({ ...nf, sig: { ...nf.sig, alg: 'RSA', key_id: foreign, extra: 'x' } }, nfCfg).ok === false);
    check('R35 P0-03 no-fork extra ENVELOPE field → ok:false (closed { claim, issuer_id, sig })', P.verifyNoForkEvidence({ ...nf, rogue: 'x' }, nfCfg).ok === false);
    check('R35 P0-03 no-fork foreign sig.key_id → ok:false', P.verifyNoForkEvidence({ ...nf, sig: { ...nf.sig, key_id: foreign } }, nfCfg).ok === false);
    check('R35 no-fork self-declared valid_as_of in the signed claim → ok:false (assurance-never-self-declared; time is not a signer field)', (() => { const cl = { purpose: 'ust:name-no-fork', domain_shard: D3, active_genesis: AG3, valid_as_of: '2026-01-01T00:00:00Z' }; const sg = sign(null, Buffer.from(P.canon(cl), 'utf8'), W1.priv).toString('base64url'); return P.verifyNoForkEvidence({ claim: cl, issuer_id: W1.key_id, sig: { alg: 'Ed25519', key_id: W1.key_id, pub: W1.pubB64, sig: sg } }, nfCfg).ok === false; })());
    // structural gate — the admitSigner choke-point rejects EVERY sig-wrapper tampering class (machine-check: a wrapper divergence can't ship)
    check('R35 admitSigner gate: every sig-wrapper tampering on a genuine attestation → NOT attested; only the genuine wrapper passes', (() => {
      if (P.verifyCheckpointUniqueness([ua3(W1), ua3(W2)], uCfg).attested !== true) return false;
      const muts = [(s) => ({ ...s, alg: 'RSA' }), (s) => ({ ...s, alg: '' }), (s) => ({ ...s, alg: 'Ed448' }), (s) => ({ ...s, key_id: foreign }), (s) => { const { key_id, ...r } = s; return r; }, (s) => ({ ...s, pub: W2.pubB64 }), (s) => ({ ...s, extra: 'x' }), (s) => { const { sig, ...r } = s; return r; }];
      return muts.every((m) => P.verifyCheckpointUniqueness([{ ...ua3(W1), sig: m(ua3(W1).sig) }, ua3(W2)], uCfg).attested === false);
    })()); }
  // round-36 P1-01/P1-02 — the nested authority pair binds key_id===keyId(pub) (admitAuthorityKey); the crypto LEAF
  // (edVerifyStrict) enforces canonical Pub32/Sig64, so a non-canonical alias never verifies (every caller is safe).
  { const A = kp('a1'.repeat(32)), msg = 'ust-round36-leaf-test', sg = sign(null, Buffer.from(msg, 'utf8'), A.priv).toString('base64url');
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const aliasOf = (s, len) => { const raw = Buffer.from(s, 'base64url'); for (const ch of alpha) { const c = s.slice(0, -1) + ch; try { const b = Buffer.from(c, 'base64url'); if (b.length === len && b.equals(raw) && b.toString('base64url') !== c) return c; } catch { /* not base64url */ } } return null; };
    check('R36 P1-02 edVerifyStrict verifies a genuine canonical Ed25519 signature', P.edVerifyStrict(A.pubB64, msg, sg) === true);
    check('R36 P1-02 edVerifyStrict REJECTS a non-canonical Sig64 alias (same 64 bytes, different wire) — canonical enforced at the crypto leaf', (() => { const a = aliasOf(sg, 64); return a !== null && P.edVerifyStrict(A.pubB64, msg, a) === false; })());
    check('R36 P1-02 edVerifyStrict REJECTS a non-canonical Pub32 alias (same 32 bytes, different wire)', (() => { const a = aliasOf(A.pubB64, 32); return a !== null && P.edVerifyStrict(a, msg, sg) === false; })());
    check('R36 P1-01 admitAuthorityKey rejects a contradictory { key_id of A, pub of B } pair (via transition destination) — usable only if key_id === keyId(pub)', (() => { const B = kp('a2'.repeat(32)); const claim = { purpose: 'ust:genesis-epoch-transition', domain_shard: 'noosphere.md', from_genesis_epoch: 'sha256:' + '11'.repeat(32), from_final_checkpoint: 'sha256:' + '22'.repeat(32), from_sequence: '0', to_active_genesis: 'sha256:' + '33'.repeat(32), to_initial_sequence: '0', to_genesis_epoch: P.genesisEpoch('sha256:' + '33'.repeat(32)), to_checkpoint_authority: { key_id: A.key_id, pub: B.pubB64 } }; const sg2 = sign(null, Buffer.from(P.canon(claim), 'utf8'), A.priv).toString('base64url'); return P.verifyEpochTransition({ claim, issuer_id: A.key_id, sig: { alg: 'Ed25519', key_id: A.key_id, pub: A.pubB64, sig: sg2 } }, { domain_shard: 'noosphere.md', from_genesis_epoch: 'sha256:' + '11'.repeat(32), from_final_checkpoint: 'sha256:' + '22'.repeat(32), from_sequence: '0', fromAuthority: { key_id: A.key_id, pub: A.pubB64 } }).ok === false; })()); }
  // round-37 P0-01/P1-01 — R1 (admit input) UNIFIED to the last two levels: a Merkle co-path admits every sibling as a
  // canonical hash (no `+` coercion grammar, no host throw), and the lattice ops admit both operands into the product.
  { const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32), 'sha256:' + 'cd'.repeat(32)]);
    check('R37 P0-01 a GENUINE key-log terminality proof is still terminal (no over-reject)', P.verifyKeylogTerminality({ root: kl.root, length: kl.length, head: kl.head }, { headProof: kl.headProof }).terminal === true);
    for (const bad of [[], {}, null, 5, 'not-a-hash', 'SHA256:' + 'AB'.repeat(32), 'sha256:' + 'ab'.repeat(20)]) {
      const r = P.verifyKeylogTerminality({ root: kl.root, length: kl.length, head: kl.head }, { headProof: { index: kl.headProof.index, siblings: [bad] } });
      check('R37 P0-01 key-log Merkle sibling ' + JSON.stringify(bad) + ' (not a canonical hash) → not terminal, NO host throw', !!r && r.terminal === false);
    }
    const good = { integrity: 'valid', identity: 'authoritative', freshness: 'fresh', time: 'anchored' }, ood = { ...good, freshness: 'NOT_AN_AXIS' };
    const floor = { integrity: 'invalid', identity: 'self-asserted', freshness: 'unverified', time: 'unproven' };
    const noThrow = (fn) => { try { return fn(); } catch { return 'THREW'; } };   // round-39 P1-02 — the lattice is now TOTAL-by-return; a throw (even coded E-ASSURANCE) is a failure of the surface contract
    check('R37/R39 joinAssurance with an OUT-OF-DOMAIN operand → RETURNS the valid operand (⊥ contributes nothing, never synthesizes strength from garbage), never a throw', JSON.stringify(noThrow(() => P.joinAssurance(ood, good))) === JSON.stringify(good));
    check('R37/R39 meetAssurance with an out-of-domain operand → RETURNS ⊥ (fail-closed, under-reports), never a throw', JSON.stringify(noThrow(() => P.meetAssurance(ood, good))) === JSON.stringify(floor));
    check('R37/R39 assuranceLE with an out-of-domain operand → FALSE (an order we cannot establish is never asserted), never a throw', noThrow(() => P.assuranceLE(ood, good)) === false);
    check('R37 P1-01 joinAssurance of two VALID states still lifts (no over-reject)', P.projectTier(P.joinAssurance(good, { integrity: 'valid', identity: 'corroborated', freshness: 'unverified', time: 'unproven' })) === 'TOP'); }
  // round-38 P1-01/02/03 — R1/R3/R4 uniformity: assuranceState admits ONCE (no two-face), the exported evidence algebra
  // admits its operands (no host throw), and a caller resource scalar may only TIGHTEN the ceiling (never expand it).
  { const good = { integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' };
    let n = 0; const twoFace = new Proxy({ ...good }, { get(t, k) { if (k === 'identity') { n++; return n === 1 ? 'self-asserted' : 'authoritative'; } return t[k]; } });
    check('R38 P1-01 (R1/R3) assuranceState on a two-face Proxy emits the ADMITTED (first) face, not a stronger re-read', P.assuranceState(twoFace).identity === 'self-asserted');
    check('R38/R39 (R1) assuranceState on a hostile getter → RETURNS a reject sentinel (a symbol, mirrors admitDeep→ADMIT_REJECT), never a throw', (() => { const r = P.assuranceState(new Proxy({ a: '1' }, { get() { throw new Error('HOSTILE'); } })); return typeof r === 'symbol'; })());
    check('R38 P1-02 (R1) quorumTrustDomains on a Proxy list with a hostile Symbol.iterator → structured, never a host throw', (() => { const h = new Proxy([{ source_id: 'a' }], { get(t, k) { if (k === Symbol.iterator) throw new Error('HOSTILE'); return t[k]; } }); try { return typeof P.quorumTrustDomains(h, { domains: { a: 'op-a' }, threshold: 1 }).count === 'number'; } catch { return false; } })());
    check('R38 P1-02 (R1) compareEvidenceOrder on a hostile Proxy operand → unproven, never a host throw', (() => { const h = new Proxy({}, { get() { throw new Error('HOSTILE'); } }); try { return P.compareEvidenceOrder(h, h) === 'unproven'; } catch { return false; } })());
    check('R38 P1-03 (R4) verifyJson maxInputBytes:Infinity → structured E-MALFORMED, never an expanded ceiling', (r => r.error === 'E-MALFORMED' && /maxInputBytes|tighten/i.test(r.detail))(P.verifyJson('{}', { maxInputBytes: Infinity }))); }
  // round-39 P1-01/02 — R4 budget admission is UNIFORM (no `?? default` swallow of a refusal; every caller resource scalar
  // TIGHTENS or is refused) and the assurance lattice + bounds validator are TOTAL-by-return consumer surfaces (the door
  // returns a reject sentinel like admitDeep, so a hostile operand yields ⊥/false/'NONE'/a bounds string, never a host throw).
  { const H = () => new Proxy({}, { get() { throw new Error('HOSTILE'); }, ownKeys() { throw new Error('HOSTILE'); } });
    const kR9 = kp('39'.repeat(32));
    const docR9 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.14', key_id: kR9.key_id, class: 'observation' }, { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' }, { r: { kind: 'captured', value: { v: 'A' } } }), kR9.priv, kR9.pubB64);
    const vd = (o) => P.verify(docR9, { context: 'data', ...o });
    check('R39 P1-01 (R4) refBudget:Infinity → E-MALFORMED (a refused budget FAILS CLOSED, never coalesces to the 256-node default)', (r => r.error === 'E-MALFORMED' && /refBudget|tighten/i.test(r.detail))(vd({ provenanceDepth: 1, resolveRef: () => null, refBudget: Infinity })));
    check('R39 P1-01 (R4) refBudget:0 → E-MALFORMED (0 is not a positive integer of nodes)', (r => r.error === 'E-MALFORMED')(vd({ provenanceDepth: 1, resolveRef: () => null, refBudget: 0 })));
    check('R39 P1-01 (R4) maxSupportedBytes:0 → E-MALFORMED, never a falsy-bypass of the capability check', (r => r.error === 'E-MALFORMED' && /maxSupportedBytes|tighten/i.test(r.detail))(vd({ maxSupportedBytes: 0 })));
    check('R39 P1-01 (R4) maxSupportedBytes:Infinity → E-MALFORMED, never a disabled capability check', (r => r.error === 'E-MALFORMED')(vd({ maxSupportedBytes: Infinity })));
    check('R39 P1-01 (R4) maxSupportedBytes:NaN → E-MALFORMED, never a falsy-bypass', (r => r.error === 'E-MALFORMED')(vd({ maxSupportedBytes: NaN })));
    const capH = P.capAssurance({ integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' }, H());
    check('R39 P1-02 (R1) capAssurance with a HOSTILE consumer ceiling → RETURNS ⊥ (fail-closed cap), never a host throw', capH.integrity === 'invalid' && capH.identity === 'self-asserted' && capH.time === 'unproven');
    check('R39 P1-02 (R1) checkBounds on a HOSTILE doc → RETURNS a bounds refusal string, never a host throw', typeof (() => { try { return P.checkBounds(H()); } catch { return null; } })() === 'string');
    check('R39 P1-02 (R1) axisRank on a non-axis key → -1 (total), never a `undefined.indexOf` throw', (() => { try { return P.axisRank('NOT_AN_AXIS', 'x') === -1; } catch { return false; } })());
    check('R38 P1-03 (R4) verifyJson maxInputBytes below the ceiling still applies (a valid tighten is honored)', P.verifyJson('{"a":1}', { maxInputBytes: 3 }).reason === 'resource_limit'); }
  // round-40 P1-01/02 — the SYNC verify door admits opts (a two-face opts Proxy cannot show one maxSupportedBytes to the
  // budget and another to the enforcement guard — R1, the last un-admitted public opts door), and capAssurance treats ONLY
  // undefined/null as absent (a falsy or non-record ceiling is MALFORMED → ⊥, never a preserved TOP — R1 + F.5 gap-2).
  { const kR40 = kp('40'.repeat(32));
    const docR40 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.14', key_id: kR40.key_id, class: 'observation' }, { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' }, { r: { kind: 'captured', value: { v: 'A' } } }), kR40.priv, kR40.pubB64);
    let reads = 0;
    const twoFaceOpts = new Proxy({ context: 'data' }, { get(t, k, r) { if (k === 'maxSupportedBytes') { reads++; return reads === 1 ? 1 : undefined; } return Reflect.get(t, k, r); } });
    const ex = P.verify(docR40, twoFaceOpts);
    check('R40 P1-01 (R1) sync verify admits opts ONCE — verifyCore never re-reads the live opts Proxy (a two-face maxSupportedBytes trap fires 0×)', reads === 0 && typeof ex.result === 'string');
    check('R40 P1-01 (R1) the two-face opts verdict is DETERMINISTIC (no compute-limit-then-skip; same input → same verdict)', P.verify(docR40, twoFaceOpts).result === ex.result);
    const top = { integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' };
    check('R40 P1-02 (R1) every MALFORMED capAssurance ceiling (falsy scalar / non-record / array: false,0,"",NaN,[],1,"x",true) → ⊥ (projectTier NONE), never a preserved TOP', [false, 0, '', Number.NaN, [], 1, 'x', true].every((c) => P.projectTier(P.capAssurance(top, c)) === 'NONE'));
    check('R40 P1-02 only a genuinely ABSENT ceiling (undefined/null) is identity; a partial record caps per axis', P.projectTier(P.capAssurance(top, undefined)) === 'TOP' && P.projectTier(P.capAssurance(top, null)) === 'TOP' && P.projectTier(P.capAssurance(top, { identity: 'self-asserted' })) === 'LIGHT'); }
  // round-41 P1-01/02 — the admitOpts snapshot is FROZEN (a preserved capability's `this`-write cannot mutate policy → no
  // LIGHT→HIGH flip; R1 inert = IMMUTABLE), and the authority SELECTORS (genesis, pinnedKeys) treat a PRESENT falsy/non-record
  // value as MALFORMED not absent (falsy ≠ absent, swept from capAssurance to resolveAuthority + the verifyCore opts door).
  { const gK = kp('a1b2'.repeat(16));
    const T41 = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const gen41 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK.key_id }, T41, gK.pubB64, 256, 1048576, '3600'), gK.priv, gK.pubB64);
    const doc41 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.14', key_id: gK.key_id, class: 'observation' }, T41, { r: { kind: 'captured', value: { v: 'A' } } }), gK.priv, gK.pubB64);
    const deriv41 = P.seal(P.buildDerivation({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.15', key_id: gK.key_id }, T41, { r: { kind: 'computed', value: { v: 'A' } } }, [{ hash: 'sha256:' + '0'.repeat(64), url: 'https://x' }]), gK.priv, gK.pubB64);
    let sawFrozen = null;
    P.verify(deriv41, { context: 'data', provenanceDepth: 1, resolveRef: function () { sawFrozen = Object.isFrozen(this); return null; } });
    check('R41 P1-01 (R1) the admitted opts snapshot handed to a capability as `this` is FROZEN (inert) — a resolveRef cannot mutate policy (acceptConsumerOverride) to flip LIGHT→HIGH', sawFrozen === true);
    check('R41 P1-02 (R1) resolveAuthority with a PRESENT falsy/scalar/array genesis → E-GENESIS (falsy ≠ absent), never a silent self-asserted', [false, 0, '', Number.NaN, [], 1, 'x'].every((g) => P.resolveAuthority(doc41, { genesis: g }).error === 'E-GENESIS'));
    check('R41 P1-02 only a genuinely ABSENT genesis (undefined/null) is self-asserted; a valid genesis resolves (no over-reject)', P.resolveAuthority(doc41, {}).strength === 'self-asserted' && P.resolveAuthority(doc41, { genesis: null }).strength === 'self-asserted' && !P.resolveAuthority(doc41, { genesis: gen41 }).error);
    check('R41 P1-02 verify with a present malformed genesis → E-GENESIS (the verifyCore opts.genesis door, not only resolveAuthority)', P.verify(doc41, { context: 'data', genesis: false }).error === 'E-GENESIS');
    // round-53 — R41 pinnedKeys sibling REMOVED: the pinned/TOFU rung and opts.pinnedKeys no longer exist.
    check('R41 P1-02 verifyStream sibling (self-audit sweep) — a PRESENT falsy/scalar genesis or checkpoint in config → complete:none with a MALFORMED detail, never silently provisional', /malformed|inert record/i.test(P.verifyStream([], { genesis: false }).detail || '') && /malformed|inert record/i.test(P.verifyStream([], { checkpoint: 0 }).detail || '')); }
  // round-42 P0-01/P1-01/P1-02 — the key-log ARRAY is DEEP-admitted (a two-face entry cannot show a signed key to verify and an
  // unsigned key to the reducer re-reads); an unminted servedNoFork DIVERTS from corroborated but is NOT liftable to HIGH; and
  // the GRANT booleans (acceptConsumerOverride/noForkConfirmed/corroborated) admit strictly (a truthy "false" is MALFORMED).
  { const gK = kp('c1d2'.repeat(16)), aB = kp('b0b0'.repeat(16)), aC = kp('c0c0'.repeat(16));
    const T42 = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const gen42 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK.key_id }, T42, gK.pubB64, 256, 1048576, '3600'), gK.priv, gK.pubB64);
    const doc42 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.14', key_id: gK.key_id, class: 'observation' }, T42, { r: { kind: 'captured', value: { v: 'A' } } }), gK.priv, gK.pubB64);
    const addB = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.01', key_id: gK.key_id, class: 'key' }, { ...T42, generated_at: '2026-07-20T02:00:00Z' }, { key_op: { kind: 'captured', value: { op: 'add', key_id: aB.key_id, pub: aB.pubB64 } } }, { prev: P.contentHash(gen42) }), gK.priv, gK.pubB64);
    let rd = 0;
    const twoFace = new Proxy(addB, { get(t, k, r) { if (k === 'state') { rd++; if (rd > 1) { const s = JSON.parse(JSON.stringify(t.state)); s.data.key_op.value.key_id = aC.key_id; s.data.key_op.value.pub = aC.pubB64; return s; } } return Reflect.get(t, k, r); } });
    const rk = P.resolveKeys(gen42, [twoFace]);
    check('R42 P0-01 (R1/R3) resolveKeys DEEP-admits the key-log — a two-face entry (signed key B / unsigned key C) never authorizes C (structured error OR authorizes only B)', !!rk.error || (rk.validKeys && !rk.validKeys.has(aC.key_id)));
    const ex = P.verify(doc42, { context: 'data', genesis: gen42, servedNoFork: {}, acceptConsumerOverride: true });
    check('R42 P1-01 (R1) an unminted servedNoFork + acceptConsumerOverride does NOT reach HIGH (override_liftable:false), yet still ≠ corroborated (rc35-P0a)', ex.result !== 'VALID:HIGH' && ex.tier !== 'TOP' && P.verify(doc42, { genesis: gen42, servedNoFork: { confirmed: true, active_genesis: P.contentHash(gen42) }, context: 'data' }).identity?.strength !== 'corroborated');
    check('R42 P1-01 the LEGIT explicit-axiom override still lifts (noForkConfirmed:true + acceptConsumerOverride:true → VALID:HIGH)', P.verify(doc42, { context: 'data', genesis: gen42, noForkConfirmed: true, acceptConsumerOverride: true }).result === 'VALID:HIGH');
    check('R42 P1-02 (R1) a wrong-typed GRANT boolean → E-MALFORMED (acceptConsumerOverride:"false" is truthy; noForkConfirmed:"yes")', P.verify(doc42, { context: 'data', genesis: gen42, noForkConfirmed: true, acceptConsumerOverride: 'false' }).error === 'E-MALFORMED' && P.verify(doc42, { context: 'data', genesis: gen42, noForkConfirmed: 'yes' }).error === 'E-MALFORMED');
    check('R42 P1-02 resolveKeys rejects a PRESENT non-array keylog → E-MALFORMED (verifyStream delegates here, no longer coalescing false→[])', P.resolveKeys(gen42, false).error === 'E-MALFORMED' && P.resolveKeys(gen42, undefined).error === undefined); }
  // round-43 P1-01/P1-02 — the STRUCTURAL closure of the coerced-boolean + falsy-selector classes (they recurred FOUR rounds
  // because each fix was per-SITE). A FROM-CODE gate: (a) NO authority selector may use the `Array.isArray(X) ? X : []` coalesce
  // (it silently empties a present malformed selector); (b) every require*/allow*/acceptConsumerOverride grant boolean is
  // REGISTERED (a new one fails until admitted + probed); (c) each grant boolean + selector has an adversarial probe.
  // round-49 P1-02 (STRUCTURAL guard) — FROM-CODE byte-door inventory. The verifyJson budget bypass (and the rev74 resolver
  // getter hazard before it) both slipped in because a NEW raw-byte read was added WITHOUT routing through the intrinsic door.
  // Scan index.mjs for the byte-admission-hazard patterns — `Buffer.from(<obj>)` / `Uint8Array.from(<obj>)` with NO encoding (an
  // array-like runs its indexed getters) and a caller-object `.byteLength` read (overridable) — and require EACH to be an
  // ALLOWLISTED post-door (snapshotBytes/snapshotBinary immutable copy) or genuine-source form. A new occurrence FAILS until
  // reviewed, so the class cannot recur silently — the exact `rawBytes.byteLength ?? Buffer.from(rawBytes)` shape fires HERE.
  { const SAFE_FROM = new Set(['Buffer.from(gS.bytes)', 'Buffer.from(kCopy)', 'Buffer.from(cS.bytes)']);   // resolveKeysBytes/resolveCadenceBytes — snapshotBytes output, immutable
    const SAFE_BYTELEN = new Set(['buf.byteLength', 'bytes.byteLength']);   // buf = Buffer.from(await r.arrayBuffer()); bytes.byteLength = decodePackage's snapshotBytes-output immutable buffer (checkAuthorityProofBytes admits before calling it)
    const unaccounted = [];
    for (const mod of ['index.mjs', 'reference-checker.mjs']) {   // round-50 P1-03 — scan the WHOLE L1 TCB, not just index.mjs (a byte read moved to reference-checker.mjs would have evaded)
      readFileSync(new URL('../../packages/ust-protocol/' + mod, import.meta.url), 'utf8').split('\n').map((l) => l.replace(/\/\/.*$/, '')).forEach((l, i) => {
        for (const m of l.matchAll(/(?:Buffer|Uint8Array)(?:\.from|\[['"]from['"]\])\(([a-zA-Z_][\w.]*)\)/g)) if (!SAFE_FROM.has('Buffer.from(' + m[1] + ')')) unaccounted.push(`${mod}:${i + 1} ${m[0]}`);   // round-50 P1-03 — also catch bracket `Buffer["from"](x)`
        for (const m of l.matchAll(/\b([a-zA-Z_]\w*)(?:\.byteLength\b|\[['"]byteLength['"]\])/g)) { if (m[1] === 'Buffer') continue; if (!SAFE_BYTELEN.has(m[1] + '.byteLength')) unaccounted.push(`${mod}:${i + 1} ${m[0]}`); }   // round-50 P1-03 — also catch computed `x["byteLength"]`
      });
    }
    // round-50 P1-03 — HONEST scope: this is a heuristic LINT over the L1 TCB (index + reference-checker) catching the DIRECT
    // byte-read shapes (dot + bracket `.from`, dot + computed `.byteLength`). It is NOT a proof — an alias (`const f = Buffer.from`),
    // helper indirection, or `new Uint8Array(arraylike)` can still evade a regex (GPT round-50 P1-03; a complete guarantee needs an
    // AST rule). The REAL proof that the doors are used is the BEHAVIORAL totality test below (hostile input → structured reject).
    check('BYTE-DOOR LINT (heuristic, index + reference-checker): every DIRECT raw-byte read (dot/bracket Buffer|Uint8Array.from(<obj>), dot/computed caller .byteLength) is an allowlisted post-door/genuine form — a new one fails until routed through the door. NOT a proof (aliases/helpers/new-Uint8Array evade a regex; the behavioral totality test is the guarantee)' + (unaccounted.length ? ' — UNACCOUNTED: ' + unaccounted.join('; ') : ''), unaccounted.length === 0);
    // round-50 P1-03/P1-02 — the BEHAVIORAL guarantee (syntax-independent): drive every raw-byte ENTRY with hostile inputs and
    // assert a STRUCTURED verdict, NEVER a host throw and NEVER acting on a forged/overridable measurement. This holds regardless
    // of HOW the bytes are read inside — it is the property the lint only approximates.
    const enc0 = (o) => new Uint8Array(Buffer.from(JSON.stringify(o), 'utf8'));
    const hostiles = [
      new Proxy(new Uint8Array(8), { getPrototypeOf() { throw new Error('trap'); }, get() { throw new Error('trap'); } }),   // Proxy w/ throwing traps
      (() => { class E extends Uint8Array { get byteLength() { return 1; } } return new E(4096); })(),                        // subclass w/ forged byteLength
      (() => { const o = { length: 8 }; for (let i = 0; i < 8; i++) Object.defineProperty(o, i, { enumerable: true, get() { throw new Error('idx'); } }); return o; })(),   // array-like w/ throwing indexed getters
    ];
    let behavioralOk = true;
    for (const h of hostiles) {
      for (const call of [() => P.verifyJson(h, { maxInputBytes: 64 }), () => P.resolveKeysBytes(h, enc0([])), () => P.resolveCadenceBytes(h, enc0([]), 'ust:20260101.00', undefined), () => P.snapshotBytes(h), () => P.admitUtf8(h)]) {
        let r; try { r = call(); } catch { behavioralOk = false; break; }   // a host throw escaping any byte entry = FAIL
        if (!r || typeof r !== 'object') { behavioralOk = false; break; }    // must be a structured result, never undefined/primitive
      }
    }
    check('BYTE-DOOR BEHAVIORAL TOTALITY (the guarantee): every raw-byte entry (verifyJson / resolveKeysBytes / resolveCadenceBytes / snapshotBytes / admitUtf8) returns a STRUCTURED verdict on a hostile Proxy / forged-byteLength subclass / throwing-getter array-like — never a host throw, never acting on a forged measurement (round-50 P1-02/P1-03)', behavioralOk);
  }
  { const idxSrc = readFileSync(new URL('../../packages/ust-protocol/index.mjs', import.meta.url), 'utf8');
    const refSrc = readFileSync(new URL('../../packages/ust-protocol/reference-checker.mjs', import.meta.url), 'utf8');
    const src = idxSrc + '\n' + refSrc;   // round-44 P1-01 — the gate scans BOTH the resolver surface AND the byte-adapter (verifyAuthorityBundle lives in reference-checker.mjs; the rev52 gate scanned only index.mjs and missed it)
    const SELECTORS = ['keylog', 'genesis', 'checkpoint', 'pinnedKeys', 'cadenceLog', 'recoveryKeys', 'genesisAuthority', 'pinnedPrior'];
    const coalesced = SELECTORS.filter((s) => new RegExp('Array\\.isArray\\(' + s + '\\)\\s*\\?\\s*' + s + '\\b|\\b' + s + '\\s*\\|\\|\\s*(\\{\\}|\\[\\])').test(src));   // round-44 P1-01 — ban BOTH `Array.isArray(X)?X:d` AND `X || {}` / `X || []` for authority selectors (both silently replace a present malformed selector with a default)
    check('R43/R44 STRUCTURAL: no authority SELECTOR uses a coalesce (`Array.isArray(X)?X:d`, `X || {}`, `X || []`) — a present malformed selector is admitted, never silently emptied/defaulted' + (coalesced.length ? ' — FOUND: ' + coalesced.join(',') : ''), coalesced.length === 0);
    const REGISTERED = new Set(['requirePerFrameValid', 'allowExperimentalAttested', 'acceptConsumerOverride', 'noForkConfirmed', 'corroborated', 'requireAuthoritative', 'requireAnchored', 'requireFreshKeylog', 'offline', 'requireVersion']);   // requireVersion is a STRING version match, not a truthy grant — registered so the scan is exhaustive
    const found = new Set([...src.matchAll(/\b(require[A-Z][A-Za-z]+|allow[A-Z][A-Za-z]+|acceptConsumerOverride)\b/g)].map((m) => m[1]));
    const unregistered = [...found].filter((f) => !REGISTERED.has(f));
    check('R43/R44 STRUCTURAL: every require*/allow*/acceptConsumerOverride security-policy boolean in index.mjs + reference-checker.mjs is REGISTERED (a new grant flag fails until admitted + adversarially probed)' + (unregistered.length ? ' — UNREGISTERED: ' + unregistered.join(',') : ''), unregistered.length === 0);
    check('R44 P0-01 verifyAuthorityBundle injects NO threshold DEFAULT — the adapter passes the consumer policy through (no `Number.isInteger(...) ? ... : 2` fallback that manufactures a quorum the sole-checker refuses)', !/uniqueness_threshold:\s*Number\.isInteger\([^)]*\)\s*\?[^:]*:\s*\d/.test(refSrc));
    check('R44 P1-01 verifyAuthorityCheckpointChain rejects a PRESENT malformed authority selector (genesisAuthority:false / recoveryKeys:0) → E-MALFORMED, never silently overridden or coalesced to {}', P.verifyAuthorityCheckpointChain([], { genesisAuthority: false }).error === 'E-MALFORMED' && P.verifyAuthorityCheckpointChain([], { recoveryKeys: 0 }).error === 'E-MALFORMED');
    const gK = kp('d1e2'.repeat(16)), T43 = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const gen43 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK.key_id }, T43, gK.pubB64, 256, 1048576, '3600'), gK.priv, gK.pubB64);
    check('R43 P1-01 verifyStream requirePerFrameValid:0 (a falsy non-boolean) → structured malformed, never DISABLES per-frame X2 signature verification', /boolean|malformed/i.test(P.verifyStream([], { genesis: gen43, requirePerFrameValid: 0 }).detail || '') && P.verifyStream([], { genesis: gen43, requirePerFrameValid: 0 }).complete !== 'complete');
    check('R43 P1-01 deriveCheckpointFreshness allowExperimentalAttested:"false" (a truthy non-boolean) → INVALID, never ENABLES the experimental attested rung', P.deriveCheckpointFreshness([], { allowExperimentalAttested: 'false' }).result === 'INVALID' && /boolean|malformed/i.test(P.deriveCheckpointFreshness([], { allowExperimentalAttested: 'false' }).detail || ''));
    check('R43 P1-02 resolveCadence keylog:false (present malformed selector) → E-MALFORMED, never coalesced to an empty (retirement-erasing) log', P.resolveCadence(gen43, [{ x: '1' }], undefined, { keylog: false }).error === 'E-MALFORMED');
    check('R43 P1-02 verifyAuthorityCheckpointChain genesis:false + a fallback genesisAuthority → NOT a silent VALID consumer-pin (a present malformed selector is rejected, never skipped to the fallback root)', P.verifyAuthorityCheckpointChain([], { genesis: false, genesisAuthority: { key_id: gK.key_id, pub: gK.pubB64 } }).result !== 'VALID');
    check('R43 legit boolean policy values still honored (requirePerFrameValid:false, allowExperimentalAttested defaults) — no over-reject', P.verifyStream([], { genesis: gen43, requirePerFrameValid: false }).error === undefined);
    const doc43 = P.seal(P.buildState({ domain_shard: gK.key_id, ust_id: 'ust:20260720.14', key_id: gK.key_id, class: 'observation' }, T43, { r: { kind: 'captured', value: { v: 'A' } } }), gK.priv, gK.pubB64);
    check('R43 the RESTRICTION booleans are measured too — a coerced requireAuthoritative:0 → E-MALFORMED, never a silently DROPPED requirement (a real boolean still restricts)', P.verify(doc43, { context: 'data', requireAuthoritative: 0 }).error === 'E-MALFORMED' && P.verify(doc43, { context: 'data', requireAuthoritative: true }).error === 'E-GENESIS' && P.verify(doc43, { context: 'data' }).result === 'VALID:LIGHT'); }
  // round-45 P0-01/P1-01/P1-02 — a SEMANTIC (behavioral, from-ENTRYPOINT) adapter/kernel gate, NOT a source regex: the prior gates
  // scanned text and stayed green while a public adapter (a) encoded the UNTRUSTED arg before the TRUSTED config (a hostile getter
  // rewrote the config the verdict used — cross-argument admission order), (b) returned a non-Freshness judgment as a public VALID,
  // and (c) normalized a malformed policy away instead of deferring to the sole-checker. These probes DRIVE the adapters and check
  // the invariant by BEHAVIOR, so a future adapter that re-reads the live graph or diverges from the kernel fails HERE.
  { const gK = kp('e5f6'.repeat(16)), Wa = kp('a1b2c3d4'.repeat(8));
    const T45 = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const gen45 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK.key_id }, T45, gK.pubB64, 256, 1048576, '3600'), gK.priv, gK.pubB64);
    const pkg = P.buildAuthorityProof({ genesis: gen45 });
    const mkCfg = () => ({ connectors: {}, witnesses: {}, domains: {}, mapRoots: [], policy: {} });
    const cfg2 = mkCfg(); let fired = false;
    const evilPkg = new Proxy(pkg, { get(t, k, r) { if (!fired) { fired = true; cfg2.witnesses[Wa.key_id] = Wa.pubB64; cfg2.domains[Wa.key_id] = 'attacker'; cfg2.policy.uniqueness_threshold = 1; } return Reflect.get(t, k, r); } });
    const base = P.checkAuthorityProof(pkg, mkCfg()), evil = P.checkAuthorityProof(evilPkg, cfg2);
    check('R45 P0-01 (R1/R3) checkAuthorityProof ISOLATES the trusted config — a hostile package getter cannot inject witnesses/threshold into the config the verdict uses (config encoded BEFORE package; identical config_id + verdict)', base.result === evil.result && base.config_id !== undefined && base.config_id === evil.config_id);
    const cfgB = { trust: { connectors: {}, witnesses: {}, domains: {} }, policy: {} };
    let tjFired = false;
    const evilInputs = { genesis: gen45, toJSON() { tjFired = true; cfgB.trust.witnesses[Wa.key_id] = Wa.pubB64; cfgB.trust.uniqueness_threshold = 1; return { genesis: gen45 }; } };
    const bEvil = P.verifyAuthorityBundle(evilInputs, cfgB);
    check('R45/R46 (R1/R3) verifyAuthorityBundle REDUCES its inputs side-effect-free — a hostile inputs.toJSON is REJECTED and NEVER EXECUTED, so it cannot mutate the trusted config the verdict uses (the automaton reads its input as DATA, never runs it)', tjFired === false && Object.keys(cfgB.trust.witnesses).length === 0 && typeof bEvil.result === 'string');
    check('R45 P1-01 verifyAuthorityBundle DIFFERENTIAL vs the sole checker — a malformed policy is INVALID at the adapter too, never normalized away to {}', (r => r.result === 'INVALID' && /policy|config/i.test(r.reason || ''))(P.verifyAuthorityBundle({ genesis: gen45 }, { trust: { connectors: {} }, policy: 'not-a-record' })));
    check('R45 P1-01 verifyAuthorityBundle success is EXCLUSIVE to a Freshness judgment — a Genesis-only proof → INDETERMINATE authority_unresolved, never a public VALID', P.verifyAuthorityBundle({ genesis: gen45 }, { trust: {}, policy: {} }).result !== 'VALID');
    check('R46 checkAuthorityProof REDUCES the config side-effect-free — a config accessor getter is NEVER executed (the automaton reads DATA, never runs it; this SUPERSEDES the rev45 source-level admission order — no code runs at the boundary at all)', (() => { let cg = 0; const c = { connectors: {} }; Object.defineProperty(c, 'witnesses', { enumerable: true, get() { cg++; return {}; } }); P.checkAuthorityProof(P.buildAuthorityProof({ genesis: gen45 }), c); return cg === 0; })());
    check('R46 (Theorem R — ρ_package) checkAuthorityProof reads the SIGNED package ONCE — a two-face term Proxy (a different term on re-read) yields the SAME verdict as the honest package (referencedIds and canon see the ONE admitted [[Get]] face; no split)', (() => { let n = 0; const real = P.buildAuthorityProof({ genesis: gen45 }); const tf = new Proxy(real, { get(t, k, r) { if (k === 'term') { n++; return n === 1 ? t.term : { rule: 'Tampered', children: [], witnesses: [] }; } return Reflect.get(t, k, r); } }); const cfg = { connectors: {}, witnesses: {}, domains: {}, policy: {} }; const a = P.checkAuthorityProof(tf, cfg), b = P.checkAuthorityProof(P.buildAuthorityProof({ genesis: gen45 }), cfg); return a.result === b.result && (a.config_id === b.config_id || (a.reason && a.reason === b.reason)); })());
    check('R46 (Theorem R) checkAuthorityProof = A ∘ (ρ_package, ρ_config) — a declared ACCESSOR anywhere in the package is REJECTED (not inert), never a VALID verdict', (() => { const evil = { term: { get rule() { return 'Genesis'; }, children: [], witnesses: [] }, witnesses: {} }; return P.checkAuthorityProof(evil, { connectors: {}, witnesses: {}, domains: {}, policy: {} }).result === 'INVALID'; })()); }
  // round-46 self-audit (Theorem R — trusted-before-untrusted, swept to the OBJECT-form sync verify surface) — the r45
  // cross-argument mutation class also lived in verify/resolveAuthority/verifyAnchor: each admits the UNTRUSTED signed arg
  // via admitDeep, which reads its [[Get]] face and FIRES a hostile getter; when the TRUSTED opts were admitted AFTER, that
  // getter mutated the still-live opts (requireAuthoritative / trustRoots / substrateVerify) the verdict reads. The fix admits
  // opts FIRST. These probes DRIVE each entry with an untrusted-arg getter that mutates the live opts and assert the verdict is
  // INVARIANT vs benign — a future public entry that admits untrusted-before-config fails HERE, from the entrypoint.
  { const gK46 = kp('c7d8'.repeat(16));
    const T46 = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const doc46 = P.seal(P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.14', key_id: gK46.key_id, class: 'observation' }, T46, { r: { kind: 'captured', value: { v: 'A' } } }), gK46.priv, gK46.pubB64);
    { const opts = { context: 'data', requireAuthoritative: true }; const evilDoc = new Proxy(doc46, { get(t, k, r) { opts.requireAuthoritative = false; opts.acceptConsumerOverride = true; return Reflect.get(t, k, r); } });
      const base = P.verify(doc46, { context: 'data', requireAuthoritative: true }), evil = P.verify(evilDoc, opts);
      check('R46 self-audit (Theorem R) verify admits the TRUSTED opts BEFORE the untrusted doc — a doc getter that drops requireAuthoritative cannot rewrite the consumer policy the verdict uses (INVALID stays INVALID; cross-argument order, sync path)', base.result === evil.result && base.result === 'INVALID'); }
    { const opts = {}; const evilDoc = new Proxy(doc46, { get(t, k, r) { opts.trustRoots = [{ domain_shard: 'noosphere.md', key_id: gK46.key_id }]; opts.corroborated = true; return Reflect.get(t, k, r); } });
      const base = JSON.stringify(P.resolveAuthority(doc46, {})), evil = JSON.stringify(P.resolveAuthority(evilDoc, opts));
      check('R46 self-audit (Theorem R) resolveAuthority admits opts BEFORE the doc — a doc getter cannot inject trustRoots/corroborated into the live opts the resolution reads (identical identity output)', base === evil); }
    { const ch = 'sha256:' + 'a'.repeat(64); const root = 'sha256:' + createHash('sha256').update('ust:leaf' + ch).digest('hex'); const proof = { root, path: [] };
      const opts = {}; const evilProof = new Proxy(proof, { get(t, k, r) { opts.substrateVerify = () => ({ final: true, time: '2026-07-20T02:00:00Z' }); return Reflect.get(t, k, r); } });
      const base = JSON.stringify(P.verifyAnchor(ch, proof, {})), evil = JSON.stringify(P.verifyAnchor(ch, evilProof, opts));
      check('R46 self-audit (Theorem R) verifyAnchor admits opts BEFORE the proof — a proof getter cannot inject substrateVerify (the substrate oracle) into the live opts; guard read and call read see the same frozen opts (identical status)', base === evil); } }
  // round-47 P0-01 (the CALCULATOR boundary — signed-vs-signed cross-argument mutation) — Theorem R's "reductions independent,
  // ORDER irrelevant" was FALSE for ≥2 live SIGNED arguments (GPT round-47): admitDeep executes the [[Get]] face, so reducing a
  // signed `genesis` fires a getter that empties the still-live signed `cadenceLog`/`keylog` BEFORE its own reduction, turning
  // E-KEY into a success. resolveCadence + resolveKeys now reduce every live argument to canonical BYTES at the door (the
  // mutation-vulnerable structural arg BEFORE the self-verifying genesis). This BEHAVIORAL gate drives each entry with a hostile
  // genesis getter that empties the sibling and asserts the verdict is INVARIANT vs the benign call — a future multi-signed-arg
  // entry that reduces a live signed arg before capturing its sibling fails HERE, from the entrypoint.
  { const gK47 = kp('9a8b'.repeat(16));
    const T47 = { generated_at: '2026-07-20T00:00:00Z', valid_from: '2026-07-20T00:00:00Z', valid_to: '2026-08-20T00:00:00Z' };
    const gen47 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK47.key_id }, T47, gK47.pubB64, 256, 1048576, '3600'), gK47.priv, gK47.pubB64);
    { const benign = JSON.stringify(P.resolveCadence(gen47, [{ x: '1' }], 'ust:20260720.01', {}));
      const log = [{ x: '1' }]; const evilGen = new Proxy(gen47, { get(t, k, r) { log.length = 0; return Reflect.get(t, k, r); } });
      const evil = JSON.stringify(P.resolveCadence(evilGen, log, 'ust:20260720.01', {}));
      check('R47 P0-01 (calculator boundary) resolveCadence — a signed genesis getter cannot empty the still-live signed cadenceLog before its reduction (canonical bytes captured at the door; attacked verdict == benign)', benign === evil); }
    { const rkSig = (r) => r.error ? 'E:' + r.error : [...r.active.keys()].sort().join(',') + '|' + [...r.validKeys.keys()].sort().join(',');
      const benign = rkSig(P.resolveKeys(gen47, [{ x: '1' }]));
      const kl = [{ x: '1' }]; const evilGen = new Proxy(gen47, { get(t, k, r) { kl.length = 0; return Reflect.get(t, k, r); } });
      const evil = rkSig(P.resolveKeys(evilGen, kl));
      check('R47 P0-01 (calculator boundary) resolveKeys — a signed genesis getter cannot empty the still-live signed keylog before its reduction (canonical bytes captured at the door; attacked resolved-set == benign)', benign === evil); } }
  // round-47 (rev69 structural rework — the CALCULATOR boundary is now a distinct EXPORT, claim bound to mechanism) —
  // resolveCadenceBytes is a pure function of immutable byte-strings (order-independent BY CONSTRUCTION: a byte-string cannot
  // mutate a sibling, JSON.parse runs no caller code) and IS the sound public boundary; the object resolveCadence is a CONVENIENCE
  // adapter that faithfully delegates to it (same verdict on the same data). This closes the rev65 over-label "migrated to bytes".
  { const gK69 = kp('7c6d'.repeat(16));
    const T69 = { generated_at: '2026-07-20T00:00:00Z', valid_from: '2026-07-20T00:00:00Z', valid_to: '2026-08-20T00:00:00Z' };
    const gen69 = P.seal(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.00', key_id: gK69.key_id }, T69, gK69.pubB64, 256, 1048576, '3600'), gK69.priv, gK69.pubB64);
    const enc69 = (o) => new Uint8Array(Buffer.from(P.canon(o), 'utf8'));
    const rBytes = P.resolveCadenceBytes(enc69(gen69), enc69([]), 'ust:20260720.01', undefined);
    const rObj = P.resolveCadence(gen69, [], 'ust:20260720.01', {});
    check('R47 (rev69 structural) resolveCadenceBytes IS the sound bytes-in boundary (pure function of immutable byte-strings, order-independent by construction) and the object resolveCadence adapter faithfully delegates to it (identical verdict on the same data)', JSON.stringify(rBytes) === JSON.stringify(rObj) && rBytes.cadence === 3600);
    const kBytes = P.resolveKeysBytes(enc69(gen69), enc69([])), kObj = P.resolveKeys(gen69, []);
    check('R47 (rev70 structural) resolveKeysBytes IS the sound bytes-in boundary (immutable byte-strings, order-independent by construction) and the object resolveKeys adapter faithfully delegates (same resolved active-set on the same data)', !kBytes.error && kBytes.active.size === 1 && !kObj.error && kObj.active.size === 1);
    // round-48 P0-01 — the bytes-in door must ENFORCE the immutable-byte-string domain, not assume it. GPT round-48: `Buffer.from`
    // runs an ARRAY-LIKE's indexed getters, so a getter in arg1 mutated the still-live bytes of arg2 BEFORE capture (a revoked key
    // restored → verdict flip). `snapshotBytes` now rejects a non-native-Uint8Array at the door, before any getter runs. PIN both
    // the honest native-Uint8Array path (a revoke retires the key) AND the attack (array-like arg1 → rejected, NO cross-arg flip).
    const T69b = { generated_at: '2026-07-20T01:00:00Z', valid_from: '2026-07-20T01:00:00Z', valid_to: '2026-08-20T01:00:00Z' };
    const revoke69 = P.seal(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260720.01', key_id: gK69.key_id }, T69b, { op: 'revoke', pub: gK69.pubB64, reason: 'retired' }, P.contentHash(gen69)), gK69.priv, gK69.pubB64);
    const gU = enc69(gen69), kU = enc69([revoke69]);
    const honestKB = P.resolveKeysBytes(gU, kU);
    const sib = new Uint8Array(kU);
    const evil = { length: gU.length };
    for (let i = 0; i < gU.length; i++) Object.defineProperty(evil, i, { enumerable: true, get() { if (i === 0) { sib.fill(0x20); sib.set(new Uint8Array(Buffer.from('[]', 'utf8'))); } return gU[i]; } });
    const attackedKB = P.resolveKeysBytes(evil, sib);
    check('R47 (rev70/round-48 P0-01) resolveKeysBytes ENFORCES the immutable-byte-string domain: a native-Uint8Array revoke retires the genesis key, AND an ARRAY-LIKE arg1 whose getter rewrites the sibling key-log to [] is REJECTED at the door (E-*) — never a cross-argument verdict flip that restores a revoked key', !honestKB.error && !honestKB.active.has(gK69.key_id) && !!attackedKB.error && !(attackedKB.active && attackedKB.active.has(gK69.key_id)));
    check('R47 (rev69/round-48 P0-01) resolveCadenceBytes likewise rejects an array-like byte argument at the door — snapshotBytes runs no caller getter before capture', !!P.resolveCadenceBytes(evil, enc69([]), 'ust:20260720.02', undefined).error); }
  // round-46 self-audit (totality) — combineSubstrates was the LONE public door the hand-maintained totality sweep
  // (round-17/18/19/24/38/39) never listed: a hostile `verifiers` Proxy (Array.isArray→true, then a throwing .filter/length
  // trap) SYNC-threw a host exception at its array-normalization. Now it fails CLOSED to an empty plugin list.
  check('R46 self-audit (totality) combineSubstrates on a HOSTILE verifiers Proxy → returns a combinator that claims no substrate (null/unavailable), NEVER a host throw at the array-normalization door', await (async () => {
    // round-48 P1-01 — the label promises TWO clauses (returns a combinator AND it claims no substrate); the old assertion
    // tested only `typeof fn === 'function'` and never CALLED the combinator, so a mutant returning a fault-injected 'anchored'
    // substrate stayed green. DRIVE the returned combinator with inert args and assert it yields null — the semantic floor.
    const hostile = new Proxy([{}], { get() { throw new Error('HOSTILE'); }, ownKeys() { throw new Error('HOSTILE'); }, getOwnPropertyDescriptor() { throw new Error('HOSTILE'); } });
    let fn; try { fn = P.combineSubstrates(hostile); } catch { return false; }   // no host throw at the array-normalization door
    if (typeof fn !== 'function') return false;                                  // clause 1: returns a combinator
    let r; try { r = await fn({}, 'root', {}); } catch { return false; }         // drive it (inert args) — still no throw
    return r === null;                                                           // clause 2: it claims NO substrate
  })());
  // round-46 self-audit (totality, FROM-CODE — closes the round-44 gate-completeness class at its root) — the totality sweep
  // was a HAND-maintained roster of exports, which is exactly why combineSubstrates fell out of it. Enumerate EVERY
  // verify*/resolve*/derive*/check*/combine*/fork*/no* export from the SOURCE and assert none SYNC-throws a host exception when
  // driven with a hostile Proxy (throwing get/ownKeys/descriptor traps) in every argument position. A new such export that
  // forgets to admit its input fails HERE — the source export list IS the roster, no hand-list to fall out of.
  check('R46 self-audit (totality, from-code) — NO public verifier/resolver export SYNC-throws a host exception on a hostile Proxy in every arg position (the SOURCE list is the roster; closes the combineSubstrates gate-completeness gap)', (() => {
    const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
    // INCLUSION is from-code: every verify*/resolve*/derive*/check*/combine*/fork*/no* export. EXCLUSION is a small,
    // PRINCIPLED, documented set (not a hand-roster of what to INCLUDE — the round-44 anti-pattern): a PRODUCER that
    // CONSTRUCTS prover data from TRUSTED args (`*Claim`: checkpointRecoveryClaim/checkpointUniquenessClaim/noForkClaim) is
    // not an untrusted-input boundary and may throw on a malformed trusted arg; `verifyOrThrow` is the throw-BY-CONTRACT
    // variant of `verify`. A new verifier (verifyX/resolveX/…) is auto-included; a new producer (X*Claim) auto-excluded.
    const isProducer = (n) => /Claim$/.test(n);
    const throwByContract = (n) => n === 'verifyOrThrow';
    const names = [...src.matchAll(/export\s+(?:async\s+)?function\s+((?:verify|resolve|derive|check|combine|fork|no)\w*)/g)].map((m) => m[1]).filter((n) => !isProducer(n) && !throwByContract(n));
    const mkHostile = () => new Proxy([{}], { get() { throw new Error('HOSTILE'); }, ownKeys() { throw new Error('HOSTILE'); }, getOwnPropertyDescriptor() { throw new Error('HOSTILE'); }, has() { throw new Error('HOSTILE'); } });
    const bad = [];
    for (const n of names) {
      const fn = P[n];
      if (typeof fn !== 'function') { bad.push(n + ' (not exported?)'); continue; }
      try { fn(mkHostile(), mkHostile(), mkHostile(), mkHostile()); } catch { bad.push(n); }   // a SYNC host throw at the door = totality breach (async entries return a Promise → no sync throw)
    }
    return bad.length === 0;
  })());
  // round-46 self-audit (rev59 — totality, from-code EXHAUSTIVE: sync AND async, EVERY export accounted for) — the rev58
  // roster covered only the verify*/resolve*/… prefix family and only SYNC throws; the assurance/evidence ALGEBRA ops
  // (assuranceState/capAssurance/compareEvidenceOrder/quorumTrustDomains/projectTier/deriveAssurance) and the 4 ASYNC entries
  // (verifyAsync/forkChoice/witnessNoFork/resolveByDiscovery) were outside it — held only by hand-checks (round-38/39). This
  // gate enumerates EVERY exported function and asserts each is TOTAL on a hostile Proxy (no sync host-throw, no async
  // promise-REJECTION) UNLESS explicitly classified MAY-THROW. So no export — present or future, sync or async, verifier or
  // algebra — is unaccounted; a new untrusted boundary that forgets to admit fails HERE.
  // round-47 P1-03 (roster completeness — RUNTIME NAMESPACE, not a source regex) — the rev59 gate enumerated
  // matchAll(/export function/) = 64 names but the module has 100 function-typed exports (GPT round-47): export-const ARROW
  // functions and RE-EXPORTS (`export { X } from './reference-checker.mjs'`) are invisible to the declaration regex — the miss
  // included the byte kernel `checkAuthorityProofBytes` ITSELF, `checkAuthorityProof`, `verifyAuthorityBundle`, `admitDeep`,
  // `contentHash`. So "totality enforced from the SOURCE export list" (rev58) and "roster made EXHAUSTIVE from-code" (rev59) were
  // BOTH overstated. This gate enumerates the RUNTIME MODULE NAMESPACE — every value whose runtime type is `function` — so an
  // arrow-const / re-export / future callable cannot evade it. Each is TOTAL on a hostile Proxy (no sync host-throw, no async
  // promise-rejection) UNLESS explicitly classified MAY-THROW; the MAY-THROW predicate covers EXACTLY the current throwers (no
  // verdict boundary exempted, no thrower unclassified — a new unclassified thrower fails HERE). All four round-47 findings
  // reproduced on live code; this closes P1-03 (bd UST-5t8).
  check('R47 P1-03 (roster completeness — RUNTIME namespace) — EVERY function-typed export of the module (100, incl. re-exports + arrow-consts + the byte kernel checkAuthorityProofBytes) is TOTAL on a hostile Proxy UNLESS explicitly classified MAY-THROW (producer / byte-string primitive / verdict class / throw-by-contract); a source-regex miss (arrow-const, re-export, future callable) can no longer evade the gate', await (async () => {
    // MAY-THROW = NOT an untrusted-object verdict boundary: a PRODUCER (build*/seal*/make*/*Claim/*Leaf/*Id/*Epoch) constructs
    // prover data from TRUSTED args; a byte/string PRIMITIVE (a Proxy is not a valid input); a verdict CLASS (Ust*, invoked with
    // `new`); the reduction primitive `admitDeep` (its 2nd arg is an internal `seen` set) + `isValid`/`verifiedEvidence` helpers;
    // `assertValid`/`verifyOrThrow` throw BY CONTRACT. Everything else — every verifier/resolver/combinator/algebra op — MUST be total.
    const MAY_THROW = MAY_THROW_TOTALITY;   // round-51 — ONE definition (module scope), cross-checked against R31 CLASS below
    // round-51 (owner: "структурно невозможное повторение из-за неполного покрытия") — the hostile fixture was ONE shape (a
    // throwing-trap Proxy), so a REVOKED Proxy (which throws on `Array.isArray`/`instanceof` ITSELF, before any trap) escaped
    // admitArray/reducePackage. The fixture is now a BATTERY of every escape shape × every export: a non-total function on ANY
    // of them fails HERE, so I never hand-hunt the next one. Enumerate the escape shapes exhaustively, not from my head.
    const BATTERY = () => [
      new Proxy([{}], { get() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, getOwnPropertyDescriptor() { throw new Error('H'); }, has() { throw new Error('H'); }, getPrototypeOf() { throw new Error('H'); } }),   // throwing traps (incl. getPrototypeOf → instanceof)
      (() => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; })(),   // REVOKED — throws on Array.isArray / instanceof / every operation
      (() => { const r = Proxy.revocable([], {}); r.revoke(); return r.proxy; })(),   // revoked ARRAY proxy (Array.isArray still throws)
      (() => { const o = { length: 4 }; for (let i = 0; i < 4; i++) Object.defineProperty(o, i, { enumerable: true, get() { throw new Error('idx'); } }); return o; })(),   // throwing-index array-like
      (() => { const o = Object.create(null); Object.defineProperty(o, 'x', { enumerable: true, get() { throw new Error('np'); } }); return o; })(),   // null-proto with a throwing own getter (defineProperty, not Object.assign which would read the getter)
    ];
    const fns = Object.keys(P).filter((k) => typeof P[k] === 'function');
    const bad = new Set();
    for (const n of fns) {
      if (MAY_THROW(n)) continue;
      for (const h of BATTERY()) {
        try { const r = P[n](h, h, h, h); if (r && typeof r.then === 'function') { try { await r; } catch { bad.add(n + ' (async reject)'); } } }
        catch { bad.add(n + ' (sync throw)'); }
      }
    }
    if (bad.size) console.error('    R47 roster non-total:', [...bad].join(', '));
    return bad.size === 0 && fns.length >= 100;   // ≥100 = the runtime namespace, never a regression to the 64-name source-regex subset
  })());
  // round-46 self-audit (crypto — Ed25519 signature MALLEABILITY) — a verifier MUST reject a non-canonical scalar S (S ≥ L, the
  // group order): S and S+L are two byte-strings for the same signature, so accepting both is malleability. edVerifyStrict
  // delegates to OpenSSL (RFC-8032, which enforces S < L) AFTER strictB64url canonicalizes the wire bytes — the property was
  // SOUND but UNTESTED. This vector proves the rejection, so a future swap to a lax/cofactored/ZIP-215 verify that accepts S+L fails HERE.
  check('R46 self-audit (crypto) edVerifyStrict REJECTS a malleated signature (S += L) — Ed25519 non-malleability (RFC-8032 S<L); the valid signature still verifies', (() => {
    const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('ab'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
    const pubB64 = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
    const msg = 'ust-malleability-vector';
    const sig = sign(null, Buffer.from(msg, 'utf8'), priv);
    const okBase = P.edVerifyStrict(pubB64, msg, sig.toString('base64url')) === true;
    const L = Buffer.from('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010', 'hex');   // Ed25519 group order, little-endian
    const S = sig.subarray(32, 64), Sm = Buffer.alloc(32); let carry = 0;
    for (let i = 0; i < 32; i++) { const v = S[i] + L[i] + carry; Sm[i] = v & 0xff; carry = v >> 8; }
    const mauled = Buffer.concat([sig.subarray(0, 32), Sm]).toString('base64url');
    return okBase && P.edVerifyStrict(pubB64, msg, mauled) === false;
  })());
  check('RECOVERY signer NOT in the genesis recovery set → not counted', VR([stmt(rf(KR), R1), stmt(rf(KR), RX)]).recovered === false);
  check('RECOVERY threshold-complete malformed replacement (BOTH signers agree on key_id ≠ keyId(pub)) → NOT recovered (admitAuthorityKey binds the pair; round-36 P1-01/P2-01 — the vacuous single-malformed vector could not see it)', (() => { const bad = { ...P.checkpointRecoveryClaim(rf(KR)), replacement_authority: { key_id: K1.key_id, pub: KR.pubB64 } }; const st = (W) => { const sg = sign(null, Buffer.from(P.canon(bad), 'utf8'), W.priv).toString('base64url'); return { claim: bad, issuer_id: W.key_id, sig: { alg: 'Ed25519', key_id: W.key_id, pub: W.pubB64, sig: sg } }; }; return VR([st(R1), st(R2)]).recovered === false; })());
  check('RECOVERY effective_sequence ≠ last+1 → not recovered (only the next checkpoint)', VR([stmt(rf(KR, '2'), R1), stmt(rf(KR, '2'), R2)]).recovered === false);
  // round-25 P1-01 — CanonicalSeq on the recovery coordinate: a coercible array `["1"]` (String(["1"])==="1") is not a
  //    canonical sequence; isSeq drops it before the signature, so it cannot authorize a recovery.
  check('round-25 P1-01 a coercible array effective_sequence `["1"]` is dropped (cannot authorize a recovery)', VR([{ claim: { ...P.checkpointRecoveryClaim(rf(KR)), effective_sequence: ['1'] }, issuer_id: R1.key_id, sig: stmt(rf(KR), R1).sig }, stmt(rf(KR), R2)]).recovered === false);
  check('RECOVERY stale last_accepted_checkpoint → not recovered (bound to the prior)', VR([stmt(rf(KR, '1', 'sha256:' + 'ee'.repeat(32)), R1), stmt(rf(KR, '1', 'sha256:' + 'ee'.repeat(32)), R2)]).recovered === false);
  check('RECOVERY valid 2-of-3 → replacement_authority + threshold + 2 signers', (r => r.recovered === true && r.replacement_authority.key_id === KR.key_id && r.threshold === '2' && r.signers.length === 2)(VR([stmt(rf(KR), R1), stmt(rf(KR), R2)])));
  check('R35 P0-02 recovery sig.key_id ≠ issuer (admitSigner binds issuer===key_id===keyId(pub)) → NOT recovered', VR([{ ...stmt(rf(KR), R1), sig: { ...stmt(rf(KR), R1).sig, key_id: 'sha256:' + 'cc'.repeat(32) } }, { ...stmt(rf(KR), R2), sig: { ...stmt(rf(KR), R2).sig, key_id: 'sha256:' + 'cc'.repeat(32) } }]).recovered === false);
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
  const etf = (over = {}) => ({ domain_shard: D, from_genesis_epoch: EPA, from_final_checkpoint: idA, from_sequence: '0', to_active_genesis: AGB, to_genesis_epoch: EPB, to_key_id: KB0.key_id, to_pub: KB0.pubB64, to_initial_sequence: '0', ...over });   // round-24 P1-02 — epoch A final sequence is 0
  const et = P.buildEpochTransition(etf(), KA0.priv, KA0.pubB64);
  const c0b = (over = {}) => P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: D, genesis_epoch: EPB, sequence: '0', previous_epoch_final_checkpoint: idA, active_genesis: AGB, current_key_id: KB0.key_id, keylog: KL, ...over }), (over._signer || KB0).priv, (over._signer || KB0).pubB64);
  const C0b = c0b();
  const chain = (c1, ets) => P.verifyAuthorityCheckpointChain([C0a, c1], { genesisAuthority: gA, epochTransitions: ets });
  const VE = (stmt, over = {}) => P.verifyEpochTransition(stmt, { domain_shard: D, from_genesis_epoch: EPA, from_final_checkpoint: idA, from_sequence: '0', fromAuthority: gA, ...over });   // round-25 P1-01: the verified prior-chain FINAL sequence is now a required canonical coordinate

  check('EPOCH A→B with authenticated transition → chain VALID (initial seq 0)', (r => r.result === 'VALID' && r.sequence === '0')(chain(C0b, { [EPB]: et })));
  // round-24 P1-02 — the public verifier now checks the signed from_sequence against epoch A's verified final sequence.
  check('round-24 P1-02 transition claiming a wrong from_sequence (999 ≠ epoch-A final 0) → chain INVALID', chain(C0b, { [EPB]: P.buildEpochTransition(etf({ from_sequence: '999' }), KA0.priv, KA0.pubB64) }).result !== 'VALID');
  check('round-24 P1-02 transition with a NON-canonical from_sequence ("0x1") → verifyEpochTransition not ok', VE(P.buildEpochTransition(etf({ from_sequence: '0x1' }), KA0.priv, KA0.pubB64)).ok === false);
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
  // round-25 P1-01 — a full transition-verification API cannot be PARTIAL: with the verified prior-chain FINAL sequence
  // coordinate OMITTED, the verifier no longer trusts the attacker's signed from_sequence and returns not-ok.
  check('round-25 P1-01 verifyEpochTransition with an OMITTED prior-chain from_sequence coordinate → not ok (no partial verification)', VE(et, { from_sequence: undefined }).ok === false);
  check('round-25 P1-01 verifyEpochTransition with a NON-canonical prior-chain from_sequence coordinate ("0x0") → not ok', VE(et, { from_sequence: '0x0' }).ok === false);
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
  check('TERM honest length-1 log (head at pos0, nothing at pos1) → terminal', P.verifyKeylogTerminality({ root: kl1.root, length: kl1.length, head: kl1.head }, kl1.headProof).terminal === true);
  const kl2 = P.buildKeylogCommitment([e0, e1]);
  check('TERM honest length-2 log (head at pos1, nothing at pos2) → terminal', P.verifyKeylogTerminality({ root: kl2.root, length: kl2.length, head: kl2.head }, kl2.headProof).terminal === true);
  const lie = P.verifyKeylogTerminality({ root: kl2.root, length: '1', head: e0 }, { headProof: kl2.prove(0) });   // present a length-2 log as length-1, hiding e1
  check('TERM strict catches a HIDDEN SUCCESSOR (length lies) → not terminal (depth-mismatch or right subtree not empty)', lie.terminal === false && /beyond|right subtree|proof depth/.test(lie.detail));   // P0-5: an under-depth proof for the lied length is now caught earlier by the depth check
  check('TERM wrong head at position L-1 → not terminal', P.verifyKeylogTerminality({ root: kl1.root, length: '1', head: 'sha256:' + '99'.repeat(32) }, kl1).terminal === false);
}

// ─── #78/M1 ASSURANCE PRODUCT-LATTICE — the formal-model F.5.0 realized as RUNNING property checks (math ⇒ code
//     ⇒ vector). M1.1: STRENGTH = four chains (2×3×4×2 = 48 — identity is 3 rungs since round-53 dropped `pinned`); capability SUPPORT is a separate Boolean lattice
//     (P(Caps), ⊆) — not a fifth coordinate. Exhaustive; deterministic, no sampling for pairwise laws.
{
  const AX = P.ASSURANCE_AXES, keys = Object.keys(AX);
  const all = []; (function rec(i, acc) { if (i === keys.length) return all.push({ ...acc }); for (const v of AX[keys[i]]) rec(i + 1, { ...acc, [keys[i]]: v }); })(0, {});
  const eq = (a, b) => keys.every((k) => a[k] === b[k]);
  check('LATTICE product = 48 states (2×3×4×2) — strength only, support is not a coordinate (M1.1); identity is 3 rungs since round-53 dropped `pinned`', all.length === 48);

  // (1) every axis a TOTAL order (all pairs comparable); (2) the product a PARTIAL order (reflexive + antisymmetric)
  let totalOK = true; for (const ax of keys) for (const x of AX[ax]) for (const y of AX[ax]) if (!(P.axisRank(ax, x) <= P.axisRank(ax, y) || P.axisRank(ax, y) <= P.axisRank(ax, x))) totalOK = false;
  check('LATTICE (1) every axis is a total order', totalOK);
  let refl = true, antisym = true; for (const a of all) { if (!P.assuranceLE(a, a)) refl = false; for (const b of all) if (P.assuranceLE(a, b) && P.assuranceLE(b, a) && !eq(a, b)) antisym = false; }
  check('LATTICE (2) product order reflexive + antisymmetric', refl && antisym);

  // (3) LATTICE laws pairwise (48²): meet a lower bound, join an upper bound, both commutative + absorptive
  let latOK = true; for (const a of all) for (const b of all) {
    const m = P.meetAssurance(a, b), j = P.joinAssurance(a, b);
    if (!(P.assuranceLE(m, a) && P.assuranceLE(m, b) && P.assuranceLE(a, j) && P.assuranceLE(b, j))) latOK = false;
    if (!(eq(m, P.meetAssurance(b, a)) && eq(j, P.joinAssurance(b, a)))) latOK = false;                 // commutative
    if (!(eq(P.meetAssurance(a, j), a) && eq(P.joinAssurance(a, m), a))) latOK = false;                 // absorption
  }
  check('LATTICE (3) meet=glb, join=lub, commutative + absorption (48² pairs)', latOK);

  // (4) A_id ⊥ A_fresh — the axes strengthen INDEPENDENTLY (gap 1/3): id-up/fresh-fixed vs fresh-up/id-fixed is INCOMPARABLE
  const idUp = { integrity: 'valid', identity: 'authoritative', freshness: 'unverified', time: 'unproven' };
  const frUp = { integrity: 'valid', identity: 'self-asserted', freshness: 'attested', time: 'unproven' };
  check('LATTICE (4) A_id / A_fresh product-incomparability (M1.4 — no ⊥): id-up vs fresh-up incomparable', !P.assuranceLE(idUp, frUp) && !P.assuranceLE(frUp, idUp));

  // (5) projectTier MONOTONE over every comparable pair (48²): a ≤ b ⇒ tier(a) ≤ tier(b)
  let monoOK = true; for (const a of all) for (const b of all) if (P.assuranceLE(a, b) && !(P.TIER_RANK[P.projectTier(a)] <= P.TIER_RANK[P.projectTier(b)])) monoOK = false;
  check('LATTICE (5) projectTier is monotone (order-preserving)', monoOK);

  // (6) the projection AGREES with the realized §14 tier (authoritative∧anchored⇒TOP; name-bound⇒HIGH) — NO 2nd truth
  const inlineTier = (id, time) => (id === 'authoritative' && time === 'anchored') ? 'TOP' : (id === 'corroborated' || id === 'authoritative') ? 'HIGH' : 'LIGHT';
  let agreeOK = true; for (const id of AX.identity) for (const time of AX.time) if (P.projectTier({ integrity: 'valid', identity: id, freshness: 'unverified', time }) !== inlineTier(id, time)) agreeOK = false;
  check('LATTICE (6) projectTier agrees with the realized §14 tier (identity+time)', agreeOK);
  check('LATTICE (6b) integrity floor unmet ⇒ NONE (INVALID upstream)', P.projectTier({ integrity: 'invalid', identity: 'authoritative', freshness: 'attested', time: 'anchored' }) === 'NONE');

  // (7) capAssurance = the ℐ_C CAPPED term (F.5b downgrade-resistance): downgrade-only (cap ≤ proven), idempotent, no-ceiling ⇒ identity
  const top = { integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' };
  let capOK = true; for (const a of all) { const c = P.capAssurance(a, { identity: 'corroborated', freshness: 'fresh' }); if (!P.assuranceLE(c, a) || !eq(P.capAssurance(c, { identity: 'corroborated', freshness: 'fresh' }), c)) capOK = false; }
  check('LATTICE (7a) capAssurance downgrade-only (cap ≤ proven) + idempotent', capOK);
  check('LATTICE (7b) no ceiling ⇒ unchanged', eq(P.capAssurance(top, null), top));
  const capped = P.capAssurance(top, { identity: 'self-asserted', freshness: 'corroborated' });
  check('LATTICE (7c) proven-TOP capped by no-trust-roots/no-domains ⇒ tier drops to LIGHT', P.projectTier(capped) === 'LIGHT' && capped.identity === 'self-asserted' && capped.freshness === 'corroborated');

  // (8) fail-closed: a missing/out-of-range axis ⇒ a RETURNED reject sentinel (round-39 — the assurance door returns like
  //     admitDeep→ADMIT_REJECT, never a throw / never a guessed state); projectTier of such a state ⇒ NONE (no tier)
  const miss = P.assuranceState({ integrity: 'valid', identity: 'authoritative', freshness: 'attested' });                         // missing `time`
  const oor = P.assuranceState({ integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'sometime' });        // out-of-range `time`
  check('LATTICE (8) missing/out-of-range axis ⇒ reject sentinel (fail-closed, total-by-return) + projectTier ⇒ NONE', typeof miss === 'symbol' && typeof oor === 'symbol' && P.projectTier({ integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'sometime' }) === 'NONE');

  // M1.1 — capability SUPPORT: a separate Boolean lattice (P(Caps), ⊆), single-sourced, |Caps| = 8
  check('M1.1 EVIDENCE_CAPS_UNIVERSE: |Caps| = 8, single-sourced from EVIDENCE_CAPS (support ≠ strength coordinate)', P.EVIDENCE_CAPS_UNIVERSE.length === 8 && ['pow-header-chain', 'transparency-log', 'authenticated-map', 'content-addressed', 'rfc3161-tsa'].every((k) => P.evidenceCaps(k).every((c) => P.EVIDENCE_CAPS_UNIVERSE.includes(c))));
  check('M1.1 support is ⊆-ordered, not a chain: transparency-log vs authenticated-map caps are incomparable sets', (() => { const a = P.evidenceCaps('transparency-log'), b = P.evidenceCaps('authenticated-map'); return !a.every((c) => b.includes(c)) && !b.every((c) => a.includes(c)); })());

  // ── C3/K3 — deriveAssurance: THE one assembler, takes ONLY a branded PredicateGraph. provePredicates maps seam
  //    verdicts → atoms; deriveAssurance projects. Strength from SEAM VERDICTS, support from image(VerifyEvidence_C).
  // round-25 P0-01 — provePredicates is the PURE UNBRANDED mapper; only verify() seals a graph (module-private). The
  //    mapping projection is exercised here via the SAME public lattice math deriveAssurance uses over the graph's atoms.
  const DA = (v) => { const g = P.provePredicates(v); const strength = P.assuranceState({ integrity: 'valid', ...g.atoms }); return { strength, support: g.support, tier: P.projectTier(strength), provenAtoms: g.provenAtoms, derivation: g.derivation }; };
  check('K3 deriveAssurance REJECTS a caller-shaped object (not a PredicateGraph) → E-ASSURANCE (round-3 P0-4 closed)',
    (r => r.error === 'E-ASSURANCE')(P.deriveAssurance({ identity: { status: 'verified', strength: 'authoritative' }, freshness: { result: 'VALID', keylog_freshness: 'attested' }, anchor: { inclusion: true, time: 'anchored' } })));
  check('K3 provePredicates is UNBRANDED — a caller cannot mint a graph the assembler will bless (round-25 P0-01: the forgery oracle is closed)',
    P.isVerifiedHandle('predicate-graph', P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' }, anchor: { inclusion: true, time: 'anchored' } })) === false
    && P.deriveAssurance(P.provePredicates({ identity: { status: 'verified', strength: 'authoritative' }, anchor: { inclusion: true, time: 'anchored' } })).error === 'E-ASSURANCE');
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
  check('C3 provePredicates graph is a deep-frozen pure value (atoms/support immutable, no post-hoc mutation — round-25 P0-01)',
    (() => { const g = P.provePredicates({}); try { g.atoms.identity = 'authoritative'; } catch {} try { g.support.push('x'); } catch {} return Object.isFrozen(g) && Object.isFrozen(g.atoms) && g.atoms.identity === 'self-asserted' && g.support.length === 0; })());

  // ── V1 (UST-sul, M1.2) — Reach_C CONFINEMENT: over the FULL verdict grid, the assembler emits ONLY tuples whose
  //    every coordinate is earned by ITS OWN seam predicate — and each coordinate is a function of ITS verdict alone
  //    (changing another verdict never moves it). This is the evidence→assurance transition the rc.35 "256 abstract
  //    combinations" check never exercised.
  {
    const ids = [undefined, { strength: 'authoritative' }, { strength: 'authoritative', status: 'verified' },
      { strength: 'authoritative', status: 'suspect' }, { strength: 'corroborated', status: 'verified' },
      { strength: 'self-asserted', status: 'verified' },
      { strength: 'consumer-override', status: 'verified' }, { strength: 'corroborated', status: 'unavailable' },
      { strength: 'corroborated', status: 'verified', freshness: 'fresh' }, { strength: 'authoritative', status: 'verified', freshness: 'fresh' }];
    const frs = [undefined, { result: 'VALID', keylog_freshness: 'corroborated' }, { result: 'VALID', keylog_freshness: 'attested' },
      { result: 'INDETERMINATE', keylog_freshness: 'corroborated' }, { keylog_freshness: 'attested' }, { result: 'VALID', keylog_freshness: 'unverified' }];
    const ans = [undefined, { inclusion: true, time: 'anchored' }, { inclusion: false, time: 'anchored' }, { inclusion: true, time: 'unproven' }];
    // the INDEPENDENT per-coordinate rules (restated here, not shared with the implementation)
    const expId = (id) => id?.status !== 'verified' ? 'self-asserted' : ['authoritative', 'corroborated'].includes(id.strength) ? (id.strength === 'authoritative' ? 'authoritative' : id.strength) : 'self-asserted';
    const expFr = (fr, id) => (fr?.result === 'VALID' && ['corroborated', 'attested'].includes(fr.keylog_freshness)) ? fr.keylog_freshness : (id?.freshness === 'fresh' ? 'fresh' : 'unverified');
    const expTm = (an) => an?.inclusion === true && an?.time === 'anchored' ? 'anchored' : 'unproven';
    let confined = true, coordinateLocal = true;
    for (const id of ids) for (const fr of frs) for (const an of ans) {
      const r = DA({ identity: id, freshness: fr, anchor: an });                        // DA = the pure projection over the UNBRANDED mapper (round-25 P0-01)
      if (r.strength.identity !== expId(id) || r.strength.freshness !== expFr(fr, id) || r.strength.time !== expTm(an) || r.strength.integrity !== 'valid') confined = false;
      if (r.tier !== P.projectTier(r.strength)) confined = false;                       // the report never carries a tier its own strength does not project
    }
    for (const id of ids) {                                                             // identity is a function of the identity verdict ALONE
      const base = DA({ identity: id }).strength.identity;
      for (const fr of frs) for (const an of ans) if (DA({ identity: id, freshness: fr, anchor: an }).strength.identity !== base) coordinateLocal = false;
    }
    check('V1 Reach_C confinement: 240-combination verdict grid — every coordinate earned by its own predicate, tier = projection', confined);
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

// ─── round-27 (3) THE INPUT-BOUNDARY GRID — the CONTROL that answers "did every exported verifier admit its input?"
//     from CODE, not memory. Each verifier gets its primary input with a READ-COUNTING getter on a key signed field; the
//     invariant is the getter fires ≤1 time (admitDeep rejects at the DESCRIPTOR → 0; a JSON/snapshot reads once → 1; an
//     UNSNAPSHOTTED multi-read TOCTOU → ≥2). This is what would have caught round-27 P0-01/02/03 before shipping: a new
//     or existing exported verifier that re-reads a caller field is FLAGGED here, in CI. Add a verifier ⇒ add a grid row.
{
  const G = kp('7e'.repeat(32)), tt = { generated_at: '2026-07-13T14:00:00Z', valid_from: '2026-07-13T14:00:00Z', valid_to: '2026-08-13T14:00:00Z' };
  const gen = P.seal(P.buildGenesis({ domain_shard: 'grid.example', ust_id: 'ust:20260713.10', key_id: G.key_id }, tt, G.pubB64), G.priv, G.pubB64);
  const doc = P.seal(P.buildState({ domain_shard: 'grid.example', ust_id: 'ust:20260713.14', key_id: G.key_id, class: 'observation' }, tt, { r: { kind: 'captured', value: { v: 'A' } } }, { prev: P.contentHash(gen) }), G.priv, G.pubB64);
  const klc = P.buildKeylogCommitment(['sha256:' + '22'.repeat(32)]);
  const cp = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'grid.example', genesis_epoch: P.genesisEpoch(P.contentHash(gen)), sequence: '0', active_genesis: P.contentHash(gen), current_key_id: G.key_id, keylog: { root: klc.root, length: klc.length, head: klc.head } }), G.priv, G.pubB64);
  const rcpt = P.buildEvidenceReceipt({ domain_shard: 'grid.example', active_genesis: P.contentHash(gen), subject: 'ust:s', proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: '1' }, issued_at: '2026-01-01T00:00:00Z' }, G.priv, G.pubB64);
  const nf = P.buildNoForkEvidence({ domain_shard: 'grid.example', active_genesis: P.contentHash(gen) }, G.priv, G.pubB64);
  // wrap `obj[key]` in a read-counter getter; returns a reader for the count.
  const spy = (obj, key) => { let n = 0; const real = obj[key]; Object.defineProperty(obj, key, { enumerable: true, configurable: true, get() { n++; return real; } }); return () => n; };
  // each row: [label, () => a fresh input with a spied field, fn]. fn is called; assert the spy fired ≤ 1.
  let gridAllOk = true; const gridJobs = [];
  // round-29 (div1, GPT round-28) — AWAIT each verifier to SETTLEMENT before counting getter reads. A synchronous
  //   read-count sees only the reads BEFORE the first await, so an async verifier that re-read a caller field AFTER an
  //   await would slip it. The grid now awaits, so a post-await TOCTOU re-read is OBSERVED (proven by the negative control).
  const g = (label, make) => gridJobs.push((async () => { const c = make(); try { await c.call(); } catch {} const ok = c.reads() <= 1; if (!ok) gridAllOk = false; check('BOUNDARY-GRID ' + label + ' admits its input (getter read ≤1 across settlement — no TOCTOU re-read)', ok); })());
  const wrapTop = (o, key) => { const clone = JSON.parse(JSON.stringify(o)); const reads = spy(clone, key); return { clone, reads }; };
  g('verify(doc)', () => { const { clone, reads } = wrapTop(doc, 'state'); return { call: () => P.verify(clone, { context: 'data' }), reads }; });
  g('verifyEvidenceReceipt(receipt)', () => { const { clone, reads } = wrapTop(rcpt, 'claim'); return { call: () => P.verifyEvidenceReceipt(clone, {}), reads }; });
  g('verifyNoForkEvidence(evidence)', () => { const { clone, reads } = wrapTop(nf, 'claim'); return { call: () => P.verifyNoForkEvidence(clone, {}), reads }; });
  g('verifyAuthorityCheckpointChain(chain[0])', () => { const clone = JSON.parse(JSON.stringify(cp)); const reads = spy(clone, 'body'); return { call: () => P.verifyAuthorityCheckpointChain([clone], {}), reads }; });
  g('verifiedGenesisContext(genesis)', () => { const { clone, reads } = wrapTop(gen, 'state'); return { call: () => P.verifiedGenesisContext(clone), reads }; });
  g('resolveCheckpointRoots(genesis)', () => { const { clone, reads } = wrapTop(gen, 'state'); return { call: () => P.resolveCheckpointRoots(clone), reads }; });
  g('verifyKeylogTerminality(proof)', () => { const clone = JSON.parse(JSON.stringify(klc.headProof)); const reads = spy(clone, 'siblings'); return { call: () => P.verifyKeylogTerminality({ root: klc.root, length: klc.length, head: klc.head }, clone), reads }; });
  g('verifyStream(frames[0])', () => { const clone = JSON.parse(JSON.stringify(doc)); const reads = spy(clone, 'state'); return { call: () => P.verifyStream([clone], {}), reads }; });
  g('verifyCheckpointRecovery(statements[0])', () => { const st = { claim: { purpose: 'ust:checkpoint-authority-recovery' }, issuer_id: 'x', sig: { sig: 'a', pub: 'b' } }; const reads = spy(st, 'claim'); return { call: () => P.verifyCheckpointRecovery([st], {}), reads }; });
  g('verifyEpochTransition(statement)', () => { const st = { claim: { purpose: 'ust:genesis-epoch-transition' }, sig: { sig: 'a', pub: 'b' } }; const reads = spy(st, 'claim'); return { call: () => P.verifyEpochTransition(st, { fromAuthority: { key_id: 'k', pub: 'p' } }), reads }; });
  g('forkChoice(candidates[0])', () => { const clone = JSON.parse(JSON.stringify(doc)); const reads = spy(clone, 'state'); return { call: () => P.forkChoice([clone], {}), reads }; });
  g('resolveByDiscovery(doc)', () => { const clone = JSON.parse(JSON.stringify(doc)); const reads = spy(clone, 'state'); return { call: () => P.resolveByDiscovery(clone, { context: 'data' }, { fetchImpl: async () => ({ ok: false, status: 404, text: async () => '' }) }), reads }; });
  g('verifyAsync(doc)', () => { const clone = JSON.parse(JSON.stringify(doc)); const reads = spy(clone, 'state'); return { call: () => P.verifyAsync(clone, { context: 'data' }), reads }; });
  // rev35 R3 (round-30 P0-01/02) — the grid now covers the RESOLVERS too: a resolver that verifies its input then RE-READS
  //   the raw object fires the spied getter ≥2 times (resolveKeys read `state` 8× before the fix). Extending the ≤1-read
  //   invariant to resolveKeys/resolveAuthority/resolveCadence makes the R3 "no post-admission raw re-read" machine-checked
  //   across the resolver surface, not just verify.
  g('resolveKeys(genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.resolveKeys(clone, []), reads }; });
  g('resolveAuthority(doc)', () => { const clone = JSON.parse(JSON.stringify(doc)); const reads = spy(clone, 'state'); return { call: () => P.resolveAuthority(clone, {}), reads }; });
  g('resolveCadence(genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.resolveCadence(clone, [], undefined, {}), reads }; });
  // rev38 R3 (round-31 P0-01/02/03) — the grid covers NESTED untrusted objects in opts/config too: admitOpts is shallow, so
  //   a resolver that verifies then re-reads a nested `opts.genesis` / `config.checkpoint` / `chain[i]` fires the getter ≥2.
  //   These lock the nested-admit fixes across the resolver surface (the class round-30 fixed only for the PRIMARY arg).
  g('resolveAuthority(opts.genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.resolveAuthority(doc, { genesis: clone }), reads }; });
  g('deriveCheckpointFreshness(chain[i].body)', () => { const clone = JSON.parse(JSON.stringify(cp)); const reads = spy(clone, 'body'); return { call: () => P.deriveCheckpointFreshness([clone], {}), reads }; });
  g('verifyStream(config.checkpoint)', () => { const clone = JSON.parse(JSON.stringify(cp)); const reads = spy(clone, 'state'); return { call: () => P.verifyStream([doc], { checkpoint: clone }), reads }; });
  // rev39 R3 (round-31, ONE control) — admitOpts now DEEP-admits every nested opts/config DATA value, so resolvers NOT
  //   individually patched are ALSO immune: these lock the nested-genesis position of four such resolvers at ≤1 read.
  g('verifyNoForkEvidence(config.genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.verifyNoForkEvidence({ claim: {} }, { genesis: clone }), reads }; });
  g('verifyCheckpointRecovery(config.genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.verifyCheckpointRecovery([], { genesis: clone }), reads }; });
  g('verifyEpochTransition(config.fromAuthority)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.verifyEpochTransition({ claim: {} }, { fromAuthority: clone }), reads }; });
  g('verifyActiveGenesisUniqueness(config.genesis)', () => { const clone = JSON.parse(JSON.stringify(gen)); const reads = spy(clone, 'state'); return { call: () => P.verifyActiveGenesisUniqueness({}, { genesis: clone }), reads }; });
  // round-29 (div1) NEGATIVE CONTROL — prove the grid's await-then-count mechanism OBSERVES a post-await read: a synthetic
  //   verifier that reads its spied input, awaits, then reads AGAIN must be seen as read-count 2 (a sync snapshot sees 1).
  { const o = {}; const rd = spy(o, 'f'); const postAwaitReader = async (x) => { void x.f; await Promise.resolve(); void x.f; }; await postAwaitReader(o).catch(() => {});
    check('BOUNDARY-GRID async-aware: a verifier that re-reads its input AFTER an await is OBSERVED as read-count 2 (the grid awaits settlement; a sync snapshot would miss it) — round-29 div1', rd() === 2); }
  await Promise.all(gridJobs);
  check('BOUNDARY-GRID: every exported verifier admits its input once (no TOCTOU re-read across the surface — coverage answered in CI, not from memory)', gridAllOk);
  // round-28 P1-02 (HARDENED after self-audit) — FROM-CODE totality by PARTITION-EXHAUSTIVENESS, not a name regex.
  //   The first fix filtered exports by `/^(verify|resolve|derive|…)/`, which is a hand-list in disguise: it SILENTLY
  //   dropped real consumer entries (checkAuthorityProof, verifiedGenesisContext, combineSubstrates) — the very
  //   "completeness control that isn't complete" class we keep closing. The sound shape: CLASSIFY every function export
  //   as either 'surface' (untrusted wire input → MUST be total) or an EXEMPTION REASON, and fail from code if ANY
  //   export is unclassified — so a newly-added export cannot be silently omitted; the author must consciously decide.
  //   Then feed a HOSTILE Proxy to every 'surface' entry and assert NO host exception escapes (I4 totality).
  const CLASS = {
    // ── SURFACE: a consumer calls these DIRECTLY with an untrusted, over-the-wire document/proof/receipt ──
    verify: 'surface', verifyAsync: 'surface', verifyStream: 'surface', verifyJson: 'surface', verifyAnchor: 'surface',
    verifyEvidenceReceipt: 'surface', verifyActiveGenesisUniqueness: 'surface', verifyAuthorityBundle: 'surface',
    verifyAuthorityCheckpointChain: 'surface', verifyCheckpointMapUniqueness: 'surface', verifyCheckpointRecovery: 'surface',
    verifyCheckpointUniqueness: 'surface', verifyEpochTransition: 'surface', verifyKeylogTerminality: 'surface',
    verifyNoForkEvidence: 'surface', resolveAuthority: 'surface', resolveByDiscovery: 'surface', resolveCadence: 'surface',
    resolveCadenceBytes: 'surface',   // round-47 rev69 — the SOUND bytes-in boundary (a pure function of immutable byte-strings; resolveCadence is its object adapter)
    resolveCheckpointRoots: 'surface', resolveKeys: 'surface', resolveKeysBytes: 'surface', deriveAssurance: 'surface', deriveCheckpointFreshness: 'surface',
    forkChoice: 'surface', noEventBacking: 'surface', verifiedGenesisContext: 'surface', checkAuthorityProof: 'surface',
    checkAuthorityProofBytes: 'surface', combineSubstrates: 'surface', witnessNoFork: 'surface',
    // ── EXEMPT (throw-by-contract): designed to throw on invalid — totality is not the contract ──
    assertValid: 'throws-by-contract', verifyOrThrow: 'throws-by-contract',
    // ── EXEMPT (producer builders): operate on the SIGNER's OWN data; a producer can only hurt themselves ──
    seal: 'producer-builder', sealAuthorityCheckpoint: 'producer-builder', verifiedEvidence: 'producer-builder (raw-facts shape)',
    buildAbsence: 'producer-builder', buildAttestation: 'producer-builder', buildAuthorityCheckpoint: 'producer-builder',
    buildAuthorityProof: 'producer-builder', buildCadenceEntry: 'producer-builder', buildCheckpoint: 'producer-builder',
    buildDerivation: 'producer-builder', buildEpochTransition: 'producer-builder', buildEvidenceReceipt: 'producer-builder',
    buildGap: 'producer-builder', buildGenesis: 'producer-builder', buildKeyLogEntry: 'producer-builder',
    buildKeylogCommitment: 'producer-builder', buildNoForkEvidence: 'producer-builder', buildRecoveryStatement: 'producer-builder',
    buildState: 'producer-builder', buildUniquenessAttestation: 'producer-builder', buildVerifiableMap: 'producer-builder',
    // ── EXEMPT (pure primitive/crypto/id/leaf/lattice): consume TRUSTED post-verification values, not untrusted wire ──
    canon: 'primitive', keyId: 'primitive', contentHash: 'primitive', merkleRoot: 'primitive', H: 'primitive', Hbytes: 'primitive',
    seed: 'primitive', strictB64url: 'primitive', admitUtf8: 'primitive', admitDeep: 'primitive (the door itself; canon-transparent)',
    snapshotBytes: 'primitive (the byte-admission door — exact native Uint8Array → immutable copy, total: a hostile Proxy yields E-BYTES-TYPE, never a throw; round-48 P0-01)',
    anyLoneSurrogate: 'primitive', edVerifyStrict: 'primitive', signedContent: 'primitive', partitionHash: 'primitive',
    blindedCommit: 'primitive', blindPartition: 'primitive', assuranceLE: 'surface', assuranceState: 'primitive (the assurance door — returns a reject sentinel like admitDeep, never a throw)',
    axisRank: 'primitive', joinAssurance: 'surface', meetAssurance: 'surface', projectTier: 'surface', capAssurance: 'surface',
    evidenceCaps: 'primitive', ustGrid: 'primitive', checkBounds: 'surface', compareEvidenceOrder: 'surface',
    quorumTrustDomains: 'surface', evidenceClass: 'primitive', parseCadenceInt: 'primitive', authorityCheckpointId: 'primitive',
    authorityScopeId: 'primitive', checkpointMapLeaf: 'primitive', checkpointRecoveryClaim: 'primitive',
    checkpointUniquenessClaim: 'primitive', epochTransitionClaim: 'primitive', evidenceReceiptClaim: 'primitive',
    evidenceReceiptId: 'primitive', genesisEpoch: 'primitive', keylogLeaf: 'primitive', nameMapLeaf: 'primitive', noForkClaim: 'primitive',
    // ── EXEMPT (pure predicate/accessor) ──
    isValid: 'predicate', isVerifiedHandle: 'predicate', isPublicDnsShard: 'predicate',
    // ── EXEMPT (result class) ──
    UstInvalid: 'result-class', UstIndeterminate: 'result-class',
    // ── EXEMPT (internal, reached only POST-admit through a public door that admits) ──
    provePredicates: 'internal (post-admit reasoning; verify() seals, a direct call mints no trust)',
  };
  const allFns = Object.keys(P).filter((k) => typeof P[k] === 'function');
  const unclassified = allFns.filter((k) => !(k in CLASS));
  check('FROM-CODE PARTITION: every function export is classified surface|exempt (no silent drop — a new export fails until classified)' + (unclassified.length ? ' — UNCLASSIFIED: ' + unclassified.join(',') : ''), unclassified.length === 0);
  const HOSTILE = () => new Proxy({}, { get() { throw new Error('HOSTILE_GET'); }, has() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, getOwnPropertyDescriptor() { throw new Error('H'); }, getPrototypeOf() { return Object.prototype; } });
  // round-51 (owner: "структурно невозможное повторение из-за неполного покрытия") — the totality sweep drove ONE hostile shape,
  // so a REVOKED Proxy (throws on `Array.isArray`/`instanceof` ITSELF) escaped admitArray/reducePackage. Drive a BATTERY of EVERY
  // escape shape at each position (others valid) — enumerate the shapes exhaustively, never hand-hunt the next one.
  const BATTERY = () => [
    HOSTILE(),                                                                     // throwing get/has/ownKeys/descriptor traps
    new Proxy([{}], { get() { throw new Error('H'); }, getPrototypeOf() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, has() { throw new Error('H'); } }),   // + throwing getPrototypeOf (instanceof)
    (() => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; })(),   // REVOKED — Array.isArray / instanceof / any op throws
    (() => { const r = Proxy.revocable([], {}); r.revoke(); return r.proxy; })(),   // revoked ARRAY proxy
    (() => { const o = { length: 4 }; for (let i = 0; i < 4; i++) Object.defineProperty(o, i, { enumerable: true, get() { throw new Error('idx'); } }); return o; })(),   // throwing-index array-like
  ];
  const surface = allFns.filter((k) => CLASS[k] === 'surface');
  // round-51 (owner sweep) — LOCK the two totality lists in the load-bearing direction: a R31 SURFACE must NEVER be R47-roster
  // MAY-THROW-exempt (that would let a real untrusted-input boundary escape the runtime-namespace net). The reverse — an EXEMPT
  // that is also total, so R47 harmlessly tests it — is fine. A surface drifting into the exemption fails HERE; no second hand-list.
  { const escaped = allFns.filter((n) => CLASS[n] === 'surface' && MAY_THROW_TOTALITY(n));
    check('MAY_THROW ⊥ SURFACE: no R31 consumer-surface export is R47-roster MAY-THROW-exempt — a surface can never escape the runtime-namespace totality net via the exemption list (round-51 hand-list sweep: the two lists are locked in the load-bearing direction)' + (escaped.length ? ' — SURFACE EXEMPTED: ' + escaped.join(',') : ''), escaped.length === 0); }
  // rev34 R1 (round-29 P1-01) — TOTALITY by a machine SIGNATURE REGISTRY, not `fn.length` + `{}`-fill. `fn.length` stops at
  //   the first DEFAULT parameter (resolveCadence.length === 1 though it takes 4 args → the 4th never tested), and `{}`-fill
  //   short-circuits many verifiers before they read the hostile position (verifyAnchor returns early on a malformed proof,
  //   never reaching the contentHash read). The registry declares the REAL arity + a VALID-SHAPED reachability fixture per
  //   position, so a HOSTILE Proxy at position i is actually REACHED with the OTHER args valid; the call is AWAITED (an
  //   async host-throw is a rejection). Every surface export MUST have a signature — a new one fails until declared.
  const netMock = () => ({ fetchImpl: async () => ({ ok: false, status: 404, text: async () => '' }), substrateVerify: () => ({ final: false }) });
  const oDoc = () => JSON.parse(JSON.stringify(doc)), oGen = () => JSON.parse(JSON.stringify(gen));
  const oOpts = () => ({ context: 'data' }), oConf = () => ({}), oHash = () => 'sha256:' + '00'.repeat(32);
  const oProof = () => ({ root: 'sha256:' + '00'.repeat(32), path: [] }), oBytes = () => new TextEncoder().encode('{}');
  const oArr = () => [], oStr = () => 'grid.example', oFrames = () => [oDoc()], oGraph = () => ({});
  const oHead = () => { const k = P.buildKeylogCommitment(['sha256:' + '22'.repeat(32)]); return { root: k.root, length: k.length, head: k.head }; };   // rev38 R1 (round-31 P2-01) — a REAL keylog head record so verifyKeylogTerminality reaches its proof argument (the old `oStr` domain string short-circuited before the hostile position → vacuous totality coverage there)
  const oStmt = () => ({ claim: {}, sig: { sig: 'a', pub: 'b' } }), oChain = () => [{ body: {}, sig: { sig: 'a', pub: 'b' } }];
  const oEv = () => ({ proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: '1' } }), oList = () => [{ source_id: 'a' }];   // round-38 P1-02 — reachability fixtures for the exported evidence-algebra surfaces (now admitted, no longer exempt as 'primitive')
  const oAssur = () => ({ integrity: 'valid', identity: 'authoritative', freshness: 'attested', time: 'anchored' });   // round-39 P1-02 — a valid-shaped assurance state; the lattice surfaces (le/meet/join/projectTier/capAssurance) now RETURN (⊥/false/'NONE') on a hostile operand rather than throw, so the sweep reaches every position
  const SIG = {
    verify: [oDoc, oOpts], verifyAsync: [oDoc, oOpts], verifyStream: [oFrames, oConf], verifyJson: [oBytes, oOpts],
    verifyAnchor: [oHash, oProof, oOpts], verifyEvidenceReceipt: [oStmt, oConf], verifyActiveGenesisUniqueness: [oProof, oConf],
    verifyAuthorityBundle: [oConf, oConf], verifyAuthorityCheckpointChain: [oChain, oConf], verifyCheckpointMapUniqueness: [oProof, oConf],
    verifyCheckpointRecovery: [oChain, oConf], verifyCheckpointUniqueness: [oChain, oConf], verifyEpochTransition: [oStmt, oConf],
    verifyKeylogTerminality: [oHead, oProof], verifyNoForkEvidence: [oStmt, oConf], resolveAuthority: [oDoc, oOpts],
    compareEvidenceOrder: [oEv, oEv], quorumTrustDomains: [oList, oConf],   // round-38 P1-02 — the exported evidence algebra is now a consumer surface in the totality sweep (admits its operands)
    assuranceLE: [oAssur, oAssur], meetAssurance: [oAssur, oAssur], joinAssurance: [oAssur, oAssur], projectTier: [oAssur], capAssurance: [oAssur, oAssur], checkBounds: [oDoc],   // round-39 P1-02 — the assurance lattice + the exported bounds validator are consumer surfaces now that the door returns a sentinel (total-by-return, never a throw)
    resolveByDiscovery: [oDoc, oOpts, netMock], resolveCadence: [oGen, oArr, oStr, oOpts], resolveCadenceBytes: [oBytes, oBytes, oStr, oBytes], resolveCheckpointRoots: [oGen],
    resolveKeys: [oGen, oArr], resolveKeysBytes: [oBytes, oBytes], deriveAssurance: [oGraph], deriveCheckpointFreshness: [oChain, oConf], forkChoice: [oFrames, oOpts],
    noEventBacking: [oConf, oConf, oFrames], verifiedGenesisContext: [oGen], checkAuthorityProof: [oConf, oConf],
    checkAuthorityProofBytes: [oBytes, oBytes], combineSubstrates: [oArr], witnessNoFork: [oStr, oHash, netMock],
  };
  const sigMissing = surface.filter((k) => !(k in SIG));
  check('FROM-CODE SIGNATURE REGISTRY: every consumer-surface export has a declared signature (real arity + a valid reachability fixture per position) — no surface export escapes the totality sweep, a new one fails until declared' + (sigMissing.length ? ' — MISSING: ' + sigMissing.join(',') : ''), sigMissing.length === 0);
  let sweepAllOk = true; const sweepThrew = [];
  for (const name of surface) {
    const sig = SIG[name]; if (!sig) continue;
    for (let pos = 0; pos < sig.length; pos++) {
      for (const h of BATTERY()) {   // round-51 — EACH escape shape at position `pos`, the other positions VALID (so the hostile arg is actually REACHED)
        const args = sig.map((f, j) => (j === pos ? h : f()));
        try { await P[name](...args); } catch { sweepAllOk = false; sweepThrew.push(name + '#' + pos); }
      }
    }
  }
  check('FROM-CODE TOTALITY (hostile BATTERY): every consumer-surface export returns structured, never a host throw, on EACH escape shape (throwing-trap Proxy, REVOKED Proxy, throwing-index array-like) in any argument position — the fixture is exhaustive, so a new non-total path fails HERE (round-51)' + (sweepThrew.length ? ' — THREW: ' + [...new Set(sweepThrew)].join(',') : ''), sweepAllOk);
  // rev34 R2 (round-29 P1-02) — the executed-check manifest is EVIDENCE, and evidence must be content-bound to its source
  //   (like a UST receipt to its state). The manifest carries the sha256 of conformance.mjs + index.mjs; the lockstep gate
  //   recomputes them and rejects a STALE manifest, so a disabled check with an un-regenerated manifest is caught at the
  //   shipped gate itself, not by external CI ordering.
  { let mfOk = false; try { const mf = JSON.parse(readFileSync(new URL('../../vectors/conformance-checks.json', import.meta.url), 'utf8')); mfOk = !!(mf && mf.source && /^[0-9a-f]{64}$/.test(mf.source.conformance || '') && /^[0-9a-f]{64}$/.test(mf.source.index || '') && Array.isArray(mf.checks)); } catch { mfOk = false; }
    check('SOURCE-BOUND MANIFEST: the executed-check manifest carries the sha256 of conformance.mjs and index.mjs — the lockstep gate recomputes them and rejects a stale manifest (evidence content-bound to its source, not trusted by CI order)', mfOk); }
}

// ─── round-27 (self-audit) CANON-TRANSPARENCY — the soundness linchpin of the input boundary: `admitDeep` must be
//     byte-transparent to canon, so the door snapshot can NEVER flip a verdict. For any x: if canon(x) succeeds then
//     admitDeep(x) is accepted AND canon(admitDeep(x)) === canon(x) (same bytes); if canon(x) throws then admitDeep(x)
//     is REJECTED. The self-audit caught a depth-64 cap that FALSE-REJECTED a valid deep doc canon accepts, and an
//     earlier function-DROP that ACCEPTED an input canon throws on — both silent verdict flips. This vector locks it.
{
  const rej = (d) => typeof d === 'symbol';
  // the soundness invariant: admitDeep is NEVER LOOSER than canon, and when it ACCEPTS it is byte-transparent — so an
  // input can never VERIFY DIFFERENTLY (or MORE permissively) through the boundary. For any x, at least one holds:
  //   • admitDeep REJECTS x            (fail-closed / stricter than canon — always safe, e.g. a Date or a getter);
  //   • admitDeep ACCEPTS and canon(admitDeep(x)) behaves IDENTICALLY to canon(x): both throw, or byte-for-byte equal.
  // A FAILURE is only: admitDeep ACCEPTS x while canon(admitDeep(x)) diverges from canon(x) (a silent verdict flip).
  let transAllOk = true;
  const trans = (x, l) => {
    let cx, tx = false; try { cx = P.canon(x); } catch { tx = true; }
    const d = P.admitDeep(x); let cd, td = false; try { cd = rej(d) ? null : P.canon(d); } catch { td = true; }
    const ok = rej(d) || (tx ? td : (!td && cd === cx));
    if (!ok) transAllOk = false;
    check('CANON-TRANSPARENT admitDeep — ' + l, ok);
  };
  let deep = {}, cur = deep; for (let i = 0; i < 200; i++) { cur.n = { v: 'x' }; cur = cur.n; }   // string-leaf deep (canon-valid)
  const shared = { s: '1' };
  // canon-VALID (string-leaf) inputs → byte-transparent:
  trans({ a: '1', b: { c: ['x', 'y'], d: 'z' } }, 'plain nested (string leaves)');
  trans({ z: '1', a: '2', m: '3' }, 'key order (canon sorts)');
  trans(deep, 'depth 200 string-leaf (no false-reject of a valid deep doc)');
  trans({ a: shared, b: shared }, 'DAG shared sub-object (accepted, not a cycle)');
  trans({ a: 'é\u{1f600}' }, 'unicode + astral scalar');
  trans(Object.assign(Object.create(null), { a: '1' }), 'null-proto input');
  // canon-INVALID inputs → the boundary fails the same way (no silent accept-and-diverge):
  trans({ a: 42 }, 'number leaf (canon: non-string leaf)');
  trans({ a: null }, 'null leaf (canon: non-string leaf)');
  trans({ a: true }, 'boolean leaf (canon: non-string leaf)');
  trans({ a: 1e400 }, 'Infinity leaf');
  trans({ f: () => 1 }, 'function value (admitDeep rejects)');
  trans({ s: Symbol('x') }, 'symbol value (admitDeep rejects)');
  trans({ d: new Date(0) }, 'Date (non-plain proto — admitDeep rejects, never a flattened {} )');
  check('CANON-TRANSPARENT: admitDeep is byte-transparent to canon (never looser; byte-identical when accepted) — the input-boundary soundness linchpin', transAllOk);
  // round-28 P0-01 fix — the LOCK: a DIFFERENTIAL FUZZ of admitDeep vs canon over a random corpus, so canon-exactness is
  //   answered by a test (not my hand-enumeration, which MISSED pollution names / non-enumerable keys / sparse arrays).
  //   Seeded LCG (deterministic); the generator deliberately emits the classes that diverged: __proto__/constructor/
  //   prototype keys, non-enumerable own props, sparse arrays, numeric-string keys, non-plain protos, deep nesting.
  let s = 0x2f6e2b1 >>> 0; const rnd = () => (s = (s * 1103515245 + 12345) >>> 0) / 0x100000000;
  const POLLUTE = ['__proto__', 'constructor', 'prototype', 'a', 'b', 'toString'];
  const gen = (depth) => {
    const r = rnd();
    if (depth <= 0 || r < 0.4) { const k = rnd(); return k < 0.5 ? String.fromCharCode(97 + ((rnd() * 26) | 0)) + (rnd() * 9 | 0) : (k < 0.7 ? (rnd() * 100 | 0) : (k < 0.85 ? null : (k < 0.95 ? (rnd() < 0.5) : (rnd() < 0.5 ? new Date(0) : Symbol('x')))));  }
    if (r < 0.7) { const n = (rnd() * 4) | 0; const a = []; for (let i = 0; i < n; i++) { if (rnd() < 0.25) { a.length = a.length + 1; } else a.push(gen(depth - 1)); } return a; }
    const o = {}; const n = (rnd() * 4) | 0;
    for (let i = 0; i < n; i++) { const key = POLLUTE[(rnd() * POLLUTE.length) | 0]; Object.defineProperty(o, key, { value: gen(depth - 1), enumerable: rnd() >= 0.2, configurable: true, writable: true }); }   // defineProperty (never assignment) so `__proto__` is a DATA key exactly as JSON.parse produces; ~20% non-enumerable
    return o;
  };
  let fuzzOk = true; const fuzzN = 3000;   // NOTE: the check label below hardcodes "3000" as a LITERAL (not `+ fuzzN +`) so the ONE string aligns across all four surfaces — conformance source (model-correspondence grep), the executed manifest (lockstep gate), the registry, and the model citation. Keep in sync if fuzzN changes.
  for (let i = 0; i < fuzzN; i++) {
    const x = gen(3);
    let cx, tx = false; try { cx = P.canon(x); } catch { tx = true; }
    const d = P.admitDeep(x); const dr = typeof d === 'symbol'; let cd, td = false; try { cd = dr ? null : P.canon(d); } catch { td = true; }
    if (!(dr || (tx ? td : (!td && cd === cx)))) { fuzzOk = false; break; }   // reject, OR (canon throws ⇒ admit throws too) OR (canon ok ⇒ byte-identical)
  }
  check('CANON-TRANSPARENT FUZZ: 3000 random inputs (pollution names / non-enumerable / sparse / non-plain proto / deep) — admitDeep is never looser than canon and byte-identical when accepted', fuzzOk);
  // rev32 R3 (round-29 P0-01) — the CONTROLLER non-bypass. A stateful Proxy answers getOwnPropertyDescriptor one value
  //   (the SIGNED state) and [[Get]] another (a tampered state). admitDeep now snapshots the VALUE through canon's OWN
  //   [[Get]] channel, so verify sees the SAME tampered face canon/contentHash see → the signature fails → INVALID (no
  //   false VALID). And verify EMITS id(x̂), the hash of the admitted snapshot, so identity is a projection of the
  //   admitted artifact, addressed by the returned id — never by a re-read of the raw input.
  {
    const g = P.seal(P.buildState({ domain_shard: A.key_id, ust_id: 'ust:20260628.14', key_id: A.key_id, class: 'observation' }, T, { x: { kind: 'captured', value: { v: 'GOOD' } } }), A.priv, A.pubB64);
    const badState = structuredClone(g.state); badState.data.x.value.v = 'TAMPERED';
    const twoFace = new Proxy(g, { get(t, k, r) { return k === 'state' ? badState : Reflect.get(t, k, r); }, getOwnPropertyDescriptor(t, k) { return Reflect.getOwnPropertyDescriptor(t, k); }, ownKeys(t) { return Reflect.ownKeys(t); }, getPrototypeOf(t) { return Reflect.getPrototypeOf(t); } });
    check('R3 NON-BYPASS: a stateful Proxy answering the descriptor one value and [[Get]] another → INVALID, not a false VALID — verify reads the SAME face canon/identity reads', P.verify(twoFace, { context: 'data' }).result === 'INVALID');
    const vGood = P.verify(g, { context: 'data' });
    check('R3 IDENTITY: verify emits id(x̂) bound to the admitted snapshot it verified — the transcript is addressed by the returned id, not by a re-read of the raw input', vGood.result === 'VALID:LIGHT' && vGood.id === P.contentHash(g));
    // rev35 R3 (round-30 P0-01) — the CONTROLLER spans the RESOLVERS, not just verify. resolveKeys verifies its genesis then
    //   reduces the key-log; a stateful Proxy that shows a SIGNED genesis A to the verify-admission and a different signed
    //   genesis B to the reducer's re-reads must NOT emit B's keys. admitting the genesis ONCE at the reducer door → verify
    //   and every read see the SAME face → the reducer emits the VERIFIED face's keys (A), never the re-read (B).
    {
      const kpR = (h) => { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(h.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' }); const pubB = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url'); return { priv, pubB, kid: P.keyId(pubB) }; };
      const RA = kpR('1a'), RB = kpR('2b'), tR = { generated_at: '2026-06-28T14:00:00Z', valid_from: '2026-06-28T14:00:00Z', valid_to: '2026-06-28T14:00:00Z' };
      const genOf = (K, uid) => P.seal(P.buildGenesis({ domain_shard: 'r3.example', ust_id: uid, key_id: K.kid }, tR, K.pubB), K.priv, K.pubB);
      const gA = genOf(RA, 'ust:20260628.140000'), gB = genOf(RB, 'ust:20260628.140001');
      let rs = 0;
      const face2 = new Proxy(gA, { ownKeys: (t) => Reflect.ownKeys(t), getOwnPropertyDescriptor: (t, k) => Reflect.getOwnPropertyDescriptor(t, k), getPrototypeOf: (t) => Reflect.getPrototypeOf(t), get(t, k, r) { if (k === 'state') { rs++; return rs === 1 ? gA.state : gB.state; } if (k === 'sig') return Reflect.get(t, k, r); return Reflect.get(t, k, r); } });
      const rr = P.resolveKeys(face2, []);
      check('R3 RESOLVER: resolveKeys admits its genesis ONCE — a two-face Proxy (signed A to verify, tampered B to the reducer) emits keys for the VERIFIED face or errors, NEVER the re-read face', !!rr.error || (rr.validKeys && !rr.validKeys.has(RB.kid)));
      // rev38 R3 (round-31 P0-01/02/03) — the class extends to NESTED untrusted objects: admitOpts is SHALLOW, so a resolver
      //   that verifies then re-reads `opts.genesis` (or config.checkpoint / a chain body) operated on a LIVE nested object.
      //   A two-face nested genesis in resolveAuthority's opts must yield the SAME output as the verified face — the unsigned
      //   re-read face never leaks (deep-admit the nested doc once).
      const gNA = P.seal(P.buildGenesis({ domain_shard: 'r3nest.example', ust_id: 'ust:20260628.140000', key_id: RA.kid }, tR, RA.pubB), RA.priv, RA.pubB);
      const gNBraw = structuredClone(gNA); gNBraw.state.data.genesis = { kind: 'computed', value: { max_partitions: '4096' } };
      let ns = 0;
      const gNP = new Proxy(gNA, { ownKeys: (t) => Reflect.ownKeys(t), getOwnPropertyDescriptor: (t, k) => Reflect.getOwnPropertyDescriptor(t, k), getPrototypeOf: (t) => Reflect.getPrototypeOf(t), get(t, k, r) { if (k === 'state') { ns++; return ns === 1 ? gNA.state : gNBraw.state; } return Reflect.get(t, k, r); } });
      const docN = P.seal(P.buildState({ domain_shard: 'r3nest.example', ust_id: 'ust:20260628.140001', key_id: RA.kid, class: 'observation' }, tR, { r: { kind: 'captured', value: { v: 'x' } } }), RA.priv, RA.pubB);
      const honestN = JSON.stringify(P.resolveAuthority(docN, { genesis: gNA }));
      const attackedN = JSON.stringify(P.resolveAuthority(docN, { genesis: gNP }));
      check('R3 NESTED: a two-face NESTED genesis in a resolver opts/config graph → the output is a projection over the VERIFIED face, never the unsigned re-read (round-31 P0-01/02/03; admitOpts is shallow, nested untrusted docs are deep-admitted once)', honestN === attackedN);
      // rev39 R3 (ONE control) — the class is closed at admitOpts (it now deep-admits every nested opts/config DATA value),
      //   NOT per-resolver: a resolver NEVER individually patched (verifyEpochTransition) is ALSO immune to a two-face nested
      //   doc. The nested Proxy is frozen once at the door → the same face reaches the inner verify and every outer read.
      let es = 0;
      const eProxy = new Proxy(gNA, { ownKeys: (t) => Reflect.ownKeys(t), getOwnPropertyDescriptor: (t, k) => Reflect.getOwnPropertyDescriptor(t, k), getPrototypeOf: (t) => Reflect.getPrototypeOf(t), get(t, k, r) { if (k === 'state') { es++; return es === 1 ? gNA.state : gNBraw.state; } return Reflect.get(t, k, r); } });
      P.verifyEpochTransition({ claim: { purpose: 'ust:genesis-epoch-transition' }, sig: { sig: 'a', pub: 'b' } }, { fromAuthority: eProxy });
      check('R3 ONE-CONTROL: admitOpts deep-admits EVERY nested opts/config DATA value once, so a resolver NOT individually patched (verifyEpochTransition) reads its nested doc ≤1 and cannot be shown a second face — the whole nested-doc re-read class is closed at ONE boundary (round-31)', es <= 1);
    }
  }
}

// rev37 R2 (round-30 P1-02) — PROOF OF EXECUTION is observed IN-PROCESS, not read from a committed (forgeable) manifest.
// The rev34 source binding proved which source the manifest CLAIMS to describe, but its `checks` array is caller-authored
// data: an attacker who disables a registered check, RECOMPUTES the source hash, and keeps the old array forges a
// fresh-looking manifest that the standalone gate accepts. Here the lockstep validation runs in the SAME process that ran
// the checks, over the IN-MEMORY `executed` set — a disabled registered check is simply ABSENT from `executed`, so this
// hard-fails the run. (The committed manifest below is retained only as a human-readable / drift artifact, no longer proof.)
{
  const REG = JSON.parse(readFileSync(new URL('../../tools/lockstep-registry.json', import.meta.url), 'utf8'));
  // the REGISTERED adversarial closure (self-contained): a registered check dropped from a synthetic executed set is
  // detected. `sample` is a NON-self record so the synthetic test does not reference this very check.
  const sample = (REG.records || []).map((r) => r.conformance_check).find((c) => c && !c.startsWith('LOCKSTEP IN-PROCESS'));
  const synthetic = new Set(executed); if (sample) synthetic.delete(sample);
  check('LOCKSTEP IN-PROCESS: a disabled registered check is CAUGHT in-process — the lockstep validation over the LIVE executed set flags any registered adversarial-closure check absent from THIS run (never a committed, forgeable manifest; round-30 P1-02)', !!sample && !synthetic.has(sample));
  // the HARD enforcement over the live set — built AFTER the check() above pushed itself, so THIS record is included too;
  // not a registered check() (fail-closes the whole run if ANY registered check did not run+pass in-process):
  const ranSet = new Set(executed);
  const unbacked = (REG.records || []).filter((r) => !r.conformance_check || !ranSet.has(r.conformance_check)).map((r) => r.id);
  if (unbacked.length) { fail++; fails.push('LOCKSTEP IN-PROCESS: registered checks that did NOT run+pass in-process → ' + unbacked.join(',')); }
}
console.log('  ust-protocol ' + P.VERSION.spec + ' conformance vs ' + V.version);
console.log('  PASS ' + pass + '   FAIL ' + fail + '   NOTES ' + note);
if (fails.length) { console.log('\n  FAILURES:'); fails.forEach(f => console.log('    ✗ ' + f)); }
else console.log('  ✓ all exercised checks pass (primitives + 6 findings + Gemini-B + HIGH + TOP)');
// round-28 P1-03 — emit the EXECUTED-check manifest on a green run: the sorted unique set of check ids that actually
// RAN and PASSED. The model-lockstep gate verifies each registered adversarial check is in THIS set (not a source
// substring), so disabling a check while leaving its name in a comment no longer fools the gate; the manifest is
// drift-gated (regenerate == committed) so a deleted check is caught.
// rev34 R2 (round-29 P1-02) — the executed manifest is BOUND to the source it was generated from: it carries the sha256
// of THIS conformance.mjs and of index.mjs, so the lockstep gate can recompute those digests and REJECT a stale manifest.
// Disabling a registered check while leaving the old manifest committed now fails at the SHIPPED gate itself (the source
// digest no longer matches), not merely by external CI ordering. The manifest is the gate's evidence — content-bound to
// its source, exactly as a UST receipt is content-bound to the state it attests.
if (!fail) {
  const srcHash = (rel) => createHash('sha256').update(readFileSync(new URL(rel, import.meta.url))).digest('hex');
  const manifest = { source: { conformance: srcHash('./conformance.mjs'), index: srcHash('./index.mjs') }, checks: [...new Set(executed)].sort() };
  writeFileSync(new URL('../../vectors/conformance-checks.json', import.meta.url), JSON.stringify(manifest, null, 0) + '\n');
}
process.exit(fail ? 1 : 0);                                              // fail-closed for CI / `npm test`
