import { readFileSync } from 'node:fs';
// @ust-protocol/operator round-trip: PRODUCE with @ust-protocol/operator (stateful) → VERIFY with ust-protocol (stateless). If they agree,
// @assurance 2 canfail:yes — every case is BUILT by this layer and VERIFIED by the base it claims to produce for;
// the differential compares its bytes against the hardened implementation's, and a control reverts the fix to prove it fires
// the two layers compose correctly (Stream↔verifyStream, KeyLog↔resolveAuthority, AnchorBatch↔verifyAnchor).
import * as P from 'ust-protocol';
import * as S from './index.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

function kp(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubRaw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32);
  return { priv, pubB64: pubRaw.toString('base64url'), key_id: P.keyId(pubRaw.toString('base64url')) };
}
const A = kp('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
// Identity here is the KEY: a document that claims no name has nothing for a verifier to confirm, so key-form is
// what LIGHT honestly looks like. Until rc.41 a name-form shard with no chain still read VALID:LIGHT, and this
// file was written then, with the reference operator's own domain hard-coded — an operator-AGNOSTIC layer naming
// one operator. Both are fixed here: key-form for the plain checks, and a generic reserved name below for the one
// check that is ABOUT a name binding.
const dom = A.key_id, NAME = 'operator.test', t = { generated_at: '2026-07-05T18:00:00Z', valid_from: '2026-07-05T18:00:00Z', valid_to: '2036-07-05T18:00:00Z' };
const id = (u, k = A) => ({ domain_shard: dom, ust_id: u, key_id: k.key_id });
const signWith = (k) => (state) => P.seal(state, k.priv, k.pubB64);
const sign = signWith(A);

let pass = 0, fail = 0; const check = (id, ok, d) => { if (ok) pass++; else { fail++; console.log('  ✗ ' + id + (d ? ' — ' + d : '')); } };

// 1. Stream (+ checkpoint) → P.verifyStream
const genesis = sign(P.buildGenesis(id('ust:20260705.18'), t, A.pubB64));
const stream = new S.Stream({ sign, genesisContentHash: P.contentHash(genesis) });
await stream.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: '1' } } });
await stream.append(id('ust:20260705.1802'), t, { sw: { kind: 'captured', value: { kp: '2' } } });
const cp = await stream.checkpoint(id('ust:20260705.1803'), t);
check('Stream→verifyStream-chain-consistent', P.verifyStream(stream.frames, { genesis, checkpoint: cp }).complete === 'chain-consistent');
check('Stream→provisional-no-checkpoint', P.verifyStream(stream.frames, { genesis }).complete === 'provisional');

// 2. KeyLog → P.resolveAuthority (authoritative)
const G = kp('bb'.repeat(32)), K = kp('cc'.repeat(32)), signG = signWith(G);
const gen = signG(P.buildGenesis({ domain_shard: NAME, ust_id: 'ust:20260705.19', key_id: G.key_id }, t, G.pubB64));
const keylog = new S.KeyLog({ genesisDoc: gen, sign: signG });
keylog.add({ domain_shard: NAME, ust_id: 'ust:20260705.1901', key_id: G.key_id }, t, K.pubB64, K.key_id);
const docK = P.seal(P.buildState({ domain_shard: NAME, ust_id: 'ust:20260705.20', key_id: K.key_id, class: 'observation' }, t, { sw: { kind: 'captured', value: { kp: '9' } } }), K.priv, K.pubB64);
// P0-03: `authoritative` needs INDEPENDENT witness no-fork evidence (+ consumer trustRoots), not a raw noForkConfirmed override.
const W = kp('dd'.repeat(32));
const nfe = { noForkEvidence: P.buildNoForkEvidence({ domain_shard: NAME, active_genesis: P.contentHash(gen) }, W.priv, W.pubB64), trustRoots: { [W.key_id]: W.pubB64 } };
const r = P.verify(docK, { genesis: keylog.genesis, keylog: keylog.entries, ...nfe, context: 'data' });
check('KeyLog→authoritative', P.isValid(r) && r.identity?.strength === 'authoritative');

// 3. AnchorBatch → P.verifyAnchor (inclusion)
const batch = new S.AnchorBatch();
stream.frames.concat([cp]).forEach(d => batch.add(P.contentHash(d)));
const built = batch.build();
const target = P.contentHash(stream.frames[1]);
check('AnchorBatch→verifyAnchor-inclusion', P.verifyAnchor(target, built.proofFor(target)).inclusion === true);
check('AnchorBatch-wrong-leaf→null', built.proofFor('sha256:' + '00'.repeat(32)) === null);

// 4. walkChain (consumer §9.5)
const f0 = stream.frames[0];
const store = new Map(stream.frames.map(d => [P.contentHash(d), d]));
const der = P.seal(P.buildDerivation(id('ust:20260705.21'), t, { x: { kind: 'computed', value: { v: '1' } } }, [{ hash: P.contentHash(f0), url: 'u0' }]), A.priv, A.pubB64);
const walk = await S.walkChain(der, async (h) => store.get(h) ?? null, { depth: 1 });
check('walkChain-depth1-verifies-referent', P.isValid(walk) && P.isValid(walk.refs[0]) && walk.refs[0]?.content_hash === P.contentHash(f0));

// 5. LAYERS (§10a): outer's seed commits subordinates' content_hashes (G20); assembleLayers verifies each + seed.
const l2 = P.seal(P.buildState({ ...id('ust:20260705.2202'), class: 'observation' }, t, { d: { kind: 'captured', value: { v: '2' } } }), A.priv, A.pubB64);
const l3 = P.seal(P.buildState({ ...id('ust:20260705.2203'), class: 'observation' }, t, { d: { kind: 'captured', value: { v: '3' } } }), A.priv, A.pubB64);
const l1 = S.sealLayerChain(P.buildState({ ...id('ust:20260705.2201'), class: 'observation' }, t, { top: { kind: 'captured', value: { v: '1' } } }), [l2, l3], sign);   // 'pub' is a RESERVED partition name (sig.pub)
check('Layers:assemble-valid', (a => a.valid === true && a.seedOk === true)(S.assembleLayers([l1, l2, l3])));
check('Layers:missing-subordinate→seed-mismatch', S.assembleLayers([l1, l2]).seedOk === false);

// 6. SUBSTRATE (bitcoin-ots): verifyAnchor delegates to substrateVerifier(deps); ≥6 conf → anchored, else unproven.
const proofS = built.proofFor(target); proofS.anchor = { substrate: 'bitcoin-ots', ots: 'b64url(OTS)', block_height: 900000 };
const depsFinal = { otsVerify: () => ({ blockHeight: 900000, blockTime: '2026-07-05T00:00:00Z' }), confirmations: () => 10 };
const depsPending = { otsVerify: () => ({ blockHeight: 900000 }), confirmations: () => 2 };
check('Substrate:bitcoin-ots-≥6conf→anchored', P.verifyAnchor(target, proofS, { substrateVerify: S.substrateVerifier(depsFinal) }).time === 'anchored');
check('Substrate:<6conf→unproven', P.verifyAnchor(target, proofS, { substrateVerify: S.substrateVerifier(depsPending) }).time === 'unproven');

// 7. CROSS-TIER + RESUMPTION (P6): separate prev-stream per tier; signed gap record; continuation.
const tiers = new S.Tiers({ sign, genesisContentHash: P.contentHash(genesis) });
const hour = tiers.stream('hour'), minute = tiers.stream('minute');
await hour.append(id('ust:20260705.23'), t, { d: { kind: 'captured', value: { v: 'h' } } });
await minute.append(id('ust:20260705.2301'), t, { d: { kind: 'captured', value: { v: 'm' } } });
check('Tiers:separate-prev-streams', tiers.tiers().length === 2 && hour.head !== minute.head);
const gapDoc = await hour.gap(id('ust:20260705.2302'), t, 'outage');
check('Tiers:signed-gap-record', P.isValid(P.verify(gapDoc, { context: 'data' })) && gapDoc.state.provenance.constituents.length === 0 && gapDoc.state.provenance.prev !== undefined);
const afterGap = await hour.append(id('ust:20260705.2303'), t, { d: { kind: 'captured', value: { v: 'h2' } } });   // continuation (not re-genesis)
check('Tiers:continuation-after-gap', afterGap.state.provenance.prev === P.contentHash(gapDoc));

// ── DIFFERENTIAL against the hardened shape (2026-07-31).
// This layer was written from the spec; a production implementation was written from operating the thing, and the
// two had diverged in the direction that matters. The hardened one passed `interval {from,to}` and chained a
// checkpoint's `prev` to the PREVIOUS CHECKPOINT (genesis for the first). This layer passed no interval and chained
// to its own head — origin-unbound, and a range verdict that can never reach `complete`.
//
// Held here rather than remembered: for identical inputs the bytes must be identical. A layer that produces
// something ALMOST like what the hardened path produces is a migration that silently loses a property.
{
  const GEN = 'sha256:' + '99'.repeat(32);
  const mk = async () => { const st = new S.Stream({ sign, genesisContentHash: GEN });
    await st.append(id('ust:20260731.100000'), t, { d: { kind: 'captured', value: { v: '1' } } });
    await st.append(id('ust:20260731.100030'), t, { d: { kind: 'captured', value: { v: '2' } } });
    return st; };
  const mine = await (await mk()).checkpoint(id('ust:20260731.10'), t);
  const hard = await mk();
  const theirs = sign(P.buildCheckpoint(id('ust:20260731.10'), t, hard.head, hard.count, GEN,
    { from: 'ust:20260731.100000', to: 'ust:20260731.100030' }));
  check('differential:checkpoint-bytes-match-hardened', P.canon(mine.state) === P.canon(theirs.state),
    'the layer and the hardened implementation disagree on the bytes of the same checkpoint');
  check('differential:interval-is-observed', mine.state.data.checkpoint.value.from === 'ust:20260731.100000'
    && mine.state.data.checkpoint.value.to === 'ust:20260731.100030',
    'the interval must bound what was ACTUALLY written, not the nominal grid');
  check('differential:first-checkpoint-roots-in-genesis', mine.state.provenance?.prev === GEN,
    'the first checkpoint must chain to the genesis, not to its own head');
}

// ── sealTree (F.9.5, rev65): the escape from a structural bound, realized in the layer where producing lives.
{
  const hs = (n) => Array.from({ length: n }, (_, i) => 'sha256:' + String(i).padStart(64, '0'));
  const idA = { ...id('ust:20260731.10'), class: 'attestation' };
  const at = (n) => S.sealTree(idA, t, hs(n), sign);
  const r64 = await at(64), r120 = await at(120), r3600 = await at(3600);
  check('sealTree:at-the-law-stays-flat', !r64.error && r64.depth === 1 && r64.nodes.length === 0);
  check('sealTree:120-seals-at-depth-2', !r120.error && r120.depth === 2 && r120.nodes.length === 2);
  // The number the model states, computed by the code rather than copied into it.
  check('sealTree:an-hour-at-second-resolution-seals-at-depth-2 (3600 → 57 nodes)',
    !r3600.error && r3600.depth === 2 && r3600.nodes.length === 57);
  check('sealTree:every-node-and-the-root-verify',
    P.isValid(P.verify(r120.root)) && r120.nodes.every((d) => P.isValid(P.verify(d))));
  check('sealTree:refuses-an-empty-set-rather-than-sealing-nothing', (await S.sealTree(idA, t, [], sign)).error === 'E-BOUNDS');
}

// ── #122 / F.5r — THE HEAD IS SHARED, AND A STALE ONE IS REFUSED.
// This lives HERE and not in the core suite: the core's tests must not depend on a layer above them. I
// nearly introduced exactly that by citing an operator check in the model's Binding.
{
  const D = { sw: { kind: 'captured', value: { kp: 'x' } } };
  const store = S.memoryStore();
  const A1 = new S.Stream({ sign, store }), B1 = new S.Stream({ sign, store });
  check('#122 the guarantee is named honestly: get/set yields detected, never prevented', A1.guarantee === 'detected');
  await A1.append(id('ust:20260705.2400'), t, D);
  let refused = null;
  try { await B1.append(id('ust:20260705.2401'), t, D); } catch (e) { refused = e.code; }
  check('#122 ADVERSARIAL: a second appender on a shared head is REFUSED — the fork is named, not produced', refused === 'E-FORK');
  const headBeforeContinue = await store.get(S.STREAM_KEYS.head);
  const C1 = await new S.Stream({ sign, store }).resumeFromStore();
  const cont = await C1.append(id('ust:20260705.2402'), t, D);
  check('#122 a stream resumed from the store continues THE SAME chain in another object',
    C1.count === 2 && cont.state.provenance.prev === headBeforeContinue);   // continues EXACTLY the head that was in the store
  const cas = (() => { const m = new Map(); return { get: (k) => m.get(k) ?? null, set: (k, v) => { m.set(k, v); },
    cas: (k, expect, next) => { if ((m.get(k) ?? null) !== expect) return false; m.set(k, next); return true; } }; })();
  {
    // retention is bounded to ONE interval: after a checkpoint the frames are still available to the
    // caller, and the next interval's first frame clears them. Otherwise a long-lived publisher keeps all.
    const st2 = new S.Stream({ sign, genesisContentHash: P.contentHash(genesis) });
    await st2.append(id('ust:20260705.2500'), t, D); await st2.append(id('ust:20260705.2501'), t, D);
    const cp2 = await st2.checkpoint(id('ust:20260705.2502'), t);
    const heldAtCheckpoint = st2.frames.length;
    await st2.append(id('ust:20260705.2503'), t, D);
    check('#122 frames are available to the caller AT the checkpoint and cleared by the next interval first frame',
      heldAtCheckpoint >= 2 && st2.frames.length === 1 && !!cp2);
  }
  check('#122 with store.cas the layer reports prevented — the stronger guarantee, and only when it holds it',
    new S.Stream({ sign, store: cas }).guarantee === 'prevented');
}

console.log('\n════════════════════════════════════════════');
console.log('  @ust-protocol/operator round-trip vs ust-protocol   PASS ' + pass + '   FAIL ' + fail);




console.log(fail ? '' : '  ✓ @ust-protocol/operator PRODUCES exactly what ust-protocol VERIFIES — layers compose');
// It EXITS. Measured 2026-07-31: this file printed `FAIL 3` and returned 0, so wiring it into CI would have added a
// step that is green while failing — the shape this repository has now met four times in one day. A check that
// cannot fail asserts nothing, and a check that fails without saying so in its exit code is worse: it looks like
// evidence.
// AND LAST: the number of checks DECLARED must equal the number COUNTED. Five checks inserted below this
// print did run — and reached neither the count nor the exit code: the suite stayed green even though they
// could have failed. That is exactly the shape the file above calls the worst. A disagreement between
// declared and counted now fails the suite by itself.
{
  const declared = (readFileSync(new URL(import.meta.url), 'utf8').match(/^\s*check\(\s*'/gm) ?? []).length;
  if (declared !== pass + fail) {
    console.log(`  ✗ ${declared} checks declared, ${pass + fail} counted — some stand BELOW the summary and reach neither the count nor the exit code`);
    process.exit(1);
  }
}
if (fail) process.exit(1);
