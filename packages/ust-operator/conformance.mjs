import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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

let pass = 0, fail = 0; const executed = [];
const check = (id, ok, d) => { if (ok) { pass++; executed.push(id); } else { fail++; console.log('  ✗ ' + id + (d ? ' — ' + d : '')); } };

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
  // ── advanceHead on its own: EVERY outcome, because an operator that builds its own documents reaches
  // the discipline only through this door. Left inside `append`, it would be reimplemented outside.
  {
    const plain = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, del: async (k) => { m.delete(k); }, _m: m }; };
    const withCas = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, del: async (k) => { m.delete(k); },
      cas: async (k, expect, next) => { if ((m.get(k) ?? null) !== expect) return false; m.set(k, next); return true; }, _m: m }; };
    const grab = async (fn) => { try { await fn(); return null; } catch (e) { return e.code; } };
    // A THROW MUST BE A RED CHECK, NEVER A CRASH: an uncaught rejection ends the suite before its summary
    // AND before the declared==counted gate, so a mutation would be 'caught' by the process dying — which
    // is the weakest signal this file can give. Every state-returning call below goes through this.
    const stateOf = (pr) => pr.then((r) => r.state, (e) => 'THREW:' + (e.code ?? e.message));

    const s1 = plain();
    check('#122 advanceHead: an UNSEEDED store accepts the first head — nobody has written yet, which is not a disagreement',
      (await S.advanceHead(s1, { expected: null, next: 'sha256:a' })) === 'detected' && (await s1.get(S.STREAM_KEYS.head)) === 'sha256:a');
    check('#122 advanceHead: extending the head we observed is accepted',
      (await S.advanceHead(s1, { expected: 'sha256:a', next: 'sha256:b' })) === 'detected');
    check('#122 ADVERSARIAL advanceHead: extending a head we did NOT observe is REFUSED — that is the fork, named before it is published',
      (await grab(() => S.advanceHead(s1, { expected: 'sha256:a', next: 'sha256:c' }))) === 'E-FORK');
    check('#122 advanceHead: the refused write left the store UNCHANGED — a refusal that still wrote would be worse than none',
      (await s1.get(S.STREAM_KEYS.head)) === 'sha256:b');
    check('#122 advanceHead: a missing next is refused rather than storing nothing under the head',
      (await grab(() => S.advanceHead(s1, { expected: 'sha256:b' }))) === 'E-FORK');

    const s2 = withCas();
    check('#122 advanceHead with cas reports PREVENTED — the stronger guarantee, and only when the store gives it',
      (await S.advanceHead(s2, { expected: null, next: 'sha256:x' })) === 'prevented');
    check('#122 ADVERSARIAL advanceHead with cas: the loser of a concurrent write is REFUSED and must not publish',
      (await grab(() => S.advanceHead(s2, { expected: null, next: 'sha256:y' }))) === 'E-FORK');
    // ── F.5r-d: the door is shaped by the EVENT. Every outcome of recordFrame / recordCheckpoint.
    {
      const st = plain();
      const r1 = await S.recordFrame(st, { expected: null, next: 'sha256:f1', ust_id: 'ust:20260705.1801' });
      check('#122 F.5r-d recordFrame: one call moves head, count and the interval start — a caller cannot advance one and forget another',
        r1.count === 1 && (await st.get(S.STREAM_KEYS.head)) === 'sha256:f1' && (await st.get(S.STREAM_KEYS.spanFrom)) === 'ust:20260705.1801' && (await st.get(S.STREAM_KEYS.spanTo)) === 'ust:20260705.1801');
      const r2 = await S.recordFrame(st, { expected: 'sha256:f1', next: 'sha256:f2', ust_id: 'ust:20260705.1802' });
      check('#122 F.5r-d recordFrame: the interval START holds while its END follows the frames — the bounds are what was WRITTEN, not what a grid predicted',
        r2.count === 2 && (await st.get(S.STREAM_KEYS.spanFrom)) === 'ust:20260705.1801' && (await st.get(S.STREAM_KEYS.spanTo)) === 'ust:20260705.1802');
      check('#122 ADVERSARIAL F.5r-d recordFrame: a REFUSED frame moves NOTHING — the guard runs first, so a stream that correctly refused to fork does not count a frame it never emitted',
        (await grab(() => S.recordFrame(st, { expected: 'sha256:stale', next: 'sha256:f3', ust_id: 'ust:20260705.1803' }))) === 'E-FORK'
        && Number(await st.get(S.STREAM_KEYS.count)) === 2 && (await st.get(S.STREAM_KEYS.spanTo)) === 'ust:20260705.1802');

      const counted = [];
      const withIncr = (() => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); },
        incr: async (k) => { counted.push(k); const n = Number(m.get(k) ?? 0) + 1; m.set(k, String(n)); return n; } }; })();
      const ri = await S.recordFrame(withIncr, { expected: null, next: 'sha256:i1', ust_id: 'ust:20260705.1801' });
      check('#122 F.5r-d recordFrame USES store.incr when the store offers it — the count is a read-modify-write, and taking the atomic primitive is not optional politeness',
        ri.count === 1 && counted.length === 1 && counted[0] === S.STREAM_KEYS.count);

      await S.recordCheckpoint(st, { contentHash: 'sha256:cp1' });
      check('#122 F.5r-d recordCheckpoint: the sealed interval is CLOSED IN THE STORE — this reset lived only in the object, so a stream resumed elsewhere read the PREVIOUS interval\'s start and would have sealed the next hour with bounds that begin before it',
        (await st.get(S.STREAM_KEYS.cpHead)) === 'sha256:cp1' && !(await st.get(S.STREAM_KEYS.spanFrom)));
      check('#122 F.5r-e recordCheckpoint CLEARS by deleting, not by writing a sentinel — the key is GONE, not holding an empty string a substrate may refuse to store',
        !st._m.has(S.STREAM_KEYS.spanFrom) || st._m.get(S.STREAM_KEYS.spanFrom) === undefined);
      check('#122 ADVERSARIAL F.5r-e a store with no `del` is REFUSED rather than silently leaving the interval open — measured in production: the empty-string write was rejected 400, the seal reported success, and the next hour would have claimed bounds beginning before itself',
        (await grab(() => S.recordCheckpoint({ get: async () => null, set: async () => {} }, { contentHash: 'sha256:cp' }))) === 'E-STORE');
      const after = await S.recordFrame(st, { expected: 'sha256:f2', next: 'sha256:f4', ust_id: 'ust:20260705.1900' });
      check('#122 F.5r-d the next interval opens at the FIRST frame after the seal, and the count stays CUMULATIVE across the boundary',
        after.count === 3 && (await st.get(S.STREAM_KEYS.spanFrom)) === 'ust:20260705.1900');

      const loaded = await S.loadStreamState(st);
      check('#122 F.5r-d loadStreamState reads the whole group back — an operator sealing an interval needs the count and the checkpoint head, and reading them one key at a time is where an operator invents its own names',
        loaded.head === 'sha256:f4' && loaded.count === 3 && loaded.cpHead === 'sha256:cp1' && loaded.spanFrom === 'ust:20260705.1900' && loaded.spanTo === 'ust:20260705.1900');
    }

    // ── F.5r-f: the fork a SINGLE writer makes when its own head write is lost. Every outcome.
    {
      const st = plain();
      check('#124 F.5r-f reconcileHead with no last emission answers UNVERIFIED — a fresh process cannot rule this out from its own information, and saying so beats assuming',
        (await stateOf(S.reconcileHead(st))) === 'unverified');

      await S.recordFrame(st, { expected: null, next: 'sha256:d1', ust_id: 'ust:20260705.1801' });
      check('#124 F.5r-f reconcileHead: the advance DID land — already-advanced, and nothing is written twice',
        (await stateOf(S.reconcileHead(st, { observed: null, published: 'sha256:d1' }))) === 'already-advanced');

      // THE SCENARIO: the document is published, the head write is LOST. The store still holds d1.
      const lost = { state: await stateOf(S.reconcileHead(st, { observed: 'sha256:d1', published: 'sha256:d2' })), head: await st.get(S.STREAM_KEYS.head) };
      check('#124 F.5r-f ADVERSARIAL the lost advance is REPAIRED, not repeated — publish succeeded, the head write did not, and the next interval must continue from what was PUBLISHED',
        lost.state === 'repaired' && lost.head === 'sha256:d2' && (await st.get(S.STREAM_KEYS.head)) === 'sha256:d2');
      // A THROW HERE MUST BE A RED CHECK, NOT A CRASH. An uncaught rejection ends the suite before its
      // summary and before the declared==counted gate, so the mutation that removes the idempotence
      // short-circuit would be "detected" by the process dying — the worst signal in the file.
      const again = await stateOf(S.reconcileHead(st, { observed: 'sha256:d1', published: 'sha256:d2' }));
      check('#124 F.5r-f the repair is IDEMPOTENT — re-asserting names the same successor of the same predecessor, so a retry is not a second advance',
        again === 'already-advanced' && (await st.get(S.STREAM_KEYS.head)) === 'sha256:d2', 'got ' + again);

      await st.set(S.STREAM_KEYS.head, 'sha256:someone-else');
      check('#124 ADVERSARIAL F.5r-f a head belonging to NEITHER our observation nor our emission is REFUSED — that is another writer extending this stream, and publishing into it is the fork',
        (await grab(() => S.reconcileHead(st, { observed: 'sha256:d1', published: 'sha256:d2' }))) === 'E-FORK');
      check('#124 F.5r-f the refusal left the stored head UNCHANGED — a refusal that still wrote would take the stream from its rightful writer',
        (await st.get(S.STREAM_KEYS.head)) === 'sha256:someone-else');

      const fresh = plain();
      const seeded = { state: await stateOf(S.reconcileHead(fresh, { observed: null, published: 'sha256:first' })) };
      check('#124 F.5r-f on an UNSEEDED store the emission stands — nobody has written, so there is nothing our advance could have raced',
        seeded.state === 'repaired' && (await fresh.get(S.STREAM_KEYS.head)) === 'sha256:first');
    }

    // ── END TO END: the whole failure, on a Stream, with a store that drops exactly one head write.
    {
      const m = new Map(); let dropNext = false;
      const flaky = { get: async (k) => m.get(k) ?? null, del: async (k) => { m.delete(k); },
        set: async (k, v) => { if (k === S.STREAM_KEYS.head && dropNext) { dropNext = false; throw new Error('network'); } m.set(k, v); } };
      const g0 = sign(P.buildGenesis(id('ust:20260705.18'), t, A.pubB64));
      const s1 = new S.Stream({ sign, genesisContentHash: P.contentHash(g0), store: flaky });
      const d1 = await s1.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: '1' } } });
      dropNext = true;
      let published2 = null;
      try { await s1.append(id('ust:20260705.1802'), t, { sw: { kind: 'captured', value: { kp: '2' } } }); }
      catch { published2 = null; }
      // The document WAS built and signed before the store was touched — a real publisher would already have
      // shipped it. Reproduce that: take its hash from a rebuild of the same state.
      const st2 = P.buildState({ ...id('ust:20260705.1802'), class: 'observation' }, t, { sw: { kind: 'captured', value: { kp: '2' } } }, { prev: P.contentHash(d1) });
      published2 = P.contentHash(sign(st2));
      check('#124 F.5r-f END TO END the store still holds the OLD head after the dropped write — this is the state in which a writer forks itself',
        (await flaky.get(S.STREAM_KEYS.head)) === P.contentHash(d1));
      const rec = { state: await stateOf(S.reconcileHead(flaky, { observed: P.contentHash(d1), published: published2 })) };
      check('#124 F.5r-f END TO END reconciling before the next interval REPAIRS the head to the published document, so the next frame extends it instead of forking it',
        rec.state === 'repaired' && (await flaky.get(S.STREAM_KEYS.head)) === published2);
    }

    // ── F.5r-g: recovering the head from what was PUBLISHED, after the emission died with its process.
    {
      const mk = async () => {
        const st = plain();
        const g0 = sign(P.buildGenesis(id('ust:20260705.18'), t, A.pubB64));
        const s1 = new S.Stream({ sign, genesisContentHash: P.contentHash(g0), store: st });
        const d1 = await s1.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: '1' } } });
        const d2 = await s1.append(id('ust:20260705.1802'), t, { sw: { kind: 'captured', value: { kp: '2' } } });
        return { st, d1, d2 };
      };

      const a1 = await mk();
      check('#124 F.5r-g the pointer already names the published head — CONSISTENT, and nothing is written',
        (await stateOf(S.recoverHead(a1.st, { lastPublished: a1.d2 }))) === 'consistent');

      const a2 = await mk();
      await a2.st.set(S.STREAM_KEYS.head, P.contentHash(a2.d1));   // the advance for d2 was published and never recorded
      const r2 = await S.recoverHead(a2.st, { lastPublished: a2.d2 });
      check('#124 F.5r-g ADVERSARIAL the published document EXTENDS the stored head — `prev` is the proof, carried in the document, that this is the successor, so the head is RECOVERED',
        r2.state === 'recovered' && (await a2.st.get(S.STREAM_KEYS.head)) === P.contentHash(a2.d2));

      const a3 = await mk();
      const fresh = plain();
      check('#124 F.5r-g an EMPTY pointer adopts the published head — nothing was ever recorded, so there is nothing to contradict',
        (await stateOf(S.recoverHead(fresh, { lastPublished: a3.d2 }))) === 'recovered'
        && (await fresh.get(S.STREAM_KEYS.head)) === P.contentHash(a3.d2));

      const a4 = await mk();
      await a4.st.set(S.STREAM_KEYS.head, 'sha256:' + 'ab'.repeat(32));
      check('#124 ADVERSARIAL F.5r-g a document that NEITHER is nor extends the stored head is REFUSED — adopting it could chain the next frame beneath another writer\'s live branch, which is the fork this prevents',
        (await grab(() => S.recoverHead(a4.st, { lastPublished: a4.d2 }))) === 'E-FORK');
      check('#124 F.5r-g the refusal left the stored head UNCHANGED — a recovery that overwrites on disagreement takes the stream from whoever holds it',
        (await a4.st.get(S.STREAM_KEYS.head)) === 'sha256:' + 'ab'.repeat(32));

      const a5 = await mk();
      check('#124 F.5r-g with NO document the answer is UNVERIFIED, not a guess — reading the published set is the operator\'s capability, and a layer that faked it would assert what it cannot observe',
        (await stateOf(S.recoverHead(a5.st, {}))) === 'unverified');

      const a6 = await mk();
      await a6.st.set(S.STREAM_KEYS.head, P.contentHash(a6.d1));
      await S.recoverHead(a6.st, { lastPublished: a6.d2 });
      const resumed = await new S.Stream({ sign, genesisContentHash: 'sha256:g', store: a6.st }).resumeFromStore();
      const d3 = await resumed.append(id('ust:20260705.1803'), t, { sw: { kind: 'captured', value: { kp: '3' } } });
      check('#124 F.5r-g END TO END after recovery the next frame extends the PUBLISHED document, not the one the stale pointer named',
        d3.state.provenance.prev === P.contentHash(a6.d2));
    }

    // ── The OTHER two members of W, each with its own outcomes. `gap` extends the chain exactly as an append
    // does; `resume` asserts a head from outside the store and is admissible only while the store agrees.
    {
      const shared = plain();
      const g0 = sign(P.buildGenesis(id('ust:20260705.18'), t, A.pubB64));
      const mk = () => new S.Stream({ sign, genesisContentHash: P.contentHash(g0), store: shared });
      const one = mk(); await one.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: '1' } } });
      const two = await mk().resumeFromStore();
      check('#122 F.5r-c gap: the FIRST gap record from the observed head is accepted',
        !!(await one.gap(id('ust:20260705.1802'), t, 'seal-delay')));
      check('#122 ADVERSARIAL F.5r-c gap: a SECOND instance emitting a gap record from the head it observed is REFUSED — a gap record extends the chain, so it forks like any append',
        (await grab(() => two.gap(id('ust:20260705.1802'), t, 'seal-delay'))) === 'E-FORK');
      check('#122 F.5r-c gap: the store holds the head of the accepted record, so the object and the store never disagree',
        (await shared.get(S.STREAM_KEYS.head)) === one.head);

      check('#122 F.5r-c resume: resuming to the head the store DOES hold is accepted — the operator and the store agree',
        !!(await mk().resume(one.head, 3)));
      check('#122 ADVERSARIAL F.5r-c resume: resuming to a head the store does NOT hold is REFUSED — that difference is another writer, and overwriting it CAUSES the fork',
        (await grab(() => mk().resume('sha256:somewhere-else', 3))) === 'E-FORK');
      check('#122 F.5r-c resume: the refused resume left the stored head UNCHANGED',
        (await shared.get(S.STREAM_KEYS.head)) === one.head);
      const fresh = plain();
      check('#122 F.5r-c resume: on an UNSEEDED store the operator claim stands — nobody has written, so there is nothing to contradict',
        !!(await new S.Stream({ sign, store: fresh }).resume('sha256:known-point', 7)) && (await fresh.get(S.STREAM_KEYS.head)) === 'sha256:known-point');
    }

    // ── Tiers: each tier is its own prev-stream. Built without the operator's store they got an IN-MEMORY head,
    // which is the private head of F.5r-a — every tier of every operator using this was forkable by construction.
    {
      const shared = plain();
      const tiers = new S.Tiers({ sign, genesisContentHash: 'sha256:genesis', store: shared });
      const lo = tiers.stream('light'), hi = tiers.stream('high');
      await lo.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: 'l' } } });
      await hi.append(id('ust:20260705.1801'), t, { sw: { kind: 'captured', value: { kp: 'h' } } });
      check('#122 F.5r-a Tiers: a tier stream writes into the OPERATOR\'s store, not into a private map',
        [...shared._m.keys()].length > 0);
      check('#122 F.5r-a Tiers: the two tiers hold DIFFERENT heads under DIFFERENT keys — one key would present one stream\'s head as another\'s',
        (await shared.get('ust:stream:light:head')) === lo.head && (await shared.get('ust:stream:high:head')) === hi.head && lo.head !== hi.head);
      const casTiers = new S.Tiers({ sign, genesisContentHash: 'sha256:genesis', store: withCas() });
      check('#122 F.5r-a Tiers: a PREVENTING store survives the per-tier namespace — dropping cas in the wrapper would silently downgrade the guarantee the stream then honestly reports',
        casTiers.stream('light').guarantee === 'prevented');
    }

    // F.5r-c — THE DOMAIN IS DERIVED FROM THE SOURCE, NOT LISTED BY HAND. The previous version of this check
    // asserted that `append` routes through the guard, which is satisfied by a layer where every OTHER
    // head-writer is unguarded — and that is exactly what it was: `gap` and `resume` wrote the head directly
    // while this check stayed green. W = every site that WRITES the head key; the claim is that W reduces to
    // the guard itself. A non-writing advance needs no membership: it makes the store lag the object, and the
    // next append's own comparison refuses it.
    const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
    const enclosing = (upto) => {
      const defs = [...upto.matchAll(/^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)|^\s*(?:async\s+)?([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{|^([A-Za-z0-9_$.]+\.prototype\.[A-Za-z0-9_$]+)\s*=/gm)];
      const KW = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'do', 'else']);   // `if (…) {` reads as a definition to a regex; it is not one
      const named = defs.map(d => d[1] ?? d[2] ?? d[3]).filter(n => n && !KW.has(n));
      return named.length ? named[named.length - 1] : '<top-level>';
    };
    const writers = [...src.matchAll(/\.(?:set|cas)\(\s*STREAM_KEYS\.head\b/g)].map(m => enclosing(src.slice(0, m.index)));
    const roster = [...new Set(writers)].sort();
    check('#122 F.5r-c the head-key WRITER ROSTER, enumerated from source, reduces to the guard — a partly guarded layer forks exactly like an unguarded one',
      writers.length >= 2 && roster.length === 1 && roster[0] === 'advanceHead', 'roster=' + JSON.stringify(roster));
    check('#122 F.5r-c CONTROL: the roster reader actually resolves enclosing names — against a planted unguarded writer it names the offender, so a green roster is not a parse failure',
      (() => { const planted = src + '\nexport async function plantedWriter(store) { await store.set(STREAM_KEYS.head, "x"); }\n';
        const w = [...planted.matchAll(/\.(?:set|cas)\(\s*STREAM_KEYS\.head\b/g)].map(m => enclosing(planted.slice(0, m.index)));
        return [...new Set(w)].sort().join(',') === 'advanceHead,plantedWriter'; })());
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
// The layer's roster is PUBLISHED, in the same shape and for the same reason as the core's: without it the
// ladder gate can only resolve checks that live in the core, so every round whose test layer lands HERE would
// be recorded as an exclusion — a structural blind spot dressed as a routine decision. Bound to the digests of
// the source it came from, so a stale roster cannot answer for a suite that has since changed.
if (!fail) {
  const srcHash = (rel) => createHash('sha256').update(readFileSync(new URL(rel, import.meta.url))).digest('hex');
  writeFileSync(new URL('../../vectors/operator-checks.json', import.meta.url),
    JSON.stringify({ source: { conformance: srcHash('./conformance.mjs'), index: srcHash('./index.mjs') }, checks: [...new Set(executed)].sort() }, null, 0) + '\n');
}
if (fail) process.exit(1);
