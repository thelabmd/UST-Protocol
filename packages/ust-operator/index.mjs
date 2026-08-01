// @ust-protocol/operator — the STATEFUL UST operator layer, built ON `ust-protocol` (the stateless base). Everything that
// needs a stream, the key-log, anchoring, or fetching+walking multiple documents. Each piece PRODUCES what
// `ust-protocol` VERIFIES (Stream↔verifyStream, KeyLog↔resolveAuthority, AnchorBatch↔verifyAnchor,
// walkChain↔depth-k). First cut: streams, key-log, anchor-batching, chain-walk. (Substrate adapter, layer
// assembly, cross-tier resumption — next.)
import * as P from 'ust-protocol';   // by PACKAGE NAME, not a relative path: a relative import across packages works
// in this monorepo and breaks the moment the tarball is installed anywhere else — measured the hour this layer
// entered the gated set, by the gate whose whole subject is that what ships must LOAD.

// ─── AnchorBatch (producer of TOP §11.1/§11.2): collect content_hashes → Merkle root → per-doc AnchorProof.
//     Verified by P.verifyAnchor. Uses P's exact ust:leaf/ust:node hashing so the two agree by construction.
function merkleProof(sortedLeaves, target) {
  let idx = sortedLeaves.indexOf(target);
  let nodes = sortedLeaves.map(h => P.Hbytes('ust:leaf', Buffer.from(h, 'utf8')));
  const path = [];
  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      if (i + 1 < nodes.length) {
        if (i === idx) path.push({ dir: 'R', hash: nodes[i + 1] });
        else if (i + 1 === idx) path.push({ dir: 'L', hash: nodes[i] });
        next.push(P.Hbytes('ust:node', Buffer.from(nodes[i] + nodes[i + 1], 'utf8')));
      } else next.push(nodes[i]);
    }
    idx = Math.floor(idx / 2); nodes = next;
  }
  return { root: nodes[0], path };
}
export class AnchorBatch {
  constructor() { this.leaves = []; }
  add(contentHash) { this.leaves.push(contentHash); return this; }
  // build the batch; returns { root, proofFor(content_hash) → AnchorProof }. The Locator is pending until the
  // operator commits `root` to its substrate (bitcoin-ots) and fills in the confirmation evidence.
  build(locator = { substrate: 'bitcoin-ots', status: 'pending' }) {
    const sorted = this.leaves.slice().sort();
    const root = sorted.length ? merkleProof(sorted, sorted[0]).root : null;
    return {
      root,
      proofFor: (ch) => sorted.includes(ch) ? { ...merkleProof(sorted, ch), anchor: locator } : null,
    };
  }
}

// ─── Stream (producer of completeness §11.3): maintain a prev-chain per (domain_shard, tier); emit checkpoints.
//     `sign(state) → signed doc` is supplied by the operator (holds the key). Verified by P.verifyStream.
// STREAM_KEYS is the LAYER's contract, not each operator's invention. Measured on a live operator: five
// values tracked externally under private names against five fields held here — one idea, two
// implementations, and nothing comparing them. Named here, two operators' state is the same shape.
export const STREAM_KEYS = Object.freeze({ head: 'ust:stream:head', count: 'ust:stream:count', cpHead: 'ust:stream:cp-head', spanFrom: 'ust:stream:span-from', spanTo: 'ust:stream:span-to' });

// Memory is the DEFAULT store, never the only one. A job that lives minutes is served by it; a publisher
// that lives months is not, and the layer must not force the second to reimplement the first.
export const memoryStore = () => { const m = new Map(); return { get: (k) => m.get(k) ?? null, set: (k, v) => { m.set(k, v); } }; };

/**
 * THE HEAD DISCIPLINE, on its own — because an operator that builds its own documents cannot reach it
 * inside `append`.
 *
 * `Stream.append` couples three things: build, sign, advance. That serves a producer whose documents the
 * layer makes. It does not serve one that assembles its own — from sources, with its own publish
 * semantics — and such an operator would otherwise reimplement the rule, which is the duplication this
 * layer exists to end. Measured on the first operator to try it.
 *
 * The rule is F.5r: extend only the head you observed. `expected` is what this writer read before
 * building; if the store no longer holds it, somebody else advanced in between and continuing would put
 * two successors under one head.
 *
 * `store.cas` PREVENTS that; a plain `get`/`set` only DETECTS it — the refusal comes one write late.
 * Which one you got is returned, never assumed.
 */
export async function advanceHead(store, { expected = null, next }) {
  if (!next) throw Object.assign(new Error('E-FORK: advanceHead needs the next head'), { code: 'E-FORK' });
  if (typeof store.cas === 'function') {
    const won = await store.cas(STREAM_KEYS.head, expected, next);
    if (!won) throw Object.assign(new Error('E-FORK: lost the compare-and-set on the stream head — a concurrent writer won, and this document must NOT be published (F.5r)'), { code: 'E-FORK' });
    return 'prevented';
  }
  const stored = await store.get(STREAM_KEYS.head);
  if (stored !== null && stored !== expected) {
    throw Object.assign(new Error('E-FORK: the stream head moved under this writer — another writer extended it, and advancing would leave two successors of one head (F.5r)'), { code: 'E-FORK' });
  }
  await store.set(STREAM_KEYS.head, next);
  return 'detected';
}

export class Stream {
  /**
   * #122 / F.5r — THE HEAD MUST NOT BE PRIVATE TO THE APPENDER.
   *
   * Two appenders, each holding its own head, both extend it successfully — and NEITHER sees the other:
   * the second's writes never enter the first's information, so the observation is identical in the world
   * with the fork and the world without. Both documents are individually VALID — the defect is in the PAIR,
   * and no producer holds the pair.
   *
   * `verifyStream` has a guard for two frames sharing a `prev`, but MEASURED (rev73) it is unreachable: the
   * chain check stands before it and fires first. A fork is not two frames in one sequence, it is TWO
   * sequences, each linear and each clean — so no consumer is ever shown it either. Detection downstream
   * does not happen; prevention upstream is the only place left.
   *
   *
   * So the head lives in a STORE shared by the appenders. `store.cas` — compare-and-set — PREVENTS the fork;
   * a plain `get`/`set` only DETECTS it on the next append. The layer states which one it got (`guarantee`)
   * and never claims the stronger.
   */
  constructor({ sign, genesisContentHash, store = memoryStore() }) {
    this.sign = sign; this.genesisContentHash = genesisContentHash ?? null; this.store = store;
    this.guarantee = typeof store.cas === 'function' ? 'prevented' : 'detected';
    // THE HEAD STARTS AT THE GENESIS, not at null: the first frame must chain to the name-binding root, or
    // `verifyStream` answers `first frame prev != genesis content_hash (M4)`. I dropped this while rewriting,
    // because I read the original line truncated to the terminal width — and restored it by reading the diff
    // rather than by guessing.
    this.cpHead = null; this.head = genesisContentHash ?? null; this.count = 0; this.spanFrom = null; this.spanTo = null;
    this.frames = [];
  }
  /** Load the state this stream left behind: the same stream continues in another process. */
  async resumeFromStore() {
    const g = (k) => this.store.get(k);
    this.head = (await g(STREAM_KEYS.head)) ?? null;
    this.count = Number((await g(STREAM_KEYS.count)) ?? 0);
    this.cpHead = (await g(STREAM_KEYS.cpHead)) ?? null;
    this.spanFrom = (await g(STREAM_KEYS.spanFrom)) ?? null;
    this.spanTo = (await g(STREAM_KEYS.spanTo)) ?? null;
    return this;
  }
  async append(idMeta, time, data, cls = 'observation') {
    const state = P.buildState({ ...idMeta, class: cls }, time, data, this.head ? { prev: this.head } : undefined);
    const doc = this.sign(state);
    const next = P.contentHash(doc);
    // ONE implementation of the discipline: `append` calls the same function an external builder calls.
    // Two bodies for one rule would drift apart silently — which is what this layer exists to end.
    // The refusal happens BEFORE the caller can publish `doc`: it is returned only after the head moved.
    await advanceHead(this.store, { expected: this.head ?? null, next });
    // THE RETENTION BOUNDARY: the caller verifies the range against the checkpoint just handed to it and
    // needs the frames at that moment, so they are cleared on the FIRST frame of the next interval —
    // retention bounded to one interval, legitimate use unbroken.
    if (this.intervalClosed) { this.frames = []; this.intervalClosed = false; }
    this.head = next; this.count++; this.frames.push(doc);
    if (!this.spanFrom) this.spanFrom = idMeta.ust_id;
    this.spanTo = idMeta.ust_id;
    await this.store.set(STREAM_KEYS.count, String(this.count));
    await this.store.set(STREAM_KEYS.spanFrom, this.spanFrom);
    await this.store.set(STREAM_KEYS.spanTo, this.spanTo);
    return doc;
  }
  // A checkpoint chains to the PREVIOUS CHECKPOINT — and the first one to the GENESIS. Chaining it to the stream's
  // own head, as this did, leaves the checkpoint chain origin-unbound: nothing ties the sequence of checkpoints to
  // the identity that issued them, so a range verdict cannot be rooted. Measured 2026-07-31 against a hardened
  // implementation that had already learned this in production and warns about it in its own logs.
  //
  // And the INTERVAL is not optional in practice. Without `{from,to}` a range verdict caps at `chain-consistent`
  // forever: a consumer can be shown that nothing was DELETED and never that nothing was MISSING. The bounds are
  // the ust_ids ACTUALLY written — the observed set, not the nominal grid — so an hour that starts late and ends
  // early states what it really covered rather than what a clock would have predicted.
  async checkpoint(idMeta, time, interval = this.observedInterval()) {
    const prev = this.cpHead ?? this.genesisContentHash ?? this.head;
    const doc = this.sign(P.buildCheckpoint(idMeta, time, this.head, this.count, prev, interval));
    this.cpHead = P.contentHash(doc);
    await this.store.set(STREAM_KEYS.cpHead, this.cpHead);   // a checkpoint moves state too, so it writes
    this.intervalClosed = true;   // the caller still needs this interval's frames — see append()

    this.spanFrom = null;                              // the next interval starts from the next frame written
    return doc;
  }
  /** The bounds of what this stream ACTUALLY wrote since the previous checkpoint, or undefined when nothing was. */
  observedInterval() {
    return this.spanFrom && this.spanTo ? { from: this.spanFrom, to: this.spanTo } : undefined;
  }
}

// ─── KeyLog (producer of HIGH §12.2): genesis-rooted append-only chain of class:key transcripts.
//     Verified/resolved by P.resolveAuthority.
export class KeyLog {
  constructor({ genesisDoc, sign }) { this.genesis = genesisDoc; this.head = P.contentHash(genesisDoc); this.entries = []; this.sign = sign; }
  #push(idMeta, time, keyOp) { const e = this.sign(P.buildKeyLogEntry(idMeta, time, keyOp, this.head)); this.head = P.contentHash(e); this.entries.push(e); return e; }
  add(idMeta, time, pub, newKeyId) { return this.#push(idMeta, time, { op: 'add', pub, new_key_id: newKeyId }); }
  // `rotate` REMOVED — rev97 retired the op from the protocol: a self-authorized succession let a compromised key
  // name its own successor. Replacing a key is now TWO events, both authorized by the signer the admissibility
  // invariant demands: `add(k, supersedes: s)` then `revoke(s, 'retired')` — the succession is STATED, not inferred.
  // This layer kept producing the retired op for four months; it surfaced the moment the layer entered the gated
  // set, which is the argument for it being in that set.
  supersede(idMeta, time, pub, newKeyId, supersedesKeyId) {
    const added = this.#push(idMeta, time, { op: 'add', pub, new_key_id: newKeyId, supersedes: supersedesKeyId });
    return added;
  }
  revoke(idMeta, time, pub, reason, compromised_since) { return this.#push(idMeta, time, { op: 'revoke', pub, reason, ...(compromised_since ? { compromised_since } : {}) }); }
}

// ─── sealTree (producer §9.2/§13): seal N referents at ANY N, by composing rather than by asking for a bigger bound.
//
// Breadth is capped at 64 per node and NO declaration raises it — unlike partitions and size, a STRUCTURAL bound
// earns no capacity ladder (F.9.5): the remedy is another level, not a larger number. An hour at a 30 s cadence is
// 120 frames; at the finest grid `ust_id` can address — one second — it is 3600. Both seal at depth 2, because
// ⌈3600/64⌉ = 57 ≤ 64. Composing is arithmetic, needs no authority at all, and a publisher with no genesis does it
// as well as one with.
//
// This lives HERE and not in the base on purpose: the base VERIFIES a composed tree, and building one is a
// producer's job. Measured 2026-07-31 — until this existed, every operator wrote it themselves, and the
// specification's own worked example showed the flat form, which is a document every verifier must refuse.
export const BREADTH = 64;
export async function sealTree(idMeta, time, hashes, sign, { breadth = BREADTH, data = null, prev } = {}) {
  if (!Array.isArray(hashes) || hashes.length === 0) return { error: 'E-BOUNDS', detail: 'sealTree needs at least one referent' };
  const seal = (cs, count, level) => sign(P.buildAttestation({ ...idMeta },
    time, data ?? { seal: { kind: 'computed', value: { frame_count: String(count), node_count: String(cs.length), level: String(level) } } },
    cs, level === 0 ? prev : undefined));   // constituents are plain hash strings — buildAttestation merkles them
  let level = [...hashes], depth = 0, nodes = [];
  while (level.length > breadth) {
    const next = [];
    for (let i = 0; i < level.length; i += breadth) {
      const doc = await seal(level.slice(i, i + breadth), level.slice(i, i + breadth).length, depth);
      nodes.push(doc); next.push(P.contentHash(doc));
    }
    level = next; depth++;
    if (depth > 8) return { error: 'E-BOUNDS', detail: 'composition exceeded the depth law at breadth ' + breadth };
  }
  const root = await seal(level, hashes.length, depth);
  return { root, nodes, depth: depth + 1, leaves: hashes.length };
}

// ─── walkChain (consumer §9.5): walk based_on/constituents referents via `fetch`, verify each, bounded + acyclic.
//     `fetch(content_hash) → doc | null`. depth-0 = local only (P.verify default). Cycle detection by content_hash.
export async function walkChain(doc, fetch, { depth = 1, breadth = 64, seen = new Set() } = {}) {
  const ch = P.contentHash(doc);
  if (seen.has(ch)) return { content_hash: ch, error: 'E-CYCLE' };
  seen.add(ch);
  const v = P.verify(doc, { context: 'data' });
  const node = { content_hash: ch, result: v.result, error: v.error, refs: [] };
  if (depth <= 0) return node;
  const refs = [...(doc.state.provenance?.based_on?.map(b => b.hash) || []), ...(doc.state.provenance?.constituents || [])];
  if (refs.length > breadth) return { ...node, error: 'E-BOUNDS' };
  for (const h of refs) {
    const r = await fetch(h);
    node.refs.push(r ? await walkChain(r, fetch, { depth: depth - 1, breadth, seen }) : { content_hash: h, result: 'unavailable' });
  }
  return node;
}

// ─── §10a SHARD CHAIN & LAYERS (selective disclosure). The outer layer's `seed` commits to its SUBORDINATE
//     layers' content_hashes (G20: no self-reference). Layer authenticity (E4) = each layer's OWN sig — the
//     seed only proves participation. A party holding layers 1..N verifies 1..N (per-party depth).
export const layerSeed = (subordinateDocs) => P.seed(subordinateDocs.map(P.contentHash));
// producer: put the layer seed into the OUTER state, then sign it (subordinates must already exist).
export function sealLayerChain(outerState, subordinateDocs, sign) {
  outerState.provenance = { ...(outerState.provenance || {}), seed: layerSeed(subordinateDocs) };
  return sign(outerState);
}
// consumer: verify a held layer set. `layers` = [outer, ...subordinates the party holds]. Each layer LIGHT-
// verified independently (E4); the outer's seed must equal the seed over the subordinates the party holds.
export function assembleLayers(layers, { outerIndex = 0 } = {}) {
  const perLayer = layers.map(l => ({ content_hash: P.contentHash(l), result: P.verify(l, { context: 'data' }).result }));
  const allValid = perLayer.every(p => typeof p.result === 'string' && p.result.slice(0, 6) === 'VALID:');   // tier-suffixed verdict (VALID:LIGHT/HIGH/TOP), not bare 'VALID'
  const outer = layers[outerIndex], subordinates = layers.filter((_, i) => i !== outerIndex);
  const seedOk = outer.state.provenance?.seed === layerSeed(subordinates);      // G20: over subordinate content_hashes
  return { valid: allValid && seedOk, seedOk, perLayer, verifiedDepth: layers.length };
}

// ─── §11.2/§17 ANCHOR SUBSTRATE registry. `bitcoin-ots`: OTS→Bitcoin header, ≥6 confirmations. The actual OTS
//     parsing + Bitcoin header access are INJECTED (`deps`) — they need external Bitcoin, the engine's job.
//     `substrateVerifier(deps)` returns the callback that `ust-protocol.verifyAnchor` delegates to.
export const substrates = {
  'bitcoin-ots': {
    minConf: 6,
    verify(locator, root, deps = {}) {
      if (locator.status === 'pending' || !locator.ots) return { final: false, detail: 'anchor pending' };
      const att = deps.otsVerify?.(locator.ots, root);                          // → {blockHeight, blockTime} | null (needs the opentimestamps lib)
      if (!att) return { final: false, detail: 'OTS not confirmed against Bitcoin' };
      const conf = deps.confirmations?.(att.blockHeight) ?? 0;                  // → # confirmations (needs a Bitcoin header source)
      return conf >= this.minConf ? { final: true, time: att.blockTime } : { final: false, detail: 'confirmations ' + conf + ' < ' + this.minConf };
    },
  },
};
export const substrateVerifier = (deps = {}) => (locator, root) => substrates[locator?.substrate]?.verify(locator, root, deps) ?? null;

// ─── §11.3 P6 cross-tier & resumption. Each (domain_shard, tier) is its own prev-stream; resumption after an
//     outage is a CONTINUATION (never a new stream-genesis) with an intervening signed gap record (§11.1).
// #122 / F.5r — EVERYTHING THAT MOVES THE HEAD MUST WRITE IT. A missing write here was caught by
// `append`'s own refusal: the next frame saw the stored head disagree with the field and refused.
// The rule takes no exceptions — otherwise the store lags the object and the guard fires on its own side.
Stream.prototype.gap = async function (idMeta, time, reason = 'seal-delay') {          // §11.1 signed gap record: class:attestation, EMPTY constituents
  const state = P.buildState({ ...idMeta, class: 'attestation' }, time, { gap: { kind: 'computed', value: { reason } } }, { prev: this.head, constituents: [] });
  const doc = this.sign(state); this.head = P.contentHash(doc); this.count++; this.frames.push(doc);
  await this.store.set(STREAM_KEYS.head, this.head);
  await this.store.set(STREAM_KEYS.count, String(this.count));
  return doc;
};
Stream.prototype.resume = async function (head, count) {   // continue after an outage from a known point
  this.head = head; this.count = count;
  await this.store.set(STREAM_KEYS.head, head); await this.store.set(STREAM_KEYS.count, String(count));
  return this;
};  // continue after outage from a known head
export class Tiers {                                                             // one prev-stream per tier, shared genesis root
  constructor({ sign, genesisContentHash }) { this.sign = sign; this.genesisContentHash = genesisContentHash; this.byTier = new Map(); }
  stream(tier) { if (!this.byTier.has(tier)) this.byTier.set(tier, new Stream({ sign: this.sign, genesisContentHash: this.genesisContentHash })); return this.byTier.get(tier); }
  tiers() { return [...this.byTier.keys()]; }                                    // declared set — a silently-absent tier is detectable vs this
}
