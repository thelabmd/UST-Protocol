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
export const memoryStore = () => { const m = new Map(); return { get: (k) => m.get(k) ?? null, set: (k, v) => { m.set(k, v); }, del: (k) => { m.delete(k); } }; };

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
export async function advanceHead(store, { expected = null, next, published = null, unseeded = false }) {
  if (!next) throw Object.assign(new Error('E-FORK: advanceHead needs the next head'), { code: 'E-FORK' });
  // F.5r-f — THE OTHER WAY A HEAD GETS TWO SUCCESSORS, AND THE ONE THIS COMPARISON CANNOT SEE.
  //
  // A publisher whose substrate has no transaction across publish-and-record must publish FIRST (recording
  // first leaves the head naming a document nobody can fetch). If that record then fails, the next interval
  // reads the SAME head, extends it again, and two published documents share one `prev` — with no second
  // writer anywhere. `expected` and `stored` are both correct and both equal, so the guard below accepts.
  //
  // The discriminating fact is not in the store: the writer knows WHAT IT PUBLISHED. `published` is the
  // content_hash of this instance's last emitted document, and the rule is that the stored head must be
  // either the head we observed or that emission — never something belonging to neither.
  //
  // Re-asserting a lost advance is IDEMPOTENT: it names the same successor of the same predecessor, so a
  // retry is not a second advance. The two directions are not symmetric — retrying is safe, proceeding past
  // a lost advance IS the fork.
  if (published) {
    const held = await store.get(STREAM_KEYS.head);
    if (held === published) return 'already-advanced';            // the write did land; nothing to do
    if (held !== null && held !== expected) {
      throw Object.assign(new Error('E-FORK: the stored head is neither the head this writer observed nor the document it last published — it belongs to a writer whose emissions this instance has not seen (F.5r-f)'), { code: 'E-FORK' });
    }
    await store.set(STREAM_KEYS.head, published);                 // re-assert OUR lost advance, not a new one
    return 'repaired';
  }
  if (typeof store.cas === 'function') {
    const won = await store.cas(STREAM_KEYS.head, expected, next);
    if (!won) throw Object.assign(new Error('E-FORK: lost the compare-and-set on the stream head — a concurrent writer won, and this document must NOT be published (F.5r)'), { code: 'E-FORK' });
    return 'prevented';
  }
  const stored = await store.get(STREAM_KEYS.head);
  if (stored !== null && stored !== expected) {
    throw Object.assign(new Error('E-FORK: the stream head moved under this writer — another writer extended it, and advancing would leave two successors of one head (F.5r)'), { code: 'E-FORK' });
  }
  // F.5r-h — AN EMPTY HEAD IS ONLY LEGITIMATE ONCE. Accepting `null` unconditionally is what a lying port
  // exploits: a store that answers "absent" on a failed read disarms the comparison above, because `null`
  // reads as "nobody has written yet" and the write proceeds. Past the first frame that reading is false —
  // this stream HAS a head — so the caller must state that it expects an unseeded stream, and only the first
  // frame does. The distinction the port failed to carry is then supplied by the one party that knows.
  if (stored === null && !unseeded) {
    throw Object.assign(new Error('E-FORK: the store reports NO head for a stream that has one — either the head was lost or the read failed and answered "absent"; neither authorizes extending (F.5r-h)'), { code: 'E-FORK' });
  }
  await store.set(STREAM_KEYS.head, next);
  return 'detected';
}

/**
 * F.5r-d — ONE DOOR PER EVENT, NOT PER VALUE. A frame entering the stream moves three stored values: the
 * head, the cumulative count, and the observed interval. They are one fact recorded three ways, and an
 * operator handed three doors becomes responsible for an ordering this layer already knows — a caller that
 * advances the head and forgets the count claims a frame it never emitted, permanently, because the count is
 * cumulative.
 *
 * THE GUARD GOES FIRST. Nothing else is written until the head is accepted, so a refused frame leaves the
 * whole group untouched. Where a partial write is still possible — no store here offers a transaction — it
 * lands on the UNDER-claiming side: a count that lags conceals no omission, while one that leads manufactures
 * evidence of an omission the publisher did not commit.
 *
 * `store.incr` is used when the store offers it, for the same reason `store.cas` is: the count is a
 * read-modify-write, and taking the stronger primitive when it exists is not optional politeness.
 */
export async function recordFrame(store, { expected = null, next, ust_id, unseeded = false }) {
  const guarantee = await advanceHead(store, { expected, next, unseeded });
  const count = typeof store.incr === 'function'
    ? await store.incr(STREAM_KEYS.count)
    : await (async () => { const c = Number((await store.get(STREAM_KEYS.count)) ?? 0) + 1; await store.set(STREAM_KEYS.count, String(c)); return c; })();
  if (ust_id) {
    if (!(await store.get(STREAM_KEYS.spanFrom))) await store.set(STREAM_KEYS.spanFrom, ust_id);
    await store.set(STREAM_KEYS.spanTo, ust_id);
  }
  return { guarantee, count: Number(count) };
}

/**
 * F.5r-d — the OTHER event: an interval was sealed. It moves the checkpoint head and OPENS the next interval.
 *
 * The interval reset used to live only in the object, never in the store — so a stream resumed in another
 * process read the PREVIOUS interval's start and would have sealed the next hour with bounds that begin
 * before it.
 *
 * F.5r-e — CLEARING IS AN OPERATION, NOT A SENTINEL. This first cleared the start by writing the empty
 * string, on the assumption that a `get`/`set` port round-trips it. Measured in production within an hour:
 * a REST key-value store has no path-form for an empty value and answered `400`, the seal reported success,
 * and the interval start still held the PREVIOUS hour's first ust_id — so the next seal would have claimed
 * an hour beginning sixty minutes before itself. Absence is not a value; a store's value domain need not
 * contain a representation of it. A store that cannot delete cannot implement an interval lifecycle, and
 * saying so is better than proceeding on a write that cannot be confirmed.
 */
export async function recordCheckpoint(store, { contentHash }) {
  if (typeof store.del !== 'function') {
    throw Object.assign(new Error('E-STORE: this store offers no `del`, so the open interval cannot be CLEARED — an interval that never closes makes the next seal claim bounds beginning before itself (F.5r-e)'), { code: 'E-STORE' });
  }
  await store.set(STREAM_KEYS.cpHead, contentHash);
  await store.del(STREAM_KEYS.spanFrom);
  return contentHash;
}

/**
 * F.5r-f — RECONCILE BEFORE EXTENDING. Call this at the START of an interval, before building anything,
 * with the content_hash of the document THIS INSTANCE published last. It answers the question the guard
 * cannot: did my own advance land?
 *
 * `already-advanced` — it did. `repaired` — it had not, and has now been re-asserted; the caller must
 * continue from `published`, NOT from whatever it read before. `E-FORK` — the stored head belongs to
 * neither, so another writer is extending this stream and this instance must not publish into it.
 *
 * A caller with no last emission — a fresh process — passes nothing and gets `unverified`: it cannot rule
 * the case out from its own information, and saying so is the honest answer. Ruling it out would require
 * reading the PUBLISHED set, which is a substrate capability this layer does not have and will not fake.
 */
export async function reconcileHead(store, { observed = null, published = null } = {}) {
  if (!published) return { state: 'unverified', head: await store.get(STREAM_KEYS.head) };
  const outcome = await advanceHead(store, { expected: observed, next: published, published });
  return { state: outcome === 'already-advanced' ? 'already-advanced' : 'repaired', head: published };
}

/**
 * F.5r-g — RECOVER THE HEAD FROM WHAT WAS PUBLISHED, because that is where the fact lives.
 *
 * `reconcileHead` needs this instance's own last emission, and a process that ended between publishing and
 * recording took that with it. Its successor holds no discriminator — but the discriminating information did
 * not vanish, it was PUBLISHED. A consumer walking the chain reads documents and never reads the producer's
 * pointer, so the pointer is a CACHE of a fact whose home is the published set.
 *
 * One document decides it, and decides it by PROOF rather than by trust: `d` carries `prev`, so `prev(d)`
 * equal to the stored head is evidence — inside the document — that `d` is that head's successor. No reliance
 * on memory, on a timestamp, or on which of two writers ran last.
 *
 * The last row REFUSES on purpose. Adopting a published head that does not extend the stored one would chain
 * the next frame beneath another writer's live branch — manufacturing the fork this whole section prevents.
 * A disagreement this recovery cannot explain is one it must not resolve.
 *
 * Reading the published set is the OPERATOR's capability; this layer verifies the relation and decides. Where
 * no document is supplied, `unverified` stands and is said rather than assumed.
 */
// F.5r-g.1 — THE COMPLETE OUTCOME SET, declared here so two operators emit the SAME word for the same
// situation. Their telemetry and their incident reports are comparable only if the vocabulary is one; that
// is the same argument that put STREAM_KEYS here rather than in each operator. Measured 2026-08-01: the
// first operator to adopt this minted its own term for the refusal, because the layer named the three
// states it RETURNS and left the one it THROWS unnamed. A vocabulary with a hole gets filled locally.
//
// CLOSED 2026-08-01 by `8a46355b` — protocol(rev80): F.5r-g.1 — a vocabulary with a hole in it gets filled
// locally. In this tree a narration is written in the commit that fixes what it describes, and blame places
// this paragraph there; noted 2026-08-05, appended rather than rewritten.
//
// The prose an operator logs around it may be in any language. The STATE is a token.
export const HEAD_STATES = Object.freeze({
  consistent: 'consistent',   // the pointer already names the last published document
  recovered: 'recovered',     // the published document EXTENDS the pointer — the advance was published, not recorded
  unverified: 'unverified',   // no document to decide with; a gap to be STATED (§11.1), never inferred
  refused: 'refused',         // the document neither is nor extends the pointer — thrown as E-FORK, named here
});

export async function recoverHead(store, { lastPublished = null } = {}) {
  const stored = (await store.get(STREAM_KEYS.head)) || null;
  if (!lastPublished) return { state: 'unverified', head: stored };
  const h = P.contentHash(lastPublished);
  const prev = lastPublished?.state?.provenance?.prev ?? null;
  if (stored === h) return { state: 'consistent', head: h };
  if (stored === null || stored === prev) {
    // Through the SINGLE guard, not around it (F.5r-c): the roster gate caught this the moment it was
    // written as a direct store write, which is exactly what that gate exists for.
    // `unseeded` здесь честно: пустой указатель принимается не по умолчанию, а ПРОТИВ опубликованного
    // документа — решение обеспечено уликой, а не отсутствием возражений (F.5r-h).
    // HEAD RECOVERY IS THE FRAME EVENT (F.5r-d), so it goes through `recordFrame` — the SAME door an ordinary
    // append uses — and moves the SAME GROUP: head, count, interval bound. It used to call `advanceHead`
    // alone, which moved the head and left `span-to` naming the PREDECESSOR and the count one short.
    //
    // MEASURED on the reference operator 2026-08-02: the first reader of that pair — a gap backfill, which
    // measures the hole from `span-to` — found a document sitting where the span said the next slot began and
    // correctly refused to declare a gap over it. The document was OUR OWN, the one the head had just adopted.
    // A stale span is not cosmetic either: §9 requires a stream checkpoint's `to` to be the LAST frame's
    // ust_id, so an hour sealed after a recovery would claim bounds that do not bound its own set.
    //
    // `unseeded` stays honest here: an empty pointer is accepted not by default but AGAINST a published
    // document — the decision is backed by evidence, not by absence of objection (F.5r-h).
    await recordFrame(store, { expected: stored, next: h, ust_id: lastPublished?.state?.id?.ust_id, unseeded: stored === null });
    return { state: 'recovered', head: h };
  }
  throw Object.assign(new Error('E-FORK: the last published document neither is nor extends the stored head — adopting it could chain the next frame beneath another writer\'s live branch, so this disagreement is refused rather than resolved (F.5r-g)'), { code: 'E-FORK' });
}

/** Read back the whole group at once — an operator sealing an interval needs the count and the checkpoint head. */
export async function loadStreamState(store) {
  const g = async (k) => (await store.get(k)) || null;
  return {
    head: await g(STREAM_KEYS.head), count: Number((await store.get(STREAM_KEYS.count)) ?? 0),
    cpHead: await g(STREAM_KEYS.cpHead), spanFrom: await g(STREAM_KEYS.spanFrom), spanTo: await g(STREAM_KEYS.spanTo),
  };
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
    // ONE implementation of the discipline: `append` calls the same door an external builder calls.
    // Two bodies for one rule would drift apart silently — which is what this layer exists to end.
    // The refusal happens BEFORE the caller can publish `doc`: it is returned only after the head moved.
    // Only the FIRST frame of a stream may meet an empty head (F.5r-h); this object knows which one that is.
    const { count } = await recordFrame(this.store, { expected: this.head ?? null, next, ust_id: idMeta.ust_id, unseeded: this.count === 0 });
    // THE RETENTION BOUNDARY: the caller verifies the range against the checkpoint just handed to it and
    // needs the frames at that moment, so they are cleared on the FIRST frame of the next interval —
    // retention bounded to one interval, legitimate use unbroken.
    if (this.intervalClosed) { this.frames = []; this.intervalClosed = false; }
    this.head = next; this.count = count; this.frames.push(doc);
    if (!this.spanFrom) this.spanFrom = idMeta.ust_id;
    this.spanTo = idMeta.ust_id;
    return doc;
  }
  // A checkpoint chains to the PREVIOUS CHECKPOINT — and the first one to the GENESIS. Chaining it to the stream's
  // own head, as this did, leaves the checkpoint chain origin-unbound: nothing ties the sequence of checkpoints to
  // the identity that issued them, so a range verdict cannot be rooted. Measured 2026-07-31 against a hardened
  // implementation that had already learned this in production and warns about it in its own logs.
//
// CLOSED 2026-07-31 by `2749655b` — protocol(rc.46): a worked example taught a refusable document — and the
// fix was not the number (#101). In this tree a narration is written in the commit that fixes what it
// describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  //
  // And the INTERVAL is not optional in practice. Without `{from,to}` a range verdict caps at `chain-consistent`
  // forever: a consumer can be shown that nothing was DELETED and never that nothing was MISSING. The bounds are
  // the ust_ids ACTUALLY written — the observed set, not the nominal grid — so an hour that starts late and ends
  // early states what it really covered rather than what a clock would have predicted.
  async checkpoint(idMeta, time, interval = this.observedInterval()) {
    const prev = this.cpHead ?? this.genesisContentHash ?? this.head;
    const doc = this.sign(P.buildCheckpoint(idMeta, time, this.head, this.count, prev, interval));
    this.cpHead = await recordCheckpoint(this.store, { contentHash: P.contentHash(doc) });
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
//
// CLOSED 2026-07-31 by `2749655b` — protocol(rc.46): a worked example taught a refusable document — and the
// fix was not the number (#101). In this tree a narration is written in the commit that fixes what it
// describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
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
// F.5r-c — THE GUARD BELONGS TO THE KEY, NOT TO THE METHOD. A gap record extends the chain exactly as an
// append does, so two instances each emitting one fork silently. This wrote the head DIRECTLY for four
// months and the check introduced one round earlier stayed green the whole time, because it named `append`
// while the obligation quantifies over every writer.
Stream.prototype.gap = async function (idMeta, time, reason = 'seal-delay') {          // §11.1 signed gap record: class:attestation, EMPTY constituents
  const state = P.buildState({ ...idMeta, class: 'attestation' }, time, { gap: { kind: 'computed', value: { reason } } }, { prev: this.head, constituents: [] });
  const doc = this.sign(state);
  const next = P.contentHash(doc);
  // A gap record IS a frame entering the stream — same event, same door, same order (F.5r-d).
  const { count } = await recordFrame(this.store, { expected: this.head ?? null, next, ust_id: idMeta.ust_id, unseeded: this.count === 0 });
  this.head = next; this.count = count; this.frames.push(doc);
  return doc;
};
// Resumption states a head from knowledge OUTSIDE the store — an operator's assertion, not an observation.
// It is admissible only while the store does not CONTRADICT it: a stored head that differs is another writer
// advancing the stream, and overwriting it CAUSES the fork rather than recovering from one. The comparison
// below is resume's own admissibility question; the WRITE still goes through the single guard.
Stream.prototype.resume = async function (head, count) {   // continue after an outage from a known point
  const stored = await this.store.get(STREAM_KEYS.head);
  if (stored !== null && stored !== head) {
    throw Object.assign(new Error('E-FORK: resuming to a head the store does not hold — another writer advanced this stream, and overwriting its head would fork it (F.5r-c)'), { code: 'E-FORK' });
  }
  await advanceHead(this.store, { expected: stored, next: head, unseeded: stored === null });
  this.head = head; this.count = count;
  await this.store.set(STREAM_KEYS.count, String(count));
  return this;
};  // continue after outage from a known head
// Each tier is its OWN prev-stream, so each needs its own head — under one key they would overwrite each
// other, which is not a fork but something worse: one stream's head presented as another's. The namespace
// is applied HERE rather than by asking the operator to hand over five stores, because the operator's
// infrastructure has one store and the partition is the layer's business.
const namespaced = (store, tier) => {
  const at = (k) => k.startsWith('ust:stream:') ? `ust:stream:${tier}:` + k.slice(11) : `${tier}:${k}`;
  const view = { get: (k) => store.get(at(k)), set: (k, v) => store.set(at(k), v) };
  // `del` carries the interval lifecycle (F.5r-e); a wrapper that drops it turns every tier into a stream
  // whose interval can never close.
  if (typeof store.del === 'function') view.del = (k) => store.del(at(k));
  // The capability must SURVIVE the wrapper: dropping `cas` here would silently downgrade a preventing
  // store to a detecting one, and the stream would then honestly report the weaker guarantee it was given.
  if (typeof store.cas === 'function') view.cas = (k, e, n) => store.cas(at(k), e, n);
  return view;
};
export class Tiers {                                                             // one prev-stream per tier, shared genesis root
  // F.5r-a — a tier stream built WITHOUT the operator's store gets an in-memory head, which is the private
  // head the whole section is about. This constructor accepted no store at all, so every tier of every
  // operator using `Tiers` was forkable by construction.
  constructor({ sign, genesisContentHash, store = memoryStore() }) { this.sign = sign; this.genesisContentHash = genesisContentHash; this.store = store; this.byTier = new Map(); }
  stream(tier) { if (!this.byTier.has(tier)) this.byTier.set(tier, new Stream({ sign: this.sign, genesisContentHash: this.genesisContentHash, store: namespaced(this.store, tier) })); return this.byTier.get(tier); }
  tiers() { return [...this.byTier.keys()]; }                                    // declared set — a silently-absent tier is detectable vs this
}
