// SPDX-License-Identifier: Apache-2.0
// UST Authority REFERENCE CHECKER (L1) — the standalone realization of rnd/REFERENCE-CHECKER.md.
//
// The topology rule made executable: a caller submits ONLY a ProofPackage {term, witnesses} + a consumer Config; the
// checker RE-DERIVES every authority judgment from leaf crypto over content-addressed bytes. It imports ONLY leaf
// primitives (canon/H/keyId/edVerifyStrict/contentHash/verify + the pure Merkle verifiers) — NEVER the authority
// PRODUCER stack (verifiedGenesisContext / verifyAuthorityCheckpointChain / deriveCheckpointFreshness /
// verifyEvidenceReceipt / verifyCheckpointUniqueness / provePredicates / deriveAssurance). So this is a genuine
// independent second derivation, and the producer stack is demoted to an untrusted PROVER that only proposes terms.
//
// Closed enum of rules (one constructor = one inference rule). Total tri-state. Bounds + cycle guard before crypto.
// Conclusions/indices/support are COMPUTED bottom-up; the term carries no trusted conclusion. `C` is a rule INDEX,
// never read from the term. Checker Soundness: check_C(π,W)=VALID(J) ⇒ ∃ derivation of J whose leaves are crypto
// verifications over W (proof: structural induction on π). TCB = this file + the imported leaf primitives.
import { canon, H, keyId, edVerifyStrict, contentHash, verify, isValid, verifyKeylogTerminality,
  verifyCheckpointMapUniqueness, evidenceCaps, compareEvidenceOrder, authorityScopeId, genesisEpoch,
  resolveKeys, buildKeylogCommitment, authorityCheckpointId, strictB64url } from './index.mjs';

export const REFERENCE_CHECKER_VERSION = '1.0.0-rc.37-L1-rev2';
// The closed constructor registry — EXACTLY one inference rule per name, and one `switch` branch below per name. This
// list is the single source of truth for the grammar↔RULES parity gate (P2-02): the spec grammar (§4) and this array
// must match, and a term naming any other constructor (incl. reserved DirectEvidence/NameAuthoritative, or the
// spec-ideal SnapshotTerminal/WitnessVote/EpochCheckpointZero that are realized as folded premises of Corroborated /
// QuorumAgreement / ActivateGenesis) is a structured INVALID('unknown rule'), never silently accepted.
export const REFERENCE_CHECKER_RULES = Object.freeze(['Genesis', 'CheckpointZero', 'CheckpointStep', 'ConnectorEvidence',
  'AfterOrder', 'Corroborated', 'MapUnique', 'QuorumAgreement', 'ReinforceMap', 'ReinforceQuorum',
  'FutureGenesisCommitment', 'ActivateGenesis', 'NameBound', 'Anchored', 'ProjectAssurance']);
const RULES = new Set(REFERENCE_CHECKER_RULES);
const DEFAULT_LIMITS = { maxNodes: 512, maxDepth: 32, maxWitnesses: 1024, maxWitnessBytes: 1 << 20 };
const BOUNDED_READ_FACTOR = 256;   // caps the single-read encode against exponential DAG expansion (totality, §10)
const isHash = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
export const witnessId = (obj) => H('ust:witness', canon(obj));   // content address a witness (for provers building packages)
const POISON = Symbol('malformed-witness');   // a caller witness with non-canonical bytes — reachable only as a structured per-use reject
// CanonicalSeq (§3): a sequence is a canonical decimal string, never a wire value coerced by Number(). Rejects "00",
// "01", "+1", "1.0", " 1" — so the P0-02 "00"→0 alias cannot form. Returns the canonical string, or null.
const decodeSeq = (x) => (typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x)) ? x
  : (typeof x === 'number' && Number.isInteger(x) && x >= 0 ? String(x) : null);
// §2 byte-semantics: read a caller value EXACTLY ONCE into an inert internal value. The counting replacer fires each
// getter once and BOUNDS the read, so a cyclic or exponentially-shared object graph is rejected (not OOM); JSON.parse
// then yields an own-data-only tree with no getters/prototype/proxy. After this the caller object is never read again.
function inertRead(v, bound) {
  let visits = 0, enc;
  try { enc = JSON.stringify(v, (_k, x) => { if (++visits > bound) throw new Error('bounded-read exceeded'); return x; }); }
  catch { return { err: 'not a bounded, acyclic, serializable value' }; }
  if (typeof enc !== 'string') return { err: 'not an encodable object' };
  return { v: JSON.parse(enc) };
}

// ── config normalization (total; §8/§10) — C is a WORLD PARAMETER, never in the term ──────────────────────────────
function normalizeConfig(rawLive) {
  // §2/§8 byte-semantics: snapshot the consumer config ONCE into an inert first-order value, then read only that —
  // kills a config that mutates or resolves via getters between reads (P1-05). config_id is computed over the snapshot.
  const ci = inertRead(rawLive, 1 << 16);
  if (ci.err) return { err: 'config is ' + ci.err };
  const raw = ci.v;
  if (raw === null || typeof raw !== 'object') return { err: 'config must be an object' };
  const connectors = raw.connectors && typeof raw.connectors === 'object' ? raw.connectors : {};
  const mapRoots = Array.isArray(raw.mapRoots) ? raw.mapRoots.filter(isHash) : [];
  const domains = raw.domains && typeof raw.domains === 'object' ? raw.domains : {};
  const witnesses = raw.witnesses && typeof raw.witnesses === 'object' ? raw.witnesses : {};
  const policy = raw.policy && typeof raw.policy === 'object' ? raw.policy : {};
  const uniqueness_threshold = Number.isInteger(policy.uniqueness_threshold) && policy.uniqueness_threshold >= 1 ? policy.uniqueness_threshold : 2;
  const C = Object.freeze({ connectors, mapRoots, domains, witnesses,
    policy: Object.freeze({ uniqueness_threshold, allowExperimentalAttested: policy.allowExperimentalAttested === true }) });
  const config_id = H('ust:consumer-config', canon({
    connectors: Object.fromEntries(Object.entries(connectors).map(([k, v]) => [k, { pub: v.pub, allowed_proof_kinds: v.allowed_proof_kinds || [], ...(v.trust_domain !== undefined ? { trust_domain: v.trust_domain } : {}) }])),
    mapRoots: [...mapRoots].sort(), domains, witnessKeys: Object.keys(witnesses).sort(),
    policy: { uniqueness_threshold: String(uniqueness_threshold), allowExperimentalAttested: C.policy.allowExperimentalAttested ? '1' : '0' } }));
  return { C, config_id };
}

// ── the checker ───────────────────────────────────────────────────────────────────────────────────────────────
export function checkAuthorityProof(pkg, rawConfig, limits = {}) {
  const L = { ...DEFAULT_LIMITS, ...limits };
  const INVALID = (reason) => ({ result: 'INVALID', reason });
  try {
    if (!pkg || typeof pkg !== 'object' || !pkg.term || typeof pkg.term !== 'object' || !pkg.witnesses || typeof pkg.witnesses !== 'object')
      return INVALID('ProofPackage must be { term, witnesses }');
    const nc = normalizeConfig(rawConfig);
    if (nc.err) return INVALID('config: ' + nc.err);
    const { C, config_id } = nc;

    // §2 byte-semantics: read every caller input EXACTLY ONCE into an inert internal value, then never touch the caller
    // object again. Kills, as a CLASS: stateful getters between hash and rule (P0-05), post-hash mutation, prototype
    // inheritance (P1-02), planted non-own fields, representation divergence between two reads, mutable witness refs.
    const ti = inertRead(pkg.term, L.maxNodes * BOUNDED_READ_FACTOR);
    if (ti.err) return INVALID('term is ' + ti.err);
    const term = ti.v;
    // §10 witness COUNT before snapshot (DoS); OWN keys only — a prototype-planted witness is invisible here and, via
    // the null-proto store below, unreachable in W. Snapshot each witness to its canonical inert form (content-address
    // stable): one bounded read → canon → parse, so hashing and every rule read see the SAME frozen bytes.
    const rawKeys = Object.keys(pkg.witnesses);
    if (rawKeys.length > L.maxWitnesses) return INVALID('too many witnesses (> ' + L.maxWitnesses + ')');
    const store = Object.create(null);
    for (const k of rawKeys) {
      const wi = inertRead(pkg.witnesses[k], L.maxWitnessBytes);
      if (wi.err) { store[k] = POISON; continue; }
      let bytes; try { bytes = canon(wi.v); } catch { store[k] = POISON; continue; }
      if (bytes.length > L.maxWitnessBytes) return INVALID('witness exceeds byte cap');
      store[k] = JSON.parse(bytes);
    }
    // §10 acyclic-DAG guard over the INERT term: sharing is expanded to a bounded tree; still reject cycles (defensive)
    // and enforce node/depth caps. Count unique nodes once; bound depth.
    let nodes = 0;
    const counted = new WeakSet();
    const boundTerm = (node, depth, onPath) => {
      if (!node || typeof node !== 'object') throw { reject: INVALID('malformed term node') };
      if (onPath.has(node)) throw { reject: INVALID('cyclic term (a node is its own ancestor)') };
      if (!RULES.has(node.rule)) throw { reject: INVALID('unknown rule "' + node.rule + '" (closed enum)') };
      if ('expected' in node || 'conclusion' in node) throw { reject: INVALID('term node must not carry a conclusion (§5 — the checker recomputes it; a stored conclusion is never trusted, P2-01)') };
      if (depth > L.maxDepth) throw { reject: INVALID('term too deep (> ' + L.maxDepth + ')') };
      if (!counted.has(node)) { counted.add(node); if (++nodes > L.maxNodes) throw { reject: INVALID('too many term nodes (> ' + L.maxNodes + ')') }; }
      onPath.add(node);
      for (const c of node.children || []) boundTerm(c, depth + 1, onPath);
      onPath.delete(node);
    };
    try { boundTerm(term, 0, new Set()); } catch (e) { if (e.reject) return e.reject; throw e; }

    // content-addressed witness fetch from the INERT store — recompute H(canon) and match (§2). The null-proto store
    // resolves OWN keys only, so a wid absent from the caller's own witnesses (e.g. planted on a prototype) is missing.
    const W = (wid) => {
      const w = store[wid];
      if (w === undefined) return { err: 'missing witness ' + wid };
      if (w === POISON) return { err: 'malformed witness bytes (non-canonical) ' + wid };
      if (witnessId(w) !== wid) return { err: 'witness_id mismatch (content address)' };
      return { w };
    };
    const R = checkTerm(term, C, W, new WeakMap());   // returns { j } | { result, reason }; memoized over the DAG
    if (!R.j) return R.result ? R : INVALID(R.reason || 'derivation failed');
    return { result: 'VALID', judgment: R.j, proof_hash: H('ust:proof-term', canon(stripExpected(term))), config_id };
  } catch (e) { return INVALID('checker threw (should be total — please report): ' + (e && e.message ? e.message : String(e))); }
}

const stripExpected = (n) => ({ rule: n.rule, ...(n.params !== undefined ? { params: n.params } : {}), ...(n.witnesses ? { witnesses: n.witnesses } : {}), children: (n.children || []).map(stripExpected) });

// dispatch — each case RE-DERIVES its judgment. Rejections are structured; nothing throws to the caller. Memoized by
// node identity so a SHARED sub-proof (a proof DAG) is checked once, not re-checked per parent.
function checkTerm(node, C, W, memo) {
  if (memo.has(node)) return memo.get(node);
  const R = checkTermInner(node, C, W, memo);
  memo.set(node, R);
  return R;
}
function checkTermInner(node, C, W, memo) {
  const ch = node.children || [], wt = node.witnesses || [], p = node.params || {};
  const bad = (reason) => ({ result: 'INVALID', reason: node.rule + ': ' + reason });
  const ind = (reason) => ({ result: 'INDETERMINATE', reason: node.rule + ': ' + reason });
  const sub = (i) => checkTerm(ch[i], C, W, memo);
  const wit = (i) => W(wt[i]);

  switch (node.rule) {
    case 'Genesis': {
      const g = wit(0); if (g.err) return bad(g.err);
      const doc = g.w;
      if (doc.state?.id?.class !== 'genesis') return bad('not class:genesis');
      if (!isValid(verify(doc, { context: 'genesis' }))) return bad('genesis integrity/signature invalid');
      if (keyId(doc.sig.pub) !== doc.state.id.key_id) return bad('genesis key not self-bound');
      const ca = doc.state?.data?.genesis?.value?.checkpoint_authority;
      if (!ca || !ca.key_id || !ca.pub || keyId(ca.pub) !== ca.key_id) return bad('malformed checkpoint_authority');
      const active_genesis = contentHash(doc);
      return { j: { kind: 'Genesis', s: authorityScopeId(active_genesis), domain: doc.state.id.domain_shard, active_genesis, chkAuth: { key_id: ca.key_id, pub: ca.pub }, genesis: doc } };
    }
    case 'CheckpointZero': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const c = wit(0); if (c.err) return bad(c.err);
      const b = c.w.body;
      if (!b || b.purpose !== 'ust:authority-checkpoint' || String(b.sequence) !== '0' || b.previous_checkpoint !== undefined || b.previous_epoch_final_checkpoint !== undefined) return bad('C0 must be a seq-0 checkpoint with no previous links');
      const sc = scopeOk(b, G.j); if (sc) return bad(sc);
      if (b.domain_shard !== G.j.domain) return bad('checkpoint domain_shard ≠ genesis domain (§2.y — a diagnostic wire field must agree with the scope)');
      const sg = sigOk(c.w, G.j.chkAuth); if (sg) return bad(sg);
      if (b.checkpoint_authority?.current_key_id !== G.j.chkAuth.key_id) return bad('current_key_id ≠ genesis checkpoint authority');
      const rot = rotationOk(b); if (rot) return bad(rot);
      if (!keylogWithinCeiling(b.keylog)) return bad('key-log length exceeds the §13 ceiling (' + KEYLOG_CEIL + ')');   // P1-04
      return { j: { kind: 'Chain', s: G.j.s, domain: G.j.domain, active_genesis: G.j.active_genesis, genesis_epoch: genesisEpoch(G.j.active_genesis), n: 0, keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, G.j.chkAuth) } };
    }
    case 'CheckpointStep': {
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      const c = wit(0); if (c.err) return bad(c.err);
      const b = c.w.body, prev = CH.j;
      if (!b || b.purpose !== 'ust:authority-checkpoint') return bad('not an authority checkpoint');
      if (String(b.sequence) !== String(prev.n + 1)) return bad('sequence ≠ prev+1');
      if (b.previous_checkpoint !== prev.head_id) return bad('previous_checkpoint ≠ prior head');
      const sc = scopeOk(b, { s: prev.s, active_genesis: agFromScope(b) }); if (sc) return bad(sc);
      if (authorityScopeId(b.active_genesis) !== prev.s) return bad('checkpoint scope ≠ chain scope (cross-scope)');
      if (b.domain_shard !== prev.domain) return bad('checkpoint domain_shard changes within the chain (§2.y)');
      const sg = sigOk(c.w, prev.activeAuthority); if (sg) return bad('signer is not the resolved active authority: ' + sg);
      if (b.checkpoint_authority?.current_key_id !== prev.activeAuthority.key_id) return bad('current_key_id ≠ resolved authority');
      const rot = rotationOk(b); if (rot) return bad(rot);
      const ap = appendOnly(prev.keylog, b.keylog, wt[1] !== undefined ? W(wt[1]) : null); if (ap.err) return ap.ind ? ind(ap.err) : bad(ap.err);
      if (!keylogWithinCeiling(b.keylog)) return bad('key-log length exceeds the §13 ceiling (' + KEYLOG_CEIL + ')');   // P1-04
      return { j: { kind: 'Chain', s: prev.s, domain: prev.domain, active_genesis: prev.active_genesis, genesis_epoch: prev.genesis_epoch, n: prev.n + 1, keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, prev.activeAuthority) } };
    }
    case 'ConnectorEvidence': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const r = wit(0); if (r.err) return bad(r.err);
      const cl = r.w.claim, sig = r.w.sig;
      if (!cl || !sig || cl.purpose !== 'ust:evidence-receipt') return bad('not an evidence receipt');
      if (keyId(sig.pub) !== sig.key_id || r.w.issuer_id !== sig.key_id) return bad('issuer_id ≠ keyId(pub)');
      if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, canon({ purpose: 'ust:evidence-receipt-signature', claim: cl }), sig.sig)) return bad('receipt signature invalid');
      for (const k of ['assurance', 'strength', 'trust_domain', 'independent', 'capability', 'attested', 'threshold']) if (k in (cl.facts || {})) return bad('receipt facts must not self-declare ' + k);
      if (cl.active_genesis !== G.j.active_genesis || cl.genesis_epoch !== genesisEpoch(cl.active_genesis)) return bad('receipt scope ≠ genesis scope');
      if (cl.domain_shard !== G.j.domain) return bad('receipt domain_shard ≠ genesis domain (§2.y)');
      if (cl.subject !== p.subject) return bad('receipt subject ≠ required subject');
      // ADMISSION FROM C ONLY (never from the term): the issuer must be a consumer-admitted connector for this kind.
      const conn = C.connectors[sig.key_id];
      if (!conn || conn.pub !== sig.pub) return ind('issuer is not a consumer-admitted connector');
      if (!Array.isArray(conn.allowed_proof_kinds) || !conn.allowed_proof_kinds.includes(cl.proof_kind)) return ind('connector not admitted for proof_kind ' + cl.proof_kind);
      return { j: { kind: 'Evidence', s: G.j.s, e: wt[0], q: cl.subject, caps: evidenceCaps(cl.proof_kind), facts: cl.facts, proof_kind: cl.proof_kind } };   // e = content-addressed evidence identity (M-REL)
    }
    case 'AfterOrder': {
      const A = sub(0), B = sub(1);
      if (!A.j || A.j.kind !== 'Evidence') return A.j ? bad('child 0 must be Evidence') : A;
      if (!B.j || B.j.kind !== 'Evidence') return B.j ? bad('child 1 must be Evidence') : B;
      if (A.j.s !== B.j.s) return bad('evidences in different scopes');
      // §3 typed order: the comparable coordinate is derived ONLY from the proof_kind's authorized caps, NEVER from
      // whatever facts happen to be present. A rfc3161-tsa (time-only) cannot assert a substrate POSITION even with a
      // planted `position` fact; a position order and an interval order are incomparable and never prove-after (P0-07).
      const soC = orderSemantic(A.j.proof_kind, A.j.facts), soT = orderSemantic(B.j.proof_kind, B.j.facts);
      if (soC.kind === 'none' || soT.kind === 'none') return ind('evidence class cannot establish temporal order');
      if (soC.kind !== soT.kind) return ind('incomparable order semantics (position vs interval)');
      if (compareEvidenceOrder({ facts: soC.facts }, { facts: soT.facts }) !== 'proven-after') return ind('commitment not proven-after the target');
      return { j: { kind: 'After', s: A.j.s, eC: A.j.e, eT: B.j.e } };   // M-REL: After is indexed by the two evidences it orders
    }
    case 'Corroborated': {
      const CH = sub(0), CM = sub(1), TG = sub(2), AF = sub(3);
      if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      if (!CM.j || CM.j.kind !== 'Evidence') return CM.j ? bad('child 1 must be Evidence (commitment)') : CM;
      if (!TG.j || TG.j.kind !== 'Evidence') return TG.j ? bad('child 2 must be Evidence (target anchor)') : TG;
      if (!AF.j || AF.j.kind !== 'After') return AF.j ? bad('child 3 must be After') : AF;
      const tm = wit(0); if (tm.err) return bad(tm.err);                                 // terminality of the HEAD key-log
      if (!verifyKeylogTerminality(CH.j.keylog, tm.w).terminal) return ind('key-log head terminality not proven');
      const s = CH.j.s;
      if (CM.j.s !== s || TG.j.s !== s || AF.j.s !== s) return bad('scope mismatch across freshness premises (cross-scope)');
      if (CM.j.q !== CH.j.head_id) return bad('commitment not bound to the checkpoint head');
      // M-REL: the After MUST order THESE two evidences, not a detached proven-after over unrelated ones (P0-01).
      if (AF.j.eC !== CM.j.e || AF.j.eT !== TG.j.e) return bad('After does not order the commitment/target evidences (detached After)');
      const support = [...new Set([...CM.j.caps, ...TG.j.caps])].sort();
      return { j: { kind: 'Freshness', s, q: TG.j.q, h: CH.j.head_id, n: CH.j.n, base: 'corroborated', aeq: {}, support } };
    }
    case 'MapUnique': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const m = wit(0); if (m.err) return bad(m.err);
      const nseq = decodeSeq(p.n); if (nseq === null) return bad('non-canonical sequence coordinate (§3 CanonicalSeq)');   // P0-02: "00" ≠ "0"
      const { proof, mapRoot } = m.w;
      if (!C.mapRoots.includes(mapRoot)) return ind('map root is not consumer-admitted (ρ ∉ C.mapRoots)');
      const u = verifyCheckpointMapUniqueness(proof, { domain_shard: G.j.domain, genesis_epoch: genesisEpoch(G.j.active_genesis), sequence: nseq, checkpoint: p.h, mapRoot });
      if (!u.attested) return ind('map non-membership not proven at (s,n)');
      return { j: { kind: 'MapUnique', s: G.j.s, n: Number(nseq), h: p.h, rho: mapRoot } };
    }
    case 'QuorumAgreement': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const nseq = decodeSeq(p.n); if (nseq === null) return bad('non-canonical sequence coordinate (§3 CanonicalSeq)');
      const t = C.policy.uniqueness_threshold;
      // WitnessVote → QuorumAgreement (§6): ADMIT each vote FIRST (authenticate + consumer-resolve + coordinate-bind),
      // THEN group by the ALREADY-VERIFIED claim. An unadmitted or off-coordinate vote never influences the group — so
      // no quorum-poison via a pre-admission reference claim (P1-01) and no foreign-domain vote (P0-03). Adding junk
      // votes cannot break an existing agreement (positive monotonicity).
      const byClaim = new Map();                                                        // verified claim → Set(distinct domains)
      for (const wid of wt) {
        const a = W(wid); if (a.err) continue;
        const { claim, issuer_id, sig } = a.w || {};
        if (!claim || !sig || claim.purpose !== 'ust:checkpoint-uniqueness-attestation') continue;
        if ('trust_domain' in claim || 'issuer_id' in claim) continue;               // no self-declared independence
        if (claim.domain_shard !== G.j.domain) continue;                             // the attested checkpoint must be in the genesis domain (§2.y, P0-03)
        if (claim.genesis_epoch !== genesisEpoch(G.j.active_genesis) || String(claim.sequence) !== nseq || claim.checkpoint !== p.h) continue;
        const pub = C.witnesses[issuer_id];                                            // trust roots FROM C, never the term
        if (!pub || pub !== sig.pub || keyId(sig.pub) !== issuer_id) continue;
        const cc = canon(claim);
        if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, cc, sig.sig)) continue;   // ADMIT (verify) before grouping
        const dom = C.domains[issuer_id]; if (dom === undefined) continue;              // consumer-resolved domain
        if (!byClaim.has(cc)) byClaim.set(cc, new Set());
        byClaim.get(cc).add(dom);                                                       // group by the VERIFIED claim
      }
      let winner = null;
      for (const [, doms] of byClaim) if (doms.size >= t && (!winner || doms.size > winner.size)) winner = doms;
      if (!winner) return ind('quorum not met: no claim reaches ' + t + ' distinct domains');
      return { j: { kind: 'QuorumAgreement', s: G.j.s, n: Number(nseq), h: p.h, D: [...winner].sort(), t } };
    }
    case 'ReinforceMap': {
      const F = sub(0), M = sub(1);
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 0 must be Freshness') : F;
      if (!M.j || M.j.kind !== 'MapUnique') return M.j ? bad('child 1 must be MapUnique') : M;
      if (F.j.s !== M.j.s || F.j.n !== M.j.n || F.j.h !== M.j.h) return bad('MapUnique does not unify with the freshness (s,n,h)');
      return { j: { ...F.j, aeq: { ...F.j.aeq, map: { root: M.j.rho } }, support: [...new Set([...F.j.support, 'map-uniqueness'])].sort() } };
    }
    case 'ReinforceQuorum': {
      const F = sub(0), Q = sub(1);
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 0 must be Freshness') : F;
      if (!Q.j || Q.j.kind !== 'QuorumAgreement') return Q.j ? bad('child 1 must be QuorumAgreement') : Q;
      if (F.j.s !== Q.j.s || F.j.n !== Q.j.n || F.j.h !== Q.j.h) return bad('QuorumAgreement does not unify with the freshness (s,n,h)');
      return { j: { ...F.j, aeq: { ...F.j.aeq, quorum: { domains: Q.j.D, threshold: String(Q.j.t) } }, support: [...new Set([...F.j.support, 'quorum'])].sort() } };
    }
    case 'FutureGenesisCommitment': {
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain (epoch A)') : CH;
      const cm = wit(0); if (cm.err) return bad(cm.err);
      const { claim, sig } = cm.w;
      if (!claim || claim.purpose !== 'ust:genesis-epoch-transition') return bad('not an epoch-transition commitment');
      if (!isHash(claim.to_active_genesis)) return bad('commitment lacks a target genesis hash');
      if (sig.key_id !== CH.j.activeAuthority.key_id || sig.pub !== CH.j.activeAuthority.pub || !edVerifyStrict(sig.pub, canon(claim), sig.sig)) return bad('commitment not signed by epoch-A authority');
      // M-REL: bind the FROM-side of the transition to chain A — domain, final checkpoint, epoch (P0-04). The bound
      // fields carry forward so the activation cannot substitute a different origin or initial coordinate.
      if (claim.domain_shard !== CH.j.domain) return bad('epoch transition domain_shard ≠ chain-A domain');
      if (claim.from_final_checkpoint !== CH.j.head_id) return bad('epoch transition from_final_checkpoint ≠ chain-A head');
      if (claim.from_genesis_epoch !== CH.j.genesis_epoch) return bad('epoch transition from_genesis_epoch ≠ chain-A epoch');
      const toInitialSeq = decodeSeq(claim.to_initial_sequence); if (toInitialSeq === null) return bad('epoch transition to_initial_sequence is not a CanonicalSeq');
      return { j: { kind: 'FutureCommitted', sA: CH.j.s, hA: CH.j.head_id, domain: CH.j.domain, hB: claim.to_active_genesis, toInitialSeq } };
    }
    case 'ActivateGenesis': {
      const FC = sub(0); if (!FC.j || FC.j.kind !== 'FutureCommitted') return FC.j ? bad('child 0 must be FutureCommitted') : FC;
      const GB = sub(1); if (!GB.j || GB.j.kind !== 'Genesis') return GB.j ? bad('child 1 must be a VERIFIED Genesis[sB] — a hash cannot introduce it') : GB;
      if (GB.j.active_genesis !== FC.j.hB) return bad('destination genesis contentHash ≠ committed target');
      if (GB.j.domain !== FC.j.domain) return bad('epoch transition crosses domains (AllowedTransition requires same domain)');   // P0-04 policy
      // EpochActivated cannot come from signer+hash equality alone — the epoch-B INITIAL checkpoint C0_B must be verified
      // under the epoch-B genesis authority and bound to the epoch-A final checkpoint at the committed sequence (P0-04).
      const c = wit(0); if (c.err) return bad('epoch-B initial checkpoint (C0_B) witness required: ' + c.err);
      const b = c.w.body;
      if (!b || b.purpose !== 'ust:authority-checkpoint') return bad('C0_B is not an authority checkpoint');
      if (b.previous_checkpoint !== undefined) return bad('C0_B must not carry a same-epoch previous_checkpoint');
      if (b.previous_epoch_final_checkpoint !== FC.j.hA) return bad('C0_B previous_epoch_final_checkpoint ≠ epoch-A final checkpoint');
      if (String(b.sequence) !== String(FC.j.toInitialSeq)) return bad('C0_B sequence ≠ committed to_initial_sequence');
      const sc = scopeOk(b, { s: GB.j.s, active_genesis: GB.j.active_genesis }); if (sc) return bad('C0_B ' + sc);
      if (b.domain_shard !== GB.j.domain) return bad('C0_B domain_shard ≠ epoch-B genesis domain (§2.y)');
      const sg = sigOk(c.w, GB.j.chkAuth); if (sg) return bad('C0_B ' + sg);
      if (b.checkpoint_authority?.current_key_id !== GB.j.chkAuth.key_id) return bad('C0_B current_key_id ≠ epoch-B genesis authority');
      const rot = rotationOk(b); if (rot) return bad('C0_B ' + rot);
      if (!keylogWithinCeiling(b.keylog)) return bad('C0_B key-log exceeds the §13 ceiling');
      return { j: { kind: 'EpochActivated', sA: FC.j.sA, sB: GB.j.s, hA: FC.j.hA, nB: Number(decodeSeq(b.sequence)), hB0: authorityCheckpointId(c.w), chkAuthB: GB.j.chkAuth } };   // authority from VERIFIED g_B + verified C0_B, never a claim
    }
    case 'NameBound': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const kl = wt.length ? W(wt[0]) : { w: [] };
      const rk = resolveKeys(G.j.genesis, Array.isArray(kl.w) ? kl.w : []);
      if (rk.error || !rk.validKeys.has(p.doc_key_id)) return ind('document key not bound in the genesis key-log');
      return { j: { kind: 'Identity', s: G.j.s, rung: 'corroborated', caps: [] } };
    }
    case 'Anchored': {
      const a = wit(0); if (a.err) return bad(a.err);
      // minimal: an anchor witness that self-declares inclusion+anchored is NOT trusted; a real substrate proof is a
      // registered direct-proof verifier (future). For L1 we admit only INDETERMINATE unless a direct verifier ran.
      return { j: { kind: 'Time', s: p.s, q: p.subject, rung: 'unproven' } };
    }
    case 'ProjectAssurance': {
      const I = sub(0), F = sub(1), T = sub(2);
      if (!I.j || I.j.kind !== 'Identity') return I.j ? bad('child 0 must be Identity') : I;
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 1 must be Freshness') : F;
      if (!T.j || T.j.kind !== 'Time') return T.j ? bad('child 2 must be Time') : T;
      if (I.j.s !== F.j.s || F.j.s !== T.j.s) return bad('assurance premises span different scopes');
      if (F.j.q !== T.j.q) return bad('freshness and time speak about different subjects (subject unification, P1-03)');
      const tier = (I.j.rung === 'authoritative' && T.j.rung === 'anchored') ? 'TOP' : (I.j.rung === 'authoritative' || I.j.rung === 'corroborated') ? 'HIGH' : 'LIGHT';
      const freshness = { base: F.j.base, anti_equivocation: { quorum: F.j.aeq.quorum || null, map: F.j.aeq.map || null } };
      return { j: { kind: 'Assurance', scope_id: I.j.s, subject: F.j.q, tier, identity: I.j.rung, time: T.j.rung, freshness, support: [...new Set([...F.j.support, ...I.j.caps])].sort() } };
    }
    default: return bad('unreachable');
  }
}

// ── leaf helpers (re-derived here, independent of the producer stack) ─────────────────────────────────────────────
function scopeOk(b, gLike) {
  if (!isHash(b.active_genesis)) return 'active_genesis is not a hash';
  if (b.genesis_epoch !== genesisEpoch(b.active_genesis)) return 'genesis_epoch not canonical (M2)';
  if (gLike.active_genesis !== undefined && b.active_genesis !== gLike.active_genesis) return 'checkpoint active_genesis ≠ genesis (scope)';
  return null;
}
const agFromScope = (b) => b.active_genesis;
const KEYLOG_CEIL = 256;   // §13 key-log ceiling — enforced at every checkpoint introduction (P1-04)
function keylogWithinCeiling(kl) {
  if (!kl || kl.length === undefined) return false;
  const n = decodeSeq(kl.length);
  return n !== null && Number(n) <= KEYLOG_CEIL;
}
// §3 OrderSemantic — the order coordinate an evidence may assert is fixed by its proof_kind's caps, NOT its facts.
// 'order' cap → a Position(substrate, position); else 'time' cap → an Interval(not_before, not_after); else none. A
// planted fact outside the authorized coordinate is stripped, so a time-only kind can never assert a position (P0-07).
function orderSemantic(proof_kind, facts) {
  const caps = evidenceCaps(proof_kind), f = facts || {};
  if (caps.includes('order')) return { kind: 'position', facts: { substrate: f.substrate, position: f.position } };
  if (caps.includes('time')) return { kind: 'interval', facts: { not_before: f.not_before, not_after: f.not_after } };
  return { kind: 'none', facts: {} };
}
function sigOk(cp, auth) {
  const s = cp.sig;
  if (!s || s.alg !== 'Ed25519' || s.key_id !== auth.key_id || s.pub !== auth.pub || keyId(s.pub) !== s.key_id) return 'signer ≠ resolved authority';
  if (strictB64url(s.sig, 64) === null || !edVerifyStrict(s.pub, canon({ purpose: 'ust:authority-checkpoint-signature', body: cp.body }), s.sig)) return 'checkpoint signature invalid';
  return null;
}
function rotationOk(b) {
  const ca = b.checkpoint_authority || {};
  const rot = [ca.next_key_id, ca.next_pub, ca.effective_sequence].filter((x) => x !== undefined).length;
  if (rot !== 0 && rot !== 3) return 'rotation fields must be all-present or all-absent';
  if (rot === 3) { if (keyId(ca.next_pub) !== ca.next_key_id) return 'keyId(next_pub) ≠ next_key_id'; if (ca.effective_sequence !== String(BigInt(b.sequence) + 1n)) return 'effective_sequence ≠ seq+1'; }
  return null;
}
const nextAuthority = (b, signer) => { const ca = b.checkpoint_authority || {}; return (ca.next_key_id !== undefined && ca.effective_sequence === String(BigInt(b.sequence) + 1n)) ? { key_id: ca.next_key_id, pub: ca.next_pub } : signer; };
function appendOnly(prevKl, newKl, entriesWit) {
  const Lp = BigInt(prevKl.length), Ln = BigInt(newKl.length);
  if (Ln < Lp) return { err: 'key-log rewind (length decreased)' };
  if (Ln === Lp) return (newKl.root === prevKl.root && newKl.head === prevKl.head) ? {} : { err: 'equal-length key-log with a different root/head (rewrite)' };
  // GROWTH requires the prefix-extension witness (the entry vector): both keylogs are prefix commitments of it.
  if (!entriesWit || entriesWit.err || !Array.isArray(entriesWit.w)) return { err: 'growth edge requires a prefix-extension witness', ind: true };
  const E = entriesWit.w;
  if (E.length > 256 || !E.every(isHash)) return { err: 'prefix witness malformed or over the §13 ceiling' };
  const kp = buildKeylogCommitment(E.slice(0, Number(Lp))), kn = buildKeylogCommitment(E.slice(0, Number(Ln)));
  if (kp.root !== prevKl.root || kp.head !== prevKl.head || kn.root !== newKl.root || kn.head !== newKl.head) return { err: 'key-logs are not prefixes of one entry vector (append-only unproven)', ind: true };
  return {};
}

// ─── PROVER (untrusted) + demoted public bundle. The prover assembles a candidate proof term π from RAW bundle
//     inputs (no verdicts, no trust); check_C is the SOLE acceptance oracle. This is the round-4 demotion: the old
//     producer stack no longer HONORS a strong verdict — it only proposes a term, and check_C accepts or rejects.
export function buildAuthorityProof(inputs = {}) {
  const { genesis, checkpoints = [], commitment, target, terminality, uniqueness, keylogEntries } = inputs || {};
  const witnesses = {};
  // normalize each witness (drop undefined-valued fields the prover may carry, e.g. an optional terminality field) so
  // the content address is over canon-clean bytes; the checker re-addresses identically.
  const put = (o) => { const c = JSON.parse(JSON.stringify(o ?? {})); const id = witnessId(c); witnesses[id] = c; return id; };
  const N = (rule, children = [], wids = [], params) => ({ rule, children, witnesses: wids, ...(params ? { params } : {}) });
  if (!genesis || !checkpoints.length) return { term: N('Genesis', [], [genesis ? put(genesis) : 'sha256:' + '00'.repeat(32)]), witnesses };
  const πG = N('Genesis', [], [put(genesis)]);
  let πChain = N('CheckpointZero', [πG], [put(checkpoints[0])]);
  const entW = keylogEntries !== undefined ? put(keylogEntries) : undefined;
  for (let i = 1; i < checkpoints.length; i++) πChain = N('CheckpointStep', [πChain], entW !== undefined ? [put(checkpoints[i]), entW] : [put(checkpoints[i])]);
  const last = checkpoints[checkpoints.length - 1], head = authorityCheckpointId(last), n = last.body.sequence;
  const πC = N('ConnectorEvidence', [πG], [put(commitment)], { subject: head });
  const πT = N('ConnectorEvidence', [πG], [put(target?.anchor)], { subject: target?.subject });
  const πAfter = N('AfterOrder', [πC, πT]);
  let root = N('Corroborated', [πChain, πC, πT, πAfter], [put(terminality || {})]);
  if (uniqueness?.map) root = N('ReinforceMap', [root, N('MapUnique', [πG], [put({ proof: uniqueness.map.proof, mapRoot: uniqueness.map.mapRoot })], { n, h: head })]);
  if (uniqueness?.attestations) root = N('ReinforceQuorum', [root, N('QuorumAgreement', [πG], uniqueness.attestations.map(put), { n, h: head })]);
  return { term: root, witnesses };
}
// The ONE public authority verdict — prover ∘ check_C. Trust (connectors/mapRoots/witnesses/domains/threshold) comes
// ONLY from config, never from inputs (§2.w / round-4 P0-02). D1: returns base + anti-equivocation basis, never a
// collapsed scalar `attested`; the legacy `attested` label is a projection requiring MapUnique behind the K1 gate.
export function verifyAuthorityBundle(inputs = {}, config = {}) {
  const trust = config?.trust || {}, policy = config?.policy || {};
  if (!inputs?.genesis) return Object.freeze({ result: 'INDETERMINATE', reason: 'authority_unresolved', detail: 'no genesis — an authority bundle roots in a verified genesis' });
  const chkCfg = { connectors: trust.connectors || {}, mapRoots: trust.mapRoots || [], witnesses: trust.witnesses || {}, domains: trust.domains || {},
    policy: { uniqueness_threshold: Number.isInteger(trust.uniqueness_threshold) ? trust.uniqueness_threshold : 2, allowExperimentalAttested: policy.allowExperimentalAttested === true } };
  const r = checkAuthorityProof(buildAuthorityProof(inputs), chkCfg);
  if (r.result !== 'VALID' || !r.judgment || r.judgment.kind !== 'Freshness')
    return Object.freeze({ result: r.result, ...(r.reason ? { reason: r.reason } : {}), ...(r.judgment ? { judgment_kind: r.judgment.kind } : {}) });
  const j = r.judgment, aeq = j.aeq || {};
  const label = aeq.map && aeq.quorum ? 'dual-attested' : aeq.map ? 'map-attested' : aeq.quorum ? 'witness-attested' : 'corroborated';
  // K1 legacy projection: the scalar `attested` requires MapUnique (cryptographic non-membership) AND the experimental opt-in.
  const legacy = (aeq.map && chkCfg.policy.allowExperimentalAttested) ? 'attested' : 'corroborated';
  return Object.freeze({ result: 'VALID', scope_id: j.s, subject: j.q, head: j.h,
    keylog_freshness: j.base, label, anti_equivocation: { quorum: aeq.quorum || null, map: aeq.map || null },
    ...(aeq.map && !chkCfg.policy.allowExperimentalAttested ? { attested_withheld: 'experimental-gate' } : {}),
    legacy_freshness: legacy, support: j.support, proof_hash: r.proof_hash, config_id: r.config_id });
}
