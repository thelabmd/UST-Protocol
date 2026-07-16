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

export const REFERENCE_CHECKER_VERSION = '1.0.0-rc.37-L1';
const RULES = new Set(['Genesis', 'CheckpointZero', 'CheckpointStep', 'ConnectorEvidence', 'AfterOrder',
  'Corroborated', 'MapUnique', 'QuorumAgreement', 'ReinforceMap', 'ReinforceQuorum',
  'FutureGenesisCommitment', 'ActivateGenesis', 'NameBound', 'Anchored', 'ProjectAssurance']);
const DEFAULT_LIMITS = { maxNodes: 512, maxDepth: 32, maxWitnesses: 1024, maxWitnessBytes: 1 << 20 };
const isHash = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
export const witnessId = (obj) => H('ust:witness', canon(obj));   // content address a witness (for provers building packages)

// ── config normalization (total; §8/§10) — C is a WORLD PARAMETER, never in the term ──────────────────────────────
function normalizeConfig(raw) {
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
  const INDET = (reason) => ({ result: 'INDETERMINATE', reason });
  try {
    if (!pkg || typeof pkg !== 'object' || !pkg.term || typeof pkg.term !== 'object' || !pkg.witnesses || typeof pkg.witnesses !== 'object')
      return INVALID('ProofPackage must be { term, witnesses }');
    const nc = normalizeConfig(rawConfig);
    if (nc.err) return INVALID('config: ' + nc.err);
    const { C, config_id } = nc;
    // §10 bounds BEFORE crypto: witness count/bytes, node count, depth, cycle guard.
    const wids = Object.keys(pkg.witnesses);
    if (wids.length > L.maxWitnesses) return INVALID('too many witnesses (> ' + L.maxWitnesses + ')');
    for (const w of Object.values(pkg.witnesses)) if (canon(w).length > L.maxWitnessBytes) return INVALID('witness exceeds byte cap');
    // §10 acyclic-DAG guard: sharing a sub-proof is ALLOWED (a proof DAG); a CYCLE (node on its own ancestor path)
    // is not. Count unique nodes once; bound depth of the DAG.
    let nodes = 0;
    const counted = new WeakSet();
    const bound = (node, depth, onPath) => {
      if (!node || typeof node !== 'object') throw { reject: INVALID('malformed term node') };
      if (onPath.has(node)) throw { reject: INVALID('cyclic term (a node is its own ancestor)') };
      if (!RULES.has(node.rule)) throw { reject: INVALID('unknown rule "' + node.rule + '" (closed enum)') };
      if (depth > L.maxDepth) throw { reject: INVALID('term too deep (> ' + L.maxDepth + ')') };
      if (!counted.has(node)) { counted.add(node); if (++nodes > L.maxNodes) throw { reject: INVALID('too many term nodes (> ' + L.maxNodes + ')') }; }
      onPath.add(node);
      for (const c of node.children || []) bound(c, depth + 1, onPath);
      onPath.delete(node);
    };
    try { bound(pkg.term, 0, new Set()); } catch (e) { if (e.reject) return e.reject; throw e; }

    // content-addressed witness fetch — recompute H(canon) and match (§2). Never trust a parsed object by identity.
    const W = (wid) => {
      const w = pkg.witnesses[wid];
      if (w === undefined) return { err: 'missing witness ' + wid };
      if (witnessId(w) !== wid) return { err: 'witness_id mismatch (content address)' };
      return { w };
    };
    const R = checkTerm(pkg.term, C, W, new WeakMap());   // returns { j } | { result, reason }; memoized over the DAG
    if (!R.j) return R.result ? R : INVALID(R.reason || 'derivation failed');
    return { result: 'VALID', judgment: R.j, proof_hash: H('ust:proof-term', canon(stripExpected(pkg.term))), config_id };
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
      const t = wit(1); if (t.err) return bad(t.err);
      const b = c.w.body;
      if (!b || b.purpose !== 'ust:authority-checkpoint' || String(b.sequence) !== '0' || b.previous_checkpoint !== undefined || b.previous_epoch_final_checkpoint !== undefined) return bad('C0 must be a seq-0 checkpoint with no previous links');
      const sc = scopeOk(b, G.j); if (sc) return bad(sc);
      if (b.domain_shard !== G.j.domain) return bad('checkpoint domain_shard ≠ genesis domain (§2.y — a diagnostic wire field must agree with the scope)');
      const sg = sigOk(c.w, G.j.chkAuth); if (sg) return bad(sg);
      if (b.checkpoint_authority?.current_key_id !== G.j.chkAuth.key_id) return bad('current_key_id ≠ genesis checkpoint authority');
      const rot = rotationOk(b); if (rot) return bad(rot);
      if (!verifyKeylogTerminality(b.keylog, t.w).terminal) return ind('key-log head terminality not proven');
      return { j: { kind: 'Chain', s: G.j.s, domain: G.j.domain, n: 0, keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, G.j.chkAuth) } };
    }
    case 'CheckpointStep': {
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      const c = wit(0); if (c.err) return bad(c.err);
      const t = wit(2); if (t.err) return bad(t.err);
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
      if (!verifyKeylogTerminality(b.keylog, t.w).terminal) return ind('key-log head terminality not proven');
      return { j: { kind: 'Chain', s: prev.s, domain: prev.domain, n: prev.n + 1, keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, prev.activeAuthority) } };
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
      return { j: { kind: 'Evidence', s: G.j.s, q: cl.subject, caps: evidenceCaps(cl.proof_kind), facts: cl.facts, proof_kind: cl.proof_kind } };
    }
    case 'AfterOrder': {
      const A = sub(0), B = sub(1);
      if (!A.j || A.j.kind !== 'Evidence') return A.j ? bad('child 0 must be Evidence') : A;
      if (!B.j || B.j.kind !== 'Evidence') return B.j ? bad('child 1 must be Evidence') : B;
      if (A.j.s !== B.j.s) return bad('evidences in different scopes');
      const cap = (e) => e.caps.includes('order') || e.caps.includes('time');
      if (!cap(A.j) || !cap(B.j)) return ind('evidence class cannot establish temporal order');
      if (compareEvidenceOrder({ verified_facts: A.j.facts }, { verified_facts: B.j.facts }) !== 'proven-after') return ind('commitment not proven-after the target');
      return { j: { kind: 'After', s: A.j.s, commitCaps: A.j.caps, targetCaps: B.j.caps } };
    }
    case 'Corroborated': {
      const CH = sub(0), CM = sub(1), TG = sub(2), AF = sub(3);
      if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      if (!CM.j || CM.j.kind !== 'Evidence') return CM.j ? bad('child 1 must be Evidence (commitment)') : CM;
      if (!TG.j || TG.j.kind !== 'Evidence') return TG.j ? bad('child 2 must be Evidence (target anchor)') : TG;
      if (!AF.j || AF.j.kind !== 'After') return AF.j ? bad('child 3 must be After') : AF;
      const s = CH.j.s;
      if (CM.j.s !== s || TG.j.s !== s || AF.j.s !== s) return bad('scope mismatch across freshness premises (cross-scope)');
      if (CM.j.q !== CH.j.head_id) return bad('commitment not bound to the checkpoint head');
      const support = [...new Set([...CM.j.caps, ...TG.j.caps])].sort();
      return { j: { kind: 'Freshness', s, q: TG.j.q, h: CH.j.head_id, n: CH.j.n, base: 'corroborated', aeq: {}, support } };
    }
    case 'MapUnique': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const m = wit(0); if (m.err) return bad(m.err);
      const { proof, mapRoot } = m.w;
      if (!C.mapRoots.includes(mapRoot)) return ind('map root is not consumer-admitted (ρ ∉ C.mapRoots)');
      const u = verifyCheckpointMapUniqueness(proof, { domain_shard: G.j.domain, genesis_epoch: genesisEpoch(G.j.active_genesis), sequence: String(p.n), checkpoint: p.h, mapRoot });
      if (!u.attested) return ind('map non-membership not proven at (s,n)');
      return { j: { kind: 'MapUnique', s: G.j.s, n: Number(p.n), h: p.h, rho: mapRoot } };
    }
    case 'QuorumAgreement': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const t = C.policy.uniqueness_threshold;
      const domains = new Set(); let ref = null;
      for (const wid of wt) {
        const a = W(wid); if (a.err) continue;
        const { claim, issuer_id, sig } = a.w || {};
        if (!claim || !sig || claim.purpose !== 'ust:checkpoint-uniqueness-attestation') continue;
        if ('trust_domain' in claim || 'issuer_id' in claim) continue;               // no self-declared independence
        if (claim.genesis_epoch !== genesisEpoch(G.j.active_genesis) || String(claim.sequence) !== String(p.n) || claim.checkpoint !== p.h) continue;
        const cc = canon(claim); if (ref === null) ref = cc; else if (cc !== ref) continue;   // BYTE-IDENTICAL claim
        const pub = C.witnesses[issuer_id];                                            // trust roots FROM C, never the term
        if (!pub || pub !== sig.pub || keyId(sig.pub) !== issuer_id) continue;
        if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, cc, sig.sig)) continue;
        const dom = C.domains[issuer_id]; if (dom === undefined) continue;              // consumer-resolved domain
        domains.add(dom);
      }
      if (domains.size < t) return ind('quorum not met: ' + domains.size + ' distinct domains < ' + t);
      return { j: { kind: 'QuorumAgreement', s: G.j.s, n: Number(p.n), h: p.h, D: [...domains].sort(), t } };
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
      return { j: { kind: 'FutureCommitted', sA: CH.j.s, hB: claim.to_active_genesis, toAuthorityExpected: claim.to_checkpoint_authority } };
    }
    case 'ActivateGenesis': {
      const FC = sub(0); if (!FC.j || FC.j.kind !== 'FutureCommitted') return FC.j ? bad('child 0 must be FutureCommitted') : FC;
      const GB = sub(1); if (!GB.j || GB.j.kind !== 'Genesis') return GB.j ? bad('child 1 must be a VERIFIED Genesis[sB] — a hash cannot introduce it') : GB;
      if (GB.j.active_genesis !== FC.j.hB) return bad('destination genesis contentHash ≠ committed target');
      return { j: { kind: 'EpochActivated', sA: FC.j.sA, sB: GB.j.s, chkAuthB: GB.j.chkAuth } };   // authority from VERIFIED g_B, not the claim
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
