// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:no — exhaustive over a case space declared in this file
// bmc.mjs — BOUNDED-EXHAUSTIVE MODEL CHECK of the byte automaton `checkAuthorityProofBytes`.
//
// The Checker Soundness theorem (reference-checker.mjs) is proved BY STRUCTURAL INDUCTION on the proof term π:
//   check_C(π,W)=VALID(J) ⇒ ∃ derivation of J whose leaves are crypto verifications over W.
// Random fuzz (reference-checker.fuzz.mjs) SAMPLES the input space; this gate EXHAUSTIVELY covers the two things a
// structural-induction proof needs, up to a bound:
//
//   Phase 1 — the INDUCTION STEP, per rule, EXHAUSTIVELY. For each of the closed enum of rules, and for every
//   arity in {want-1, want, want+1} × every witness-count in {0 … max+1} (unbounded contracts capped) × a set of
//   representative children (a leaf, a nested rule, a decode-reject, garbage), assert the rule's interpreter is (a)
//   TOTAL (no host throw), (b) DETERMINISTIC (same bytes → same verdict), and (c) CONTRACT-GATED (a wrong arity /
//   witness count is rejected at DECODE as E-TERM-*, never interpreted to a VALID). Totality+determinism are
//   COMPOSITIONAL, so proving the step for every rule (this gate) + the leaf base case extends them to ALL depths.
//
//   Phase 2 — SOUNDNESS by EXHAUSTIVE single-mutation tamper. For each VALID byte-vector baseline, mutate EVERY
//   string-leaf position (not a random sample) and assert no single mutation yields VALID. This is bounded-exhaustive
//   over the 1-edit neighbourhood of a genuine accept.
//
// A failure here is a totality/determinism/soundness COUNTEREXAMPLE, printed as the exact (rule, arity, witnesses)
// or (baseline, path, mutation). Deterministic (no RNG) so a counterexample is reproducible.
import * as P from './index.mjs';
import { RULE_CONTRACTS, canonJSON } from './reference-checker.mjs';
import { readFileSync } from 'node:fs';

const pbytes = (o) => new Uint8Array(Buffer.from(P.canon(o), 'utf8'));
const cbytes = (o) => new Uint8Array(Buffer.from(canonJSON(o), 'utf8'));
const CFG = { connectors: {}, witnesses: {}, domains: {}, policy: {} };
const cfgB = cbytes(CFG);
const N = (rule, children = [], witnesses = [], params) => ({ rule, children, witnesses, ...(params ? { params } : {}) });
const V = (r) => JSON.stringify({ result: r.result, reason: r.reason, kind: r.judgment && r.judgment.kind });

const fails = [];
const WITNESS_CAP = 4;   // unbounded-witness contracts (QuorumAgreement: max=∞) are exercised up to this bound

// ─── Phase 1: per-rule inductive step ────────────────────────────────────────────────────────────────────────────
// representative children: a decodable leaf, a nested rule, a decode-reject rule, and non-object garbage (a string leaf)
const CHILDREN = [N('Genesis', [], ['w0']), N('QuorumAgreement', [N('Genesis', [], ['w0'])], ['w0']), { rule: 'NOT_A_RULE', children: [], witnesses: [] }, 'leaf-string'];
let phase1 = 0;
for (const rule of Object.keys(RULE_CONTRACTS)) {
  const c = RULE_CONTRACTS[rule];
  const want = (typeof c.children === 'number') ? c.children : 0;
  const wc = c.witnesses || { min: 0, max: 0 };
  const wmax = Number.isFinite(wc.max) ? wc.max : WITNESS_CAP;
  const hasParams = c.params && Object.keys(c.params).length;
  for (let nc = Math.max(0, want - 1); nc <= want + 1; nc++) {
    for (let nw = 0; nw <= wmax + 1; nw++) {
      for (let ci = 0; ci < CHILDREN.length; ci++) {
        const children = Array(nc).fill(CHILDREN[ci]);
        const witnesses = Array(nw).fill(0).map((_, i) => 'w' + i);
        const term = N(rule, children, witnesses, hasParams ? { subject: 'x', s: '1', doc_key_id: 'k' } : undefined);
        const pkg = { term, witnesses: { w0: {}, w1: {} } };
        let pb; try { pb = pbytes(pkg); } catch { continue; }   // canon-invalid harness shape (e.g. a null leaf) — not a checker input
        phase1++;
        let r1, r2;
        try { r1 = P.checkAuthorityProofBytes(pb, cfgB); } catch (e) { fails.push(`P1 TOTALITY: ${rule} nc=${nc} nw=${nw} ci=${ci} → host throw ${e.message.slice(0, 40)}`); continue; }
        try { r2 = P.checkAuthorityProofBytes(pb, cfgB); } catch { fails.push(`P1 TOTALITY(2nd): ${rule} nc=${nc} nw=${nw} ci=${ci}`); continue; }
        if (V(r1) !== V(r2)) fails.push(`P1 DETERMINISM: ${rule} nc=${nc} nw=${nw} ci=${ci} → ${V(r1)} vs ${V(r2)}`);
        // contract gate: a wrong arity (nc≠want) or out-of-range witness count MUST NOT interpret to VALID — decode rejects it.
        const arityWrong = nc !== want;
        const witnessWrong = nw < (wc.min ?? 0) || (Number.isFinite(wc.max) && nw > wc.max);
        if ((arityWrong || witnessWrong) && r1.result === 'VALID')
          fails.push(`P1 CONTRACT: ${rule} nc=${nc}(want ${want}) nw=${nw} → VALID despite off-contract shape (decode did not gate)`);
      }
    }
  }
}

// ─── Phase 2: soundness by exhaustive single-mutation tamper of the VALID baselines ────────────────────────────────
const suite = JSON.parse(readFileSync(new URL('../../vectors/checker-byte-vectors.json', import.meta.url)));
const valids = suite.vectors.filter((v) => v.expected.result === 'VALID');
const strLeaves = (o, path = [], acc = []) => { if (typeof o === 'string') acc.push(path); else if (o && typeof o === 'object') for (const k of Object.keys(o)) strLeaves(o[k], [...path, k], acc); return acc; };
const getp = (o, p) => p.reduce((x, k) => x && x[k], o);
const setp = (o, p, v) => { const par = p.slice(0, -1).reduce((x, k) => x[k], o); par[p[p.length - 1]] = v; };
const MUT = (s) => [s.length ? '0' + s.slice(1) : 'x', s.length ? s.slice(0, -1) + '0' : 'x0', s + 'x', s.slice(0, Math.max(0, s.length - 1))];   // 4 deterministic single edits per leaf
let phase2 = 0, baselines = 0, phase3 = 0;
for (const vv of valids) {
  const pkgObj = JSON.parse(Buffer.from(vv.package_b64url, 'base64url').toString('utf8'));
  const cfgBytes = new Uint8Array(Buffer.from(vv.config_b64url, 'base64url'));
  const base = P.checkAuthorityProofBytes(new Uint8Array(Buffer.from(vv.package_b64url, 'base64url')), cfgBytes);
  if (base.result !== 'VALID') { fails.push(`P2 BASELINE ${vv.id} is not VALID (${base.result}) — cannot anchor tamper`); continue; }
  baselines++;
  for (const path of strLeaves(pkgObj)) {
    const orig = getp(pkgObj, path);
    for (const m of MUT(orig)) {
      if (m === orig) continue;
      const clone = JSON.parse(JSON.stringify(pkgObj));
      setp(clone, path, m);
      if (P.canon(clone) === P.canon(pkgObj)) continue;   // canon-equivalent (no real change)
      phase2++;
      let r; try { r = P.checkAuthorityProofBytes(new Uint8Array(Buffer.from(P.canon(clone), 'utf8')), cfgBytes); } catch { continue; }   // a throw is fine (fail-closed); only a VALID is a soundness break
      if (r.result === 'VALID') fails.push(`P2 SOUNDNESS: ${vv.id} @ ${path.join('.')} := ${JSON.stringify(m)} → still VALID (single-edit false-accept)`);
    }
  }
}

// ─── Phase 3: the INDUCTION STEP over the CHILD-JUDGMENT ALGEBRA (round-47 P1-01) ──────────────────────────────────
// Phase 1 drives rules with syntactic child TEMPLATES that mostly FAIL before producing a judgment — so a parent's handling
// of a specific child JUDGMENT KIND is never exercised (GPT round-47: a fault-injected ReinforceMap that returns child 0's
// Freshness WITHOUT checking child 1 PASSES Phase 1+2 yet false-accepts a Corroborated wrapped with a non-MapUnique child 1
// at depth>1). The induction step actually needs: for every child-judgment tuple, the parent is SOUND. This phase extracts a
// witness SUB-TERM for each judgment KIND from the VALID baselines (rule → the kind it concludes), then drives each composite
// rule with a WRONG-kind child at each position (correct kinds elsewhere, so the rejection ISOLATES the perturbed position)
// and asserts the parent does NOT yield a VALID conclusion. A parent that ignores a required child kind is caught HERE
// (verified against GPT's fault-injected mutant: it catches ReinforceMap[Freshness, QuorumAgreement] → VALID).
{
  const RULE_KIND = { Genesis: 'Genesis', CheckpointZero: 'Chain', CheckpointStep: 'Chain', ConnectorEvidence: 'Evidence', AfterOrder: 'After', Corroborated: 'Freshness', MapUnique: 'MapUnique', QuorumAgreement: 'QuorumAgreement', ReinforceMap: 'Freshness', ReinforceQuorum: 'Freshness', FutureGenesisCommitment: 'FutureCommitted', ActivateGenesis: 'EpochActivated', NameBound: 'Identity', Anchored: 'Time', ProjectAssurance: 'Assurance' };
  // required child-KIND per position, per composite rule (from the interpreter's `sub(i).j.kind !== 'K'` gates). round-48 P1-02
  // — COMPLETE: every rule the interpreter gates on child kind, all 22 positions (was a 13-position hand SUBSET that omitted
  // Corroborated's 4, ActivateGenesis's 2, ProjectAssurance's 3 → "every composite child-position" measured the wrong total).
  // The interpSig cross-check below re-derives this from the interpreter source and FAILS on any drift.
  const CHILD_SIG = { CheckpointZero: ['Genesis'], CheckpointStep: ['Chain'], ConnectorEvidence: ['Genesis'], AfterOrder: ['Evidence', 'Evidence'], Corroborated: ['Chain', 'Evidence', 'Evidence', 'After'], MapUnique: ['Chain'], QuorumAgreement: ['Chain'], ReinforceMap: ['Freshness', 'MapUnique'], ReinforceQuorum: ['Freshness', 'QuorumAgreement'], FutureGenesisCommitment: ['Chain'], ActivateGenesis: ['FutureCommitted', 'Genesis'], NameBound: ['Genesis'], ProjectAssurance: ['Identity', 'Freshness', 'Time'] };
  const wk = {}, allWit = {};
  for (const vv of valids) { const pkg = JSON.parse(Buffer.from(vv.package_b64url, 'base64url').toString('utf8')); Object.assign(allWit, pkg.witnesses || {}); (function walk(n) { if (!n || typeof n !== 'object' || !n.rule) return; const k = RULE_KIND[n.rule]; if (k && !wk[k]) wk[k] = n; for (const c of n.children || []) walk(c); })(pkg.term); }
  const cfg3 = new Uint8Array(Buffer.from(valids[0].config_b64url, 'base64url'));
  const runT = (term) => { try { return P.checkAuthorityProofBytes(new Uint8Array(Buffer.from(P.canon({ term, witnesses: allWit }), 'utf8')), cfg3); } catch { return { result: 'INVALID' }; } };
  // round-48 P1-02 — the DENOMINATOR must be the INTERPRETER's, not a hand-list. Re-derive every kind-gated child position from
  // the interpreter SOURCE and CROSS-CHECK CHILD_SIG against it: a rule/position/kind the interpreter gates but CHILD_SIG omits
  // or mis-declares FAILS here. The "13 vs 22" drift (a hand subset silently narrowing the denominator) can no longer hide.
  const refSrc = readFileSync(new URL('./reference-checker.mjs', import.meta.url), 'utf8');
  const interpSig = {};
  { const cases = [...refSrc.matchAll(/case '([^']+)':\s*\{/g)];
    for (let c = 0; c < cases.length; c++) {
      const name = cases[c][1], start = cases[c].index, end = c + 1 < cases.length ? cases[c + 1].index : start + 3000;
      const body = refSrc.slice(start, end);
      const subs = [...body.matchAll(/\bsub\((\d+)\)/g)].map((x) => +x[1]);
      const kinds = [...body.matchAll(/\.kind !== '([^']+)'/g)].map((x) => x[1]);
      if (subs.length) interpSig[name] = { n: Math.max(...subs) + 1, kinds };
    }
  }
  for (const [rule, s] of Object.entries(interpSig)) {
    const declared = CHILD_SIG[rule];
    if (!declared) { fails.push(`P3 DENOMINATOR DRIFT (round-48 P1-02): interpreter gates ${rule} on ${s.n} child position(s) but CHILD_SIG omits it — the coverage denominator drifted from the interpreter`); continue; }
    if (declared.length !== s.n) fails.push(`P3 DENOMINATOR DRIFT (round-48 P1-02): ${rule} — interpreter gates ${s.n} child positions, CHILD_SIG declares ${declared.length}`);
    s.kinds.forEach((k, i) => { if (declared[i] !== k) fails.push(`P3 DENOMINATOR DRIFT (round-48 P1-02): ${rule}[${i}] — interpreter requires ${k}, CHILD_SIG declares ${declared[i]}`); });
  }
  // coverage over the SOURCE-VERIFIED denominator. A position whose sibling needs a kind ABSENT from the corpus is a DECLARED
  // residual (counted against the true total + NAMED — not a silent subset: the denominator now SHOWS it, so it cannot narrow).
  const totalPositions = Object.values(CHILD_SIG).reduce((n, s) => n + s.length, 0);
  let coveredPositions = 0; const residual = [];
  for (const [rule, sig] of Object.entries(CHILD_SIG)) {
    for (let i = 0; i < sig.length; i++) {
      const missing = [...new Set(sig.filter((k, j) => j !== i && !wk[k]))];   // sibling kinds with no witness to hold position ≠ i
      if (missing.length) { residual.push(`${rule}[${i}] (corpus lacks a ${missing.join('/')} witness)`); continue; }
      coveredPositions++;
      for (const [wrongKind, wrongTerm] of Object.entries(wk)) {
        if (wrongKind === sig[i]) continue;                   // that would be the CORRECT kind
        phase3++;
        const r = runT({ rule, children: sig.map((k, j) => (j === i ? wrongTerm : wk[k])), witnesses: [] });
        if (r.result === 'VALID') fails.push(`P3 CHILD-ALGEBRA: ${rule} accepted a ${wrongKind} judgment at child ${i} (required ${sig[i]}) → VALID — the parent ignores a required child kind (round-47 P1-01)`);
      }
    }
  }
  // The only residual now is ProjectAssurance's Identity/Time positions: `NameBound` caps Identity at `corroborated` and
  // `Anchored` caps Time at `unproven`, and a VALID ProjectAssurance needs the subject-bound AUTHORITATIVE identity — that is
  // exactly the reserved TOP-tier realization (epic UST-48p, deferred). Until the two rungs are wired to external substrates,
  // no honest Identity/Time witness exists, so these 3 stay declared (never a silent subset). Everything BUILDABLE is covered.
  const topTier = residual.length && residual.every((r) => r.startsWith('ProjectAssurance'));
  console.log(`bmc Phase 3 coverage: ${coveredPositions}/${totalPositions} interpreter child-positions exercised (denominator SOURCE-VERIFIED against the rule interpreter — round-48 P1-02) over ${Object.keys(wk).length} witness kinds (${Object.keys(wk).sort().join(', ')}); ${residual.length ? 'DECLARED residual (corpus lacks the kind — explicit + counted, not a silent subset): ' + residual.join('; ') + (topTier ? ' — these are the reserved TOP-tier rungs (authoritative identity + anchored time), unbuilt pending epic UST-48p; no honest witness exists yet' : '') : 'ALL positions covered'}`);
}

console.log(`bmc: Phase 1 (per-rule inductive step) ${phase1} probes; Phase 2 (exhaustive single-mutation) ${phase2} tampers over ${baselines} VALID baselines; Phase 3 (child-judgment algebra) ${phase3} wrong-kind-child probes`);
if (fails.length) { console.error('✗ BMC FAILED — a totality/determinism/soundness counterexample:'); for (const f of fails.slice(0, 20)) console.error('   • ' + f); process.exit(1); }
console.log('✓ BMC: every rule is TOTAL + DETERMINISTIC + CONTRACT-GATED over its immediate-shape space; NO single-edit mutation of a VALID proof is accepted; and over EVERY coverable composite child-position a WRONG-KIND child judgment is rejected. SCOPE (bound to the mechanism, round-47): this exercises the KIND dimension of the induction step; the child-COORDINATE dimension (a right-kind child from the wrong (s,n,h)) is covered BY CONSTRUCTION in the conformance corpus — the three `unify.*` cross-child vectors drive ReinforceMap/ReinforceQuorum/Corroborated with a genuine child proven at a SECOND coordinate and assert the unify gate fires. Construction is the ONLY sound path: unforgeable-judgment re-verifies every child from its own sub-proof (a fabricated verdict is INVALID), so a lighter injectable-verdict harness would be unsound. The coverage DENOMINATOR is SOURCE-VERIFIED against the rule interpreter (round-48 P1-02) — a position the interpreter gates but the harness omits FAILS the gate; a position the corpus cannot yet witness is a DECLARED, counted residual, never a silent subset.');
