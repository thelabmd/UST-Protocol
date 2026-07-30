// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — the implementation is exercised against an abstract model written in this same file
// temporal-bmc.mjs — BOUNDED-EXHAUSTIVE MODEL CHECK of the key-log TEMPORAL state machine (§12.2 #75 ROOT 2).
//
// bmc.mjs covers the STRUCTURAL dimension (the proof term). This covers the TEMPORAL dimension: the key-log is a state
// machine whose keys move active → rotated-out / revoked(retired) / revoked(compromised), and whose safety property is
//   TEMPORAL SOUNDNESS: a key that is not ACTIVE at step k cannot authorize a key-log entry at step k.
// Interleaving bugs (add→retire→re-add, rotate-then-sign-with-old, re-revoke a compromised key) hide in specific ORDERINGS
// that a hand-written vector rarely hits. This gate enumerates EVERY reachable event sequence up to a bound and, for each:
//   (A) DIFFERENTIAL — an INDEPENDENT abstract reference model of the state machine must agree with resolveKeys on the
//       resolved (active, all, compromised) sets. Any divergence is a counterexample.
//   (B) ATTACK — at the end of each honest sequence, appending an entry signed by EVERY currently non-active key (retired /
//       rotated-out / compromised) must be REJECTED (E-KEY). Exhaustive over sequences × non-active signers.
// Deterministic (fixed key pool, fixed clock) so a counterexample reproduces.
import * as P from './index.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const kp = (seedHex) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubB64 = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pubB64, key_id: P.keyId(pubB64) };
};
const DOMAIN = 'noosphere.md';
const G = kp('a0'.repeat(32));
const POOL = [kp('b1'.repeat(32)), kp('c2'.repeat(32)), kp('d3'.repeat(32))];   // 3 non-genesis keys — re-add exercises the K_n(t) interval logic
const byKid = new Map([[G.key_id, G], ...POOL.map((k) => [k.key_id, k])]);
const T = (n) => { const m = 10 + n; return { generated_at: `2026-07-20T00:${String(m).padStart(2, '0')}:00Z`, valid_from: '2026-07-20T00:00:00Z', valid_to: '2026-08-20T00:00:00Z' }; };   // strictly increasing, nondecreasing timeline
const seal = (state, signer) => P.seal(state, signer.priv, signer.pubB64);
const genesis = seal(P.buildGenesis({ domain_shard: DOMAIN, ust_id: 'ust:20260720.00', key_id: G.key_id }, T(0), G.pubB64, 256, 1048576, '3600'), G);

// ── the ABSTRACT reference model (independent of resolveKeys) ──────────────────────────────────────────────────────
// state: { active:Set<kid>, all:Set<kid>, compromised:Set<kid> }. An event is {op, signer, target}. Returns null if the
// event is ILLEGAL, else the next state. Derived from the NORMATIVE F.5e transition system (round-47 P1-02) — NOT read off the
// implementation, so the differential below is a genuine independent witness, not a shared-blind-spot tautology.
const step = (s, ev) => {
  if (!s.active.has(ev.signer)) return null;                                  // signer must be active
  const active = new Set(s.active), all = new Set(s.all), comp = new Set(s.compromised);
  if (ev.op === 'add') {
    if (comp.has(ev.target)) return null;                                     // compromised is terminal — never re-authorized
    all.add(ev.target); active.add(ev.target);
    // rev97 (§F.5e.0): `rotate` is gone — a self-authorized succession let a compromised-but-undeclared key name its
    // own successor, turning a detected compromise into an undetected one. `supersedes` does the same bookkeeping
    // while the entry stays ROOT-authorized: the superseded key leaves `active`, and the authority to say so never
    // belonged to it.
    if (ev.supersedes !== undefined && ev.supersedes !== ev.target) { active.delete(ev.supersedes); }
  } else if (ev.op === 'retire' || ev.op === 'compromise') {
    // F.5e (normative, derived from the SPEC — not copied from the impl, round-47 P1-02): `revoke(k, r)` requires `k ∈ bind`
    // and `k ∉ compromised` (terminality). It does NOT require `k ∈ active` — a redundant revoke of a rotated-out / retired
    // (non-compromised) key is admissible and harmless (adjudicated: nondecreasing timeline can only move retirement LATER),
    // so a RETIRED key may be re-revoked as COMPROMISED (a legitimate later discovery of an earlier compromise).
    if (!all.has(ev.target)) return null;                                     // revoke of a never-authorized key (k ∉ bind)
    if (comp.has(ev.target)) return null;                                     // compromise is TERMINAL — no re-revoke / downgrade
    active.delete(ev.target);
    if (ev.op === 'compromise') comp.add(ev.target);
  }
  return { active, all, compromised: comp };
};

// build the concrete SIGNED key-log entry for an event, chained onto prevHash, at time index n
const buildEntry = (ev, prevHash, n) => {
  const signer = byKid.get(ev.signer), tgt = byKid.get(ev.target);
  let keyOp;
  if (ev.op === 'add') keyOp = { op: 'add', pub: tgt.pubB64, new_key_id: tgt.key_id, ...(ev.supersedes !== undefined ? { supersedes: ev.supersedes } : {}) };
  else if (ev.op === 'retire') keyOp = { op: 'revoke', pub: tgt.pubB64, reason: 'retired' };
  else keyOp = { op: 'revoke', pub: tgt.pubB64, reason: 'compromised', compromised_since: '2026-07-20T00:05:00Z' };
  const id = { domain_shard: DOMAIN, ust_id: `ust:20260720.${String((n % 23) + 1).padStart(2, '0')}`, key_id: signer.key_id };   // HH must be 00-23
  return seal(P.buildKeyLogEntry(id, T(n + 1), keyOp, prevHash), signer);
};

// ── enumerate every reachable event sequence up to LEN, DFS over the abstract model ────────────────────────────────
const LEN = 3;
const fails = [];
let sequences = 0, differentials = 0, attacks = 0, illegals = 0;
const S0 = { active: new Set([G.key_id]), all: new Set([G.key_id]), compromised: new Set() };

const legalEvents = (s) => {
  const evs = [];
  // §F.5e.3: the enumerator generated every ACTIVE key as a candidate signer, which is the invariant BEFORE the
  // restriction. Key-log mutation is now root-only, so an honest sequence has exactly one signer — and the
  // non-active-signer attack sweep below still exercises every other key against it.
  for (const signer of [...s.active].filter((k) => k === G.key_id)) {
    for (const t of byKid.keys()) {
      if (t === G.key_id) continue;                                           // never re-add into genesis (its kid is fixed)
      evs.push({ op: 'add', signer, target: t });
      for (const sup of [...s.active].filter((k) => k !== t && k !== G.key_id)) evs.push({ op: 'add', signer, target: t, supersedes: sup });
    }
    // F.5e revoke targets EVERY bound key (`k ∈ bind`), not only active ones — so the enumerator NOW reaches retired→compromised
    // (re-revoking a rotated-out / retired key as compromised), the ordering the round-47 audit named but the old `s.active`
    // generator never produced. step() filters the truly-illegal ones (a compromised target → null); the differential covers the rest.
    for (const t of s.all) { if (t === signer) continue; evs.push({ op: 'retire', signer, target: t }); evs.push({ op: 'compromise', signer, target: t }); }
  }
  return evs;
};

const setEq = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

function dfs(absState, log, prevHash, n) {
  // (A) DIFFERENTIAL — resolveKeys on the honest log so far must match the abstract model
  if (log.length > 0) {
    sequences++;
    const r = P.resolveKeys(genesis, log);
    if (r.error) { fails.push(`DIFF: honest sequence rejected by resolveKeys (${r.error}: ${r.detail}) — model says legal: ${log.map((_, i) => i).join(',')}`); }
    else {
      differentials++;
      const implActive = new Set(r.active.keys()), implAll = new Set(r.validKeys.keys());
      const implComp = new Set([...r.revoked].filter(([, v]) => v.reason === 'compromised').map(([k]) => k));
      if (!setEq(implActive, absState.active)) fails.push(`DIFF ACTIVE @len${log.length}: impl {${[...implActive].map(short).join(',')}} vs model {${[...absState.active].map(short).join(',')}}`);
      if (!setEq(implAll, absState.all)) fails.push(`DIFF ALL @len${log.length}: impl {${[...implAll].map(short).join(',')}} vs model {${[...absState.all].map(short).join(',')}}`);
      if (!setEq(implComp, absState.compromised)) fails.push(`DIFF COMPROMISED @len${log.length}: impl {${[...implComp].map(short).join(',')}} vs model {${[...absState.compromised].map(short).join(',')}}`);

      // (B) ATTACK — every currently NON-active key (in `all` but not `active`) must NOT be able to sign the next entry
      for (const kid of absState.all) {
        if (absState.active.has(kid)) continue;                               // active keys legitimately can sign
        attacks++;
        const attacker = byKid.get(kid);
        const evilOp = { op: 'add', pub: POOL[0].pubB64, new_key_id: POOL[0].key_id };   // any op; the point is the SIGNER is non-active
        const evilId = { domain_shard: DOMAIN, ust_id: 'ust:20260720.23', key_id: attacker.key_id };
        const evil = seal(P.buildKeyLogEntry(evilId, T(n + 1), evilOp, prevHash), attacker);
        const ra = P.resolveKeys(genesis, [...log, evil]);
        if (!ra.error) fails.push(`ATTACK @len${log.length}: a NON-ACTIVE key ${short(kid)} (rotated-out/revoked/compromised) signed entry ${log.length} and resolveKeys ACCEPTED — temporal soundness break`);
      }

      // (C) ILLEGAL-TARGET TRANSITION (round-47 P1-02) — the COMPROMISE-TERMINALITY transitions the F.5e target precondition
      // EXCLUDES, signed by an ACTIVE key, must be REJECTED (E-KEY). This tests target-state legality DIRECTLY, not via the
      // differential (whose abstract model had copied the terminality rule from the impl — the shared blind spot the audit
      // exposed) — and it enumerates the re-revoke-of-compromised the old `legalEvents` never produced. ADJUDICATION (round-47):
      // a revoke of a rotated-out NON-compromised target is NOT illegal — the impl accepts it and it is harmless (the key is
      // already inactive; a nondecreasing timeline means a redundant revoke can only move the retirement time LATER, never
      // un-retire), so target-active is NOT required for revoke; only compromise is terminal.
      const asigner = [...absState.active][0];
      const illegalEvs = [];
      for (const kid of absState.compromised) illegalEvs.push({ op: 'retire', signer: asigner, target: kid }, { op: 'compromise', signer: asigner, target: kid }, { op: 'add', signer: asigner, target: kid }, { op: 'rotate', signer: asigner, target: kid });   // compromise is TERMINAL — no re-revoke, no re-authorize
      // §F.5e.3 — narrowing the LEGAL enumerator to a root signer shrank the space 798 → 186, which would have traded
      // an exhaustive proof for two hand-written examples. So every ACTIVE NON-ROOT key is swept here as a mutator
      // instead: the sequences left the legal side and must be provably refused, not merely absent.
      for (const kid of absState.active) {
        if (kid === G.key_id) continue;
        for (const t of byKid.keys()) if (t !== kid) illegalEvs.push({ op: 'add', signer: kid, target: t });
        illegalEvs.push({ op: 'compromise', signer: kid, target: G.key_id });
      }
      for (const ev of illegalEvs) {
        illegals++;
        const entry = buildEntry(ev, prevHash, n);
        const ri = P.resolveKeys(genesis, [...log, entry]);
        if (!ri.error) fails.push(`ILLEGAL @len${log.length}: ${ev.op}(${short(ev.target)}) signed by ${short(ev.signer)} — a non-root mutator or a re-touched COMPROMISED key (terminal) — resolveKeys ACCEPTED it (target-state legality break)`);
      }
    }
  }
  if (n >= LEN) return;
  for (const ev of legalEvents(absState)) {
    const next = step(absState, ev);
    if (!next) continue;
    const entry = buildEntry(ev, prevHash, n);
    dfs(next, [...log, entry], P.contentHash(entry), n + 1);
  }
}
function short(kid) { if (kid === G.key_id) return 'G'; const i = POOL.findIndex((k) => k.key_id === kid); return i >= 0 ? 'K' + (i + 1) : kid.slice(0, 6); }

dfs(S0, [], P.contentHash(genesis), 0);

console.log(`temporal-bmc: ${sequences} reachable event sequences (len ≤ ${LEN}, ${POOL.length + 1} keys); ${differentials} differential checks vs an independent abstract model; ${attacks} non-active-signer attacks; ${illegals} illegal-target transitions (F.5e-excluded, incl. re-revoke-of-compromised)`);
if (fails.length) { console.error('✗ TEMPORAL BMC FAILED — a counterexample in the key-log state machine:'); for (const f of fails.slice(0, 20)) console.error('   • ' + f); process.exit(1); }
console.log('✓ TEMPORAL BMC: over EVERY reachable key-log event sequence (incl. retired→compromised, now enumerated), resolveKeys agrees with an abstract model DERIVED FROM THE NORMATIVE F.5e SPEC — not copied from the impl, so the differential is a genuine independent witness; NO non-active key can authorize a later entry; and EVERY compromise-terminality transition is REJECTED directly (round-47 P1-02, structural step 2/3)');
