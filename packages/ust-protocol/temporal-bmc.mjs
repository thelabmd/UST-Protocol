// SPDX-License-Identifier: Apache-2.0
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
// event is ILLEGAL (the impl must reject it too — checked separately), else the next state.
const step = (s, ev) => {
  if (!s.active.has(ev.signer)) return null;                                  // signer must be active
  const active = new Set(s.active), all = new Set(s.all), comp = new Set(s.compromised);
  if (ev.op === 'add' || ev.op === 'rotate') {
    if (comp.has(ev.target)) return null;                                     // compromised is terminal — never re-authorized
    all.add(ev.target); active.add(ev.target);
    if (ev.op === 'rotate' && ev.signer !== ev.target) { active.delete(ev.signer); }   // the superseded signer leaves active
  } else if (ev.op === 'retire' || ev.op === 'compromise') {
    if (!all.has(ev.target)) return null;                                     // revoke of a never-authorized key
    if (comp.has(ev.target)) return null;                                     // compromised is terminal — cannot re-revoke
    if (!active.has(ev.target)) return null;                                  // already left active (rotated-out/revoked): the impl rejects a revoke of a non-active key at the active-signer/target gate
    active.delete(ev.target);
    if (ev.op === 'compromise') comp.add(ev.target);
  }
  return { active, all, compromised: comp };
};

// build the concrete SIGNED key-log entry for an event, chained onto prevHash, at time index n
const buildEntry = (ev, prevHash, n) => {
  const signer = byKid.get(ev.signer), tgt = byKid.get(ev.target);
  let keyOp;
  if (ev.op === 'add') keyOp = { op: 'add', pub: tgt.pubB64, new_key_id: tgt.key_id };
  else if (ev.op === 'rotate') keyOp = { op: 'rotate', pub: tgt.pubB64, new_key_id: tgt.key_id };
  else if (ev.op === 'retire') keyOp = { op: 'revoke', pub: tgt.pubB64, reason: 'retired' };
  else keyOp = { op: 'revoke', pub: tgt.pubB64, reason: 'compromised', compromised_since: '2026-07-20T00:05:00Z' };
  const id = { domain_shard: DOMAIN, ust_id: `ust:20260720.${String((n % 23) + 1).padStart(2, '0')}`, key_id: signer.key_id };   // HH must be 00-23
  return seal(P.buildKeyLogEntry(id, T(n + 1), keyOp, prevHash), signer);
};

// ── enumerate every reachable event sequence up to LEN, DFS over the abstract model ────────────────────────────────
const LEN = 3;
const fails = [];
let sequences = 0, differentials = 0, attacks = 0;
const S0 = { active: new Set([G.key_id]), all: new Set([G.key_id]), compromised: new Set() };

const legalEvents = (s) => {
  const evs = [];
  for (const signer of s.active) {
    for (const t of byKid.keys()) {
      if (t === G.key_id) continue;                                           // never re-add/rotate-into genesis (its kid is fixed)
      evs.push({ op: 'add', signer, target: t });
      evs.push({ op: 'rotate', signer, target: t });
    }
    for (const t of s.active) { if (t === signer) continue; evs.push({ op: 'retire', signer, target: t }); evs.push({ op: 'compromise', signer, target: t }); }
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

console.log(`temporal-bmc: ${sequences} reachable event sequences (len ≤ ${LEN}, ${POOL.length + 1} keys); ${differentials} differential checks vs an independent abstract model; ${attacks} non-active-signer attacks`);
if (fails.length) { console.error('✗ TEMPORAL BMC FAILED — a counterexample in the key-log state machine:'); for (const f of fails.slice(0, 20)) console.error('   • ' + f); process.exit(1); }
console.log('✓ TEMPORAL BMC: over EVERY reachable key-log event sequence, resolveKeys agrees with an independent abstract state machine (active/all/compromised), and NO non-active key (rotated-out / retired / compromised) can authorize a later entry (bounded-exhaustive temporal soundness)');
