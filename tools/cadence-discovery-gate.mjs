// SPDX-License-Identifier: Apache-2.0
// @assurance 4 canfail:cited:packages/ust-protocol/drift-guards.test.mjs — fixtures built here; the refusal is asserted against them
// Cadence-discovery gate — a declared grid must be REACHABLE, and an unreachable one must never be mistaken for absence.
//
// Why: the cadence mechanism was complete and unusable. `resolveCadence` verifies every entry (signature, class, domain,
// prev-chain from the genesis content hash, a currently-ACTIVE signer, monotonic effective_from, canonical integer
// seconds) — but discovery fetched exactly two paths, so nothing ever handed it a log. A publisher could sign a cadence
// change and no verifier would find it. The measured consequence for the reference operator: `resolveCadence` → null,
// so its stream tops out at `chain-consistent` (no-deletion) and can never reach `complete` (no-omission), which is the
// verdict a paid range claim rests on.
//
// The load-bearing distinction, inherited from the key-log rather than invented (round-18 P0-03):
//   · 404/410  → ABSENT. The publisher declares no change; the genesis value stands. Benign, and the common case.
//   · anything else → INDETERMINATE. NEVER `[]`, because an empty log silently erases a cadence CHANGE and the range is
//     then judged against the OLD grid: a finer new cadence reads as holes, a coarser one reads as `complete` while
//     frames are missing. A completeness verdict manufactured by a transport failure is the one thing it must never be.
import * as P from '../packages/ust-protocol/index.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

const kp = (fill) => {
  const seed = Buffer.alloc(32, fill);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  return { priv, pub, key_id: P.keyId(pub) };
};
const ROOT = kp(0xa1), OP = kp(0xb2), ALIEN = kp(0xc3);
const DOMAIN = 'cadence-gate.example';
const T = (h, m = '00') => ({ generated_at: `2026-07-26T${h}:${m}:00Z`, valid_from: `2026-07-26T${h}:${m}:00Z`, valid_to: `2026-07-26T${h}:${m}:00Z` });

// genesis WITHOUT cadence (the reference operator's live shape), plus a key-log adding the operational key
const genesis = P.seal(P.buildGenesis({ domain_shard: DOMAIN, ust_id: 'ust:20260726.09', key_id: ROOT.key_id }, T('09'), ROOT.pub, 512), ROOT.priv, ROOT.pub);
const genH = P.contentHash(genesis);
const keylog = [P.seal(P.buildKeyLogEntry({ domain_shard: DOMAIN, ust_id: 'ust:20260726.09', key_id: ROOT.key_id }, T('09', '05'), { op: 'add', pub: OP.pub, new_key_id: OP.key_id }, genH), ROOT.priv, ROOT.pub)];
const cadEntry = (secs, effFrom, signer, prev = genH) =>
  P.seal(P.buildCadenceEntry({ domain_shard: DOMAIN, ust_id: 'ust:20260726.09', key_id: signer.key_id }, T('09', '10'), secs, effFrom, prev), signer.priv, signer.pub);
const CAD = cadEntry(30, 'ust:20260726.10', ROOT);   // §F.5e.3/#107 — cadence mutation is ROOT-ONLY; this fixture used OP and so encoded the very hole the rule closes

// a document of this publisher, at a moment after the cadence takes effect
const doc = P.seal(P.buildState({ domain_shard: DOMAIN, ust_id: 'ust:20260726.11', key_id: OP.key_id, class: 'observation' },
  T('11'), { x: { kind: 'captured', value: { v: '1' } } }, { prev: genH }), OP.priv, OP.pub);

// ── a fetch stub: routes the three well-known paths, with per-path status control ──────────────────────────────────
const serve = ({ cadence = 'ok', cadenceBody, cadenceStatus }) => async (url) => {
  const body = (o) => ({ ok: true, status: 200, headers: new Map(), body: null, text: async () => JSON.stringify(o), arrayBuffer: async () => Buffer.from(JSON.stringify(o)) });
  const notFound = (s) => ({ ok: false, status: s, text: async () => '', arrayBuffer: async () => Buffer.alloc(0) });
  if (url.endsWith('/.well-known/ust-genesis')) return body(genesis);
  if (url.endsWith('/.well-known/ust-keylog')) return body(keylog);
  if (url.endsWith('/.well-known/ust-cadence')) {
    if (cadence === 'absent') return notFound(404);
    if (cadence === 'gone') return notFound(410);
    if (cadence === 'error') return notFound(cadenceStatus ?? 503);
    if (cadenceBody !== undefined) return { ok: true, status: 200, text: async () => cadenceBody, arrayBuffer: async () => Buffer.from(cadenceBody) };
    return body([CAD]);
  }
  return notFound(404);
};
const discover = (cfg) => P.resolveByDiscovery(doc, { offline: false, noForkConfirmed: true }, { fetchImpl: serve(cfg) });

// ── 1. the path is actually requested ─────────────────────────────────────────────────────────────────────────────
{
  const seen = [];
  const spy = async (url, init) => { seen.push(new URL(url).pathname); return serve({})(url, init); };
  await P.resolveByDiscovery(doc, { offline: false, noForkConfirmed: true }, { fetchImpl: spy });
  ok('discovery REQUESTS /.well-known/ust-cadence', seen.includes('/.well-known/ust-cadence'), 'fetched: ' + seen.join(', '));
}

// ── 2. a served, valid log resolves and is reported ───────────────────────────────────────────────────────────────
{
  const r = await discover({});
  ok('a served cadence log resolves to the declared grid', r.resolution?.cadence === '30', 'got ' + JSON.stringify(r.resolution?.cadence));
  ok('the log is handed back so verifyStream needs no second fetch', Array.isArray(r.resolution?.cadence_log) && r.resolution.cadence_log.length === 1);
}

// ── 3. ABSENT is benign, and reported as a positive fact ──────────────────────────────────────────────────────────
for (const [label, mode] of [['404', 'absent'], ['410', 'gone']]) {
  const r = await discover({ cadence: mode });
  ok(`an ABSENT cadence log (${label}) is benign — the document still resolves`, !r.resolution?.error && r.resolution?.status !== 'INDETERMINATE', JSON.stringify(r.resolution).slice(0, 120));
  ok(`an ABSENT cadence log (${label}) reports cadence: null rather than omitting the field`, 'cadence' in (r.resolution || {}) && r.resolution.cadence === null);
}

// ── 4. PRESENT-but-UNREADABLE: the coordinate goes UNKNOWN, and the cost is SCOPED to the range ───────────────────
// round-233 (#169) — this section used to assert the WHOLE resolution went INDETERMINATE, which withheld an identity
// verdict over a coordinate `resolveAuthority` never reads and `ustGrid` reads only inside verifyStream. Two things must
// hold, and the old assertion covered one: the value is never substituted, AND the cost never leaves the range. The
// identity half is asserted by EQUALITY against the ABSENT run rather than against a named expectation, so a change to
// what identity resolves to cannot leave this green.
const benign = await discover({ cadence: 'absent' });
for (const s of [500, 503, 403, 429]) {
  const r = await discover({ cadence: 'error', cadenceStatus: s });
  ok(`HTTP ${s} on the cadence log → the coordinate is UNKNOWN, never "no cadence declared"`,
    !('cadence' in (r.resolution || {})) && r.resolution?.cadence_unknown?.reason === 'unavailable' &&
    /cadence-log present but unreadable/.test(r.resolution?.cadence_unknown?.detail || ''), JSON.stringify(r.resolution).slice(0, 130));
  ok(`HTTP ${s} leaves IDENTITY untouched — an unknown cadence lands on the range only`,
    r.verdict?.result === benign.verdict?.result && r.resolution?.strength === benign.resolution?.strength &&
    r.resolution?.status === undefined && r.resolution?.error === undefined,
    JSON.stringify({ absent: benign.resolution?.strength, unreadable: r.resolution?.strength }).slice(0, 120));
}
{
  // A browser CORS rejection carries NO status at all — the live shape, and a different door into the same branch.
  const cors = async (url, init) => { if (url.endsWith('/.well-known/ust-cadence')) throw new TypeError('Failed to fetch'); return serve({})(url, init); };
  const r = await P.resolveByDiscovery(doc, { offline: false, noForkConfirmed: true }, { fetchImpl: cors });
  ok('a cadence fetch REJECTED with no status (browser CORS) reads UNKNOWN, not undeclared, and identity still resolves',
    !('cadence' in (r.resolution || {})) && !!r.resolution?.cadence_unknown && r.resolution?.strength === benign.resolution?.strength,
    JSON.stringify(r.resolution).slice(0, 130));
}

// ── 5. the raw-byte boundary: the same four checks the key-log gets ────────────────────────────────────────────────
{
  const dup = '[' + JSON.stringify(CAD).replace('"ust":"1.0"', '"ust":"1.0","ust":"9.9"') + ']';
  const r = await discover({ cadenceBody: dup });
  ok('a duplicate member in the cadence log is E-CANON on the RAW bytes', /E-CANON/.test(r.resolution?.error || ''), JSON.stringify(r.resolution).slice(0, 130));
}
{
  const r = await discover({ cadenceBody: '{not json' });
  // MEASURED: the raw-byte dup-key scanner runs FIRST and reports E-CANON ('expected key') for malformed JSON, exactly
  // as it does for the key-log. So the assertion is the PROPERTY — refused with a structural error, never silently empty —
  // not a particular code. My first expectation named E-MALFORMED and was simply wrong about the order.
  ok('unparseable cadence log is REFUSED structurally, never silently empty', /^E-(CANON|MALFORMED)/.test(r.resolution?.error || ''), JSON.stringify(r.resolution).slice(0, 120));
}
{
  const r = await discover({ cadenceBody: JSON.stringify(CAD) });     // an object, not an array
  ok('a non-array cadence log → E-MALFORMED', /not a JSON array/.test(r.resolution?.error || ''));
}

// ── 6. forgery: discovery must not widen what resolveCadence already refuses ───────────────────────────────────────
{
  const r = await discover({ cadenceBody: JSON.stringify([cadEntry(30, 'ust:20260726.10', ALIEN)]) });
  ok('a cadence entry signed OUTSIDE the authorized key set is refused through discovery', !!r.resolution?.error && !/^E-CANON/.test(r.resolution.error), JSON.stringify(r.resolution).slice(0, 140));
}
{
  // §F.5e.3 / #107 — the ROOT-ONLY conjunct must hold THROUGH discovery too. OP is genuinely in the key log and
  // genuinely `active`, so this is the case an "authorized key set" check passes and the rule must still refuse.
  const r = await discover({ cadenceBody: JSON.stringify([cadEntry(30, 'ust:20260726.10', OP)]) });
  ok('an OPERATIONAL key (active, in the key log) cannot move the grid through discovery — ROOT-ONLY (§F.5e.3)',
    /E-KEY/.test(r.resolution?.error || '') && /GENESIS ROOT/.test(r.resolution?.error || ''), JSON.stringify(r.resolution).slice(0, 160));
}
{
  const r = await discover({ cadenceBody: JSON.stringify([cadEntry(30, 'ust:20260726.10', ROOT, 'sha256:' + 'ee'.repeat(32))]) });
  ok('a cadence entry not chained to the genesis content hash is refused through discovery', /E-PREV/.test(r.resolution?.error || ''), JSON.stringify(r.resolution).slice(0, 140));
}
{
  const tampered = JSON.parse(JSON.stringify(CAD));
  tampered.state.data.cadence_op.value.cadence = '1';                 // rewrite the grid without re-signing
  const r = await discover({ cadenceBody: JSON.stringify([tampered]) });
  ok('a TAMPERED cadence value is refused (the signature covers the grid)', !!r.resolution?.error, JSON.stringify(r.resolution).slice(0, 140));
}

// ── 7. the resolution is time-relative: a change not yet in force must not apply ───────────────────────────────────
{
  const future = cadEntry(5, 'ust:20260727.00', ROOT);
  const r = await discover({ cadenceBody: JSON.stringify([CAD, cadEntry(5, 'ust:20260727.00', ROOT, P.contentHash(CAD))]) });
  ok('a cadence change effective LATER does not apply to this document', r.resolution?.cadence === '30', 'got ' + JSON.stringify(r.resolution?.cadence));
  void future;
}

console.log(`\n  cadence discovery   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ a declared grid is reachable; an unreachable one reads UNKNOWN — never mistaken for "no cadence declared", and never wider than the range');
