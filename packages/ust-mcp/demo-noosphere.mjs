// A real noosphere space-weather state through the verify ladder. Shows exactly what an agent LEARNS at each
// tier and what it STILL doesn't know. Data is live NOAA SWPC; keys are DEMO stand-ins (not noosphere's real
// key), so identity is honestly "self-asserted" until we supply a genesis. (These are the same results
// ust_verify / ust_resolve return over the MCP.)
import * as P from 'ust-protocol';
import { createPrivateKey, createPublicKey } from 'node:crypto';

function kp(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubRaw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32);
  return { priv, pubB64: pubRaw.toString('base64url'), key_id: P.keyId(pubRaw.toString('base64url')) };
}
const ROOT = kp('a0'.repeat(32));   // stands in for noosphere.md's genesis / name-binding root
const OP = kp('0b'.repeat(32));     // stands in for noosphere.md's operational signing key
const signOP = (s) => P.seal(s, OP.priv, OP.pubB64), signROOT = (s) => P.seal(s, ROOT.priv, ROOT.pubB64);

// 1 ── REAL space-weather data (live NOAA SWPC), with a fallback if the sandbox is offline
async function fetchSW() {
  try {
    const kpJson = await (await fetch('https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json', { signal: AbortSignal.timeout(8000) })).json();
    const last = kpJson[kpJson.length - 1];   // { time_tag, Kp: <number>, a_running, station_count }
    const windJson = await (await fetch('https://services.swpc.noaa.gov/products/summary/solar-wind-speed.json', { signal: AbortSignal.timeout(8000) })).json();
    const w = windJson[0];                     // { proton_speed: <number>, time_tag }
    // UST is string-only — the capture boundary stringifies the source numbers VERBATIM (no rounding).
    return { kp: String(last.Kp), kp_time: last.time_tag, wind: String(w.proton_speed), src: 'NOAA SWPC (LIVE)' };
  } catch { return { kp: '3.33', kp_time: '2026-07-05T00:00:00', wind: '530', src: 'NOAA SWPC (fallback — sandbox offline)' }; }
}
const sw = await fetchSW();

// 2 ── build the UST 1.0 doc as noosphere would (captured partitions), sign with the operational key
const t = { generated_at: '2026-07-05T15:00:03Z', valid_from: '2026-07-05T15:00:00Z', valid_to: '2026-07-05T16:00:00Z' };
const state = P.buildState({ domain_shard: 'noosphere.md', ust_id: 'ust:20260705.15', key_id: OP.key_id, class: 'observation' }, t,
  { kp: { kind: 'captured', value: { index: sw.kp, observed_at: sw.kp_time } }, solar_wind: { kind: 'captured', value: { speed_km_s: sw.wind } } });
const doc = signOP(state);

console.log('\n  DATA: ' + sw.src + ' — Kp=' + sw.kp + ' · solar wind=' + sw.wind + ' km/s');
console.log('  DOC : ' + JSON.stringify(doc).length + ' bytes, signed. data + hashes + sig — the agent receives THIS.\n');

// 3 ── LIGHT: what any agent gets from the doc ALONE
const light = P.verify(doc, { context: 'data' });
console.log('  ── ust_verify (LIGHT — the doc alone) ──');
console.log('     result        ' + light.result);
console.log('     publisher      ' + light.publisher + '   (CLAIMED)');
console.log('     identity       ' + light.identity.strength + '   ← doc alone does NOT prove the key is really noosphere.md');
console.log('     time           ' + light.time.strength);
console.log('     content_hash   ' + light.content_hash.slice(0, 34) + '…');

// 4 ── HIGH: supply noosphere.md's genesis + key-log → name authority
const genesis = signROOT(P.buildGenesis({ domain_shard: 'noosphere.md', ust_id: 'ust:20260101.00', key_id: ROOT.key_id }, t, ROOT.pubB64));
const add = signROOT(P.buildKeyLogEntry({ domain_shard: 'noosphere.md', ust_id: 'ust:20260101.0001', key_id: ROOT.key_id }, t, { op: 'add', pub: OP.pubB64, new_key_id: OP.key_id }, P.contentHash(genesis)));
const high = P.verify(doc, { genesis, keylog: [add], noForkConfirmed: true, context: 'data' });
console.log('\n  ── ust_verify (HIGH — with noosphere.md genesis + key-log + no-fork) ──');
console.log('     identity       ' + high.identity.strength + '/' + high.identity.status + '   ← key now PROVABLY bound to noosphere.md');

// 5 ── tamper one real value → INVALID (integrity)
const tampered = JSON.parse(JSON.stringify(doc)); tampered.state.data.kp.value.index = '9';   // fake a severe storm
console.log('\n  ── tamper: flip Kp ' + sw.kp + ' → 9 (fake a storm), re-verify ──');
console.log('     result        ' + P.verify(tampered, { context: 'data' }).result + '   ← one byte changed, caught');

// 6 ── the honest payoff
console.log('\n  ════ WHAT THE AGENT LEARNS (verified) ════');
console.log('     ✓ WHO    key provably bound to noosphere.md  (HIGH, via genesis+key-log)');
console.log('     ✓ INTACT not one byte changed since signing  (tamper → INVALID, shown)');
console.log('     ✓ WHERE-FROM-INDEPENDENT  travels with the data — cache/mirror/another agent, still verifies');
console.log('     ~ WHEN   only the CLAIMED generated_at so far; a TOP anchor would make time provable');
console.log('\n  ════ WHAT IT STILL DOESN\'T KNOW (by design — fixation, not truth) ════');
console.log('     ✗ whether Kp=' + sw.kp + ' is CORRECT — noosphere could sign a wrong reading;');
console.log('       UST proves they COMMITTED to it unchanged, NOT that the number is true.');
console.log('     → so the agent knows WHOM to hold accountable + that nothing was tampered — a real,');
console.log('       bounded guarantee, not an oracle of truth.\n');
