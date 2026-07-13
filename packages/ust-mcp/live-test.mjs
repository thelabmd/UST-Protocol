// SPDX-License-Identifier: Apache-2.0
// LIVE battle-test: spawn the ACTUAL stdio server as a subprocess, talk MCP over the wire, run the agent flow
// end-to-end (build → sign with own key → verify). This is not a unit test — it exercises the real transport.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import * as P from 'ust-protocol';

function kp(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pubRaw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32);
  return { priv, pubB64: pubRaw.toString('base64url'), key_id: P.keyId(pubRaw.toString('base64url')) };
}
const A = kp('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
const t = { generated_at: '2026-07-05T16:00:00Z', valid_from: '2026-07-05T16:00:00Z', valid_to: '2036-07-05T16:00:00Z' };

let pass = 0, fail = 0; const check = (id, ok, d) => { if (ok) pass++; else { fail++; console.log('  ✗ ' + id + (d ? ' — ' + d : '')); } };
const call = async (client, name, args) => JSON.parse((await client.callTool({ name, arguments: args })).content[0].text);
const rawCall = async (client, name, args) => { const r = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, body: JSON.parse(r.content[0].text) }; };

const transport = new StdioClientTransport({ command: 'node', args: ['server.mjs'] });
const client = new Client({ name: 'ust-live-test', version: '1' }, { capabilities: {} });
await client.connect(transport);

const tools = await client.listTools();
check('live:tools/list = 12', tools.tools.length === 12, 'got ' + tools.tools.length);
check('live:key_id over the wire', (await call(client, 'ust_key_id', { pub: A.pubB64 })).key_id === A.key_id);

// THE agent flow, entirely over MCP: build → sign with own key → verify
const built = await call(client, 'ust_build_observation', { domain_shard: 'helioradar.com', ust_id: 'ust:20260705.16', key_id: A.key_id, time: t, data: { sw: { kind: 'captured', value: { kp: '3.3' } } } });
const sig = edSign(null, Buffer.from(built.signing_input, 'utf8'), A.priv).toString('base64url');
const doc = { ust: '1.0', state: built.state, sig: { alg: 'Ed25519', key_id: A.key_id, pub: A.pubB64, sig } };
check('live:build→sign→verify = VALID', (await call(client, 'ust_verify', { doc })).result.startsWith('VALID'));
const bad = JSON.parse(JSON.stringify(doc)); bad.state.data.sw.value.kp = '9.9';
// #44 agent-safety over the wire: a tampered doc is an ERROR RESPONSE (isError) carrying the structured verdict —
// the agent cannot skip it as a data field. `soft:true` opts into the advisory path (INVALID returned as data).
const tRes = await rawCall(client, 'ust_verify', { doc: bad });
check('live:tampered → isError (agent must acknowledge)', tRes.isError === true);
check('live:tampered isError carries structured verdict', tRes.body.verdict?.error === 'E-CANON' && tRes.body.verdict.obligation === '§4.4 partition-hash');
check('live:tampered soft:true → returned as DATA', (await rawCall(client, 'ust_verify', { doc: bad, soft: true })).body.result === 'INVALID');

// ust_verify_stream over the wire — a range as one authority's chain (genesis+checkpoint, no signed cadence ⇒
// chain-consistent: no-deletion proven; `complete` would additionally require a signed cadence + interval bounds)
const g = P.seal(P.buildGenesis({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.14', key_id: A.key_id }, t, A.pubB64), A.priv, A.pubB64);
const fr0 = P.seal(P.buildState({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.1401', key_id: A.key_id, class: 'observation' }, t, { r: { kind: 'captured', value: { n: '1' } } }, { prev: P.contentHash(g) }), A.priv, A.pubB64);
const fr1 = P.seal(P.buildState({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.1402', key_id: A.key_id, class: 'observation' }, t, { r: { kind: 'captured', value: { n: '2' } } }, { prev: P.contentHash(fr0) }), A.priv, A.pubB64);
const hd = P.contentHash(fr1);
const ckp = P.seal(P.buildCheckpoint({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.1403', key_id: A.key_id }, t, hd, 2, hd), A.priv, A.pubB64);
check('live:verify_stream = chain-consistent', (await call(client, 'ust_verify_stream', { frames: [fr0, fr1], genesis: g, checkpoint: ckp })).complete === 'chain-consistent');

// ust_fork_choice over the wire (#45): the per-slot guard + the honest no-substrate path both dispatch.
const sa = P.seal(P.buildState({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.1405', key_id: A.key_id, class: 'observation' }, t, { r: { kind: 'captured', value: { n: '1' } } }), A.priv, A.pubB64);
const sb = P.seal(P.buildState({ domain_shard: 'helioradar.com', ust_id: 'ust:20260705.1405', key_id: A.key_id, class: 'observation' }, t, { r: { kind: 'captured', value: { n: '2' } } }), A.priv, A.pubB64);
check('live:fork_choice mixed ust_id → E-MALFORMED', (await call(client, 'ust_fork_choice', { candidates: [fr0, fr1], offline: true })).result === 'E-MALFORMED');
check('live:fork_choice same ust_id, no substrate → INDETERMINATE', (await call(client, 'ust_fork_choice', { candidates: [sa, sb], offline: true })).result === 'INDETERMINATE');

await client.close();
console.log('\n════════════════════════════════════════════');
console.log('  ust-mcp LIVE (real stdio transport)   PASS ' + pass + '   FAIL ' + fail);
console.log(fail ? '' : '  ✓ agent talks to the running MCP server and verifies over the wire');
process.exit(fail ? 1 : 0);
