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

const transport = new StdioClientTransport({ command: 'node', args: ['server.mjs'] });
const client = new Client({ name: 'ust-live-test', version: '1' }, { capabilities: {} });
await client.connect(transport);

const tools = await client.listTools();
check('live:tools/list = 8', tools.tools.length === 8, 'got ' + tools.tools.length);
check('live:key_id over the wire', (await call(client, 'ust_key_id', { pub: A.pubB64 })).key_id === A.key_id);

// THE agent flow, entirely over MCP: build → sign with own key → verify
const built = await call(client, 'ust_build_observation', { domain_shard: 'helioradar.com', ust_id: 'ust:20260705.16', key_id: A.key_id, time: t, data: { sw: { kind: 'captured', value: { kp: '3.3' } } } });
const sig = edSign(null, Buffer.from(built.signing_input, 'utf8'), A.priv).toString('base64url');
const doc = { ust: '1.0', state: built.state, sig: { alg: 'Ed25519', key_id: A.key_id, pub: A.pubB64, sig } };
check('live:build→sign→verify = VALID', (await call(client, 'ust_verify', { doc })).result === 'VALID');
const bad = JSON.parse(JSON.stringify(doc)); bad.state.data.sw.value.kp = '9.9';
check('live:tampered = INVALID', (await call(client, 'ust_verify', { doc: bad })).result === 'INVALID');

await client.close();
console.log('\n════════════════════════════════════════════');
console.log('  ust-mcp LIVE (real stdio transport)   PASS ' + pass + '   FAIL ' + fail);
console.log(fail ? '' : '  ✓ agent talks to the running MCP server and verifies over the wire');
process.exit(fail ? 1 : 0);
