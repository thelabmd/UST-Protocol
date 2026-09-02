// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:no — a real stdio process answers for itself over the wire
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

const transport = new StdioClientTransport({ command: 'node', args: [new URL('./server.mjs', import.meta.url).pathname] });   // P1-07: absolute path — CWD-independent (was 'server.mjs')
const client = new Client({ name: 'ust-live-test', version: '1' }, { capabilities: {} });
await client.connect(transport);

const tools = await client.listTools();
check('live:tools/list = 17', tools.tools.length === 17, 'got ' + tools.tools.length);
check('live:key_id over the wire', (await call(client, 'ust_key_id', { pub: A.pubB64 })).key_id === A.key_id);

// THE agent flow, entirely over MCP: build → sign with own key → verify
// round-53 (UST-ybn): the agent flow (build → sign with own key → verify, no genesis) is the LIGHT key-identity case — a
// name-form domain_shard would be an unbindable domain claim (→ INDETERMINATE). The honest LIGHT identity is the KEY: key-form domain_shard = key_id.
const built = await call(client, 'ust_build_observation', { domain_shard: A.key_id, ust_id: 'ust:20260705.16', key_id: A.key_id, time: t, data: { sw: { kind: 'captured', value: { kp: '3.3' } } } });
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
// #75 P1-04 — INDETERMINATE is ALSO non-VALID → isError (agent must acknowledge + retry, not skip). maxSupportedBytes:1 forces resource_limit.
const iRes = await rawCall(client, 'ust_verify', { doc, maxSupportedBytes: 1 });
check('live:INDETERMINATE → isError (must acknowledge, not skip)', iRes.isError === true && iRes.body.verdict?.result === 'INDETERMINATE');
check('live:INDETERMINATE soft:true → returned as DATA (retry advisory)', (await rawCall(client, 'ust_verify', { doc, maxSupportedBytes: 1, soft: true })).body.result === 'INDETERMINATE');

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
check('live:fork_choice mixed ust_id → E-MALFORMED', (await call(client, 'ust_fork_choice', { candidates: [fr0, fr1], offline: true })).error === 'E-MALFORMED');
check('live:fork_choice same ust_id, no substrate → INDETERMINATE', (await call(client, 'ust_fork_choice', { candidates: [sa, sb], offline: true })).result === 'INDETERMINATE');

// #177 — BOTH privacy modes reachable in ONE call, asserted OVER THE WIRE. Measured 2026-08-31, CLOSED 2026-08-31 by `decKeys` on `ust_verify`: the tool declared seventeen properties, `disclosures` among them and
// `decKeys` absent, so an agent could open a `blinded` partition and had no way to check an `encrypted` one at
// all. Half of §10 unreachable through the interface we give agents, while our own position is that an agent is
// a first-class publisher. The vectors drive it — the claim is normative, so it is not a fixture chosen here.
{
  const { readFileSync } = await import('node:fs');
  const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'));
  const ok = V.vectors.find((v) => v.id === 'privacy-encrypted-disclosure');
  const dis = V.vectors.find((v) => v.id === 'privacy-encrypted-channels-disagree');
  const ask = (v, withKey) => call(client, 'ust_verify', { doc: v.doc, offline: true, soft: true,
    disclosures: { [v.disclosure.partition]: { nonce: v.disclosure.nonce, value: v.disclosure.value } },
    ...(withKey ? { decKeys: { [v.key.key_id]: v.key.raw } } : {}) });
  const opened = await ask(ok, true);
  check('live:decKeys — an agent reaches the ENCRYPTED mode in one ust_verify call and the partition opens',
    opened.result === 'VALID:LIGHT' && (opened.disclosed || []).includes(ok.disclosure.partition), JSON.stringify(opened.result));
  // The load-bearing half: the key must be USED, not accepted and dropped. A surface that swallowed the argument
  // would answer VALID here and be indistinguishable from a correct one on every honest document.
  const caught = await ask(dis, true);
  check('live:decKeys is genuinely USED — channels that disagree give the agent E-COMMIT, not VALID', caught.error === 'E-COMMIT', JSON.stringify(caught.error));
  const blind = await ask(dis, false);
  check('live:without the key that same document verifies — the divergence is invisible, which is WHY the key must travel (F.7a.2)', blind.result === 'VALID:LIGHT', JSON.stringify(blind.result));
  // §14.8 per-channel: an agent holding only the disclosure completed ONE channel of two, and must be told so. On
  // THIS document the two channels contradict each other, so a surface reporting it as fully disclosed would hand
  // an agent a word meaning "every channel agreed" about a record where none did.
  check('live:a one-channel result reaches the agent as PARTIAL, never as disclosed — the word must not outrun the check',
    !(blind.disclosed || []).includes(dis.disclosure.partition)
    && (blind.disclosed_partial || []).some((x) => x.partition === dis.disclosure.partition && x.checked === 'commit' && x.unchecked === 'aead'),
    JSON.stringify({ disclosed: blind.disclosed, partial: blind.disclosed_partial }));
  check('live:and the partial report names the key the agent would need to finish the check',
    (blind.disclosed_partial || [])[0]?.needs_key_id === dis.doc.state.data[dis.disclosure.partition].enc.key_id);
}

// #178 — the AGENT round trip for a private partition, over the real transport. Measured 2026-09-02 and CLOSED 2026-09-02 by the three builders taking `privacy` in their data: `blinded` is the mode the principal audience needs most — publish existence, time and integrity
// WITHOUT the value — and it needs no key at all, so the reason that kept it off this surface was true of
// `encrypted` and false here. The envelope returns in the SAME object as the state: an agent cannot receive one
// without the other, which is the structural form of an obligation the CLI can only state in a flag.
{
  const B = kp('bb'.repeat(32));
  const ID = { domain_shard: B.key_id, ust_id: 'ust:20260902.21', key_id: B.key_id };
  const built = await call(client, 'ust_build_observation', { ...ID, time: t, data: {
    station:  { kind: 'captured', value: { name: 'Baltic-1' } },
    position: { kind: 'captured', privacy: 'blinded', value: { lat: '54.71' } },
  } });
  check('live:#178 the envelope comes back WITH the state — an agent cannot take one without the other',
    !!built.disclosures?.position?.nonce && built.disclosures.position.value.lat === '54.71', JSON.stringify(Object.keys(built.disclosures || {})));
  check('live:#178 the wire carries a commitment and no value — existence and time without the value, which is the whole point',
    built.state.data.position.commit?.startsWith('sha256:') && built.state.data.position.value === undefined);

  const sg = edSign(null, Buffer.from(built.signing_input, 'utf8'), B.priv).toString('base64url');
  // #178 — assembled BY THE SURFACE now, not by hand. The private key stayed outside; what came back inside is
  // the check that the parts verify, which nothing in this flow performed before.
  const sealed = await call(client, 'ust_seal', { state: built.state, pub: B.pubB64, sig: sg });
  check('live:#178 ust_seal assembles and DERIVES key_id from pub — a caller can no longer state one that disagrees',
    sealed.doc?.sig?.key_id === B.key_id && sealed.doc.sig.pub === B.pubB64, JSON.stringify(sealed.doc?.sig || {}).slice(0, 90));
  const doc = sealed.doc;
  const opened = await call(client, 'ust_verify', { doc, offline: true, soft: true, disclosures: built.disclosures });
  check('live:#178 the agent reads its OWN document back with the envelope it was handed — the round trip closes on this surface',
    opened.result === 'VALID:LIGHT' && (opened.disclosed || []).includes('position'), `${opened.result} ${JSON.stringify(opened.disclosed)}`);
  // the load-bearing negative: a nonce the tool did NOT generate must not open the commitment, or the envelope
  // would be decoration and any value could be claimed as the disclosed one.
  const forged = await call(client, 'ust_verify', { doc, offline: true, soft: true,
    disclosures: { position: { nonce: built.disclosures.position.nonce, value: { lat: 'ELSEWHERE' } } } });
  check('live:#178 a different value against the same nonce is E-COMMIT — the commitment binds, so the envelope is evidence rather than decoration',
    forged.error === 'E-COMMIT', `${forged.result} ${forged.error || ''}`);
}

// #178 — the load-bearing half of `ust_seal`: it must REFUSE. A tool that assembles whatever it is handed is a
// convenience; one that will not return a document a reader would reject is a check the flow did not have.
{
  const C = kp('cc'.repeat(32));
  const b = await call(client, 'ust_build_observation', { domain_shard: C.key_id, ust_id: 'ust:20260902.23', key_id: C.key_id, time: t, data: { y: { kind: 'captured', value: { v: '2' } } } });
  const good = edSign(null, Buffer.from(b.signing_input, 'utf8'), C.priv).toString('base64url');
  const bad = await rawCall(client, 'ust_seal', { state: b.state, pub: C.pubB64, sig: good.slice(0, -4) + 'AAAA' });
  check('live:#178 ust_seal REFUSES a signature that does not verify — it will not hand back a document a reader would reject',
    bad.isError === true, JSON.stringify(bad.body || {}).slice(0, 90));
  const ok = await call(client, 'ust_seal', { state: b.state, pub: C.pubB64, sig: good });
  check('live:#178 CONTROL — the same call with the real signature returns a document that verifies',
    (await call(client, 'ust_verify', { doc: ok.doc, offline: true })).result === 'VALID:LIGHT');
}

// #178 — THE KEY-HOLDER SPLIT, played out over the wire. The agent holds no key at any point: it asks for the
// sealing request, an external holder seals exactly the string it was handed, and the agent assembles. The
// load-bearing assertions are that the result is BYTE-IDENTICAL to the all-in-one producer (one derivation, two
// processes — F.7a.2's corollary demands the first, not the second) and that a sealer working from its own
// derivation is caught by a caller with no key at all.
{
  const { createCipheriv, randomBytes } = await import('node:crypto');
  const KEY = randomBytes(32), KEY_B64 = KEY.toString('base64url');
  const D = kp('dd'.repeat(32));
  const ID = { domain_shard: D.key_id, ust_id: 'ust:20260903.13' };
  const value = { kp: '5.8' };

  const req = await call(client, 'ust_sealing_request', { name: 'reading', value, ...ID });
  check('live:#178 the sealing request carries the commitment, the plaintext and the IV — and NO key travelled',
    req.commit?.startsWith('sha256:') && typeof req.plaintext === 'string' && typeof req.iv === 'string' && req.disclosures?.reading?.nonce === req.nonce);

  const sealWith = (iv) => { const b = Buffer.from(iv, 'base64url');
    const c = createCipheriv('aes-256-gcm', KEY, b);
    const body = Buffer.concat([c.update(Buffer.from(req.plaintext, 'utf8')), c.final()]);
    return Buffer.concat([b, body, c.getAuthTag()]).toString('base64url'); };

  const built = await call(client, 'ust_attach_encryption', { name: 'reading', commit: req.commit, key_id: 'ops-2026-09', ct: sealWith(req.iv) });
  const direct = P.encryptPartition('reading', value, { ...ID, nonce: req.nonce, key_id: 'ops-2026-09', key: KEY_B64 }).partition;
  check('live:#178 the split output is BYTE-IDENTICAL to encryptPartition — one derivation, two processes',
    JSON.stringify(built.partition) === JSON.stringify(direct), JSON.stringify(built.partition).slice(0, 90));

  const wrong = await rawCall(client, 'ust_attach_encryption', { name: 'reading', commit: req.commit, key_id: 'ops-2026-09', ct: sealWith(randomBytes(12).toString('base64url')) });
  check('live:#178 a sealer that used its OWN IV is caught by a caller holding no key — the seam is checked, not trusted',
    wrong.isError === true, JSON.stringify(wrong.body || {}).slice(0, 80));

  // and the assembled partition goes back into a builder untouched — a result is not a declaration
  const st = await call(client, 'ust_build_observation', { ...ID, key_id: D.key_id, time: t, data: { reading: built.partition } });
  check('live:#178 an assembled encrypted partition passes THROUGH the builder — a built result is not a declaration to rebuild',
    st.state?.data?.reading?.commit === req.commit);
}

await client.close();
console.log('\n════════════════════════════════════════════');
console.log('  ust-mcp LIVE (real stdio transport)   PASS ' + pass + '   FAIL ' + fail);
console.log(fail ? '' : '  ✓ agent talks to the running MCP server and verifies over the wire');
process.exit(fail ? 1 : 0);
