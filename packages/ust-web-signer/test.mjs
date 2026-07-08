// SPDX-License-Identifier: Apache-2.0
// Cross-compat proof: a document SIGNED by ust-web-signer (WebCrypto) must verify VALID under ust-protocol
// (node:crypto) — two independent implementations agreeing that the bytes/preimage/signature line up.
import * as W from './index.mjs';
import * as P from '../ust-protocol/index.mjs';

let pass = 0, fail = 0;
const check = (id, ok, d) => { if (ok) pass++; else { fail++; console.log('  ✗ ' + id + (d ? ' — ' + d : '')); } };

const signer = await W.generateSigner({ extractable: false });
check('key_id derives the same on both sides', signer.key_id === P.keyId(signer.pub), signer.key_id + ' vs ' + P.keyId(signer.pub));

const { ust_id, time } = W.nowFrame(new Date('2026-07-08T12:34:56Z'));
const doc = await W.signObservation(signer, {
  ust_id, time,
  data: { capture: { kind: 'captured', value: { text: 'the exact bytes I saw — café ☕' } } },
});

// content_hash agrees across impls (byte-identical canon + preimage)
check('content_hash agrees (web-signer vs ust-protocol)', (await W.contentHash(doc)) === P.contentHash(doc));

// ust-protocol (the independent verifier) accepts the web-signed doc
const r = P.verify(doc, { context: 'data' });
check('ust-protocol verify → VALID:LIGHT', r.result === 'VALID:LIGHT', 'got ' + r.result);
check('identity is the KEY (self-certifying, no claimed name)', r.publisher_claimed === signer.key_id && r.publisher === undefined);
check('domain_shard == key_id (self-certifying)', doc.state.id.domain_shard === signer.key_id);
check('no url/origin/source leaked into signed state', JSON.stringify(doc.state.data).match(/https?:|origin|source|url/i) === null);

// tamper → INVALID (integrity holds)
const bad = JSON.parse(JSON.stringify(doc)); bad.state.data.capture.value.text = 'edited';
check('tampered text → INVALID', P.verify(bad, { context: 'data' }).result === 'INVALID');

console.log('\n════════════════════════════════════════════');
console.log('  ust-web-signer × ust-protocol   PASS ' + pass + '   FAIL ' + fail);
console.log(fail ? '' : '  ✓ web-signed documents verify under the independent Node verifier');
process.exit(fail ? 1 : 0);
