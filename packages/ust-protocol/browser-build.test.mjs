// SPDX-License-Identifier: Apache-2.0
// @assurance 4 canfail:no — the browser build must never turn its own inability into a verdict about a document.
// The grade is deliberately NOT 1b: what this file compares are two BUILDS of one package, not two independent
// implementations. They share every line except the crypto faculty, so their agreement says nothing about what
// escaped both authors — only that a refusal does not become a verdict. Claiming 1b would be exactly the
// over-claim the assurance map exists to refuse.
//
// WHY THIS FILE EXISTS AT ALL. Measured 2026-08-09 (#144): the browser build of the core was loaded by NO gate.
// `_crypto.browser.mjs` was named in exactly two places — the `browser` map in `package.json` and a comment —
// and the cross-implementation test that looks like it covers this (`ust-web-signer/test.mjs`) imports the NODE
// build of the core. So the build shipped in rc.68 had never been executed by anything before a human ran it.
// CLOSED 2026-08-09 by this file: the build is now loaded and executed in CI (`npm run test:browser-build`).
//
// WHAT IT ASSERTS. Not `canon`/`keyId` parity — those are the pure parts, they agree by construction and their
// agreement is exactly what stayed green while a valid signature was being called INVALID. This asserts a
// VERDICT over a real document: a build that cannot perform the signature check must answer INDETERMINATE.
//
// THE NORM IS NOT LOCAL TO THIS FILE. F-theorem clause 5: a verifier that holds the inputs and does not evaluate
// the function "declines to compute — the honest report is still INDETERMINATE(reason), never a guessed verdict".
// A verifier that ACCUSES is worse than one that overclaims: an overclaim can be audited by a careful reader,
// an accusation about an honest document leaves that reader nothing to notice.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, copyFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as NODE_BUILD from './index.mjs';

// The `browser` field in package.json is a BUNDLER instruction; Node does not honour it. To execute the browser
// build we reproduce what a bundler does — the same core sources with the browser faculty in place of the node
// one — rather than trusting that the two builds differ only where we think they do.
// Copied by PROPERTY (every module of the package), not by a hand-written list: the first list held the three
// static imports and missed `reference-checker.mjs`, which the core reaches through a dynamic import. A list
// maintained by hand falls behind the code — the same mechanism this repository keeps meeting elsewhere.
const SRC = new URL('./', import.meta.url).pathname;
const here = (f) => SRC + f;
const dir = mkdtempSync(join(tmpdir(), 'ust-browser-build-'));
for (const f of readdirSync(SRC)) {
  if (!f.endsWith('.mjs') && f !== 'package.json') continue;
  if (f.endsWith('.test.mjs') || f === '_crypto.browser.mjs') continue;
  copyFileSync(here(f), join(dir, f));
}
copyFileSync(here('_crypto.browser.mjs'), join(dir, '_crypto.mjs'));
const BROWSER_BUILD = await import(pathToFileURL(join(dir, 'index.mjs')).href);

// The document and BOTH expectations come from the conformance vector, not from a fixture chosen here: the claim
// "a build without the primitive answers INDETERMINATE" is normative for every implementation, so it belongs in
// the vector file a port reads. This file executes the without-faculty half; `conformance.mjs` — running under the
// build that HAS the primitive — executes the with-faculty half of the same vector.
const VECTOR = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'))
  .vectors.find((v) => v.id === 'faculty-absent-ed25519');
const DOC = VECTOR.doc;

test('the vector exists and states BOTH halves — otherwise this file asserts against itself', () => {
  assert.ok(VECTOR, 'conformance vector `faculty-absent-ed25519` is missing');
  assert.equal(VECTOR.absent_faculty, 'ed25519-verify');
  assert.equal(VECTOR.expect_with_faculty, 'VALID:LIGHT');
  assert.deepEqual(VECTOR.expect_without_faculty, { result: 'INDETERMINATE', reason: 'unsupported_alg' });
});

test('control: the document is genuinely fine — the node build meets the with-faculty half', () => {
  const r = NODE_BUILD.verify(DOC);
  assert.equal(r.result, VECTOR.expect_with_faculty, `got ${r.result} ${r.error ?? ''}`);
});

test('control: we really loaded the BROWSER build — its signing faculty refuses by name', () => {
  // Vacuity pin. Without it, a copy that silently kept the node faculty would make every assertion below pass
  // while proving nothing — the exact shape of green that let #144 ship.
  assert.throws(
    () => BROWSER_BUILD.seal({ any: 'state' }, {}, 'x'),
    /E-UNSUPPORTED/,
    'the loaded build still has a working signing faculty — the substitution did not take effect',
  );
});

test('a build that CANNOT check a signature must not say the signature FAILED', () => {
  const r = BROWSER_BUILD.verify(DOC);
  assert.notEqual(
    r.result,
    'INVALID',
    `the browser build accused an honest document: ${r.result} ${r.error ?? ''} ${r.detail ?? ''}`,
  );
});

test('the without-faculty half of the vector holds EXACTLY, reason included', () => {
  const r = BROWSER_BUILD.verify(DOC);
  assert.equal(r.result, VECTOR.expect_without_faculty.result, `got ${r.result} ${r.error ?? ''}`);
  assert.equal(
    r.reason,
    VECTOR.expect_without_faculty.reason,
    `the reason must name inability, got reason=${r.reason} detail=${r.detail ?? ''}`,
  );
});

// ── #144 — WHOSE STRICTNESS IS IT. `S >= L` is a non-canonical signature a strict verifier MUST reject, and until
// this round nothing here checked it: the rejection came from whichever library the faculty wrapped, so the
// conformance vector was testing OpenSSL. That is invisible on the node build, where the library answers anyway —
// a test there would be vacuous, green whether or not we check. The build WITHOUT the faculty makes it
// observable: if the rejection is ours, a malleable signature still answers `false`; if it was borrowed, the same
// call refuses instead, because there is no library to borrow from.
const MALLEABLE = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'))
  .vectors.find((v) => v.kind === 'malleability-reject');

test('a valid signature is UNDECIDABLE without the faculty — the control for the two below', () => {
  assert.throws(() => BROWSER_BUILD.edVerifyStrict(MALLEABLE.pub_b64url, MALLEABLE.signed_content, MALLEABLE.valid_sig), /E-UNSUPPORTED/);
});

test('non-canonical S is rejected by ARITHMETIC, not by a borrowed library', () => {
  assert.equal(
    BROWSER_BUILD.edVerifyStrict(MALLEABLE.pub_b64url, MALLEABLE.signed_content, MALLEABLE.sig_malleable),
    MALLEABLE.expect_without_faculty,
    'a build with no Ed25519 faculty must still answer false on S >= L — otherwise the strictness is the library\'s, and two conforming verifiers may disagree where implementations are known to (I4)',
  );
});

test('the node build agrees on both halves — the strictness did not MOVE, it was ADDED', () => {
  assert.equal(NODE_BUILD.edVerifyStrict(MALLEABLE.pub_b64url, MALLEABLE.signed_content, MALLEABLE.valid_sig), true);
  assert.equal(NODE_BUILD.edVerifyStrict(MALLEABLE.pub_b64url, MALLEABLE.signed_content, MALLEABLE.sig_malleable), false);
});

// round-239 (UST-mbso) — THE OTHER HALF, and the one that was missing for a month. Everything above asserts what the
// browser build must REFUSE. Nothing asserted what it must REACH, so a build that refused EVERY name-form document
// stayed green: #144 wired the async faculty into `verifyAsync` only, while `resolveByDiscovery` reached authority
// through synchronous resolvers, and `crypto.subtle` — present in every browser this ships to — was never consulted
// for the genesis, the key log or the cadence. Measured on the live page 2026-08-30: the reference operator's own
// public stream read INDETERMINATE, and the page said so in the words of a build that "cannot", beside a browser
// that could.
//
// The fixture is built by the NODE build because the browser build cannot sign, and the VERDICT is given by the
// BROWSER build. No network: `fetchImpl` serves the three well-known surfaces from memory, which is also why this
// can assert an exact tier — a witness probe would make the result depend on someone else's uptime.
const kp = (seedHex) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pubB64: pub, key_id: NODE_BUILD.keyId(pub) };
};

test('with crypto.subtle present, the browser build RESOLVES a name — HIGH is not gated on the node primitive', async () => {
  assert.ok(globalThis.crypto?.subtle, 'this runtime has no crypto.subtle — the premise of the test is absent, not satisfied');
  const ck = kp('d9'.repeat(32));
  const D = 'browser-faculty.example';
  const at = (h) => ({ generated_at: `2026-07-26T${h}:00:00Z`, valid_from: `2026-07-26T${h}:00:00Z`, valid_to: `2026-07-26T${h}:00:00Z` });
  const gen = NODE_BUILD.seal(NODE_BUILD.buildGenesis({ domain_shard: D, ust_id: 'ust:20260726.08', key_id: ck.key_id }, at('08'), ck.pubB64, 512), ck.priv, ck.pubB64);
  const doc = NODE_BUILD.seal(NODE_BUILD.buildState({ domain_shard: D, ust_id: 'ust:20260726.11', key_id: ck.key_id, class: 'observation' },
    at('11'), { x: { kind: 'captured', value: { v: '1' } } }, { prev: NODE_BUILD.contentHash(gen) }), ck.priv, ck.pubB64);
  // A SIGNED cadence entry, not an empty log — and that is the difference between a gate that covers its domain and
  // one that covers a third of it. Discovery makes THREE pure signature-bearing calls (genesis, cadence, authority);
  // with `ust-cadence` served as `[]` the middle one verifies nothing, so reverting its wrapper would leave this
  // green. Each of the three now reddens it on its own.
  const cadEntry = NODE_BUILD.seal(NODE_BUILD.buildCadenceEntry({ domain_shard: D, ust_id: 'ust:20260726.0900', key_id: ck.key_id },
    at('09'), '3600', 'ust:20260726.10', NODE_BUILD.contentHash(gen)), ck.priv, ck.pubB64);
  const ok = (o) => ({ ok: true, status: 200, text: async () => JSON.stringify(o), arrayBuffer: async () => Buffer.from(JSON.stringify(o)) });
  const fetchImpl = async (url) => url.endsWith('/.well-known/ust-genesis') ? ok(gen)
    : url.endsWith('/.well-known/ust-keylog') ? ok([])
    : url.endsWith('/.well-known/ust-cadence') ? ok([cadEntry])
    : ({ ok: false, status: 404, text: async () => '', arrayBuffer: async () => Buffer.alloc(0) });

  const r = await BROWSER_BUILD.resolveByDiscovery(doc, { noForkConfirmed: true }, { fetchImpl });

  const n = await NODE_BUILD.resolveByDiscovery(doc, { noForkConfirmed: true }, { fetchImpl });

  // ANTI-VACUITY FIRST, and it is not decoration: the load-bearing claim below is that the two builds AGREE, and
  // two builds that both refuse also agree. So the node run must have actually resolved something before its
  // agreement is worth asserting. Written after the first draft of this test demanded `VALID:HIGH` and failed —
  // on the NODE build too. The tier was never the faculty's to give: a caller-asserted no-fork resolves
  // `consumer-override`, which does not bind the NAME, so LIGHT is correct here and HIGH needs a witness this
  // fixture deliberately does not serve. The defect was refusal-to-decide; the tier was my own wrong expectation.
  assert.equal(n.resolution?.error, undefined, 'the node run did not resolve — the agreement asserted below would be vacuous');
  assert.equal(n.resolution?.publisher, D);
  assert.ok(n.resolution?.strength, 'the node run produced no identity strength — nothing to compare against');

  assert.doesNotMatch(String(r.resolution?.error ?? ''), /E-UNSUPPORTED/,
    'the browser build refused to DECIDE with the faculty available — the async signature faculty is not reaching the authority path');
  assert.equal(r.resolution?.publisher, D, 'authority did not resolve to the publisher the genesis names');
  assert.equal(r.resolution?.capacity?.maxPartitions, 512,
    'the capacity grant is the resolution the document needs to exceed the anonymous floor — withheld, a large document reads INDETERMINATE for a reason that is not about it');
  // The faculty must supply a MISSING INPUT, never a different answer: same bytes, same verdict, same strength.
  assert.equal(r.verdict?.result, n.verdict?.result, 'the two builds disagree on the same bytes');
  assert.equal(r.resolution?.strength, n.resolution?.strength, 'the two builds disagree on identity strength');
});

process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
