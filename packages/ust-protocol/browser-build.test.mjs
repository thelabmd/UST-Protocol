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

process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
