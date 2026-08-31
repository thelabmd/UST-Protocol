// SPDX-License-Identifier: Apache-2.0
// @assurance 4 canfail:no — a build that cannot run a cipher must never turn that into a verdict about a document.
//
// WHY THIS FILE EXISTS. Measured 2026-08-31 (#176), before the faculty existed — CLOSED 2026-08-31 by the
// `AEAD_IMPLEMENTED` declaration and this file: a build carrying Ed25519 and no
// AES-GCM was handed an honest document with a correct disclosure and a correct key, and answered
//
//     INVALID  E-COMMIT   "AEAD↔commit mismatch: secret"
//
// The faculty was the only difference between that and `VALID:LIGHT`. So the verifier's own inability was
// rendered as an accusation against the publisher — on the axis where a wrong verifier is silently dangerous
// rather than merely wrong. The cause is mechanical: `aeadDecrypt` returned `null` both for "the tag did not
// verify" (the document's defect) and for "the primitive is absent" (the verifier's limit). One signal, two
// mechanisms; and having only one, it had to pick, and it picked the accusation.
//
// The fix is a DECLARATION — `AEAD_IMPLEMENTED` — read before any document is. The model states why discovery by
// attempt cannot work (F.7a.2, second corollary): an absent primitive and an unauthentic ciphertext are the same
// observation. This file executes the half of the claim that the reference build cannot show, because the
// reference build implements both algorithms: it runs a build declaring ONLY the MTI, which §17 makes an
// ordinary conforming configuration, not a broken one.
//
// NOT AN ARTIFICIAL CASE. A verifier implementing `AES-256-GCM` and not `XChaCha20-Poly1305` is exactly what §17
// permits, and is what any porting implementation will be on its first day.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, copyFileSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as FULL_BUILD from './index.mjs';

// Same construction as `browser-build.test.mjs`: copy the package BY PROPERTY (every module), then replace the
// faculty. A hand-written file list falls behind the code — the failure mode this repository keeps meeting.
const SRC = new URL('./', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'ust-mti-only-'));
for (const f of readdirSync(SRC)) {
  if ((!f.endsWith('.mjs') && f !== 'package.json') || f.endsWith('.test.mjs') || f === '_crypto.browser.mjs') continue;
  copyFileSync(join(SRC, f), join(dir, f));
}
// The ONLY edit: the declaration shrinks to the MTI. Every primitive stays present and callable — which is the
// point. If the core decided by calling, this build would behave identically to the full one and the test would
// pass while proving nothing.
const faculty = readFileSync(join(SRC, '_crypto.mjs'), 'utf8')
  .replace("export const AEAD_IMPLEMENTED = ['AES-256-GCM', 'XChaCha20-Poly1305'];",
           "export const AEAD_IMPLEMENTED = ['AES-256-GCM'];");
writeFileSync(join(dir, '_crypto.mjs'), faculty);
const MTI_ONLY = await import(pathToFileURL(join(dir, 'index.mjs')).href);

// Both expectations come from the corpus, not from a fixture chosen here: the claim is normative for every
// implementation, so it belongs in the file a port reads.
const VECTOR = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'))
  .vectors.find((v) => v.id === 'faculty-absent-aead-xchacha');
const OPTS = () => ({
  context: 'data',
  disclosures: { [VECTOR.disclosure.partition]: { nonce: VECTOR.disclosure.nonce, value: VECTOR.disclosure.value } },
  decKeys: { [VECTOR.key.key_id]: VECTOR.key.raw },
});

test('the subkey derivation matches the CFRG vector — the one piece of cipher arithmetic we wrote', async () => {
  // Pinned against the STANDARD, not against our own output. An implementation that is wrong here round-trips
  // perfectly against itself and produces ciphertexts no other implementation can open — the failure mode a
  // self-consistency test cannot see.
  const { hchacha20 } = await import('./_crypto.mjs');
  const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'));
  const vec = V.vectors.find((v) => v.kind === 'hchacha20');
  assert.ok(vec, 'the corpus carries no hchacha20 vector — a port would have nothing to check its derivation against');
  const got = Buffer.from(hchacha20(Buffer.from(vec.input_hex.key, 'hex'), Buffer.from(vec.input_hex.nonce16, 'hex'))).toString('hex');
  assert.equal(got, vec.expect_hex);
  // CONTROL: the comparison can fail. A one-bit change in the nonce must not reach the same subkey.
  const off = Buffer.from(vec.input_hex.nonce16, 'hex'); off[0] ^= 1;
  assert.notEqual(Buffer.from(hchacha20(Buffer.from(vec.input_hex.key, 'hex'), off)).toString('hex'), vec.expect_hex);
});

test('the vector exists and states BOTH halves — otherwise this file asserts against itself', () => {
  assert.ok(VECTOR, 'conformance vector `faculty-absent-aead-xchacha` is missing');
  assert.equal(VECTOR.absent_faculty, 'aead-xchacha20-poly1305');
  assert.equal(VECTOR.expect_with_faculty, 'VALID:LIGHT');
  assert.deepEqual(VECTOR.expect_without_faculty, { result: 'INDETERMINATE', reason: 'unsupported_alg' });
});

test('control: the document is genuinely fine — the full build meets the with-faculty half', () => {
  const r = FULL_BUILD.verify(VECTOR.doc, OPTS());
  assert.equal(r.result, VECTOR.expect_with_faculty, `got ${r.result} ${r.error ?? r.reason ?? ''}`);
});

test('control: we really loaded the REDUCED build — its declaration is short by exactly the optional algorithm', async () => {
  // Vacuity pin. Without it, a copy that silently kept the full declaration would make the assertion below pass
  // while proving nothing — the shape of green that let the defect above live undetected.
  const reduced = await import(pathToFileURL(join(dir, '_crypto.mjs')).href);
  assert.deepEqual(reduced.AEAD_IMPLEMENTED, ['AES-256-GCM']);
  assert.ok(FULL_BUILD.REGISTRY.aeadAlgs.includes('XChaCha20-Poly1305'),
    'the algorithm this build declines is still REGISTERED — otherwise the document would be refused at admission and never reach the faculty');
});

test('a build that cannot run the cipher says so — INDETERMINATE(unsupported_alg), never a verdict about the document', () => {
  const r = MTI_ONLY.verify(VECTOR.doc, OPTS());
  assert.equal(r.result, VECTOR.expect_without_faculty.result, `got ${r.result} ${r.error ?? ''}`);
  assert.equal(r.reason, VECTOR.expect_without_faculty.reason);
});

test('and it does NOT reach for E-COMMIT — the regression this file was written for', () => {
  const r = MTI_ONLY.verify(VECTOR.doc, OPTS());
  assert.notEqual(r.error, 'E-COMMIT', 'the verifier blamed the publisher for its own missing cipher (#176)');
  assert.notEqual(r.result, 'INVALID');
});

test('the reduced build still runs the MTI normally — it lost one algorithm, not the mode', () => {
  const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'));
  const gcm = V.vectors.find((v) => v.id === 'privacy-encrypted-disclosure');
  const r = MTI_ONLY.verify(gcm.doc, {
    context: 'data',
    disclosures: { [gcm.disclosure.partition]: { nonce: gcm.disclosure.nonce, value: gcm.disclosure.value } },
    decKeys: { [gcm.key.key_id]: gcm.key.raw },
  });
  assert.equal(r.result, 'VALID:LIGHT', `got ${r.result} ${r.error ?? r.reason ?? ''}`);
  assert.deepEqual(r.disclosed, [gcm.disclosure.partition]);
});

test('an unauthentic ciphertext is still the DOCUMENT\'s defect — the declaration did not soften E-COMMIT', () => {
  // The pair that makes the distinction real: same build, same key, a ciphertext that decrypts to another value.
  const V = JSON.parse(readFileSync(new URL('../../vectors/conformance-vectors.json', import.meta.url), 'utf8'));
  const dis = V.vectors.find((v) => v.id === 'privacy-encrypted-channels-disagree');
  const r = MTI_ONLY.verify(dis.doc, {
    context: 'data',
    disclosures: { [dis.disclosure.partition]: { nonce: dis.disclosure.nonce, value: dis.disclosure.value } },
    decKeys: { [dis.key.key_id]: dis.key.raw },
  });
  assert.equal(r.error, 'E-COMMIT', `got ${r.result} ${r.error ?? r.reason ?? ''}`);
});

process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
