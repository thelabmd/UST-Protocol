// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the graph is WALKED from source and the mapped core is EXECUTED with the Node globals deleted; both builds recompute the same vectors, so a divergence is measured rather than asserted
// #143 — "the core is browser-portable" is a claim about RUNNING, and this runs it.
//
// WHY NOT A BUNDLER. Bundling answers "do the imports resolve". Measured 2026-08-08: with the crypto faculty
// substituted, the core bundled GREEN to 261 KB while carrying 51 references to `Buffer` — a Node GLOBAL, not
// an import, which no bundler reports and which throws on the first call in a page. A green bundle would have
// been read as portability and shipped a runtime failure to the consumer's browser.
//
// CLOSED 2026-08-08 by round 184 — this gate IS that measurement, made repeatable and wired into CI as a step.
//
// So this gate does the two things a bundler cannot:
//
//   1. RESOLVES the module graph under the package's `browser` map and refuses any surviving `node:` import.
//   2. RUNS the mapped core in a child process with the Node globals DELETED — `Buffer`, `process`, `require`,
//      `__dirname` — and exercises the API. A dependency on any of them surfaces as a throw, not as silence.
//
// And the payoff check: the browser build must produce the SAME hashes as the Node build. A portable core that
// disagrees with itself across platforms is worse than one that does not build — the documents would verify in
// one place and not the other, which is the cross-language split the whole canon discipline exists to prevent.

import { readFileSync, writeFileSync, mkdtempSync, cpSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Path written whole, not assembled from segments: the assurance map reads a tool's own source to decide
// whether its grade-2 claim ("derived from the enforcing code") is earned, and a path in pieces hides the
// evidence that this gate walks `packages/ust-protocol/` rather than trusting a list.
const PKG_DIR = join(ROOT, 'packages/ust-protocol');
const pkg = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8'));
const BROWSER_MAP = pkg.browser ?? {};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '✓' : '✗'} ${name}${ok || !detail ? '' : ' — ' + detail}`);
  if (!ok) failures++;
};

// ─── 1. the graph, under the browser map ────────────────────────────────────────────────────────────────
// `import … from`, bare `import '…'`, RE-EXPORTS (`export … from '…'`) and dynamic `import('…')`.
// The re-export form is here because leaving it out is how this gate first passed while the runtime failed:
// the graph looked like four modules and the process pulled in a fifth. A graph walk that misses an edge
// reports a clean graph, which is the most confident way to be wrong.
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\s[\s\S]*?from\s+'([^']+)'|(?:^|\n)\s*import\s+'([^']+)'|\bimport\(\s*'([^']+)'/g;
const seen = new Set();
const nodeImports = [];
const graph = [];

(function walk(rel) {
  const mapped = BROWSER_MAP['./' + rel] ? BROWSER_MAP['./' + rel].replace(/^\.\//, '') : rel;
  if (seen.has(mapped)) return;
  seen.add(mapped);
  graph.push(mapped);
  const src = readFileSync(join(PKG_DIR, mapped), 'utf8');
  for (const m of src.matchAll(IMPORT_RE)) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (!spec) continue;
    if (spec.startsWith('node:')) { nodeImports.push(`${mapped} → ${spec}`); continue; }
    if (spec.startsWith('.')) walk(spec.replace(/^\.\//, ''));
    else nodeImports.push(`${mapped} → ${spec} (bare specifier)`);
  }
})('index.mjs');

check(`the browser graph resolves without a Node import (${graph.length} modules: ${graph.join(', ')})`,
  nodeImports.length === 0, nodeImports.join('; '));

// ─── 2. run it with the Node globals removed ────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'ust-browser-'));
for (const f of graph) cpSync(join(PKG_DIR, f), join(dir, f));
// The bundler substitution, performed by hand: the browser file takes the mapped name.
for (const [from, to] of Object.entries(BROWSER_MAP)) {
  cpSync(join(PKG_DIR, to.replace(/^\.\//, '')), join(dir, from.replace(/^\.\//, '')));
}

const VECTORS = { canonInput: { b: '2', a: '1' }, hashInput: 'ust:leaf', keyPub: 'D1UnrRs1r3Dkl5Objd5RicXH-gq-mCzImFoSWI4UOc4' };
const runner = `
// Delete the Node globals BEFORE the core is loaded. The import is dynamic for exactly that reason: a static
// import is hoisted above the deletions and would be evaluated while they still exist.
for (const g of ['Buffer', 'process', 'require', '__dirname', '__filename', 'global']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const P = await import('${join(dir, 'index.mjs')}');
const out = {
  build: (await import('${join(dir, '_crypto.mjs')}')).CRYPTO_BUILD,
  canon: P.canon(${JSON.stringify(VECTORS.canonInput)}),
  h: P.H('ust:leaf', 'x'),
  keyId: P.keyId('${VECTORS.keyPub}'),
  contentHash: P.contentHash({ ust: '1.0', state: { id: { domain_shard: 'example.test' } } }),
  strictOk: P.strictB64url('${VECTORS.keyPub}', 32) !== null,
  strictAlias: P.strictB64url('${VECTORS.keyPub.slice(0, -1)}5', 32) === null,
};
console.log(JSON.stringify(out));
`;

let browserOut;
try {
  browserOut = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', runner],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
  check('the core RUNS with Buffer/process/require deleted', true);
} catch (e) {
  check('the core RUNS with Buffer/process/require deleted', false,
    String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 160) ?? 'no output');
}

check('the browser build is the one that ran', browserOut?.build === 'browser', `got ${browserOut?.build}`);

// ─── 3. the two builds must AGREE ───────────────────────────────────────────────────────────────────────
if (browserOut) {
  const N = await import(join(PKG_DIR, 'index.mjs'));
  const nodeOut = {
    canon: N.canon(VECTORS.canonInput),
    h: N.H('ust:leaf', 'x'),
    keyId: N.keyId(VECTORS.keyPub),
    contentHash: N.contentHash({ ust: '1.0', state: { id: { domain_shard: 'example.test' } } }),
    strictOk: N.strictB64url(VECTORS.keyPub, 32) !== null,
    strictAlias: N.strictB64url(VECTORS.keyPub.slice(0, -1) + '5', 32) === null,
  };
  for (const k of Object.keys(nodeOut)) {
    check(`node and browser agree on ${k}`, String(nodeOut[k]) === String(browserOut[k]),
      `node=${String(nodeOut[k]).slice(0, 40)} browser=${String(browserOut[k]).slice(0, 40)}`);
  }
}

// ─── 4. the refusals are refusals, not false verdicts ───────────────────────────────────────────────────
const refusalRunner = `
const C = await import('${join(dir, '_crypto.mjs')}');
const out = {};
for (const fn of ['ed25519Verify', 'ed25519Sign', 'aesGcmDecrypt']) {
  try { C[fn](); out[fn] = 'RETURNED'; } catch (e) { out[fn] = /E-UNSUPPORTED/.test(e.message) ? 'refused' : 'threw:' + e.message.slice(0, 40); }
}
console.log(JSON.stringify(out));
`;
try {
  const r = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', refusalRunner], { encoding: 'utf8' }).trim());
  // A `false` here would read as "the signature did not verify" — a VERDICT the browser build has no right to.
  check('the browser build REFUSES Ed25519/AES by name instead of returning a verdict',
    r.ed25519Verify === 'refused' && r.ed25519Sign === 'refused' && r.aesGcmDecrypt === 'refused', JSON.stringify(r));
} catch (e) {
  check('the browser build REFUSES Ed25519/AES by name instead of returning a verdict', false, String(e.message).slice(0, 120));
}

// ─── 5. NEGATIVE CONTROLS — a gate that cannot go red is a decoration ───────────────────────────────────
//
// Both legs above are green on this tree, and green proves nothing on its own: the graph walk missed a
// re-export once and still reported a clean graph. So each leg is driven to FAIL here, deliberately, on
// inputs whose defect is known.

// (a) the graph leg: the SAME walk without the browser map must FIND the Node import it exists to catch.
{
  const seenN = new Set();
  const found = [];
  (function walkNoMap(rel) {
    if (seenN.has(rel)) return;
    seenN.add(rel);
    for (const m of readFileSync(join(PKG_DIR, rel), 'utf8').matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2] ?? m[3];
      if (!spec) continue;
      if (spec.startsWith('node:')) found.push(`${rel} → ${spec}`);
      else if (spec.startsWith('.')) walkNoMap(spec.replace(/^\.\//, ''));
    }
  })('index.mjs');
  check('negative control: WITHOUT the browser map the same walk finds the Node import',
    found.length > 0, 'the walk found nothing to catch — it would pass an unmapped core');
}

// (b) the run leg: a module that touches `Buffer` must DIE in the same globals-deleted child.
{
  const probe = join(dir, '__negative-control.mjs');
  writeFileSync(probe, 'export const touch = () => Buffer.from("x").length;\n');
  const runner2 = `
for (const g of ['Buffer']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const M = await import('${probe}');
M.touch();
console.log('SURVIVED');
`;
  let survived = false;
  try {
    survived = execFileSync(process.execPath, ['--input-type=module', '--eval', runner2],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).includes('SURVIVED');
  } catch { survived = false; }
  check('negative control: a module touching Buffer DIES in the same harness', survived === false,
    'Buffer survived deletion — the run leg would pass a core that uses it');
}

// ─── 6. the LIGHT floor — one surface, portable by construction ─────────────────────────────────────────
//
// `ust-light` took the opposite decision to the core and it is the right one for a FLOOR: its synchrony was
// incidental, so it became ASYNCHRONOUS EVERYWHERE on WebCrypto rather than growing a second build. There is
// no `browser` map to apply here — the single file is the browser file — so the check is simply that it
// carries no Node import and runs with the globals gone. A floor that refuses the browser is not a floor.
{
  const LIGHT = join(ROOT, 'packages/ust-light/index.mjs');
  const src = readFileSync(LIGHT, 'utf8');
  const nodeSpecs = [...src.matchAll(IMPORT_RE)].map((m) => m[1] ?? m[2] ?? m[3]).filter((x) => x && !x.startsWith('.'));
  check(`ust-light imports nothing from a platform (${nodeSpecs.length ? nodeSpecs.join(', ') : 'none'})`,
    nodeSpecs.length === 0, nodeSpecs.join(', '));

  const lightRunner = `
for (const g of ['Buffer', 'process', 'require', '__dirname', '__filename', 'global']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const L = await import('${LIGHT}');
const kp = await L.keypair();
const id = { domain_shard: kp.key_id, ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' };
const time = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const doc = await L.seal(await L.buildState(id, time, { t: { kind: 'captured', value: { c: '21.5' } } }), kp.privateKey, kp.pub);
const v = await L.verify(doc);
console.log(JSON.stringify({ result: v.result, ch: await L.contentHash(doc) }));
`;
  try {
    const out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', lightRunner],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
    // The whole round trip — keypair, build, seal, verify — with no Node global in reach.
    check('ust-light builds, seals and VERIFIES with Buffer/process/require deleted', out.result === 'VALID:LIGHT', `got ${out.result}`);
  } catch (e) {
    check('ust-light builds, seals and VERIFIES with Buffer/process/require deleted', false,
      String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 150) ?? 'no output');
  }
}

console.log(failures === 0
  ? '\n  browser portability: the mapped core and the LIGHT floor both run without Node globals'
  : `\n  browser portability: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
