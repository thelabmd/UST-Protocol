// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — a hostile Proxy over an export roster taken from the source
// test:module-seam-totality — S1 MODULE-SEAM closure (trust-boundary law UST-5tm). A NOT-OURS module (a substrate
// verifier: OTS / Rekor / git / IPFS / Bitcoin — OPEN-ENDED, third-party) has a HOSTILE invocation AND a HOSTILE
// return: it may throw on the call, or return a revoked / throwing-trap Proxy that host-throws when we touch or decode
// it. Every public entrypoint that reaches a substrate seam MUST return a STRUCTURED verdict, never a host throw.
// This is the axis the conformance hostile-ARG battery does NOT cover (there the hostile value is the opts/doc; HERE it
// is the module's RETURN). It drives each seam with a battery of hostile module returns + a throwing module, and pins
// the count of substrateVerify() INVOCATION sites from source so a NEW seam fails RED until it is driven here.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as P from './index.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

let pass = 0; const F = [];
const ok = (name, cond) => { cond ? pass++ : F.push(name); };

// Hostile module RETURNS — each is a substrateVerify() that hands back a shape which host-throws when touched/decoded.
const HOSTILE_RETURNS = {
  'throws-on-call':          () => { throw new Error('hostile module throw'); },
  'revoked-proxy':           () => { const { proxy, revoke } = Proxy.revocable({ final: true, time: '2020-01-01T00:00:00Z' }, {}); revoke(); return proxy; },
  'throwing-getPrototypeOf': () => new Proxy({ final: true, time: '2020-01-01T00:00:00Z' }, { getPrototypeOf() { throw new Error('trap-getProto'); } }),
  'throwing-getOwnPropDesc': () => new Proxy({ final: true, time: '2020-01-01T00:00:00Z' }, { getOwnPropertyDescriptor() { throw new Error('trap-gopd'); } }),
  'throwing-then-getter':    () => new Proxy({ final: true }, { get(t, p) { if (p === 'then') throw new Error('trap-then'); return Reflect.get(t, p); } }),
  'null-proto-throwing-get': () => { const o = Object.create(null); Object.defineProperty(o, 'final', { get() { throw new Error('trap-final'); }, enumerable: true, configurable: true }); return o; },
};

// A valid-enough input so the substrate call is ACTUALLY reached, then the hostile module return is handled.
const contentHash = 'sha256:' + 'a'.repeat(64);
const anchorRoot = P.H('ust:leaf', contentHash);
const proof = { root: anchorRoot, path: [], anchor: 'anchor-x' };
const docWithProof = { proof: { anchor: 'anchor-x', root: anchorRoot, path: [] } };
// #42 — a genuinely signed root statement, so the seam is REACHED: an unadmitted authority would refuse before it.
const rootKp = (() => { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('a7'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url'); return { priv, pub }; })();
const rootStatement = P.buildNameMapRoot({ map_root: contentHash }, rootKp.priv, rootKp.pub);
const rootAuthorities = { [P.keyId(rootKp.pub)]: rootKp.pub };

// SEAM ROSTER — the public entrypoints that reach a substrate module seam (resolveByDiscovery is covered by the
// from-source pin + the shared decodeSubstrate total door; it is not run behaviorally here because it needs a live transport).
const SEAMS = [
  { name: 'verifyAnchor', run: (mod) => P.verifyAnchor(contentHash, proof, { substrateVerify: mod }) },
  { name: 'verifyAsync', run: (mod) => P.verifyAsync(docWithProof, { substrateVerify: mod }) },
  // #42 — the map-root anchor seam. It AWAITS the not-ours module directly before handing its receipt to the core
  // door, so a hostile return/throw must become a structured refusal here too, not a host throw one level up.
  { name: 'proveMapRootAnchor', run: (mod) => P.proveMapRootAnchor(rootStatement, proof, { mapAuthorities: rootAuthorities, substrateVerify: mod }) },
];

for (const seam of SEAMS) {
  for (const [shape, mod] of Object.entries(HOSTILE_RETURNS)) {
    let threw = false, res;
    try { res = await seam.run(mod); } catch (e) { threw = true; res = e && e.message; }
    ok(`${seam.name} × ${shape} → structured verdict, never host-throw`, !threw && res !== null && typeof res === 'object');
  }
}

// Control: an honest final substrate return still earns `anchored` (the guard did NOT over-reject).
const c = P.verifyAnchor(contentHash, proof, { substrateVerify: () => ({ final: true, time: '2020-01-01T00:00:00Z' }) });
ok('control: honest final substrate return → anchored (no over-rejection)', c && c.time === 'anchored' && c.status === 'verified');

// FROM-SOURCE no-drift guard: count substrateVerify() INVOCATION sites (excluding line comments). A NEW seam increments
// this and fails RED until it is added to the SEAMS roster above and re-pinned — the roster can never silently drift.
const src = readFileSync(fileURLToPath(new URL('./index.mjs', import.meta.url)), 'utf8');
let invocations = 0;
for (const ln of src.split('\n')) {
  const idx = ln.indexOf('substrateVerify(');
  if (idx === -1) continue;
  const c2 = ln.indexOf('//');
  if (c2 !== -1 && c2 < idx) continue;   // the match is inside a line comment, not a real invocation
  invocations++;
}
const PINNED = 4;   // verifyAnchorCore + verifyAsync + anchoredByProofs + proveMapRootAnchor (#42). Update WITH the SEAMS roster when a new substrate invocation site lands.
ok(`from-source: substrateVerify() invocation sites == ${PINNED} (a NEW seam must be driven in SEAMS + re-pinned)`, invocations === PINNED);

console.log(`\n  module-seam-totality (S1 — NOT-OURS module returns are TOTAL, trust-boundary law UST-5tm)   PASS ${pass}   FAIL ${F.length}`);
if (F.length) { F.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log(`  ✓ every public substrate seam returns a structured verdict on a hostile module return/throw — never a host throw; invocation roster pinned from source`);
