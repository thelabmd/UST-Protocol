// SPDX-License-Identifier: Apache-2.0
// Inclusion-connector gate — anchor inclusion is a CONNECTOR, and the seam must hold like every other not-ours seam.
//
// Owner call 2026-07-26: core + connectors at every level is what makes this adoptable, so the protocol does not name a
// substrate's tree. The tagged `ust:leaf`/`ust:node` walk stays as the BUNDLED reference connector — one convention
// among several — and an operator with an RFC 6962 log supplies `opts.inclusionVerify`.
//
// Two things must both be true, and they pull against each other, which is why this is gated:
//   · nothing already in the field breaks — the bundled default still confirms every proof issued before delegation
//   · the seam is hostile-safe — a connector is a third-party module, so its return and its throw are untrusted input
import * as P from '../packages/ust-protocol/index.mjs';

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

const CH = 'sha256:' + 'a'.repeat(64), SIB = 'sha256:' + 'b'.repeat(64);
const leaf = (s) => P.Hbytes('ust:leaf', Buffer.from(s, 'utf8'));
const node = (s) => P.Hbytes('ust:node', Buffer.from(s, 'utf8'));
const goodRoot = node(SIB + leaf(CH));
const goodProof = { path: [{ dir: 'L', hash: SIB }], root: goodRoot, anchor: { substrate: 'x' } };
const alien = { path: [{ shape: 'rfc6962' }], root: 'sha256:' + 'c'.repeat(64), anchor: { substrate: 'x' } };

// ── the bundled connector still works, both ways
ok('bundled connector confirms a valid path', P.verifyAnchor(CH, goodProof).inclusion === true);
ok('bundled connector rejects a wrong root',
  P.verifyAnchor(CH, { ...goodProof, root: 'sha256:' + 'd'.repeat(64) }).inclusion === false);
ok('bundled connector rejects a malformed path entry',
  P.verifyAnchor(CH, { ...goodProof, path: [{ dir: 'X', hash: SIB }] }).error === 'E-ANCHOR');
ok('a proof the bundled connector cannot walk is refused, not accepted', P.verifyAnchor(CH, alien).inclusion === false);

// ── delegation: the connector decides, and the core does not recompute behind its back
ok('a connector returning true is believed even when the bundled walk would fail',
  P.verifyAnchor(CH, alien, { inclusionVerify: () => true }).inclusion === true);
ok('a connector returning false is believed even when the bundled walk would pass',
  P.verifyAnchor(CH, goodProof, { inclusionVerify: () => false }).inclusion === false);
ok('the connector receives the content hash and the whole proof', (() => {
  let seen = null;
  P.verifyAnchor(CH, alien, { inclusionVerify: (c, p) => { seen = [c, p && p.root]; return true; } });
  return seen && seen[0] === CH && seen[1] === alien.root;
})());

// ── the seam is a CLOSED TYPED leaf: a strict Boolean, nothing else mints inclusion
for (const bad of ['yes', 1, {}, [], null, undefined, 'true', 0]) {
  ok(`a non-Boolean connector return (${JSON.stringify(bad)}) cannot mint inclusion`,
    P.verifyAnchor(CH, alien, { inclusionVerify: () => bad }).inclusion === false);
}

// ── totality: a hostile connector never host-throws out of the door
const hostiles = {
  'throws on call': () => { throw new Error('hostile'); },
  'returns a throwing-getter Proxy': () => new Proxy({}, { get() { throw new Error('H'); }, has() { throw new Error('H'); } }),
  'returns a revoked Proxy': () => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; },
};
for (const [name, fn] of Object.entries(hostiles)) {
  let r, threw = false;
  try { r = P.verifyAnchor(CH, alien, { inclusionVerify: fn }); } catch { threw = true; }
  ok(`hostile connector (${name}) → structured reject, never a host throw`, !threw && r && r.inclusion === false);
}

// ── async is named honestly rather than silently downgraded
const as = P.verifyAnchor(CH, alien, { inclusionVerify: async () => true });
ok('an async connector is named, not silently treated as unproven', as.inclusion === false && /ASYNC/.test(as.detail || ''));

// ── and the substrate seam is untouched by any of this
ok('substrate still delegated separately (inclusion OK, substrate is the caller job)',
  /substrate not verified/.test(P.verifyAnchor(CH, goodProof).detail || ''));
ok('a connector cannot mint anchored TIME — that is still the substrate seam',
  P.verifyAnchor(CH, alien, { inclusionVerify: () => true }).time === 'unproven');

console.log(`\n  inclusion connector   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ inclusion is delegable, the bundled connector still confirms everything already in the field, and the seam is total');
