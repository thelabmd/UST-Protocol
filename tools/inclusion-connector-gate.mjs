// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — a hostile connector return admitted through the seam the core defines
// Inclusion-connector gate — anchor inclusion is a CONNECTOR, and the seam must hold like every other not-ours seam.
//
// Owner call 2026-07-26: core + connectors at every level is what makes this adoptable, so the protocol does not name a
// substrate's tree. The tagged `ust:leaf`/`ust:node` walk stays as the BUNDLED reference connector — one convention
// among several — and an operator with an RFC 6962 log supplies `opts.inclusionVerify`.
//
// Two things must both be true, and they pull against each other, which is why this is gated:
//   · nothing already in the field breaks — the bundled default still confirms every proof issued before delegation
//   · the seam is hostile-safe — a connector is a third-party module, so its return and its throw are untrusted input
import { readFileSync } from 'node:fs';
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

// ── async is named honestly rather than silently downgraded — and, since round 236 (#173), WITHHELD rather than
// refused. This asserted `inclusion === false`, which was the defect: a promise is a fact about the CALLER's host
// (WebCrypto's sha256 is async, so every browser connector is one), never a claim about the proof. Naming stays
// required; refusing does not. The sync door is the one under test here — the async door pre-resolves the seam.
const as = P.verifyAnchor(CH, alien, { inclusionVerify: async () => true });
ok('an async connector is NAMED and WITHHELD on the sync door, never a refusal of the proof',
  !('inclusion' in as) && as.time === 'unproven' && /ASYNC/.test(as.detail || ''));
// the asymmetry the repair must not have swallowed: a connector that RETURNS false has computed and refused
ok('a connector that RETURNS false still refuses — withholding did not swallow a real refusal',
  P.verifyAnchor(CH, alien, { inclusionVerify: () => false }).inclusion === false);

// ── and the substrate seam is untouched by any of this
ok('substrate still delegated separately (inclusion OK, substrate is the caller job)',
  /substrate not verified/.test(P.verifyAnchor(CH, goodProof).detail || ''));
ok('a connector cannot mint anchored TIME — that is still the substrate seam',
  P.verifyAnchor(CH, alien, { inclusionVerify: () => true }).time === 'unproven');

// ── the ROUTER (#95 finish): a caller composes what it has INSTALLED and passes it unconditionally ─────────────────
// The point of `null` meaning "not claimed" is that a caller need not know in advance whether it holds a connector for
// this substrate — so MCP and the CLI can pass a composed router always. MEASURED before this existed: an empty router
// killed a VALID proof with "inclusion path does not reach root", blaming the proof for the caller having no plugin.
ok('an EMPTY router does not kill a valid proof — it declines and the bundled walk decides',
  P.verifyAnchor(CH, goodProof, { inclusionVerify: P.combineInclusion([]) }).inclusion === true);
ok('a router whose every plugin DECLINES falls through to the bundled walk',
  P.verifyAnchor(CH, goodProof, { inclusionVerify: P.combineInclusion([() => null, () => undefined]) }).inclusion === true);
ok('a plugin that CLAIMS false is believed — a claim is not a decline',
  P.verifyAnchor(CH, goodProof, { inclusionVerify: P.combineInclusion([() => false]) }).inclusion === false);
ok('a THROWING plugin does not shadow a later one that claims',
  P.verifyAnchor(CH, alien, { inclusionVerify: P.combineInclusion([() => { throw new Error('x'); }, () => true]) }).inclusion === true);
ok('the FIRST plugin to claim wins; a later one cannot overturn it',
  P.verifyAnchor(CH, alien, { inclusionVerify: P.combineInclusion([() => false, () => true]) }).inclusion === false);
ok('a router still cannot mint anchored TIME',
  P.verifyAnchor(CH, alien, { inclusionVerify: P.combineInclusion([() => true]) }).time === 'unproven');
ok('a hostile verifiers ARRAY (throwing Proxy) fails CLOSED to an empty router, never a host throw', (() => {
  const hostile = new Proxy([], { get() { throw new Error('H'); }, ownKeys() { throw new Error('H'); } });
  try { return P.verifyAnchor(CH, goodProof, { inclusionVerify: P.combineInclusion(hostile) }).inclusion === true; } catch { return false; }
})());

// the rekor connector claims ONLY a declared rfc6962-raw tree, and never guesses a leaf convention
ok('the rekor inclusion connector DECLINES a proof that does not declare its scheme (returns null, not false)', await (async () => {
  // AUDIT #114 — this returned TRUE when the import failed, so a missing connector was a PASS, measured. It is a
  // WORKSPACE package, always present in a correct tree: absence means the tree is broken, not that the check is
  // inapplicable. Graceful degradation belongs at RUNTIME, where the connector is genuinely optional; a gate that
  // degrades gracefully is a gate that stops asking.
  let mod; try { mod = await import('../packages/ust-rekor-verify/index.mjs'); } catch (e) { console.log(`    ✗ ust-rekor-verify could not be imported (${String(e.code || e.message).slice(0, 50)}) — the connector under test is absent, so this proves nothing`); return false; }
  if (typeof mod.inclusionVerify !== 'function') return false;
  return mod.inclusionVerify(CH, goodProof) === null && P.verifyAnchor(CH, goodProof, { inclusionVerify: P.combineInclusion([mod.inclusionVerify]) }).inclusion === true;
})(), 'it must not answer for a tree the publisher never declared — a guessed leaf convention verifies somebody else\'s entry');
// ── the WITH-CONNECTOR half of the two-sided construction vectors (round 204, F.9.5-c.6).
//
// The corpus states TWO results for one input: a build with no connector for the declared construction WITHHOLDS,
// and the same bytes under a build that claims it verify. `conformance.mjs` runs the first half — it is the core,
// and the core implements no foreign construction. This runs the second, because only here is a connector present.
// Without it the vectors would pin the refusal and leave the NAME meaning nothing, which is the defect they exist
// to close: `rfc6962-raw` was defined in prose in two packages and by no artifact a port could reproduce.
{
  const CORPUS = JSON.parse(readFileSync(new URL('../vectors/conformance-vectors.json', import.meta.url), 'utf8')).vectors;
  const CASES = CORPUS.filter((v) => v.expect_with_connector !== undefined);
  // A corpus-driven check that selects nothing passes quietly — say the size.
  ok('the corpus carries two-sided construction vectors (with-connector half)', CASES.length === 2, `found ${CASES.length}`);

  let rekor = null;
  try { rekor = (await import('@ust-protocol/rekor-verify')).inclusionVerify; } catch { /* not installed */ }
  ok('the Rekor connector is importable — the with-connector half is EXERCISED, not skipped', typeof rekor === 'function');

  if (typeof rekor === 'function') {
    const inc = P.combineInclusion([rekor]);
    for (const v of CASES) {
      const proof = { root: v.root, path: v.path ?? [], ...(v.inclusion ? { inclusion: v.inclusion } : {}), anchor: { substrate: 'bitcoin-ots', ...(v.inclusion ? { inclusion: v.inclusion } : {}) } };
      const r = P.verifyAnchor(v.content_hash, proof, { inclusionVerify: inc });
      ok(`${v.id} — with a connector claiming '${v.inclusion?.construction}', the answer is ${JSON.stringify(v.expect_with_connector)}`,
        r.inclusion === v.expect_with_connector.inclusion, `got inclusion=${r.inclusion} reason=${r.reason ?? '-'}`);
    }
  }
}

console.log(`\n  inclusion connector   PASS ${pass}   FAIL ${fail.length}`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ inclusion is delegable, the bundled connector still confirms everything already in the field, and the seam is total');
