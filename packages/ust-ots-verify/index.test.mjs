// #69 Theme A2 regression: finality REQUIRES the committed value to match the REAL Bitcoin block merkle root
// AND >= minConfirmations. Offline: a captured real genesis .ots + a mock explorer serving the real block.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { makeSubstrateVerify, parseOtsBitcoin, toVerifiedEvidence } from './index.mjs';

const F = JSON.parse(readFileSync(new URL('./test-fixture.json', import.meta.url)));

// `opentimestamps` is an OPTIONAL peer (P1-08): the connector lazily loads it and declines when absent, so a
// CONSUMER never pulls its dependency chain — `request`, deprecated since 2020, and with it two critical
// advisories. It is deliberately NOT a devDependency either, because every contributor's `npm i` would then pull
// the same chain and the first thing a would-be auditor sees is a red audit they cannot act on.
//
// The cost of that is a test suite that can silently stop exercising the real substrate, which is worse than the
// audit noise. So the fail direction is split, exactly as it is everywhere else here: "is it relevant?" fails OPEN
// locally, "is it safe?" fails CLOSED in CI. A contributor without the library is TOLD, once, how to get it; CI
// cannot be green without it.
const OTS_PRESENT = await import('opentimestamps').then(() => true, () => false);
if (!OTS_PRESENT) {
  if (process.env.CI) {
    console.error('\n✗ opentimestamps is NOT installed and this is CI — the real substrate path would not be exercised.');
    console.error('  The workflow must install it: `npm i --no-save opentimestamps` before `npm run test:connectors`.');
    console.error('  A green run without it would mean the OTS connector was never tested against the real library.\n');
    process.exit(1);
  }
  console.error('\n  ℹ  opentimestamps is not installed — the 9 checks over the REAL substrate path are SKIPPED.');
  console.error('     It is an optional peer on purpose (its dependency chain carries two critical advisories).');
  console.error('     To run them:  npm i --no-save opentimestamps\n');
}

// a mock explorer: block-height→hash, block→{merkle_root,timestamp}, tip→height. `merkle` and `tip` overridable.

// The checks below drive the REAL library through the connector. Absent it they are SKIPPED, never failed: a
// contributor's clean tree must not read as nine broken things. CI cannot reach this branch — the guard above
// exits non-zero there, so a green CI always means these ran.
const otsTest = (name, fn) => test(name, { skip: OTS_PRESENT ? false : 'opentimestamps not installed (optional peer)' }, fn);

const mockExplorer = ({ merkle = F.merkle_root, tip = F.height + 100 } = {}) =>
  (async (url) => {
    const u = String(url);
    if (u.endsWith(`/block-height/${F.height}`)) return { text: async () => F.hash };
    if (u.endsWith(`/block/${F.hash}`)) return { json: async () => ({ merkle_root: merkle, timestamp: F.timestamp }) };
    if (u.endsWith('/blocks/tip/height')) return { text: async () => String(tip) };
    throw new Error('unexpected ' + u);
  });

otsTest('real genesis .ots + a SINGLE explorer → final:true but labelled explorer-single (#71-followup: 1 ≠ corroborated)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mockExplorer(), explorers: ['x'] });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, true);
  assert.equal(r.assurance, 'explorer-single');   // one source is a trusted oracle, honestly labelled
});

// a per-base mock: explorer A honest, explorer B configurable (merkle mismatch / unreachable).
const mock2 = ({ bMerkle = F.merkle_root, bDown = false } = {}) => (async (url) => {
  const u = String(url), isB = u.startsWith('B/');
  if (isB && bDown) throw new Error('B unreachable');
  const merkle = isB ? bMerkle : F.merkle_root;
  if (u.endsWith(`/block-height/${F.height}`)) return { text: async () => F.hash };
  if (u.endsWith(`/block/${F.hash}`)) return { json: async () => ({ merkle_root: merkle, timestamp: F.timestamp }) };
  if (u.endsWith('/blocks/tip/height')) return { text: async () => String(F.height + 100) };
  throw new Error('unexpected ' + u);
});

otsTest('#71 — 2-of-2 independent explorers AGREE → final, labelled explorer-corroborated', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mock2(), explorers: ['A', 'B'], quorum: 2 });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, true);
  assert.equal(r.assurance, 'explorer-corroborated');
});

// a per-base mock for THREE explorers — A/B honest, C configurable (a LATE disagreement).
const mock3 = ({ cMerkle = F.merkle_root } = {}) => (async (url) => {
  const u = String(url), isC = u.startsWith('C/');
  const merkle = isC ? cMerkle : F.merkle_root;
  if (u.endsWith(`/block-height/${F.height}`)) return { text: async () => F.hash };
  if (u.endsWith(`/block/${F.hash}`)) return { json: async () => ({ merkle_root: merkle, timestamp: F.timestamp }) };
  if (u.endsWith('/blocks/tip/height')) return { text: async () => String(F.height + 100) };
  throw new Error('unexpected ' + u);
});

otsTest('#71-followup P1 — A agree, B agree, C DISAGREE → NOT final (a late conflict is queried, not skipped)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mock3({ cMerkle: '22'.repeat(32) }), explorers: ['A', 'B', 'C'], quorum: 2 });
  assert.equal((await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root)).final, false);   // quorum met by A+B, but C's conflict is definitive
});

otsTest('#71-followup P1 — quorum:1 → assurance explorer-single (never corroborated for one source)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mock2(), explorers: ['A', 'B'], quorum: 1 });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, true);
  assert.equal(r.assurance, 'explorer-single');
});

otsTest('#71 — a second explorer DISAGREES on the merkle root → NOT final (definitive conflict)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mock2({ bMerkle: '11'.repeat(32) }), explorers: ['A', 'B'], quorum: 2 });
  assert.equal((await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root)).final, false);
});

otsTest('#71 — quorum 2 but only 1 explorer reachable → NOT final (insufficient corroboration)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mock2({ bDown: true }), explorers: ['A', 'B'], quorum: 2 });
  assert.equal((await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root)).final, false);
});

otsTest('P0 #69 A2 — explorer returns a WRONG merkle root → NOT final (structure alone is not proof)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mockExplorer({ merkle: '00'.repeat(32) }), explorers: ['x'] });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, false);
});

otsTest('block not yet buried (tip = height+2 → 3 conf) → NOT final', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mockExplorer({ tip: F.height + 2 }), explorers: ['x'] });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, false);
});

otsTest('explorer unreachable → unproven, never a false final', async () => {
  const down = async () => { throw new Error('network'); };
  const sv = makeSubstrateVerify({ fetchImpl: down, explorers: ['x'] });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, F.root);
  assert.equal(r.final, false);
});

test('.ots does not attest THIS root → null (claim ≠ proof)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mockExplorer(), explorers: ['x'] });
  const r = await sv({ substrate: 'bitcoin-ots', ots: F.ots }, 'sha256:' + 'cd'.repeat(32));
  assert.equal(r, null);
});

test('non-bitcoin substrate → null (router delegates onward)', async () => {
  const sv = makeSubstrateVerify({ fetchImpl: mockExplorer(), explorers: ['x'] });
  assert.equal(await sv({ substrate: 'rekor' }, F.root), null);
});

test('parseOtsBitcoin extracts the attested block height', () => {
  const parsed = parseOtsBitcoin(Buffer.from(F.ots, 'base64'));
  assert.equal(parsed.height, F.height);
});

test('P1-06 toVerifiedEvidence maps a FINAL result to typed pow-header-chain evidence; non-final ⇒ null', () => {
  const ev = toVerifiedEvidence('sha256:subj', { final: true, block_height: '800000', time: '2026-07-01T00:00:00Z' });
  assert.equal(ev.proof_kind, 'pow-header-chain');
  assert.equal(ev.facts.substrate, 'bitcoin');
  assert.equal(ev.facts.position, '800000');
  assert.equal(ev.facts.not_before, '2026-07-01T00:00:00Z');
  assert.equal(toVerifiedEvidence('sha256:subj', { final: false }), null);
});

test('totality (round-46 self-audit): a hostile anchor declines (null), never a host throw', async () => {
  const mk = () => new Proxy([{}], { get() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, getOwnPropertyDescriptor() { throw new Error('H'); } });
  const junk = [null, undefined, {}, [], 'x', 123, mk()];
  const sv = makeSubstrateVerify({ fetchImpl: async () => { throw new Error('net'); } });
  for (const j of junk) { const r = await sv(j, j); assert.ok(r === null || (r && typeof r === 'object'), 'substrateVerify must decline/structured, never host-throw'); }
});
