// The invariants that are diarium's OWN, not the protocol's. ust-protocol already proves that a seal verifies; what is
// unproven until tested here is the discipline layered on top — order taken from the chain rather than the filesystem,
// a refusal to extend a broken store, the cap, and one closure owing exactly one entry.
//
// Every case runs the real binary as a subprocess in a throwaway directory, because a test that imports the module
// would not exercise the thing that actually ships: an argv-driven CLI resolving its store from cwd.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, unlinkSync, copyFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../bin/diarium.mjs', import.meta.url));

const mk = () => mkdtempSync(join(tmpdir(), 'diarium-test-'));
const run = (cwd, ...argv) => {
  try { return { code: 0, out: execFileSync(process.execPath, [CLI, ...argv], { cwd, encoding: 'utf8', stdio: 'pipe' }) }; }
  catch (e) { return { code: e.status ?? 1, out: (e.stdout || '') + (e.stderr || '') }; }
};
const entries = (cwd) => readdirSync(join(cwd, 'diarium')).filter((f) => f.endsWith('.ust.json')).sort();
const doc = (cwd, f) => JSON.parse(readFileSync(join(cwd, 'diarium', f), 'utf8'));
const seed = (cwd, ref, text = 'a recap of what was understood') => {
  writeFileSync(join(cwd, 'e.md'), text);
  run(cwd, 'closed', ref);
  return run(cwd, 'write', ref, join(cwd, 'e.md'));
};

test('a first entry is genesis; a second chains to it by content hash, not by name', () => {
  const d = mk();
  seed(d, 'a#1', 'first');
  seed(d, 'a#2', 'second');
  const [f1, f2] = entries(d);
  const d1 = doc(d, f1), d2 = doc(d, f2);
  assert.equal(d1.state.provenance?.prev, undefined, 'the first entry must carry no prev');
  assert.ok(d2.state.provenance.prev.startsWith('sha256:'));
  assert.equal(run(d, 'verify').code, 0);
});

test('order comes from the chain: renaming every file changes nothing', () => {
  const d = mk();
  seed(d, 'a#1', 'oldest'); seed(d, 'a#2', 'middle'); seed(d, 'a#3', 'newest');
  const before = run(d, 'read', '--depth', '3').out;
  // Rename into an order that sorts the opposite way. A store that took its order from the filesystem would flip here.
  entries(d).forEach((f, i) => renameSync(join(d, 'diarium', f), join(d, 'diarium', `zz${9 - i}_renamed.ust.json`)));
  assert.equal(run(d, 'verify').code, 0, 'renaming is not tampering');
  assert.equal(run(d, 'read', '--depth', '3').out, before, 'the reading order must be unchanged');
});

test('the whole store relocated still verifies — a seal is not bound to where it sits', () => {
  const d = mk(), d2 = mk();
  seed(d, 'a#1'); seed(d, 'a#2');
  mkdirSync(join(d2, 'diarium'), { recursive: true });
  for (const f of entries(d)) copyFileSync(join(d, 'diarium', f), join(d2, 'diarium', f));
  assert.equal(run(d2, 'verify').code, 0);
});

test('an edited entry fails, and the broken seal is reported before its structural fallout', () => {
  const d = mk();
  seed(d, 'a#1', 'what actually happened'); seed(d, 'a#2');
  const f = entries(d)[0];
  const x = doc(d, f);
  x.state.data.entry.value.text = 'a quieter version';
  writeFileSync(join(d, 'diarium', f), JSON.stringify(x) + '\n');
  const r = run(d, 'verify');
  assert.equal(r.code, 1);
  assert.match(r.out, /seal does NOT verify/);
  const lines = r.out.split('\n').filter((l) => l.includes('•'));
  assert.match(lines[0], /seal does NOT verify/, 'the finding must lead, not its consequences');
});

test('an entry deleted from the middle leaves a gap that verify names', () => {
  const d = mk();
  seed(d, 'a#1'); seed(d, 'a#2'); seed(d, 'a#3');
  unlinkSync(join(d, 'diarium', entries(d)[1]));
  const r = run(d, 'verify');
  assert.equal(r.code, 1);
  assert.match(r.out, /resolves to no entry here/);
});

test('a duplicated entry is a fork, not a silent extra file', () => {
  const d = mk();
  seed(d, 'a#1'); seed(d, 'a#2'); seed(d, 'a#3');
  const f = entries(d)[1];
  copyFileSync(join(d, 'diarium', f), join(d, 'diarium', 'copy_' + f));
  const r = run(d, 'verify');
  assert.equal(r.code, 1);
  assert.match(r.out, /FORK: 2 entries claim the same prev/);
});

test('write refuses to extend a broken store rather than chaining onto damage', () => {
  const d = mk();
  seed(d, 'a#1'); seed(d, 'a#2');
  const f = entries(d)[0];
  const x = doc(d, f);
  x.state.data.entry.value.text = 'tampered';
  writeFileSync(join(d, 'diarium', f), JSON.stringify(x) + '\n');
  const before = entries(d).length;
  const r = seed(d, 'a#3');
  assert.equal(r.code, 1);
  assert.match(r.out, /refusing to extend a broken store/);
  assert.equal(entries(d).length, before, 'nothing may be written while the store is broken');
});

test('the cap declared in rules.md is enforced, and it is the file that decides', () => {
  const d = mk();
  seed(d, 'a#1');
  const rules = join(d, 'diarium', 'rules.md');
  writeFileSync(rules, readFileSync(rules, 'utf8').replace(/^cap:\s*\d+/m, 'cap: 40'));
  writeFileSync(join(d, 'long.md'), 'x'.repeat(41));
  run(d, 'closed', 'a#2');
  const r = run(d, 'write', 'a#2', join(d, 'long.md'));
  assert.equal(r.code, 1);
  assert.match(r.out, /is 40/);
  writeFileSync(join(d, 'ok.md'), 'x'.repeat(40));
  assert.equal(run(d, 'write', 'a#2', join(d, 'ok.md')).code, 0, 'exactly at the cap must pass');
});

test('a closure owes an entry: status fails until it is discharged', () => {
  const d = mk();
  run(d, 'closed', 'a#7', '--title', 'something closed');
  const owed = run(d, 'status');
  assert.equal(owed.code, 1, 'status is the gate — it must fail while an entry is owed');
  assert.match(owed.out, /a#7/);
  writeFileSync(join(d, 'e.md'), 'what I learned');
  run(d, 'write', 'a#7', join(d, 'e.md'));
  assert.equal(run(d, 'status').code, 0);
});

test('"nothing learned" is recorded structurally, so it can be counted', () => {
  const d = mk();
  writeFileSync(join(d, 'e.md'), 'I no longer hold this task.');
  run(d, 'closed', 'a#1');
  run(d, 'write', 'a#1', join(d, 'e.md'), '--nothing-learned');
  assert.equal(doc(d, entries(d)[0]).state.data.entry.value.learned, 'none');
});

test('the seal carries a durable task reference, and invents nothing when there is no global id', () => {
  const d = mk();
  seed(d, 'PROJ-abc');
  const t = doc(d, entries(d)[0]).state.data.entry.value.task;
  assert.equal(t.ref, 'PROJ-abc');
  assert.equal(t.source, 'tracker-local');
  assert.equal(t.id, undefined, 'no identifier may be fabricated for a tracker that has none');
});

test('the closure time travels into the seal, so lived and reconstructed stay distinguishable', () => {
  const d = mk();
  seed(d, 'a#1');
  const v = doc(d, entries(d)[0]).state.data.entry.value;
  assert.ok(v.task.closed_at, 'without the closure time the interval is unobservable');
});

test('an empty store reads and verifies without inventing a chain', () => {
  const d = mk();
  const r = run(d, 'read');
  assert.equal(r.code, 0);
  assert.match(r.out, /no entries yet/);
  assert.equal(run(d, 'verify').code, 0);
});

test('a settings.json that does not parse fails loudly instead of being ignored', () => {
  const d = mk();
  run(d, 'scan');
  writeFileSync(join(d, 'diarium', 'settings.json'), '{ not json');
  const r = run(d, 'scan');
  assert.equal(r.code, 1);
  assert.match(r.out, /does not parse/);
});

test('the signing seed is never printed, on any command', () => {
  const d = mk();
  seed(d, 'a#1');
  const s = readFileSync(join(d, '.env'), 'utf8').match(/^DIARIUM_SEED=(\S+)/m)[1];
  for (const argv of [['scan'], ['status'], ['read'], ['verify'], ['render'], []]) {
    assert.ok(!run(d, ...argv).out.includes(s), `the seed leaked into the output of: diarium ${argv.join(' ') || '(no args)'}`);
  }
  writeFileSync(join(d, 'e2.md'), 'second');
  run(d, 'closed', 'a#2');
  assert.ok(!run(d, 'write', 'a#2', join(d, 'e2.md')).out.includes(s), 'the seed leaked into write output');
});

test('every stored entry verifies under the protocol directly, with no diarium involved', async () => {
  const d = mk();
  seed(d, 'a#1'); seed(d, 'a#2');
  const P = await import('ust-protocol');
  for (const f of entries(d)) assert.equal(P.verify(doc(d, f), { context: 'data' }).result, 'VALID:LIGHT');
});

test.after(() => { for (const p of readdirSync(tmpdir()).filter((f) => f.startsWith('diarium-test-'))) rmSync(join(tmpdir(), p), { recursive: true, force: true }); });
