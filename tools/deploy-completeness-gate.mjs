// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — deploy call sites extracted from the CLI source
// Deploy COMPLETENESS gate — a deploy is constructed from the complete discovery set or not at all.
//
// MEASURED, 2026-07-27: five sites construct a deploy. Two passed the cadence log and the preserved witness anchors;
// THREE passed neither — `ust witness --deploy` and both `ust genesis --deploy` roads. So a witness anchoring run, or
// a re-run of genesis, NULLED /.well-known/ust-cadence and DESTROYED every Rekor/OTS anchor the served witness held.
// The anchors are the only evidence that an hour was ever notarised; nothing warned, and the loss is silent because a
// deploy that serves a VALID but emptier document looks exactly like a healthy one.
//
// CLOSED 2026-07-27 — // The DATA half closed with the mechanism, on 2026-07-27: `collectServed()` also RESTORES
// anchors from a local log when the domain is unreachable, so a loss already suffered is repaired and not merely
// prevented — 2 witness anchors were recovered from the live domain [measured]. Noted here afterwards. Noted
// 2026-08-05, appended rather than rewritten.
//
// That is not three bugs. It is one missing assembler, found three times: every call site enumerated the artifacts
// itself, so every call site could forget one. The structural close is `collectServed()` — the single place that
// knows what a complete set IS, preserving live anchors before synthesising and loading the cadence log beside the
// genesis. Call sites no longer enumerate; they ask for the set and spread it whole.
//
// This gate is what stops the SIXTH site from hand-rolling the set again — the failure mode a fix alone cannot close.
import { readFileSync } from 'node:fs';

const U = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const SRC = U('packages/ust-cli/index.mjs');
const lines = SRC.split('\n');

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// ── 1. the assembler exists and is the ONLY place the set is built
// The property is ONE assembler of the served set, not one SPELLING of the call. `collectServed` now PREFERS the
// ceremony's own witness log — it carries the signed supersession a derivation cannot know about (F.5z.5) — and
// falls back to deriving, so the call reads `witnessText ?? buildWitnessLog(...)`. Matching the old literal reported
// zero builders and would have blocked a fix that made the set MORE complete, which is the opposite of this gate's job.
const builders = lines.map((l, i) => ({ l, n: i + 1 })).filter((x) => /witnessText:.*buildWitnessLog\(/.test(x.l));
check(/export async function collectServed\(/.test(SRC), 'collectServed is gone — the set has no single assembler again');
check(builders.length === 1,
  `${builders.length} sites build the served set with buildWitnessLog (expected exactly 1, inside collectServed): ` +
  builders.map((b) => 'ust-cli/index.mjs:' + b.n).join(', ') + ' — a second builder is a second place to forget an artifact');

// ── 2. every deploy call takes the set WHOLE. A call that names artifacts individually is enumerating again.
const DEPLOY = /\b(wranglerDeploy|cfPublish)\(\{/g;
let m; let sites = 0;
while ((m = DEPLOY.exec(SRC)) !== null) {
  const n = SRC.slice(0, m.index).split('\n').length;
  const decl = /^export async function (wranglerDeploy|cfPublish)/.test(lines[n - 1] || '');
  if (decl) continue;                                  // the definitions themselves destructure, correctly
  sites++;
  const stmt = lines.slice(n - 1, n + 2).join(' ');
  check(/\.\.\.\s*(served|await collectServed|\(await collectServed)/.test(stmt),
    `deploy at ust-cli/index.mjs:${n} does not spread a collectServed() set — it enumerates artifacts itself, which is how three sites silently nulled the cadence log and destroyed the served witness anchors`);
}
check(sites >= 4, `only ${sites} deploy call sites found — the probe has gone blind and the gate would pass vacuously`);

// ── 3. the assembler must actually carry BOTH artifacts that were being lost
const fn = SRC.slice(SRC.indexOf('export async function collectServed('));
const body = fn.slice(0, fn.indexOf('\nexport ', 10));
check(/ust-cadence/.test(body), 'collectServed no longer loads the cadence log — the artifact three sites were nulling');
check(/ust-witness/.test(body) && /preserving|restoring/.test(body), 'collectServed no longer preserves live witness anchors — the loss it exists to stop');
check(/anchors\s*=\s*anchorsOf\(await r\.text\(\)\)/.test(body) || /preserving/.test(body), 'the live-preserve leg is gone');

// ── 4. each leg must be able to FAIL
check(!/\.\.\.\s*(served|await collectServed)/.test('cfPublish({ domain, genesisText, keylogText })'), 'the spread probe accepts a hand-built call — leg would pass for anything');
check(/witnessText:.*buildWitnessLog\(/.test('  witnessText: buildWitnessLog(x)'), 'the builder probe cannot see a builder');
check(/witnessText:.*buildWitnessLog\(/.test('  witnessText: mine ?? buildWitnessLog(x)'), 'the builder probe cannot see a builder behind a fallback');
check(!/witnessText:.*buildWitnessLog\(/.test('  const witnessText = null;'), 'the builder probe matches a line with no builder');

console.log(`\n  deploy completeness   PASS ${pass}   FAIL ${fail.length}   (1 assembler · ${sites} call sites)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ one assembler, every deploy takes the set whole — no site can forget an artifact');
