// SPDX-License-Identifier: Apache-2.0
// Ceremony self-check gate (rev95) — a ceremony's self-check must assert the invariant the ceremony PRESERVES,
// never a property of the WORLD it does not determine.
//
// The defect it exists for [measured 2026-07-27]: `ust rotate` asked
// `resolveAuthority(...).strength === 'authoritative'` while supplying only `noForkConfirmed`, which yields
// `consumer-override` — the value #98 had HARDENED the protocol to withhold that same day, precisely so a caller's
// boolean cannot name a canonical. The ceremony therefore demanded of a flag a property the protocol had just
// decided that flag may not confer, and it died on its own check EVERY time. Rotation is the only recovery from
// key compromise, so the recovery path was unavailable and nothing said so.
//
// The other two ceremonies asked correctly — and that was LUCK. Nothing stated the rule and nothing stopped a
// fourth from copying the wrong one. This gate is what turns three lucky cases into one invariant.
//
// WORLD-PROPERTY VOCABULARY: name authority, witness confirmation, network reachability. A ceremony holds a cold
// key, a fetched log and a declared parameter — it cannot determine any of those, so asking about them either
// fails always or passes vacuously, and both read to an operator as the other.
import { readFileSync } from 'node:fs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// The DOMAIN is every self-check in the ceremony surface, read out of the source — a new one enters this set by
// existing, which is what makes the rule survive the next ceremony.
const lines = SRC.split('\n');
const sites = [];
lines.forEach((l, i) => { if (/self-check FAILED/.test(l)) sites.push({ line: i + 1, text: l }); });
check(sites.length >= 4, `only ${sites.length} self-check sites found — the probe has gone blind`);

// A self-check may not condition on a world property. These are the resolver calls that ANSWER a world question.
const WORLD = [
  ['resolveAuthority', 'name authority — depends on witness evidence a ceremony neither holds nor should'],
  ['noForkConfirmed', 'a caller no-fork assertion — #98 hardened the protocol so this can never confer authority'],
  ['acceptConsumerOverride', 'a consumer opt-in — the ceremony is not the consumer'],
  ["'authoritative'", 'the authoritative rung is a property of the world, not of what the ceremony produced'],
];
for (const s of sites) {
  // the whole statement, not just the line: a check may span the two lines above it
  // the window must INCLUDE the matched line: the condition and its exit live ON it. The first version excluded
  // it and the gate was vacuous — the mutation test caught that, a reading of the code would not have.
  const stmt = lines.slice(Math.max(0, s.line - 4), s.line + 1).join(' ');
  for (const [needle, why] of WORLD) {
    check(!stmt.includes(needle),
      `ceremony self-check at ust-cli/index.mjs:${s.line} conditions on ${needle} — ${why}. Assert what the ceremony PRESERVES instead (rev95).`);
  }
}

// and every self-check must EXIT — a check whose failure branch cannot run is not a check. The rotation branch
// called a bare rl.close() where its three neighbours use rl?.close(), and `rl` is built lazily since rc.43, so
// the failure threw a TypeError BEFORE printing its diagnosis: the operator saw a stack, not the reason.
for (const s of sites) {
  const stmt = lines.slice(Math.max(0, s.line - 4), s.line + 1).join(' ');
  if (!/\brl\b/.test(stmt)) continue;
  check(!/[^?]\brl\.close\(\)/.test(stmt),
    `ceremony self-check at ust-cli/index.mjs:${s.line} calls a bare rl.close() — rl is built LAZILY, so the failure branch throws before it can report. Use rl?.close().`);
}

// the pin must be able to fail
check(WORLD.length >= 4 && sites.length >= 4, 'the vocabulary or the site set shrank — the gate would pass vacuously');

console.log(`\n  ceremony self-check   PASS ${pass}   FAIL ${fail.length}   (${sites.length} self-check sites × ${WORLD.length} world properties)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every ceremony self-check asserts what the ceremony preserves, and every failure branch can report');
