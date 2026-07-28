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

// ── askHidden must OWN stdin, and the roster is ENUMERATED rather than claimed ────────────────────────────────────
//
// `askHidden` reads a passphrase in raw mode so it never echoes. A readline interface opened BEFORE it takes stdin
// over and echoes the line itself — the secret prints while the code looks correct. A guard was added on 2026-07-27
// after the owner watched a root passphrase print, and its comment stated: "Every caller now builds its readline
// LAZILY, and this guard makes a future eager one loud instead of silent."
//
// THE CLAIM WAS FALSE WHEN WRITTEN. `cmdGenesis` still opened its interface eagerly, so from rc.43 the guard REFUSED
// every silver and gold genesis ceremony — the tool that mints a name's identity, broken at the two profiles an
// operator actually uses, and unnoticed because no gate performs a passphrase ceremony. That is the difference
// between asserting a property over a domain and enumerating the domain: the sentence "every caller" was the bug.
{
  const callers = [];
  for (const m of SRC.matchAll(/askHidden\(/g)) {
    const line = SRC.slice(0, m.index).split('\n').length;
    if (/export async function askHidden/.test(lines[line - 1] || '')) continue;   // the definition itself
    // walk back to the enclosing function
    let fn = -1;
    for (let i = line - 1; i >= 0; i--) if (/^(export )?(async )?function \w+|^async function \w+/.test(lines[i])) { fn = i; break; }
    if (fn >= 0) callers.push({ line, fn, name: (lines[fn].match(/function (\w+)/) || [, '?'])[1] });
  }
  check(callers.length >= 3, `only ${callers.length} askHidden call sites found — the roster probe has gone blind and this whole section would pass vacuously`);

  for (const c of callers) {
    // the enclosing function's readline must be created LAZILY, on first use, not at entry
    const body = lines.slice(c.fn, c.line).join('\n');
    const eager = /^\s*const rl = createInterface\(/m.test(body);
    const lazy = /rl \?\?= createInterface\(/.test(body);
    check(!eager, `${c.name} opens its readline EAGERLY (ust-cli/index.mjs) and then calls askHidden at :${c.line} — the open interface owns stdin and echoes the passphrase, so askHidden's guard refuses and the whole ceremony dies. Build it lazily: \`let rl = null; const ask = (q) => { rl ??= createInterface(...); return rl.question(q); };\``);
    check(lazy, `${c.name} calls askHidden at :${c.line} but no lazy \`rl ??= createInterface(\` is visible above it — the roster is enumerated, so a new caller must adopt the pattern rather than inherit a claim about it`);
    // a lazy rl means every close must be null-safe, or the failure path throws instead of reporting
    const after = lines.slice(c.fn, c.fn + 400).join('\n');
    const bare = (after.match(/(?<!\?)\brl\.close\(\)/g) || []).length;
    check(bare === 0, `${c.name} contains ${bare} bare rl.close() call(s) while its rl is lazy — a failure before the first prompt throws a TypeError instead of printing why`);
  }
}


// ── askHidden must OWN stdin AT THE MOMENT IT RUNS, not merely have been built lazily ─────────────────────────────
//
// Lazy construction was necessary and NOT sufficient, and the gap cost the owner a failed ceremony on a machine
// deliberately cut off from the network. By the time the passphrase is asked, the ceremony has already asked several
// questions, so the interface EXISTS — lazily built, but open — and askHidden's guard refuses one step before the
// files are written. The tool was correct and the ceremony still died.
//
// So the caller must hand stdin BACK: close the interface and null the handle immediately before each attempt, and
// let the lazy getter re-create it for whatever is asked next. Inside the loop, not once before it — askHidden's own
// no-tty fallback delegates to `ask`, which re-opens the interface, so a second attempt met an open reader again.
//
// And the retry must be BOUNDED: unbounded, it spins forever the moment stdin cannot answer.
{
  for (const m of SRC.matchAll(/askHidden\(/g)) {
    const line = SRC.slice(0, m.index).split('\n').length;
    if (/export async function askHidden/.test(lines[line - 1] || '')) continue;
    const before = lines.slice(Math.max(0, line - 6), line).join('\n');
    check(/rl\?\.close\(\);\s*rl = null;/.test(before),
      `the askHidden call at ust-cli/index.mjs:${line} does not hand stdin back first (\`rl?.close(); rl = null;\` within the five lines above it). Building the interface lazily is not enough — by this point earlier questions have opened it, and the guard will refuse one step before the ceremony writes anything.`);
    const loop = lines.slice(Math.max(0, line - 8), line + 2).join('\n');
    if (/\b(while|for)\s*\(/.test(loop)) {
      check(/tries|attempts|max|>\s*\d/.test(loop),
        `the askHidden call at :${line} retries in an UNBOUNDED loop — an exhausted pipe or a detached terminal makes it spin forever, printing the same prompt on a machine that may have nobody watching`);
    }
  }
}


console.log(`\n  ceremony self-check   PASS ${pass}   FAIL ${fail.length}   (${sites.length} self-check sites × ${WORLD.length} world properties)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every ceremony self-check asserts what the ceremony preserves, and every failure branch can report');
