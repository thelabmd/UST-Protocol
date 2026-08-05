// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — every command is RUN; the domain is read from the dispatcher, not from a list beside it
//
// Command-reachability gate — a command the tool dispatches must be a command the tool can ENTER.
//
// MEASURED, 2026-08-03: `ust key add` called `discoveryFetcher(domain)` and NOTHING IN THE TREE DEFINED IT. The call
// was written to a helper that was never created, so the command threw `ReferenceError: discoveryFetcher is not
// defined` on its first line of work — and shipped that way in the published package (`@ust-protocol/cli`, dist-tag
// `latest`) for five days. Every gate was green throughout, including the printed-command gate, because that gate
// checks a printed command STRING against the dispatch table and never asks whether the function behind the table
// can run at all. A name that is only ever CALLED, never defined, is invisible to every check that reads source.
//
// CLOSED 2026-08-03 — The helper was defined on 2026-08-03 in the commit that added this gate — one
// `/.well-known/` reader shared by every ceremony command, in place of two private copies — and ships in `cli
// rc.100`. Noted 2026-08-05, appended rather than rewritten.
//
// So this gate does the one thing none of the others did: it RUNS each command, far enough to reach its first
// refusal, and asserts the refusal is a NAMED one. A domain refusal ("--domain <d> required", "cannot fetch genesis
// for …") means the body was entered and did its own work. A JS runtime error means the body could not run.
//
// The distinction is the whole gate, and it is deliberately one-sided: an unknown-shaped refusal is ACCEPTED (this
// gate is not a spelling test for error prose), while the runtime-error vocabulary below is CLOSED and fails. That
// direction is the right one — a new refusal message must not break the build, and a new way to be unreachable must.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../packages/ust-cli/index.mjs', import.meta.url));
const SRC = readFileSync(CLI, 'utf8');
let pass = 0, fail = 0; const fails = [];
const check = (ok, msg) => { if (ok) pass++; else { fail++; fails.push(msg); } };

// THE DOMAIN, read from the dispatcher — the same source the printed-command gate reads, deliberately not a second
// hand-maintained list. A command added to the table is probed here without anyone remembering to add it.
const runObj = SRC.match(/const run = \{[^}]*\}/);
check(!!runObj, 'the command dispatch table could not be read — this gate would be vacuous');
const COMMANDS = [...new Set([...(runObj?.[0] ?? '').matchAll(/(\w+):/g)].map((m) => m[1]))];
check(COMMANDS.length >= 8, `only ${COMMANDS.length} commands found — the probe has gone blind`);

// Arguments chosen to reach the body and stop at its FIRST refusal: a reserved-for-invalid domain (RFC 2606) so no
// packet leaves the machine, a road argument where the command requires one, and a file path that cannot be read.
const ARGS = {
  verify: ['/nonexistent-file-for-the-gate.json'],
  explain: ['/nonexistent-file-for-the-gate.json'],   // #137 — same first refusal as verify: the body is entered, the file is not readable
  canon: ['/nonexistent-file-for-the-gate.json'],
  names: ['/nonexistent-directory-for-the-gate'],   // F.5t-a — the body IS entered: an unreadable path yields NOTHING EXAMINED, which the command refuses rather than passing

  stream: ['/nonexistent-file-for-the-gate.json'],
  forkchoice: ['/nonexistent-a.json', '/nonexistent-b.json'],
  discovery: ['probe.invalid'],
  genesis: ['--domain', 'probe.invalid', '--profile', 'gold'],   // gold REFUSES by design — a named refusal, no keys minted
  key: ['add', '--domain', 'probe.invalid', '--root', '/nonexistent-root.b64'],
  rotate: ['--domain', 'probe.invalid', '--root', '/nonexistent-root.b64'],
  cadence: ['--domain', 'probe.invalid', '--root', '/nonexistent-root.b64', '--seconds', '30', '--effective-from', 'ust:20260101.00'],
  reroot: ['--domain', 'probe.invalid'],
  publish: ['self', '--domain', 'probe.invalid', '--genesis', '/nonexistent-genesis.json'],
  mirror: ['probe.invalid'],
  witness: ['rekor', '--domain', 'probe.invalid'],
};
// A command in the table with no probe argument is a HOLE, not a pass: it would be silently unprobed, which is the
// exact shape of the defect this gate exists for.
for (const c of COMMANDS) check(ARGS[c] !== undefined, `command \`${c}\` is dispatched but has no probe here — add one rather than leaving it unrun`);

// The CLOSED vocabulary of "the body could not run". Every entry is a JS runtime failure, never a domain refusal.
const UNREACHABLE = [
  /\bis not defined\b/, /\bis not a function\b/, /\bis not iterable\b/, /\bis not a constructor\b/,
  /Cannot read propert/, /Cannot access '.*' before initialization/, /Assignment to constant variable/,
  /undefined is not an object/, /\bReferenceError\b/, /\bTypeError\b/, /\bSyntaxError\b/,
];

for (const c of COMMANDS) {
  const args = ARGS[c]; if (!args) continue;
  const r = spawnSync(process.execPath, [CLI, c, ...args], { encoding: 'utf8', timeout: 25000, input: '', env: { ...process.env, NO_COLOR: '1' } });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
  const hit = UNREACHABLE.find((re) => re.test(out));
  check(!hit, `\`ust ${c}\` could not be ENTERED — ${hit}: ${out.split('\n').filter(Boolean).slice(-1)[0]?.slice(0, 120)}`);
  // and it must actually have STOPPED. A probe that hangs or is killed proves nothing about reachability, and a
  // command that exits 0 on these arguments has accepted a nonexistent file or an unreachable domain as success.
  check(r.signal === null && r.status !== null, `\`ust ${c}\` did not terminate under the probe (signal ${r.signal})`);
}

// CONTROL — the discriminator must fire on a body that genuinely cannot run, or every green above is worthless.
// Measured against a synthetic module rather than by trusting the regexes to be right by inspection.
{
  const probe = spawnSync(process.execPath, ['-e', 'const f = () => { thisIsNotDefinedAnywhere(1); }; try { f(); } catch (e) { console.error("✗ " + e.message); process.exit(1); }'], { encoding: 'utf8' });
  const out = `${probe.stdout ?? ''}${probe.stderr ?? ''}`;
  check(UNREACHABLE.some((re) => re.test(out)), 'CONTROL: the unreachable-vocabulary did NOT fire on a real ReferenceError — the gate is blind');
  const ok = spawnSync(process.execPath, ['-e', 'console.error("✗ --domain <d> required"); process.exit(1);'], { encoding: 'utf8' });
  check(!UNREACHABLE.some((re) => re.test(`${ok.stdout ?? ''}${ok.stderr ?? ''}`)), 'CONTROL: the vocabulary fired on an ordinary domain refusal — the gate would reject working commands');
}

console.log(`\n  command reachability   PASS ${pass}   FAIL ${fail}   (${COMMANDS.length} commands entered)`);
if (fails.length) { console.log('\n  FAILURES:'); fails.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every dispatched command can be ENTERED — a body that cannot run is not a green build');
