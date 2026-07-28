// SPDX-License-Identifier: Apache-2.0
// Printed-command gate — an instruction the tool prints must be one the tool can run.
//
// MEASURED, 2026-07-28: the air-gapped handoff told the operator to run `ust publish --domain … --genesis … --keylog …`
// and he did. The real surface is `ust publish cf` — `cf` is a road argument, not a flag — so the CLI answered with
// its help screen and nothing happened. He had just finished a ceremony on a disconnected machine, carried the files
// out, and the next instruction was wrong.
//
// The handoff was written from my memory of the command rather than from the command. That is the whole defect class:
// text ABOUT code, authored beside the code, drifting from it silently — the same shape as a spec example the
// reference implementation rejects, and as a version stamped in four places where only three moved.
//
// So: every command string the tool prints is extracted and checked against the dispatch table it will actually be
// dispatched through, and a subcommand that requires a road argument must carry one.
import { readFileSync } from 'node:fs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// the DOMAIN, read from the dispatcher rather than from a list beside it
const runObj = SRC.match(/const run = \{[^}]*\}/);
check(!!runObj, 'the command dispatch table could not be read — the gate would be vacuous');
const COMMANDS = new Set([...(runObj?.[0] ?? '').matchAll(/(\w+):/g)].map((m) => m[1]));
check(COMMANDS.size >= 8, `only ${COMMANDS.size} subcommands found — the dispatch probe has gone blind`);

// subcommands whose FIRST positional is a required road, not a flag. Declared, because the requirement lives in the
// command's own usage line and a printed instruction that omits it produces the help screen and no work.
const REQUIRES_ROAD = { publish: ['cf', 'self'], witness: ['rekor'] };

// Only STRING LITERALS the tool prints — comments and usage prose are not instructions an operator copies.
const lines = SRC.split('\n');
let checked = 0;
for (const [n, line] of lines.entries()) {
  if (/^\s*(\/\/|\*)/.test(line)) continue;                      // a comment is not an instruction
  if (!/console\.log|^\s*['"`]|^\s*\$\{?T\}?/.test(line) && !/^\s{4}['"`]/.test(line)) continue;
  for (const m of line.matchAll(/(?:^|[\s'"`])(?:npx @ust-protocol\/cli|ust) ([a-z]+)(?: ([a-z-]+))?/g)) {
    const [, sub, next] = m;
    if (!COMMANDS.has(sub)) continue;                            // English prose that happens to contain "ust"
    checked++;
    const roads = REQUIRES_ROAD[sub];
    if (!roads) continue;
    check(roads.includes(next),
      `ust-cli/index.mjs:${n + 1} prints \`ust ${sub}${next ? ' ' + next : ''}…\`, but \`${sub}\` takes a required road argument (${roads.join(' | ')}). Without it the CLI answers with its help screen and does nothing — which is what an operator saw after carrying files off an air-gapped machine.`);
  }
}
check(checked >= 5, `only ${checked} printed commands found — the extraction has gone blind and this gate would pass vacuously`);

// each leg must be able to fail
check(!COMMANDS.has('nonexistent-subcommand'), 'the dispatch probe accepts a command the table lacks');
check(REQUIRES_ROAD.publish?.length > 0, 'the road table is empty — every printed publish would pass');

console.log(`\n  printed commands   PASS ${pass}   FAIL ${fail.length}   (${COMMANDS.size} subcommands · ${checked} printed instructions checked)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every command the tool prints is one the tool can run');
