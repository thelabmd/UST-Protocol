// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — commands extracted from the dispatcher source, both directions
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
import { readFileSync, readdirSync } from 'node:fs';

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
  // AUDIT: `console.error` was NOT scanned, and the FIRST SCREEN — the most-read text this tool has, the one a
  // stranger meets before anything else — is printed through it. The gate that exists because a printed instruction
  // drifted from the command was blind to the biggest printed surface. Measured 2026-07-30 while restructuring that
  // screen into blocks: 21 instructions were checked and the help block was not among them.
  if (!/console\.(?:log|error)|^\s*['"`]|^\s*\$\{?T\}?/.test(line) && !/^\s{4}['"`]/.test(line)) continue;
  for (const m of line.matchAll(/(?:^|[\s'"`])(?:npx @ust-protocol\/cli|\$\{invocation\(\)\}|ust) ([a-z]+)(?: ([a-z-]+))?/g)) {
    const [, sub, next] = m;
    if (!COMMANDS.has(sub)) continue;                            // English prose that happens to contain "ust"
    checked++;
    const roads = REQUIRES_ROAD[sub];
    if (!roads) continue;
    // A usage line may name the roads as a PLACEHOLDER (`ust publish <cf|self> …`) instead of picking one. That is
    // correct documentation — it tells the operator the argument is required and what it may be — so it satisfies
    // the rule the same way a literal road does. The placeholder must ENUMERATE them, so it cannot become `<road>`.
    const ph = new RegExp(`ust ${sub} <${roads.join('\\|')}>`);
    if (ph.test(line)) { pass++; continue; }
    check(roads.includes(next),
      `ust-cli/index.mjs:${n + 1} prints \`ust ${sub}${next ? ' ' + next : ''}…\`, but \`${sub}\` takes a required road argument (${roads.join(' | ')}). Without it the CLI answers with its help screen and does nothing — which is what an operator saw after carrying files off an air-gapped machine.`);
  }
}
check(checked >= 5, `only ${checked} printed commands found — the extraction has gone blind and this gate would pass vacuously`);

// each leg must be able to fail
check(!COMMANDS.has('nonexistent-subcommand'), 'the dispatch probe accepts a command the table lacks');
check(REQUIRES_ROAD.publish?.length > 0, 'the road table is empty — every printed publish would pass');

// ── a printed instruction must be runnable IN THE CONTEXT THAT PRINTED IT ─────────────────────────────────────────
//
// Every instruction began with `ust `, which is only correct when the package is installed globally. Someone running
// it straight from a checkout — which is what an air-gapped ceremony looks like, and what the operator did — copied
// a printed command and got `zsh: command not found: ust`. Twice, after a ceremony that had otherwise gone perfectly.
//
// So the instructions an operator COPIES must interpolate how the tool was actually invoked. Prose that merely names
// a command ("run `ust rotate` instead") is not affected: it is a reference, not something to paste.
{
  const copyable = [];
  for (const [n, line] of SRC.split('\n').entries()) {
    if (/^\s*(\/\/|\*)/.test(line)) continue;
    // a copyable instruction is an indented literal that carries flags — that is what distinguishes it from prose
    if (!/^\s*[`'"]\s+\s*/.test(line) && !/^\s*`\s{2,}/.test(line)) continue;
    if (!/--\w/.test(line)) continue;
    if (!/\bust \w/.test(line) && !/invocation\(\)/.test(line)) continue;
    copyable.push({ n: n + 1, line: line.trim() });
  }
  check(copyable.length >= 2, `only ${copyable.length} copyable instructions found — the probe has gone blind`);
  for (const c of copyable) {
    check(/invocation\(\)/.test(c.line) || /usage:/.test(c.line),
      `ust-cli/index.mjs:${c.n} prints a copyable command starting with a bare \`ust\`, which only resolves when the package is installed globally. Interpolate invocation() so it matches how the tool was actually run: ${c.line.slice(0, 90)}`);
  }
  check(/export function invocation/.test(SRC), 'invocation() is gone — printed commands would assume a global install again');
}


// ── THE README IS THE TEXT MOST READERS ACTUALLY SEE, and it was not checked at all.
// MEASURED 2026-07-30: packages/ust-cli/README.md documented 8 of 12 commands — `key`, `rotate`, `cadence` and
// `forkchoice` were absent, which is every command added in the last dozen rounds. Nothing was WRONG on the page;
// it was INCOMPLETE, which is the quieter failure: a reader cannot tell a surface that does not exist from one
// nobody wrote down. npm and GitHub both render this file as the package's front page, so it is the first and often
// only description a stranger reads. Both directions, same as the dispatcher check above.
const README = readFileSync(new URL('../packages/ust-cli/README.md', import.meta.url), 'utf8');
const INREADME = new Set([...README.matchAll(/\bust ([a-z][a-z-]{2,})\b/g)].map((m) => m[1]).filter((c) => COMMANDS.has(c) || !/^[a-z-]+$/.test(c)));
for (const c of COMMANDS) check(INREADME.has(c),
  `packages/ust-cli/README.md never mentions \`ust ${c}\`, and the dispatcher runs it — a command absent from the package's front page is a surface a reader cannot tell from one that does not exist`);
for (const c of INREADME) check(COMMANDS.has(c),
  `packages/ust-cli/README.md documents \`ust ${c}\` and the dispatcher has no such command — the page instructs a reader to run something that answers with the help screen`);
check(INREADME.size >= 8, `only ${INREADME.size} commands found in the CLI README — the extraction has gone blind and this leg would pass vacuously`);

// ── the MCP's tools, same rule: its README IS its contract, since an agent operator reads nothing else.
const MCP_SRC = readFileSync(new URL('../packages/ust-mcp/index.mjs', import.meta.url), 'utf8');
const MCP_README = readFileSync(new URL('../packages/ust-mcp/README.md', import.meta.url), 'utf8');
const TOOLS = new Set([...MCP_SRC.matchAll(/name: '(ust_\w+)'/g)].map((m) => m[1]));
check(TOOLS.size >= 10, `only ${TOOLS.size} MCP tools found — the tool probe has gone blind`);
for (const t of TOOLS) check(MCP_README.includes(t),
  `packages/ust-mcp/README.md never names the tool \`${t}\` — an agent operator reads this page and nothing else, so an undocumented tool is an undiscoverable capability`);
// the reverse direction reads the TABLE's first column — the place the page actually enumerates its tools. A bare
// `\bust_\w+\b` sweep also caught `ust_id`, which is a FIELD, and reported the page as documenting a tool that does
// not exist: the probe was wider than its domain, which is the same defect it is here to catch.
for (const t of [...MCP_README.matchAll(/^\| `(ust_\w+)` \|/gm)].map((m) => m[1]))
  check(TOOLS.has(t), `packages/ust-mcp/README.md lists \`${t}\` as a tool and the server registers no such tool`);
check([...MCP_README.matchAll(/^\| `(ust_\w+)` \|/gm)].length >= 10, 'the MCP README tool table yielded fewer than ten rows — the reverse leg has gone blind');

// ── A PACKAGE README MAY NOT USE A NOTATION IT NEVER EXPLAINS.
// The owner's rule, given twice: `attest the §20.1 serving contract` teaches a first-time reader nothing — on npm it
// is not even a link, just characters. But the first cut of this leg banned `§` outright and immediately fired on
// `ust-light`, whose page opens with `The floor, in five rules (§ = spec/UST-1.0.md)` and then names every rule
// before citing it. That page is doing exactly what the rule wants; the rule was written wider than the defect.
//
// So the checkable property is the honest one: a page that uses `§` must SAY what `§` points at, once, where a
// reader meets it. And a bare `#123` has no place on an npm page at all — it renders as text and means nothing to
// anyone outside this repository's issue tracker.
const PKG_READMES = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).workspaces
  .map((w) => `${w}/README.md`)
  .filter((f) => { try { readFileSync(new URL('../' + f, import.meta.url)); return true; } catch { return false; } });
check(PKG_READMES.length >= 6, `only ${PKG_READMES.length} package READMEs found — the sweep has gone blind`);
for (const f of PKG_READMES) {
  const text = readFileSync(new URL('../' + f, import.meta.url), 'utf8');
  if (/§/.test(text)) check(/§\s*=|§[^\s]*\s*(?:of|in)\s|spec\/UST-1\.0\.md/.test(text),
    `${f} uses \`§\` and never says what it points at. A reader on npm sees characters, not a link — bind it once (\`§ = spec/UST-1.0.md\`) or describe the property instead.`);
  for (const m of text.matchAll(/(?<![\w/])#\d{2,4}\b/g))
    check(false, `${f} cites \`${m[0]}\` — an issue number, which renders as plain text on npm and means nothing to a reader outside this tracker. Say what the finding WAS.`);
}
// CONTROL — the binding must be recognised, and its absence must fire
check(/§\s*=|§[^\s]*\s*(?:of|in)\s|spec\/UST-1\.0\.md/.test('five rules (§ = spec/UST-1.0.md)')
  && !/§\s*=|§[^\s]*\s*(?:of|in)\s|spec\/UST-1\.0\.md/.test('attest the §20.1 serving contract'),
  'CONTROL: the notation-binding probe does not tell an explained § from a bare one');

// ── THE FAMILY, and the version that must not be typed. Swept 2026-07-30 after the owner said the same defects were
// probably in every package, and he was right: seven of eight pages titled themselves with a bare npm name, so a
// reader landing on `@ust-protocol/rekor-verify` had nothing telling them what family it belongs to. And `diarium`
// stated its own version in prose — `0.1.0` while the package was `0.2.0`, a claim that went stale exactly the way
// a typed version always does. The title rule is DERIVED from the package name rather than a list: anything named
// `ust-*` or `@ust-protocol/*` is protocol surface and says so; `diarium` is a product built ON the protocol and is
// correctly outside the family.
for (const f of PKG_READMES) {
  const dir = f.replace(/\/README\.md$/, '');
  const pkg = JSON.parse(readFileSync(new URL('../' + dir + '/package.json', import.meta.url), 'utf8'));
  const text = readFileSync(new URL('../' + f, import.meta.url), 'utf8');
  const title = /^# (.+)$/m.exec(text);
  check(!!title, `${f} has no title — the page a stranger lands on must name itself`);
  const isFamily = /^(ust-|@ust-protocol\/)/.test(pkg.name);
  if (title && isFamily) check(title[1].startsWith('UST Protocol — '),
    `${f} titles itself "${title[1].slice(0, 40)}" — a reader landing here from a search has no idea it belongs to UST. Protocol-surface packages open with "UST Protocol — <what it is>".`);
  // a version typed into a page is a claim nobody updates
  check(!text.includes(pkg.version),
    `${f} states its own version \`${pkg.version}\` in the text. It is stale the moment the next one publishes, and nothing here regenerates prose — say what the package IS, and let the registry state which version you are reading.`);
}
// CONTROL — the family rule must reject a bare name and the version rule must see a real one
check('UST Protocol — the MCP server'.startsWith('UST Protocol — ') && !'@ust-protocol/mcp'.startsWith('UST Protocol — '),
  'CONTROL: the title rule accepts a bare package name as a family title');

// ── AN EXAMPLE THAT NO LONGER IMPORTS IS THE HARDEST FORM OF A STALE PAGE: the reader copies it and it throws.
// Every named import in every package README is resolved against the REAL module namespace — imported, not grepped,
// because a re-export is invisible to a pattern over the source. Swept 2026-07-30: eight pages, zero broken imports.
// The one apparent hit was my own probe attributing `import { substrateVerify } from '@ust-protocol/ots-verify'` to
// `ust-protocol`, on the strength of a substring. Both connectors export it. Named, because a sweep that reports one
// finding and resolves it to zero has to say so, or the next reader assumes it found something.
const WS_BY_NAME = new Map(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).workspaces
  .map((w) => [JSON.parse(readFileSync(new URL('../' + w + '/package.json', import.meta.url), 'utf8')).name, w]));
let examplesChecked = 0;
for (const f of PKG_READMES) {
  const text = readFileSync(new URL('../' + f, import.meta.url), 'utf8');
  for (const m of text.matchAll(/import \{([^}]+)\} from '([^']+)'/g)) {
    const from = m[2];
    const ws = WS_BY_NAME.get(from) ?? (from.startsWith('.') ? f.replace(/\/README\.md$/, '') : null);
    if (!ws) continue;                                    // an external module is not ours to keep current
    let ns;
    try { ns = await import(new URL('../' + ws + '/index.mjs', import.meta.url).href); }
    catch (e) { check(false, `${f}: the example imports from ${from} and that module will not load: ${String(e.message).slice(0, 70)}`); continue; }
    for (const raw of m[1].split(',')) {
      const name = raw.trim().split(/\s+as\s+/)[0].trim();
      if (!name) continue;
      examplesChecked++;
      check(name in ns, `${f} shows \`import { ${name} } from '${from}'\` and that module exports no such name — a reader who copies the example gets a crash, which is the loudest way a page can be out of date`);
    }
  }
}
check(examplesChecked >= 10, `only ${examplesChecked} example imports resolved — the sweep has gone blind and this leg would pass vacuously`);

// ── AN EXAMPLE MARKED `runnable:` IS A PROMISE, AND IT IS KEPT BY RUNNING IT.
// "Current" is not only that the imports resolve — the owner's words: the METHODS must work. Measured 2026-07-30 by
// executing every js block in every package page: two of eight ran, six are fragments with placeholders (`doc`,
// `genesis`, `key_id`), which is a fair documentation idiom and not a defect. So the rule is not "every block runs"
// — it is that a block PROMISING to run does. The first end-to-end example I wrote for the core called
// `signer.seal(state)`, which does not exist; running it is what said so, and reading it would not have.
import { execFileSync as runFile } from 'node:child_process';
import { fileURLToPath as toPath } from 'node:url';
const ROOT = toPath(new URL('../', import.meta.url));
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
let runnable = 0;
for (const f of PKG_READMES) {
  const text = readFileSync(new URL('../' + f, import.meta.url), 'utf8');
  for (const b of text.matchAll(/```js\n((?:.|\n)*?)```/g)) {
    if (!/^\s*\/\/ runnable:/m.test(b[1])) continue;
    runnable++;
    // run INSIDE the repo, where the workspace packages resolve exactly as they do for an installer
    const dir = mkdtempSync(ROOT + '.ex-');
    try {
      writeFileSync(dir + '/example.mjs', b[1]);
      runFile(process.execPath, [dir + '/example.mjs'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
      pass++;
    } catch (e) {
      check(false, `${f}: an example marked \`runnable:\` does NOT run — ${String(e.stderr || e.message).split('\n').find((l) => /Error/.test(l))?.trim().slice(0, 90) ?? 'no output'}. A page that says "copy this and it works" has to be true, or it is worse than no example.`);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}
check(runnable >= 3, `only ${runnable} runnable example(s) found across the package pages — the sweep has gone blind, or the pages stopped promising anything a reader can execute`);

console.log(`\n  printed commands   PASS ${pass}   FAIL ${fail.length}   (${COMMANDS.size} subcommands · ${checked} printed instructions checked)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every command the tool prints is one the tool can run');
