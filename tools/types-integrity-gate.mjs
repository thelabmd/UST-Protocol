// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:yes — the TypeScript compiler decides, and the export set comes from the imported module
// TYPES-INTEGRITY GATE — a declaration file we ship must COMPILE, and must declare exactly what the module exports.
//
// MEASURED 2026-07-30, from a consumer's tree rather than from here: `ust-protocol/index.d.ts` carried two TS1016
// errors — a required parameter after an optional one, which JavaScript permits and TypeScript does not. Our core
// writes `buildAbsence(id, time, name, reason, extra = {}, prev)`, legal JS, and the generator transcribed it
// literally into an illegal declaration.
//
// The consequence is why this gate exists rather than a lint rule. A parse error TRUNCATES a declaration file:
// everything after it is invisible. `resolveKeys` sits three lines past the second error and read as "does not
// exist" to a consumer who had done nothing wrong. `skipLibCheck` does not save anyone — it skips CHECKING, not
// PARSING. So the failure is silent on both sides: we saw green, they saw a function that was not there.
//
// And nine exports had no declaration at all, because the generator matched SYNTAX FORMS (`export function`,
// `export const`) and the module also uses `export { … } from` and `export class`. That is the same defect this
// repository has closed under other names all week: a probe that samples where it must enumerate. So the export
// set here is read from the IMPORTED MODULE — the artifact decides, never a pattern over its text.
//
// Both legs run for every workspace package that ships types, and the roster is derived from the root manifest.
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const fail = [];
let vocabularies = 0;
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const TSC = ROOT + 'node_modules/.bin/tsc';
check(existsSync(TSC), 'typescript is not installed — this gate cannot compile anything and would pass vacuously. It is a devDependency for exactly this reason: a claim that we ship types is worth what a compiler says about them.');

const compile = (file) => {
  try { execFileSync(TSC, ['--noEmit', file], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return []; }
  catch (e) { return String(e.stdout || e.message).split('\n').filter((l) => /error TS/.test(l)); }
};

const WORKSPACES = JSON.parse(readFileSync(ROOT + 'package.json', 'utf8')).workspaces;
let checked = 0;
for (const w of WORKSPACES) {
  const pkg = JSON.parse(readFileSync(ROOT + w + '/package.json', 'utf8'));
  const main = pkg.main ?? 'index.mjs';
  const dts = w + '/' + main.replace(/\.m?js$/, '.d.ts');
  if (!existsSync(ROOT + dts)) continue;              // a package that ships no types makes no claim to check
  checked++;

  // ── leg 1: it must COMPILE. Not "look right" — compile.
  const errs = compile(ROOT + dts);
  check(errs.length === 0,
    `${dts} does NOT compile (${errs.length} error(s)): ${errs[0]?.replace(ROOT, '').slice(0, 110)} — a declaration file with a parse error TRUNCATES: everything below the error is invisible to every consumer, and nothing warns them`);

  // ── leg 2: it must declare exactly the module's exports, BOTH directions
  const declared = new Set([...readFileSync(ROOT + dts, 'utf8')
    .matchAll(/^export (?:declare )?(?:function|const|class) (\w+)/gm)].map((m) => m[1]));
  let ns;
  try { ns = await import(new URL('../' + w + '/' + main, import.meta.url).href); }
  catch (e) { check(false, `${w}/${main} will not import, so its declarations cannot be checked against anything: ${String(e.message).slice(0, 80)}`); continue; }
  const exported = Object.keys(ns);
  for (const name of exported) check(declared.has(name),
    `${pkg.name} exports \`${name}\` at runtime and declares no type for it — a typed consumer who deleted their hand-written declarations cannot reach it, and nothing tells them why`);
  for (const name of declared) check(exported.includes(name),
    `${dts} declares \`${name}\` and the module exports no such name — a promise about a door that is not there`);
  check(exported.length > 0, `${pkg.name} exports nothing at runtime — the namespace probe has gone blind and both directions above would pass for free`);

  // ── leg 3: a DECLARED VOCABULARY must equal the value it describes. A const whose keys and string values
  // are written into the declaration is the most useful kind for a consumer and the most dangerous kind to
  // let drift: renaming a member in the source leaves the old name compiling against a value that no longer
  // has it. Compare the declaration against the RUNTIME object, not against the source that produced both.
  for (const m of readFileSync(ROOT + dts, 'utf8').matchAll(/^export const (\w+): Readonly<\{([^}]*)\}>/gm)) {
    // A vocabulary member is a STRING or a LIST of strings — `ROLE_CLASSES` maps a role to the classes it
    // admits. Reading only the string form scored that declaration as `{}` and failed a correct file: the
    // checker has to know every shape the generator can emit, or the pair drifts in the direction where the
    // GATE is wrong, which is the worse one because it trains you to edit the code until the gate is happy.
    const declaredPairs = Object.fromEntries([
      ...[...m[2].matchAll(/([A-Za-z_$][\w$]*): '([^']*)'/g)].map((x) => [x[1], x[2]]),
      ...[...m[2].matchAll(/([A-Za-z_$][\w$]*): readonly \[([^\]]*)\]/g)]
        .map((x) => [x[1], x[2].split(',').map((t) => t.trim().replace(/^'|'$/g, '')).filter(Boolean)]),
    ]);
    check(JSON.stringify(declaredPairs) === JSON.stringify(ns[m[1]]),
      `${pkg.name} declares \`${m[1]}\` as ${JSON.stringify(declaredPairs)} and the value is ${JSON.stringify(ns[m[1]])} — a vocabulary that disagrees with itself is worse than an undeclared one, because a consumer compiles against the wrong word`);
    vocabularies++;
  }
}
check(checked >= 5, `only ${checked} package(s) ship declarations — the roster has gone blind`);
check(vocabularies >= 3, `only ${vocabularies} declared vocabular(y/ies) were compared against their values — the leg has gone blind and would pass for free`);

// ── the compile leg must be able to FAIL, proven against the exact shape that shipped: JS allows a defaulted
// parameter before a required one, TypeScript does not, and that is what truncated the file.
{
  const probe = ROOT + '.types-gate-control.d.ts';
  try {
    execFileSync(process.execPath, ['-e', `require('fs').writeFileSync(${JSON.stringify(probe)}, 'export function f(a: unknown, b?: unknown, c: unknown): unknown;\\n')`], { stdio: 'ignore' });
    const e = compile(probe);
    check(e.length > 0 && /TS1016/.test(e.join(' ')),
      'CONTROL: a required parameter after an optional one compiled clean — the compile leg is not running, and every file above passed for free');
  } finally { try { execFileSync(process.execPath, ['-e', `require('fs').rmSync(${JSON.stringify(probe)}, {force:true})`], { stdio: 'ignore' }); } catch { /* nothing to remove */ } }
}

console.log(`\n  types integrity   PASS ${pass}   FAIL ${fail.length}   (${checked} packages ship declarations · compiled by tsc · export set read from the imported module)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every shipped declaration file compiles and declares exactly what its module exports');
