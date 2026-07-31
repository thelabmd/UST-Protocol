// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:yes literal-ok:the escape-hatch list is the SYNTAX BANNED, not the domain measured — the domain is the probe file and the compiler decides it — the TypeScript compiler decides, and a control probe must fail for the right reason
// CONSUMER-PROBE GATE (#117) — a typed consumer must be able to USE this package with the declarations we ship.
//
// Every other types gate here asks a question about the declarations in isolation: do they parse (#116), do they
// name exactly the runtime exports (#116). Both can hold while the package is still unusable — a declaration that
// demands nine arguments for a call the runtime accepts is well-formed, complete, and makes a consumer write a
// wrapper. MEASURED on a consumer moving onto rc.45: 18 errors, all `TS18046`, in six shapes.
//
// So this gate asks the consumer's question instead: compile a file that IMPORTS the package and does the four
// things every consumer does — build, canonicalise, verify, read the verdict — under `--strict`, with no casts
// and no shadowing. `as`, `any` and `declare module` are refused, because each of them is the wrapper this gate
// exists to make unnecessary: a probe allowed to cast would pass against declarations nobody can use.
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PROBE = 'tools/consumer-probe.ts';
const TSC = ROOT + 'node_modules/.bin/tsc';
const ARGS = ['--noEmit', '--strict', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'es2022'];

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const compile = (file) => {
  try { execFileSync(TSC, [...ARGS, file], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return []; }
  catch (e) { return String(e.stdout || e.message).split('\n').filter((l) => /error TS/.test(l)); }
};

// ── leg 1: the probe compiles. This is the whole promise, and `tsc` is the only thing that can judge it.
const errs = compile(ROOT + PROBE);
check(errs.length === 0,
  `${PROBE} does NOT type-check against the declarations we ship (${errs.length} error(s)): ${errs[0]?.replace(ROOT, '').slice(0, 130)} — a consumer who deletes their hand-written types is left with exactly this, so the error is theirs before it is ours`);

// ── leg 2: no escape hatches, counted in CODE. Comments discuss `as` and `declare module` by name — the first
// version of this check read those and reported four casts in a file with none, which is the gate being wrong
// about its own domain. Comments are blanked, not stripped, so nothing else shifts.
// Import statements are blanked for the same reason: `import * as P` is a namespace binding, not a cast, and the
// first run of this leg reported it as one. Third detector today whose first output was its own noise — so the
// rule is to locate the hit and read it before believing it, not to trust a count.
const RAW = readFileSync(ROOT + PROBE, 'utf8');
const SRC = RAW
  .replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (m) => ' '.repeat(m.length))
  .replace(/^import[^\n]*$/gm, (m) => ' '.repeat(m.length));
for (const [rx, what] of [
  [/\bas\s+[A-Za-z{[]/, '`as` cast'],
  [/:\s*any\b|<any>/, '`any`'],
  [/\bdeclare\s+module\b/, '`declare module` shadowing'],
  [/@ts-(ignore|expect-error|nocheck)/, 'a `@ts-` suppression'],
]) check(!rx.test(SRC), `${PROBE} uses ${what} — that is the wrapper this gate exists to make unnecessary, and a probe allowed to use it passes against declarations no consumer can use`);

// ── leg 3: the probe must actually TOUCH the surface. A probe that imports and does nothing compiles forever.
// the import leg reads the RAW file — SRC has imports blanked, so checking for the import inside SRC asks a
// question the blanking already answered. Two legs, two domains: escape hatches in code, the import in the file.
check(/from 'ust-protocol'/.test(RAW), `${PROBE} does not import the package under test`);
const touched = [...SRC.matchAll(/\bP\.(\w+)\s*\(/g)].map((m) => m[1]);
check(new Set(touched).size >= 5, `${PROBE} calls only ${new Set(touched).size} export(s) — too thin to speak for a consumer; build, canonicalise, address, verify and judge are the minimum`);

// ── the compile leg must be able to FAIL, and for the RIGHT reason: a consumer-shaped mistake, not a syntax error.
{
  const ctl = ROOT + '.probe-gate-control.ts';
  try {
    writeFileSync(ctl, "import * as P from 'ust-protocol';\nexport const x: string = P.verify({});\n");
    const e = compile(ctl);
    check(e.length > 0 && /TS2322/.test(e.join(' ')),
      `CONTROL: assigning a verdict to a \`string\` compiled clean (${e.join(' ').slice(0, 80) || 'no errors'}) — the compile leg is not running, and the probe above passed for free`);
  } finally { rmSync(ctl, { force: true }); }
}

console.log(`\n  consumer probe   PASS ${pass}   FAIL ${fail.length}   (${new Set(touched).size} exports touched · tsc --strict · no casts, no shadowing)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ a typed consumer can build, verify and judge with the declarations we ship — no wrapper, no cast');
