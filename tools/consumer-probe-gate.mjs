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
// `--pretty false` is LOAD-BEARING, not cosmetic. MEASURED 2026-08-05: tsc coloured its diagnostics, so the
// bytes between `error` and `TS2322` were escape sequences and the /error TS/ filter below matched NOTHING —
// every compile returned an empty error list, which this gate reads as "compiled clean". The whole probe passed
// for free, and only the CONTROL leg noticed. A filter over rendered TEXT is a dependency on a renderer nobody
// pinned; the exit code is the fact, and the text is a description of it.
// CLOSED 2026-08-05, in this same edit: `--pretty false` removes the rendering and the catch clause returns a
// synthetic diagnostic on a non-zero exit matching no pattern, so a renderer cannot empty this gate again.
// Proven by mutation — declare `verify` as `any` and the CONTROL leg reddens.
const ARGS = ['--noEmit', '--strict', '--pretty', 'false', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'es2022'];

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const compile = (file) => {
  try { execFileSync(TSC, [...ARGS, file], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return []; }
  catch (e) {
    // The EXIT CODE decided that this failed; the lines are only how we report it. A non-zero exit whose output
    // matches no pattern must still count as a failure, or a renderer change silently empties this gate again.
    const lines = String(e.stdout || e.message).split('\n').filter((l) => /error TS/.test(l));
    return lines.length ? lines : ['error TS????: tsc exited non-zero and no diagnostic line was recognised — ' + String(e.stdout || e.message).slice(0, 200)];
  }
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

// ── leg 4: the DECLARED shapes must still be the runtime's. A named interface is the one thing in this file
// that is hand-written rather than derived, so it is the one thing that can go stale — the exact defect #105
// named ("a precise stale declaration is worse than a loose complete one"). So the values are REBUILT here and
// every declared key must be present on the real thing. A key that disappears fails; a key that is declared
// optional may be absent, which is what `id?` on the verdict is for.
{
  const P = await import('ust-protocol');
  const c = await import('node:crypto');
  const seed = Buffer.from('bb'.repeat(32), 'hex').subarray(0, 32);
  const priv = c.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = c.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  const state = P.buildGenesis({ domain_shard: 'e.com', ust_id: 'ust:20260628.10', key_id: P.keyId(pub) }, '2026-06-28T10:00:00Z', pub);
  const doc = P.seal(state, priv, pub);
  const verdict = P.verify(doc);

  const DTS = readFileSync(ROOT + 'packages/ust-protocol/index.d.ts', 'utf8');
  const keysOf = (iface) => {
    const m = new RegExp(`export interface ${iface} \\{([^}]*)\\}`).exec(DTS);
    if (!m) return null;
    return m[1].split(';').map((f) => f.trim()).filter(Boolean)
      .map((f) => ({ name: f.split(/[?:]/)[0].trim(), optional: /^[^:?]+\?/.test(f) }));
  };
  // BOTH BRANCHES of each union get a real value: the resolved branch from a corpus key-log vector that actually
  // resolves, the error branch from a rejected one. A union declared and checked on one branch only is half a
  // promise — and the branch nobody checks is the one that rots.
  const V = JSON.parse(readFileSync(ROOT + 'vectors/conformance-vectors.json', 'utf8')).vectors;
  const okKeylog = V.find((v) => v.kind === 'keylog-state' && v.expect && v.expect.active_count !== undefined);
  const withFrames = V.find((v) => v.frames);
  check(!!okKeylog && !!withFrames, 'the corpus has no resolving key-log vector or no framed stream vector — the union legs below would have nothing real to check against');
  const keysOk = okKeylog ? P.resolveKeys(okKeylog.genesis, okKeylog.keylog) : {};
  const keysErr = okKeylog ? P.resolveKeys(okKeylog.genesis, 'not-a-log') : {};
  const streamOk = withFrames ? P.verifyStream(withFrames.frames) : {};

  for (const [iface, value, what] of [['UstState', state, 'a builder'], ['UstDocument', doc, 'seal'], ['UstVerdict', verdict, 'verify'],
                                      ['UstKeysResolved', keysOk, 'resolveKeys on a resolving log'], ['UstError', keysErr, 'resolveKeys on a rejected log'],
                                      ['UstStreamComplete', streamOk, 'verifyStream on real frames']]) {
    const fields = keysOf(iface);
    check(fields !== null && fields.length > 0, `the declaration file has no \`${iface}\` interface to check — the shape leg has no domain and would pass vacuously`);
    for (const f of fields ?? []) check(f.optional || Object.hasOwn(value, f.name),
      `\`${iface}\` declares \`${f.name}\` and what ${what} actually returns has no such key (${Object.keys(value).join(', ')}) — a precise STALE declaration is worse than a loose complete one, which is the defect these interfaces exist inside a gate to avoid`);
  }
  // and the other direction: a key the runtime ALWAYS has and the declaration withholds is a promise not made
  // THE REVERSE DIRECTION MUST COVER EVERY DECLARED INTERFACE, NOT A LIST I REMEMBERED. `UstVerdict` was absent
  // from this list, and a real consumer's build caught what the gate did not: the core emits `publisher` or
  // `publisher_claimed` depending on whether the name resolved, and the declaration mentioned neither. A gate
  // whose domain is hand-picked checks the instances it thought of — the exact defect this repository keeps
  // finding under other names. So the interfaces are ENUMERATED from the declaration file, and one without a
  // sample FAILS rather than being quietly skipped.
  const SAMPLES = { UstState: state, UstDocument: doc, UstVerdict: verdict, UstKeysResolved: keysOk, UstError: keysErr, UstStreamComplete: streamOk };
  const declaredIfaces = [...DTS.matchAll(/export interface (\w+) \{/g)].map((m) => m[1]);
  check(declaredIfaces.length >= 5, `only ${declaredIfaces.length} interface(s) found in the declaration file — the enumeration has gone blind`);
  for (const name of declaredIfaces) check(Object.hasOwn(SAMPLES, name),
    `\`${name}\` is declared and this gate has no real value to check it against — add one. An interface nobody samples is a promise nobody verifies, which is how \`UstVerdict\` went two fields stale until a consumer's build failed.`);
  for (const [iface, value] of declaredIfaces.filter((n) => SAMPLES[n]).map((n) => [n, SAMPLES[n]])) {
    const declared = new Set((keysOf(iface) ?? []).map((f) => f.name));
    for (const k of Object.keys(value)) check(declared.has(k),
      `${iface}: the runtime always returns \`${k}\` and the declaration does not mention it — a consumer cannot reach a value we do in fact promise`);
  }
}

// ── leg 5: THE INEXPRESSIBLE RESIDUAL MUST STAY EMPTY, or be named. TypeScript can only make a SUFFIX
// optional, so a parameter the runtime guards that sits BEFORE an unguarded one cannot be declared optional at
// all — the declaration is then sound and incomplete, and a consumer padding it with `undefined` is doing the
// right thing without being told so. MEASURED today: zero such parameters. That is worth asserting rather than
// assuming, because the day one appears it must be NAMED, not silently accepted as "just how it is".
{
  const SRC_MJS = readFileSync(ROOT + 'packages/ust-protocol/index.mjs', 'utf8');
  const DTS2 = readFileSync(ROOT + 'packages/ust-protocol/index.d.ts', 'utf8');
  const residual = [];
  for (const m of DTS2.matchAll(/^export function (\w+)\(([^)]*)\)/gm)) {
    const declared = m[2].split(',').map((x) => x.trim());
    const sig = new RegExp(`export (?:const|function|async function) ${m[1]}\\s*=?\\s*\\(([^)]*)\\)`).exec(SRC_MJS);
    if (!sig) continue;
    const real = sig[1].split(',').map((x) => x.trim());
    declared.forEach((d, i) => { if (!/\?:/.test(d) && /=/.test(real[i] ?? '')) residual.push(`${m[1]}(${d.split(':')[0]})`); });
  }
  check(residual.length === 0,
    `${residual.length} parameter(s) carry a DEFAULT in the source and are declared REQUIRED: ${residual.slice(0, 5).join(', ')}. ` +
    `That is the inexpressible residual — TypeScript makes only a SUFFIX optional — and it must be NAMED in the ` +
    `declaration so a consumer knows padding with \`undefined\` is legitimate, not a workaround.`);
}

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
