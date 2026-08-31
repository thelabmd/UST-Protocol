// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the two rosters CLASSIFY a domain that is read, they do not stand in for it — `PURE_KINDS` names which corpus kinds a build with no Ed25519/AES can run, and the counts beside it are measured; the domain itself is `vectors/conformance-vectors.json`, whose kind total and not-run complement are both pinned above, so a kind added to the corpus reddens this gate instead of slipping past a hand-written list
//   — the graph is WALKED from source, the mapped core is EXECUTED with the Node globals deleted, and both builds run the CORPUS (round 200; until then this gate carried five values of its own and compared the builds only to each other)
// #143 — "the core is browser-portable" is a claim about RUNNING, and this runs it.
//
// WHY NOT A BUNDLER. Bundling answers "do the imports resolve". Measured 2026-08-08: with the crypto faculty
// substituted, the core bundled GREEN to 261 KB while carrying 51 references to `Buffer` — a Node GLOBAL, not
// an import, which no bundler reports and which throws on the first call in a page. A green bundle would have
// been read as portability and shipped a runtime failure to the consumer's browser.
//
// CLOSED 2026-08-08 by round 184 — this gate IS that measurement, made repeatable and wired into CI as a step.
//
// So this gate does the two things a bundler cannot:
//
//   1. RESOLVES the module graph under the package's `browser` map and refuses any surviving `node:` import.
//   2. RUNS the mapped core in a child process with the Node globals DELETED — `Buffer`, `process`, `require`,
//      `__dirname` — and exercises the API. A dependency on any of them surfaces as a throw, not as silence.
//
// And the payoff check: the browser build must produce the SAME hashes as the Node build. A portable core that
// disagrees with itself across platforms is worse than one that does not build — the documents would verify in
// one place and not the other, which is the cross-language split the whole canon discipline exists to prevent.

import { readFileSync, writeFileSync, mkdtempSync, cpSync, readdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Path written whole, not assembled from segments: the assurance map reads a tool's own source to decide
// whether its grade-2 claim ("derived from the enforcing code") is earned, and a path in pieces hides the
// evidence that this gate walks `packages/ust-protocol/` rather than trusting a list.
const PKG_DIR = join(ROOT, 'packages/ust-protocol');
const pkg = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8'));
const BROWSER_MAP = pkg.browser ?? {};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '✓' : '✗'} ${name}${ok || !detail ? '' : ' — ' + detail}`);
  if (!ok) failures++;
};

// ─── 1. the graph, under the browser map ────────────────────────────────────────────────────────────────
// `import … from`, bare `import '…'`, RE-EXPORTS (`export … from '…'`) and dynamic `import('…')`.
// The re-export form is here because leaving it out is how this gate first passed while the runtime failed:
// the graph looked like four modules and the process pulled in a fifth. A graph walk that misses an edge
// reports a clean graph, which is the most confident way to be wrong.
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\s[\s\S]*?from\s+'([^']+)'|(?:^|\n)\s*import\s+'([^']+)'|\bimport\(\s*'([^']+)'/g;
const seen = new Set();
const nodeImports = [];
const graph = [];

(function walk(rel) {
  const mapped = BROWSER_MAP['./' + rel] ? BROWSER_MAP['./' + rel].replace(/^\.\//, '') : rel;
  if (seen.has(mapped)) return;
  seen.add(mapped);
  graph.push(mapped);
  const src = readFileSync(join(PKG_DIR, mapped), 'utf8');
  for (const m of src.matchAll(IMPORT_RE)) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (!spec) continue;
    if (spec.startsWith('node:')) { nodeImports.push(`${mapped} → ${spec}`); continue; }
    if (spec.startsWith('.')) walk(spec.replace(/^\.\//, ''));
    else nodeImports.push(`${mapped} → ${spec} (bare specifier)`);
  }
})('index.mjs');

check(`the browser graph resolves without a Node import (${graph.length} modules: ${graph.join(', ')})`,
  nodeImports.length === 0, nodeImports.join('; '));

// ─── 2. run it with the Node globals removed ────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'ust-browser-'));
for (const f of graph) cpSync(join(PKG_DIR, f), join(dir, f));
// The bundler substitution, performed by hand: the browser file takes the mapped name.
for (const [from, to] of Object.entries(BROWSER_MAP)) {
  cpSync(join(PKG_DIR, to.replace(/^\.\//, '')), join(dir, from.replace(/^\.\//, '')));
}

// ─── the input corpus is THE CORPUS (round 200) ─────────────────────────────────────────────────────────
//
// Until round 200 this gate carried five values of its own — `{canonInput, hashInput, keyPub}` plus two inline
// literals — and compared the two builds against EACH OTHER. That answers "do the builds agree", which is a real
// question and the one this gate is named for, but it is not the question anyone reading a green line assumes:
// two builds sharing a wrong `canon` agree perfectly. Round 184's registry entry went further and claimed *"the
// existing corpus passing unchanged IS the evidence"* — measured 2026-08-10 and false: the browser build touched
// exactly two vectors of 232 (`faculty-absent-ed25519`, `malleability-reject`, in `browser-build.test.mjs`).
//
// So the inputs come from the corpus, both builds are compared against its DECLARED expectations, and the
// build-to-build comparison stays on top of that. The domain is ENUMERATED and its size asserted below — a
// corpus-driven check that silently selects nothing is the failure mode this repository meets most often.
// CLOSED 2026-08-10 (round 200): the inputs are the corpus, both builds are judged against its declared
// expectations, and the private five-value roster is gone.
//
// WHICH KINDS, and why not all of them: the browser build has no Ed25519 and no AES (#144 — it REFUSES rather
// than answering), so only kinds decidable by pure primitives can run here. Those are the five below plus the
// simple half of `canon-reject`. The three `canon-reject` entries whose runner needs `verify`/`verifyJson`
// (`ts-fractional`, `ts-offset`, `dupkey`) are named, counted and skipped — not silently dropped.
const CORPUS = JSON.parse(readFileSync(join(ROOT, 'vectors/conformance-vectors.json'), 'utf8')).vectors;
const PURE_KINDS = ['canon', 'hash', 'key_id', 'b64url', 'content-hash'];
const CR_NEEDS_VERIFY = (id) => /ts-|dupkey/.test(id);
const CASES = CORPUS.filter((v) => PURE_KINDS.includes(v.kind)
  || (v.kind === 'canon-reject' && !CR_NEEDS_VERIFY(v.id)));
const SKIPPED = CORPUS.filter((v) => v.kind === 'canon-reject' && CR_NEEDS_VERIFY(v.id)).map((v) => v.id);

// The count is asserted, per kind, so a kind that disappears from the corpus (or never matched) reddens here
// instead of shrinking the domain quietly. These are MEASURED 2026-08-10, not chosen; a pin is a tripwire, so it is
// STANDING by design and moves only when someone deliberately changes the domain.
const EXPECTED_CASES = { canon: 11, 'canon-reject': 4, hash: 5, key_id: 1, b64url: 6, 'content-hash': 1 };
// …and the COMPLEMENT is pinned too, which is what keeps `PURE_KINDS` from being this gate's real domain. A kind
// added to the corpus lands in the not-run set and reddens the count below, so the author must decide whether it
// belongs here — instead of it passing unnoticed because a hand-written list did not mention it.
const EXPECTED_KINDS_TOTAL = 52, EXPECTED_KINDS_NOT_RUN = 46;   // 51/45 → 52/46 on 2026-08-31: `privacy-encrypted` (#175) needs a document AND a key, so it joins the not-run complement rather than PURE_KINDS. measured 2026-08-14 — rounds 216-220 add `map-currency`, `refusal-shape`, `stream-floor` and `map-root-anchor`, all classified NOT-RUN: its input is a signed document plus a consumer trust configuration, so it needs the Ed25519 faculty the browser build refuses by name (46/40 on 2026-08-13, 45/39 earlier that day, 44/38 on 2026-08-10)
// 45 → 46: `anchor-refusal` (#155). NOT runnable by pure primitives, and for a reason worth stating: its input is
// an ANCHOR rather than a document, and deciding it needs the witness path — a fetch, a connector, and the RFC 6962
// climb. It is the first kind whose declared result is a REFUSAL REASON rather than a verdict.
// 45 → 46 NOT-RUN, 50 → 51 TOTAL: `anchor-construction-absent` (round 235 / #172). Classified NOT runnable by pure
// primitives — its vectors carry a whole signed document AND compare TWO verify() runs of it (with the proof and
// without), so deciding one needs the verifier, not `canon`/`keyId`. The kind exists because the defect lived in the
// RELATION between those two runs: a verdict that must be EQUAL across them and a coordinate that must not be.
// 44 → 45: `partition-kind` (#154). Classified as NOT runnable by pure primitives — its vectors carry whole
// signed documents, so deciding one needs the verifier, not `canon`/`keyId`. The kind exists because the
// partition-kind DOMAIN had to enter the corpus: two implementations compared over vectors that never carried
// `absence` agreed on every vector while disagreeing in production.
{
  const kinds = new Set(CORPUS.map((v) => v.kind));
  const notRun = [...kinds].filter((k) => !PURE_KINDS.includes(k) && k !== 'canon-reject').sort();
  check(`the corpus domain is accounted: ${kinds.size} kinds, ${PURE_KINDS.length + 1} runnable by pure primitives, ${notRun.length} needing a faculty or a document`,
    kinds.size === EXPECTED_KINDS_TOTAL && notRun.length === EXPECTED_KINDS_NOT_RUN,
    `kinds ${kinds.size} (pin ${EXPECTED_KINDS_TOTAL}), not-run ${notRun.length} (pin ${EXPECTED_KINDS_NOT_RUN}) — a new kind must be classified here, not ignored`);
}
{
  const got = {};
  for (const v of CASES) got[v.kind] = (got[v.kind] ?? 0) + 1;
  const diff = Object.entries(EXPECTED_CASES).filter(([k, n]) => got[k] !== n).map(([k, n]) => `${k}: expected ${n}, found ${got[k] ?? 0}`);
  check(`the corpus supplies ${CASES.length} cases both builds must reproduce (${Object.entries(EXPECTED_CASES).map(([k, n]) => k + ' ' + n).join(', ')}; ${SKIPPED.length} canon-reject need verify and are skipped: ${SKIPPED.join(', ')})`,
    diff.length === 0, diff.join('; '));
}
// ONE executor, used by BOTH builds. Written once as source text and evaluated on each side rather than typed
// twice: two copies of the runner would make this gate compare two executors as much as two builds, which is the
// defect it was just fixed for. The text is deliberately dependency-free — no Buffer, no Node builtins — so it
// survives the global deletion below.
const EXEC_SRC = `
  const out = [];
  for (const v of cases) {
    let got;
    try {
      switch (v.kind) {
        case 'canon': got = P.canon(v.input); break;
        case 'canon-reject': {
          // the corpus expresses one entry by DESCRIPTION rather than by an input literal: a non-NFC string
          // cannot survive a JSON round trip as itself, so the runner rebuilds it, exactly as conformance.mjs does.
          const input = v.input !== undefined ? v.input : { note: 'e' + String.fromCharCode(0x301) };
          let threw = false;
          try { P.canon(input); } catch (e) { threw = e && e.code === 'E-CANON'; }
          got = threw ? 'E-CANON' : 'NO-THROW';
          break;
        }
        case 'hash': got = P.H(v.tag, P.canon(v.input)); break;
        case 'key_id': got = P.keyId(v.pub_b64url); break;
        case 'b64url': got = String(P.strictB64url(v.value, v.bytes) !== null); break;
        case 'content-hash': got = P.contentHash(v.doc); break;
        default: got = 'UNRUN:' + v.kind;
      }
    } catch (e) { got = 'THREW:' + ((e && e.message) ? String(e.message).slice(0, 60) : String(e)); }
    out.push([v.id, String(got)]);
  }
  return out;
`;
// What the CORPUS says each case must produce — also one function, for the same reason.
const expectationOf = (v) => {
  switch (v.kind) {
    case 'canon': return v.expect_canon;
    case 'canon-reject': return 'E-CANON';
    case 'b64url': return String(v.expect);
    default: return v.expect;                     // hash · key_id · content-hash
  }
};

const runner = `
// Delete the Node globals BEFORE the core is loaded. The import is dynamic for exactly that reason: a static
// import is hoisted above the deletions and would be evaluated while they still exist.
for (const g of ['Buffer', 'process', 'require', '__dirname', '__filename', 'global']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const P = await import('${join(dir, 'index.mjs')}');
const cases = ${JSON.stringify(CASES)};
const exec = (P, cases) => { ${EXEC_SRC} };
const out = {
  build: (await import('${join(dir, '_crypto.mjs')}')).CRYPTO_BUILD,
  results: exec(P, cases),
};
console.log(JSON.stringify(out));
`;

let browserOut;
try {
  browserOut = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', runner],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
  check('the core RUNS with Buffer/process/require deleted', true);
} catch (e) {
  check('the core RUNS with Buffer/process/require deleted', false,
    String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 160) ?? 'no output');
}

check('the browser build is the one that ran', browserOut?.build === 'browser', `got ${browserOut?.build}`);

// ─── 3. BOTH builds must match the CORPUS, and each other ───────────────────────────────────────────────
// The order matters. "The builds agree" is checked LAST, because on its own it is satisfied by two builds that
// are wrong together — the reading a green line invites and the one this gate could not support until now.
if (browserOut) {
  const N = await import(join(PKG_DIR, 'index.mjs'));
  const nodeResults = new Function('P', 'cases', EXEC_SRC)(N, CASES);
  const browserResults = new Map(browserOut.results ?? []);
  const nodeMap = new Map(nodeResults);

  const wrongNode = [], wrongBrowser = [], disagree = [];
  for (const v of CASES) {
    const want = String(expectationOf(v));
    const n = nodeMap.get(v.id), b = browserResults.get(v.id);
    if (n !== want) wrongNode.push(`${v.id}: got ${String(n).slice(0, 24)} want ${want.slice(0, 24)}`);
    if (b !== want) wrongBrowser.push(`${v.id}: got ${String(b).slice(0, 24)} want ${want.slice(0, 24)}`);
    if (n !== b) disagree.push(`${v.id}: node ${String(n).slice(0, 20)} browser ${String(b).slice(0, 20)}`);
  }
  check(`the NODE build reproduces all ${CASES.length} corpus cases`, wrongNode.length === 0, wrongNode.slice(0, 3).join('; '));
  check(`the BROWSER build reproduces all ${CASES.length} corpus cases`, wrongBrowser.length === 0, wrongBrowser.slice(0, 3).join('; '));
  check('the two builds agree case for case', disagree.length === 0, disagree.slice(0, 3).join('; '));
  check('every corpus case actually RAN in the browser build — a missing id would make the two checks above vacuous',
    CASES.every((v) => browserResults.has(v.id)) && browserResults.size === CASES.length,
    `ran ${browserResults.size} of ${CASES.length}`);
}

// ─── 4. the refusals are refusals, not false verdicts ───────────────────────────────────────────────────
const refusalRunner = `
const C = await import('${join(dir, '_crypto.mjs')}');
const out = {};
for (const fn of ['ed25519Verify', 'ed25519Sign', 'aesGcmDecrypt']) {
  try { C[fn](); out[fn] = 'RETURNED'; } catch (e) { out[fn] = /E-UNSUPPORTED/.test(e.message) ? 'refused' : 'threw:' + e.message.slice(0, 40); }
}
console.log(JSON.stringify(out));
`;
try {
  const r = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', refusalRunner], { encoding: 'utf8' }).trim());
  // A `false` here would read as "the signature did not verify" — a VERDICT the browser build has no right to.
  check('the browser build REFUSES Ed25519/AES by name instead of returning a verdict',
    r.ed25519Verify === 'refused' && r.ed25519Sign === 'refused' && r.aesGcmDecrypt === 'refused', JSON.stringify(r));
} catch (e) {
  check('the browser build REFUSES Ed25519/AES by name instead of returning a verdict', false, String(e.message).slice(0, 120));
}

// ─── 5. NEGATIVE CONTROLS — a gate that cannot go red is a decoration ───────────────────────────────────
//
// Both legs above are green on this tree, and green proves nothing on its own: the graph walk missed a
// re-export once and still reported a clean graph. So each leg is driven to FAIL here, deliberately, on
// inputs whose defect is known.

// (a) the graph leg: the SAME walk without the browser map must FIND the Node import it exists to catch.
{
  const seenN = new Set();
  const found = [];
  (function walkNoMap(rel) {
    if (seenN.has(rel)) return;
    seenN.add(rel);
    for (const m of readFileSync(join(PKG_DIR, rel), 'utf8').matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2] ?? m[3];
      if (!spec) continue;
      if (spec.startsWith('node:')) found.push(`${rel} → ${spec}`);
      else if (spec.startsWith('.')) walkNoMap(spec.replace(/^\.\//, ''));
    }
  })('index.mjs');
  check('negative control: WITHOUT the browser map the same walk finds the Node import',
    found.length > 0, 'the walk found nothing to catch — it would pass an unmapped core');
}

// (b) the run leg: a module that touches `Buffer` must DIE in the same globals-deleted child.
{
  const probe = join(dir, '__negative-control.mjs');
  writeFileSync(probe, 'export const touch = () => Buffer.from("x").length;\n');
  const runner2 = `
for (const g of ['Buffer']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const M = await import('${probe}');
M.touch();
console.log('SURVIVED');
`;
  let survived = false;
  try {
    survived = execFileSync(process.execPath, ['--input-type=module', '--eval', runner2],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).includes('SURVIVED');
  } catch { survived = false; }
  check('negative control: a module touching Buffer DIES in the same harness', survived === false,
    'Buffer survived deletion — the run leg would pass a core that uses it');
}

// ─── 6. the LIGHT floor — one surface, portable by construction ─────────────────────────────────────────
//
// `ust-light` took the opposite decision to the core and it is the right one for a FLOOR: its synchrony was
// incidental, so it became ASYNCHRONOUS EVERYWHERE on WebCrypto rather than growing a second build. There is
// no `browser` map to apply here — the single file is the browser file — so the check is simply that it
// carries no Node import and runs with the globals gone. A floor that refuses the browser is not a floor.
{
  const LIGHT = join(ROOT, 'packages/ust-light/index.mjs');
  const src = readFileSync(LIGHT, 'utf8');
  const nodeSpecs = [...src.matchAll(IMPORT_RE)].map((m) => m[1] ?? m[2] ?? m[3]).filter((x) => x && !x.startsWith('.'));
  check(`ust-light imports nothing from a platform (${nodeSpecs.length ? nodeSpecs.join(', ') : 'none'})`,
    nodeSpecs.length === 0, nodeSpecs.join(', '));

  const lightRunner = `
for (const g of ['Buffer', 'process', 'require', '__dirname', '__filename', 'global']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
const L = await import('${LIGHT}');
const kp = await L.keypair();
const id = { domain_shard: kp.key_id, ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' };
const time = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const doc = await L.seal(await L.buildState(id, time, { t: { kind: 'captured', value: { c: '21.5' } } }), kp.privateKey, kp.pub);
const v = await L.verify(doc);
console.log(JSON.stringify({ result: v.result, ch: await L.contentHash(doc) }));
`;
  try {
    const out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', lightRunner],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
    // The whole round trip — keypair, build, seal, verify — with no Node global in reach.
    check('ust-light builds, seals and VERIFIES with Buffer/process/require deleted', out.result === 'VALID:LIGHT', `got ${out.result}`);
  } catch (e) {
    check('ust-light builds, seals and VERIFIES with Buffer/process/require deleted', false,
      String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 150) ?? 'no output');
  }
}

// ─── 7. THE DOMAIN — every package DECIDES, and the decision is checked in BOTH directions ──────────────
//
// #148. Sections 1–6 above are correct and their domain was two packages, named in this file. Everything else
// was outside by OMISSION, and an omission reads as coverage: `ust-web-signer` — whose entire subject is
// signing in a page — had no gate touching it, and measured 2026-08-15 it runs a full seal with `Buffer`,
// `process` and `require` deleted. A package that IS portable and is watched by nothing is the same defect as
// one that is not portable and says nothing; both are a limit nobody stated. CLOSED 2026-08-15 by this section.
//
// So the domain is now read from disk, every package carries `ust:browser` in its own manifest, and the two
// directions are checked against each other:
//
//   native | mapped  → EXECUTED here with the Node globals gone. A declaration nothing runs is a claim.
//   node-only        → its README says so where a stranger reads it, AND it genuinely depends on Node.
//
// That second half is the anti-swap leg and it is the one worth arguing for. Without it, a package that became
// portable keeps its `node-only` label forever — green, and wrong in the direction that costs a consumer a tier.
// CLOSED 2026-08-15 — the domain is enumerated from `packages/` and every package carries a stance, so a new
// package is red here until someone decides for it. Proven by mutation in three directions: relabelling a
// portable package node-only reddens, relabelling a node-only package portable reddens, deleting a stance
// reddens. The first of those found a defect in this very leg, and that story is told where it happened.
{
  const PKGS_DIR = join(ROOT, 'packages');
  const STANCES = ['native', 'mapped', 'node-only'];
  const MIN_WHY = 80;

  const pkgs = readdirSync(PKGS_DIR, { withFileTypes: true }).filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((d) => existsSync(join(PKGS_DIR, d, 'package.json')))
    .map((d) => ({ dir: d, json: JSON.parse(readFileSync(join(PKGS_DIR, d, 'package.json'), 'utf8')) }));

  check(`the portability domain is READ from packages/, not listed here (${pkgs.length} package(s): ${pkgs.map((p) => p.dir).join(', ')})`,
    pkgs.length >= 5, `found ${pkgs.length} — the enumeration has lost its subject and every leg below would be vacuous`);

  // Shipped source of a package, taken from its own `files` declaration — the set npm actually publishes, so
  // the question "does this package depend on Node" is asked of the artifact a consumer installs.
  //
  // A first version guessed the set by filename and excluded `*.test.mjs`. `ust-web-signer`'s test is called
  // `test.mjs`, so it stayed in, and its `process.exit(…)` certified a package with no Node dependency at all as
  // Node-dependent — the anti-swap leg, the one leg here worth having, silently answering yes for the wrong file.
  // Measured by the mutation that relabelled that package, which is the only reason it was found.
  const shippedSources = (dir, files) => (files ?? []).flatMap((entry) => {
    const rel = String(entry).replace(/^\.\//, '');
    const abs = join(PKGS_DIR, dir, rel);
    if (!existsSync(abs)) return [];
    if (rel.endsWith('/')) return readdirSync(abs).filter((f) => f.endsWith('.mjs')).map((f) => readFileSync(join(abs, f), 'utf8'));
    return rel.endsWith('.mjs') ? [readFileSync(abs, 'utf8')] : [];
  });
  // Comments are stripped before the question is asked. Round 223 paid for the other way round: a package that
  // reaches no network at all was pulled into a gate's domain by the word `fetch` inside its own prose.
  const codeOf = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/([^:])\/\/.*$/gm, '$1');
  const NODE_DEP = /from\s+'node:|import\s+'node:|(?<![.\w$])(Buffer|process|__dirname|__filename|require)\s*[.(\[]/;
  const dependsOnNode = (dir, files) => shippedSources(dir, files).some((s) => NODE_DEP.test(codeOf(s)));

  // Portable packages are EXECUTED. A probe per package, because their surfaces differ — and the map must cover
  // the portable set exactly, so a newly-portable package is red here until someone writes it something to do.
  const PROBE = {
    'ust-protocol': `const P = await import('${join(dir, 'index.mjs')}');
      console.log(JSON.stringify({ ok: (await P.contentHash({ ust: '1.0', state: { id: { domain_shard: 'e.example', ust_id: 'ust:20260815.09' }, time: {}, data: {} } })).startsWith('sha256:') }));`,
    'ust-light': `const L = await import('${join(ROOT, 'packages/ust-light/index.mjs')}');
      const kp = await L.keypair();
      console.log(JSON.stringify({ ok: typeof kp.key_id === 'string' && kp.key_id.length > 0 }));`,
    'ust-web-signer': `const W = await import('${join(ROOT, 'packages/ust-web-signer/index.mjs')}');
      const s = await W.generateSigner();
      const doc = await W.signObservation(s, { ust_id: 'ust:20260815.09',
        time: { generated_at: '2026-08-15T09:00:00Z', valid_from: '2026-08-15T09:00:00Z', valid_to: '2026-08-15T09:00:00Z' },
        data: { m: { value: 'x' } } });
      console.log(JSON.stringify({ ok: doc.sig?.alg === 'Ed25519' && (await W.contentHash(doc)).startsWith('sha256:') }));`,
  };

  const portable = pkgs.filter((p) => ['native', 'mapped'].includes(p.json['ust:browser']?.stance)).map((p) => p.dir);
  check(`every portable package has an execution probe (${portable.join(', ')})`,
    portable.every((d) => PROBE[d]), `missing a probe for: ${portable.filter((d) => !PROBE[d]).join(', ')} — a stance nothing runs is a claim, not a check`);
  check(`no probe outlives its package (${Object.keys(PROBE).join(', ')})`,
    Object.keys(PROBE).every((d) => portable.includes(d)),
    `${Object.keys(PROBE).filter((d) => !portable.includes(d)).join(', ')} is probed and no longer declared portable — a probe list that outlives its subject reads as coverage`);

  for (const { dir: d, json } of pkgs) {
    const m = json['ust:browser'];
    if (!m || !STANCES.includes(m.stance)) {
      check(`packages/${d} declares ust:browser.stance`, false,
        `add "ust:browser": { "stance": "${STANCES.join('|')}", "why": "…" } — every other package decided, and silence is the one answer this gate refuses`);
      continue;
    }
    check(`packages/${d} states WHY its stance is what it is (${m.stance})`, String(m.why ?? '').trim().length >= MIN_WHY,
      `under ${MIN_WHY} characters is a placeholder, not a decision`);

    if (m.stance === 'mapped') {
      check(`packages/${d} declares 'mapped' and carries a browser map`, !!json.browser && Object.keys(json.browser).length > 0,
        'a mapped stance with no `browser` field maps nothing — the bundler would take the Node file');
    }

    if (m.stance === 'node-only') {
      // (a) said where a stranger reads it — an ANCHOR is pinned, never a sentence: pinning the wording would
      //     make an editorial improvement break the build, which is a defect this repository has shipped before.
      const readme = existsSync(join(PKGS_DIR, d, 'README.md')) ? readFileSync(join(PKGS_DIR, d, 'README.md'), 'utf8') : '';
      check(`packages/${d}/README.md states the limit under a **Browser:** anchor`, /^\*\*Browser:\s*node-only/m.test(readme),
        'a manifest field is machine-readable and a README is what a person reads; the limit has to be in both');
      // (b) …and it is TRUE. This is the direction that keeps the two from swapping in silence.
      // vacuity: a package whose declared `files` carry no module at all would answer "no Node dependency" for
      // the reason that there is nothing to read, which is not the same answer and must not look like one.
      const sources = shippedSources(d, json.files);
      check(`packages/${d} ships at least one module for the question to be asked of (${sources.length})`, sources.length > 0,
        'its `files` declaration lists no .mjs, so the leg below would be answering over an empty set');
      check(`packages/${d} declared node-only genuinely depends on Node`, dependsOnNode(d, json.files),
        'nothing in its shipped source imports node: or touches a Node global — the declaration is stale, and a stale limit costs a consumer a tier it could have had');
    }
  }

  // Portable stances are EXECUTED, with every Node global not merely deleted but booby-trapped.
  for (const d of portable.filter((d) => PROBE[d])) {
    const runner = `
for (const g of ['Buffer', 'process', 'require', '__dirname', '__filename', 'global']) {
  try { delete globalThis[g]; } catch {}
  try { Object.defineProperty(globalThis, g, { get() { throw new Error('NODE GLOBAL USED: ' + g); }, configurable: true }); } catch {}
}
${PROBE[d]}`;
    try {
      const out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', runner],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
      check(`packages/${d} declared portable RUNS with Buffer/process/require deleted`, out.ok === true, 'the probe returned false');
    } catch (e) {
      check(`packages/${d} declared portable RUNS with Buffer/process/require deleted`, false,
        String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 150) ?? 'no output');
    }
  }

  // ── CONTROLS — each leg discriminates rather than passing on anything
  check('CONTROL: an unknown stance is not accepted', !STANCES.includes('portable-ish'));
  check('CONTROL: the node-dependence probe reads CODE, not prose',
    !NODE_DEP.test(codeOf('// this module used to require Buffer and process.env\nexport const x = 1;')),
    'a comment describing a removed Node dependency would certify a stale node-only declaration');
  check('CONTROL: the node-dependence probe DOES see a real use',
    NODE_DEP.test(codeOf("import { readFileSync } from 'node:fs';")) && NODE_DEP.test(codeOf('const b = Buffer.from(x);')),
    'the probe answers no to a genuine Node dependency, so every node-only declaration below is unchecked');
  check('CONTROL: the README anchor is not satisfied by the word appearing anywhere',
    !/^\*\*Browser:\s*node-only/m.test('This package is node-only in practice.'),
    'the anchor would match prose, and the statement would not have to be findable');
}

// ─── 8. #144 — the browser REACHES A VERDICT, and still refuses a forgery ────────────────────────────────
//
// Sections 1-5 prove the mapped core RUNS. That is a different claim from "a browser can verify a document":
// until now it could not, because `verifyCore` is synchronous and a browser offers Ed25519 only through the
// asynchronous `crypto.subtle`, so the honest answer was INDETERMINATE(unsupported_alg) — correct, and useless.
//
// `verifyAsync` resolves the signatures the core asked about and runs it again with real answers. Both halves
// are pinned here, on the SAME bytes, because either alone would be satisfiable by a defect: the refusal alone
// says nothing was gained, and the verdict alone would not show that the synchronous door still refuses rather
// than having been quietly loosened. The adversarial leg is the one that matters most — a path that resolves
// signatures asynchronously is exactly where a forgery would try to enter.
{
  const runner = `
const L = await import('${join(ROOT, 'packages/ust-light/index.mjs')}');
const B = await import('${join(dir, 'index.mjs')}');
const kp = await L.keypair();
const id = { domain_shard: kp.key_id, ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' };
const time = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const doc = await L.seal(await L.buildState(id, time, { t: { kind: 'captured', value: { c: '21.5' } } }), kp.privateKey, kp.pub);
const sync = B.verify(doc, { context: 'data' });
const asy = await B.verifyAsync(doc, { context: 'data' });
const bad = JSON.parse(JSON.stringify(doc));
bad.sig.sig = (bad.sig.sig[0] === 'A' ? 'B' : 'A') + bad.sig.sig.slice(1);
const tampered = await B.verifyAsync(bad, { context: 'data' });
const other = JSON.parse(JSON.stringify(doc));
other.state.data.t.value.c = '99.9';
const swapped = await B.verifyAsync(other, { context: 'data' });
console.log(JSON.stringify({ sync: sync.result + '/' + (sync.reason || ''), asy: asy.result, tampered: tampered.result + '/' + (tampered.error || ''), swapped: swapped.result }));
`;
  let out = null;
  try {
    out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', runner],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
  } catch (e) {
    check('#144 the browser build decides a document', false,
      String(e.stderr || e.message).split('\n').filter((l) => /Error|NODE GLOBAL/.test(l))[0]?.slice(0, 160) ?? 'no output');
  }
  if (out) {
    // The synchronous door is UNCHANGED: it still refuses rather than guessing. If this ever reads VALID, the
    // faculty leaked into the sync path and every Node consumer's guarantee moved with it.
    check(`#144 the SYNC door still refuses for want of the primitive (${out.sync})`, out.sync === 'INDETERMINATE/unsupported_alg',
      'the synchronous verify() answered something other than the honest refusal');
    // …and the async door reaches the verdict the reference reaches on the same bytes.
    // Static label, measured value in the detail: a name assembled at run time cannot be cited by the ladder
    // registry, which points at a check BY ITS TEXT.
    check('#144 verifyAsync REACHES a verdict in the browser build', out.asy === 'VALID:LIGHT',
      `got ${out.asy} — the browser still cannot decide a document the reference calls VALID:LIGHT`);
    // ADVERSARIAL: the resolution path may not launder a forgery.
    check(`#144 ADVERSARIAL a tampered signature is REFUSED through the async path (${out.tampered})`, out.tampered === 'INVALID/E-SIG',
      'a flipped signature byte survived the asynchronous resolution — the memo answered for a triple it was not obtained for');
    // ADVERSARIAL: the same key, a DIFFERENT signing input. A memo keyed on anything less than the whole triple
    // would hand this document the answer obtained for the first one.
    check(`#144 ADVERSARIAL altered CONTENT under the same key is REFUSED (${out.swapped})`, out.swapped === 'INVALID',
      'mutated content verified — a resolved signature answered for a message it was never obtained for');
  }
}

// ─── 9. #144 in the CLEAN-ROOM verifier — the file `llms.txt` hands to machines ─────────────────────────
//
// Section 8 proves the mapped CORE reaches a verdict. This covers the other verifier we publish, and it is the
// one a machine is told to fetch: `docs/llms.txt` names `ust-verify.mjs` as the zero-dependency file to run. It
// carried the original #144 collapse long after the core closed it — one `catch` answering `false` both to "bad
// signature" and to "this engine cannot check Ed25519", which the caller turns into INVALID:E-SIG. A verifier we
// RECOMMEND, calling honest documents forged on any engine whose WebCrypto lacks Ed25519.
//
// The second half is the one that matters: without the faculty the verifier genuinely cannot tell a tampered
// document from an intact one, so BOTH must answer INDETERMINATE. Getting the tampered one "right" would be luck,
// and a check that rewarded it would be rewarding a guess.
{
  const runner = `
const L = await import('${join(ROOT, 'packages/ust-light/index.mjs')}');
const V = await import('${join(ROOT, 'docs/ust-verify.mjs')}');
const kp = await L.keypair();
const id = { domain_shard: kp.key_id, ust_id: 'ust:20260715.12', key_id: kp.key_id, class: 'observation' };
const time = { generated_at: '2026-07-15T12:00:00Z', valid_from: '2026-07-15T12:00:00Z', valid_to: '2026-07-15T13:00:00Z' };
const doc = await L.seal(await L.buildState(id, time, { t: { kind: 'captured', value: { c: '21.5' } } }), kp.privateKey, kp.pub);
const bad = JSON.parse(JSON.stringify(doc)); bad.sig.sig = (bad.sig.sig[0] === 'A' ? 'B' : 'A') + bad.sig.sig.slice(1);
const withGood = (await V.verify(doc, { context: 'data' })).result;
const withBad  = (await V.verify(bad, { context: 'data' })).result;
const real = crypto.subtle.importKey.bind(crypto.subtle);
crypto.subtle.importKey = async (f, k, a, ...r) => {
  if (a && a.name === 'Ed25519') { const e = new Error('Unrecognized algorithm name'); e.name = 'NotSupportedError'; throw e; }
  return real(f, k, a, ...r);
};
const g = await V.verify(doc, { context: 'data' });
const b = await V.verify(bad, { context: 'data' });
console.log(JSON.stringify({ withGood, withBad, noFacGood: g.result + '/' + (g.reason || ''), noFacBad: b.result + '/' + (b.reason || '') }));
`;
  let out = null;
  try {
    out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', runner],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim());
  } catch (e) {
    check('#144 the clean-room verifier decides a document', false,
      String(e.stderr || e.message).split('\n').filter((l) => /Error/.test(l))[0]?.slice(0, 160) ?? 'no output');
  }
  if (out) {
    check('#144 clean-room WITH the faculty is unchanged', out.withGood === 'VALID:LIGHT' && out.withBad === 'INVALID',
      `got ${out.withGood} / ${out.withBad} — the fix moved a verdict on an engine that HAS Ed25519, and it must not`);
    check('#144 clean-room WITHOUT the faculty WITHHOLDS on an honest document', out.noFacGood === 'INDETERMINATE/unsupported_alg',
      `got ${out.noFacGood} — a verifier we recommend to machines is calling an honest document forged`);
    check('#144 clean-room WITHOUT the faculty withholds on a TAMPERED one too, rather than guessing right',
      out.noFacBad === 'INDETERMINATE/unsupported_alg',
      `got ${out.noFacBad} — it did not check the signature, so any verdict about it would be luck`);
  }
}

console.log(failures === 0
  ? '\n  browser portability: every package declares a browser stance, each portable one RUNS without Node globals, and each node-only one says so and still means it'
  : `\n  browser portability: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
