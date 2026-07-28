// SPDX-License-Identifier: Apache-2.0
// Type-declaration generator — from the source, with no dependency and no build step.
//
// #105: not one published package shipped types, so every TypeScript consumer hand-wrote a declaration for
// our API. A hand-written declaration about someone else's interface can be correct; it cannot be CURRENT,
// and it cannot say that it is not. The reference operator's declared `buildCheckpoint` with five parameters —
// a faithful description of rc.12 — and could not warn that rc.12 was twenty candidates old, so the sixth
// parameter was unreachable from the product and every hour sealed without interval bounds.
//
// WHY GENERATED AND NOT WRITTEN. A hand-written .d.ts here would reproduce the exact defect one level in: a
// second source of truth that drifts silently. Generating from the source makes drift impossible by
// construction — the declaration cannot describe a version the source is not.
//
// WHY NOT `tsc --declaration`. This repository has ZERO dependencies, dev included, and the source carries no
// JSDoc. Generating properly through TypeScript would mean adding a toolchain and annotating 2300 lines — a
// large change to a deliberate property, bought for convenience. So: parse the export surface directly.
//
// WHAT THIS DOES AND DOES NOT BUY. Names and ARITY are exact, and arity is precisely what failed: the consumer
// needed to know a sixth parameter existed. Value types are `unknown` until someone refines them by hand,
// which is honest — a loose declaration that is complete beats a precise one that is stale. Refinement is
// incremental and the gate keeps it in sync either way.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;

// A parameter is OPTIONAL when it carries a default. Rest stays rest. Destructured objects keep no names —
// naming them would invent an interface the source does not declare.
export function parseParams(raw) {
  if (!raw.trim()) return [];
  const out = []; let depth = 0, cur = '';
  for (const ch of raw) {
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((p, i) => {
    const s = p.trim();
    const rest = s.startsWith('...');
    const optional = s.includes('=');
    const bare = s.replace(/^\.\.\./, '').split('=')[0].trim();
    const name = /^[A-Za-z_$][\w$]*$/.test(bare) ? bare : `arg${i}`;
    return { name, optional, rest };
  });
}

// A trailing parameter with no default can still be OPTIONAL in fact: the body guards it. `buildCheckpoint`
// takes `interval` last and spreads `...(interval ? {…} : {})`, so calling with five arguments is legal and a
// declaration that demands six would be STRICTER THAN THE CODE — a different way of being wrong about the same
// signature. So: scan the body for a guard on that name and mark it optional. Only TRAILING parameters qualify,
// scanning right to left and stopping at the first that is not guarded, because an optional argument in the
// middle is not omissible anyway.
function guardedInBody(name, body) {
  const n = name.replace(/[$]/g, '\\$');
  return new RegExp(`(\\?\\?|\\|\\||&&|\\?\\.)\\s*${n}\\b|\\b${n}\\s*(\\?\\?|\\?[^.]|===\\s*undefined|!==\\s*undefined|\\|\\||&&)|!\\s*${n}\\b`).test(body);
}
// The body must end where the FUNCTION ends. A fixed-size window spills into the next declaration and picks up
// its guards: with 4000 characters, `buildCheckpoint`'s required `prev` was relaxed to optional by a guard
// belonging to a function further down the file. Anchor on structure, not on a distance — the same correction
// this repo's offline-ceremony gate needed for the same reason.
function bodyOf(src, from) {
  let depth = 0, i = from;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return src.slice(from, i + 1); }
  }
  return src.slice(from, from + 4000);
}

function relaxTrailing(params, body) {
  for (let i = params.length - 1; i >= 0; i--) {
    if (params[i].optional || params[i].rest) continue;
    if (guardedInBody(params[i].name, body)) params[i].optional = true;
    else break;
  }
  return params;
}

export function declarationsFor(src) {
  const decls = [];
  for (const m of src.matchAll(/^export (?:async )?function (\w+)\s*\(([\s\S]*?)\)\s*\{/gm)) {
    const body = bodyOf(src, m.index + m[0].length - 1);
    decls.push({ kind: 'function', name: m[1], params: relaxTrailing(parseParams(m[2]), body), async: /^export async/.test(m[0]) });
  }
  for (const m of src.matchAll(/^export const (\w+)\s*=\s*(?:async\s*)?\(([\s\S]*?)\)\s*=>/gm)) {
    // An arrow has either a BLOCK body (`=> {`) or an EXPRESSION body. Brace-matching is right for the first
    // and wrong for the second: `buildCheckpoint` is `=> buildState({…})`, so the first `{` belongs to an
    // argument, and matching it returns an object literal instead of the body. The guard on `interval` lives
    // AFTER that literal closes, so the parameter looked required. Decide by what follows the arrow.
    const after = src.slice(m.index + m[0].length);
    const isBlock = /^\s*\{/.test(after);
    const end = (() => { const nx = src.indexOf('\nexport ', m.index + 1); return nx < 0 ? src.length : nx; })();
    const body2 = isBlock ? bodyOf(src, m.index + m[0].length + after.indexOf('{')) : src.slice(m.index + m[0].length, end);
    decls.push({ kind: 'function', name: m[1], params: relaxTrailing(parseParams(m[2]), body2), async: /=\s*async/.test(m[0]) });
  }
  for (const m of src.matchAll(/^export const (\w+)\s*=\s*(?!\(|async)/gm)) {
    if (!decls.some((d) => d.name === m[1])) decls.push({ kind: 'const', name: m[1] });
  }
  return decls.sort((a, b) => a.name.localeCompare(b.name));
}

const render = (pkg, decls) => {
  const head = [
    '// GENERATED by tools/gen-types.mjs — do not edit by hand.',
    '//',
    '// Names and ARITY come from the source and cannot drift from it: `npm run types` regenerates, and',
    '// `types-parity-gate` fails when a declaration and its export disagree. Value types are `unknown`',
    '// where nobody has refined them yet — a complete loose declaration beats a precise stale one, which',
    '// is the defect this file exists to prevent (#105).',
    `// Package: ${pkg}`,
    '',
  ];
  const body = decls.map((d) => {
    if (d.kind === 'const') return `export const ${d.name}: unknown;`;
    const ps = d.params.map((p) => `${p.rest ? '...' : ''}${p.name}${p.optional && !p.rest ? '?' : ''}: ${p.rest ? 'unknown[]' : 'unknown'}`).join(', ');
    return `export function ${d.name}(${ps}): ${d.async ? 'Promise<unknown>' : 'unknown'};`;
  });
  return head.concat(body, ['']).join('\n');
};

const workspaces = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces;
let wrote = 0, total = 0;
for (const w of workspaces) {
  let pkg;
  try { pkg = JSON.parse(readFileSync(join(root, w, 'package.json'), 'utf8')); } catch { continue; }
  if (pkg.private) continue;
  // A package with no `main` and no `exports` is NOT IMPORTABLE — it is dispatched through `bin`. Generating
  // declarations for it publishes an API surface a consumer cannot reach: `@ust-protocol/cli` has 57 exports in
  // index.mjs, all of them for its own regression suite, and none reachable as `import … from '@ust-protocol/cli'`
  // because Node's implicit main is index.JS. Declaring them would be a promise about a door that is not there.
  if (!pkg.main && !pkg.exports) { console.log(`  ${pkg.name.padEnd(30)}   — binary only (bin), not importable: no declarations`); continue; }
  const main = pkg.main ?? 'index.mjs';
  let src;
  try { src = readFileSync(join(root, w, main), 'utf8'); } catch { continue; }
  const decls = declarationsFor(src);
  if (!decls.length) continue;
  writeFileSync(join(root, w, main.replace(/\.m?js$/, '.d.ts')), render(pkg.name, decls));
  wrote++; total += decls.length;
  console.log(`  ${pkg.name.padEnd(30)} ${String(decls.length).padStart(3)} declarations`);
}
console.log(`\n  ✓ ${total} declarations across ${wrote} packages — generated, never hand-written`);
