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
import { pathToFileURL } from 'node:url';
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
// #117 — THE QUESTION THIS ASKS DECIDES WHETHER THE ANSWER IS SOUND. It used to ask "does a guard mentioning this
// name exist ANYWHERE in the body?", and existence is the wrong quantifier: one guarded use plus one unguarded use
// still crashes when the argument is omitted. Measured, that shipped: `assertValid(verdict?: unknown)` — declared
// optional, while `assertValid()` throws `E-MALFORMED — no verdict`. TypeScript admitted a call that can never
// succeed, which is the exact failure mode #116 existed to end, one level down.
//
// So the quantifier is UNIVERSAL now: optional iff EVERY occurrence of the name is guarded. That is fail-closed —
// an unprovable parameter stays required, costing a consumer a pad, never a runtime crash — and it REMOVES some
// optionals that were there before. Removing them is the point.
//
// A use counts as guarded when it is the subject of a guard (`x ??`, `x ?.`, `x ===/!== undefined`, `x &&`, `!x`,
// `x ||`), the object of one (`?? x`, `&& x`), or sits inside a `?:` whose test mentions the name. Anything else
// — a bare read, a property access, a call — is an unguarded use and settles it.
function guardedInBody(name, rawBody) {
  const n = name.replace(/[$]/g, '\\$');
  // COMMENTS ARE NOT USES. `buildGenesis` guards `roles` completely and stayed required, because the sentence
  // above it explains what a non-empty `roles` means — prose mentioning the name defeated a universal quantifier
  // over occurrences. Blanked rather than deleted so every index below still lines up with the real source.
  const body = rawBody.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
  // A guard protects a REGION, not a character. `...(prev !== undefined ? { prev } : {})` mentions `prev` twice and
  // both are safe, because the guard heads the whole parenthesised group. Counting guard SITES scored that 1-of-2
  // and demoted a genuinely optional parameter — measured while writing this, and it is the same mistake in the
  // opposite direction: too strict is not automatically safe, it just moves the cost onto every consumer.
  const SITE = new RegExp(`\\b${n}\\s*(?:\\?\\.|\\?\\?|===\\s*undefined|!==\\s*undefined|\\|\\||&&|\\?[^.])|!\\s*${n}\\b`, 'g');
  const ALL = new RegExp(`\\b${n}\\b`, 'g');
  const occurrences = [...body.matchAll(ALL)].map((m) => m.index);
  if (!occurrences.length) return false;                           // never mentioned ⇒ nothing proven, stay required

  // the region a guard site protects: the innermost parentheses enclosing it (its whole conditional expression).
  const regions = [];
  for (const s of body.matchAll(SITE)) {
    let depth = 0, open = -1;
    for (let i = s.index; i >= 0; i--) {                           // walk left to the unmatched `(`
      const c = body[i];
      if (c === ')') depth++;
      else if (c === '(') { if (depth === 0) { open = i; break; } depth--; }
    }
    if (open < 0) { regions.push([s.index, s.index + s[0].length]); continue; }   // not parenthesised: the site only
    depth = 0;
    for (let i = open; i < body.length; i++) {
      const c = body[i];
      if (c === '(') depth++;
      else if (c === ')') { depth--; if (depth === 0) { regions.push([open, i + 1]); break; } }
    }
  }
  return occurrences.every((at) => regions.some(([a, b]) => at >= a && at < b));
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

export function declarationsFor(src, resolveModule) {
  const decls = [];
  // `export { a, b } from './other.mjs'` — a form this generator did not read, so SEVEN names left the module at
  // runtime with no declaration at all (measured 2026-07-30: 108 declared against 117 exported). A consumer who
  // deletes their hand-written types loses them silently. The names are followed into the module they come from
  // and declared from ITS source, so a re-export is typed like anything else rather than dropped.
  for (const m of src.matchAll(/^export \{([^}]+)\} from '([^']+)';/gm)) {
    const names = m[1].split(',').map((x) => x.trim().split(/\s+as\s+/).pop().trim()).filter(Boolean);
    const from = resolveModule?.(m[2]);
    if (!from) { for (const n of names) decls.push({ kind: 'const', name: n, type: 'unknown' }); continue; }
    const inner = declarationsFor(from);
    for (const n of names) {
      const d = inner.find((x) => x.name === n);
      decls.push(d ? { ...d, name: n } : { kind: 'const', name: n, type: 'unknown' });
    }
  }
  // `export class X extends Error` — the third form the generator did not know. Two error classes left the module
  // undeclared, and a consumer catching them by type had nothing to catch by.
  for (const m of src.matchAll(/^export class (\w+)(?:\s+extends\s+(\w+))?\s*\{/gm))
    decls.push({ kind: 'class', name: m[1], extends: m[2] ?? null });
  for (const m of src.matchAll(/^export (?:async )?function (\w+)\s*\(([\s\S]*?)\)\s*\{/gm)) {
    const body = bodyOf(src, m.index + m[0].length - 1);
    const isA = /^export async/.test(m[0]);
    decls.push({ kind: 'function', name: m[1], params: relaxTrailing(parseParams(m[2]), body), async: isA, ret: returnTypeOf(body, isA) });
  }
  for (const m of src.matchAll(/^export const (\w+)\s*=\s*(?:async\s*)?\(([\s\S]*?)\)\s*=>/gm)) {
    // An arrow has either a BLOCK body (`=> {`) or an EXPRESSION body. Brace-matching is right for the first
    // and wrong for the second: `buildCheckpoint` is `=> buildState({…})`, so the first `{` belongs to an
    // argument, and matching it returns an object literal instead of the body. The guard on `interval` lives
    // AFTER that literal closes, so the parameter looked required. Decide by what follows the arrow.
    const after = src.slice(m.index + m[0].length);
    const isBlock = /^\s*\{/.test(after);
    // An EXPRESSION arrow ends at its own semicolon, not at the next `export`. Slicing to the next export
    // swallowed the statements between — `isValid`'s one-line predicate arrived with `const CLASSES = […]`
    // attached, so the predicate test never matched and a human-written `boolean` beat the generator. Walk to
    // the first `;` at depth zero.
    const end = (() => {
      let d = 0;
      for (let k = m.index + m[0].length; k < src.length; k++) {
        const c = src[k];
        if ('([{'.includes(c)) d++;
        else if (')]}'.includes(c)) d--;
        else if (c === ';' && d === 0) return k;
      }
      const nx = src.indexOf('\nexport ', m.index + 1);
      return nx < 0 ? src.length : nx;
    })();
    const body2 = isBlock ? bodyOf(src, m.index + m[0].length + after.indexOf('{')) : src.slice(m.index + m[0].length, end);
    const isA2 = /=\s*async/.test(m[0]);
    decls.push({ kind: 'function', name: m[1], params: relaxTrailing(parseParams(m[2]), body2), async: isA2, ret: returnTypeOf(body2, isA2) });
  }
  for (const m of src.matchAll(/^export const (\w+)\s*=\s*(?!\(|async)/gm)) {
    // A CONST HAS EXACTLY ONE INITIALIZER, so unlike a return type there is nothing to disagree with. Where it
    // is an object literal of quoted strings — a declared vocabulary such as STREAM_KEYS or HEAD_STATES — the
    // keys AND the values are stated outright and a consumer can reach them. Measured 2026-08-01: every const
    // in the operator package shipped as `unknown`, so the first typed consumer of the state vocabulary could
    // not name a state without re-declaring the layer's own contract locally — the divergence that vocabulary
    // exists to prevent. Anything that is not a literal-of-strings stays `unknown`: no guessing.
    if (!decls.some((d) => d.name === m[1])) {
      const tail = src.slice(m.index + m[0].length);
      const lit = tail.match(/^\s*(?:Object\.freeze\(\s*)?\{([\s\S]*?)\}\s*\)?\s*;/);
      let type;
      if (lit) {
        // Comments first: a `//` explanation after an entry may contain commas, and counting them as
        // separators made every vocabulary look like it held non-string members. Measured — the first
        // attempt at this changed nothing at all, silently.
        const bare = lit[1].replace(/\/\/[^\n]*/g, '');
        const parts = bare.split(',').map((x) => x.trim()).filter(Boolean);
        const pairs = parts.map((x) => x.match(/^([A-Za-z_$][\w$]*)\s*:\s*'([^']*)'$/));
        if (parts.length && pairs.every(Boolean)) {
          type = 'Readonly<{ ' + pairs.map((e) => `${e[1]}: '${e[2]}'`).join('; ') + ' }>';
        }
      }
      // A vocabulary is sometimes a MAP OF LISTS — `ROLE_CLASSES` is role → the classes that role admits, and
      // it shipped as `unknown` because this reader knew maps of strings and lists of strings but not the
      // composition. Same defect, same consequence: a typed consumer cannot name what a role admits without
      // re-typing the protocol's own table.
      if (!type) {
        const lit = tail.match(/^\s*(?:Object\.freeze\(\s*)?\{([\s\S]*?)\}\s*\)?\s*;/);
        if (lit) {
          const entries = [...lit[1].matchAll(/([A-Za-z_$][\w$]*)\s*:\s*(?:Object\.freeze\(\s*)?\[([^\]]*)\]/g)];
          const bare = lit[1].replace(/\/\/[^\n]*/g, '');
          const members = (bare.match(/[A-Za-z_$][\w$]*\s*:/g) || []).length;
          if (entries.length && entries.length === members) {
            const parts = entries.map((e) => {
              const items = e[2].split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.match(/^'([^']*)'$/));
              return items.every(Boolean) ? `${e[1]}: readonly [${items.map((m) => `'${m[1]}'`).join(', ')}]` : null;
            });
            if (parts.every(Boolean)) type = 'Readonly<{ ' + parts.join('; ') + ' }>';
          }
        }
      }
      // A vocabulary is just as often an ORDERED list as a map — `PREV_ONLY_SUBTYPES` is the §11.3 C2 subtype
      // set, and it shipped as `unknown` because this reader only knew object literals. Same defect, same
      // consequence: a typed consumer cannot name a subtype without re-typing the protocol's own vocabulary,
      // which is exactly what exporting it was meant to prevent.
      if (!type) {
        const arr = tail.match(/^\s*(?:Object\.freeze\(\s*)?\[([\s\S]*?)\]\s*\)?\s*;/);
        if (arr) {
          const items = arr[1].replace(/\/\/[^\n]*/g, '').split(',').map((x) => x.trim()).filter(Boolean);
          const strs = items.map((x) => x.match(/^'([^']*)'$/));
          if (items.length && strs.every(Boolean)) type = 'readonly [' + strs.map((e) => `'${e[1]}'`).join(', ') + ']';
        }
      }
      decls.push({ kind: 'const', name: m[1], ...(type ? { type } : {}) });
    }
  }
  return decls.sort((a, b) => a.name.localeCompare(b.name));
}

// RETURN TYPES, inferred from the body rather than left at `unknown`. Not decoration: the acceptance test for
// #105 is the reference operator DELETING its hand-written declaration, and it could not, because its file
// returned `Record<string, unknown>` where this one returned `unknown` — four call sites stopped compiling.
// A declaration too loose to replace the thing it supersedes has not finished the job.
// Only shapes the source states outright are read; anything else stays `unknown`, which is the honest answer.
function returnTypeOf(rawBody, isAsync) {
  // Strip leading comments before matching the body's FIRST expression. `buildCheckpoint` carries a §11.3
  // annotation between its arrow and its call, so a pattern anchored on the body's start matched the comment
  // instead and the return stayed `unknown`. Third variant today of the same lesson: match the structure, not a
  // position that happens to work on the cases in front of me.
  const body = rawBody.replace(/^(?:\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)\s*)+/, '');
  // `expr` must be declared BEFORE the first rule reads it. It was not, and the temporal dead zone made every
  // literal-shape inference throw silently — the same defect that killed the genesis ceremony on its first run
  // this morning, committed again the same day by the person who fixed it. A gate exists for that one and
  // watches only `cmdGenesis`: named an instance, not the class.
  const expr = body.replace(/^\s*return\s+/, '').trim();
  const inner = (() => {
    // An object literal states its OWN KEYS, so emit them instead of collapsing to `Record<string, unknown>`.
    // Property access then resolves — `doc.state` exists rather than being an index into an opaque record —
    // which is the difference between a consumer narrowing its own data and a consumer unable to reach a field
    // at all. The hand-written declaration this replaces named the shape by hand (`SealedDoc`); the keys are
    // derivable, the NAME is not, and a structural type serves the same purpose without inventing one.
    // Find the RETURNED object literal by balancing braces, not by a regex anchored at the end of a string:
    // a block body is `{ … return { … }; }`, so the literal sits in the middle and every positional pattern I
    // tried matched the wrong brace. Balance from `return {` and read the top-level keys.
    // A function with MORE THAN ONE object-return shape must not have one of them declared as its type. Measured
    // 2026-07-30 (UST#116): six declarations typed only `{ error, detail }` — the GUARD clause — because this read
    // the FIRST `return {` it found and stopped. `resolveKeys` returns that shape on refusal and
    // `{active, validKeys, revoked, history, head, …}` on success, so a consumer writing the correct thing got a
    // compile error and reached for `as any`. Sampling the first branch is the same defect as sampling a syntax
    // form: it describes the case in front of the probe, not the function. Where the shapes disagree the honest
    // declaration is `unknown` — it forces the caller to narrow instead of confidently misleading them.
    // A SHAPE IS ITS KEYS, NOT ITS TEXT. The rule above is right and stays: where two returns disagree on what
    // a consumer can reach, declaring one of them is confidently misleading. But comparing the raw source made
    // every branch whose VALUE EXPRESSIONS differ look like a disagreement — `{ state: 'unverified', head: await
    // store.get(k) }` and `{ state: cond ? a : b, head: published }` offer a consumer exactly the same two
    // fields. Measured 2026-08-01 by the first typed consumer of `reconcileHead`: the declaration shipped
    // `Promise<unknown>`, and reading `r.state` did not compile — the same wall #117 was about, reached by a
    // different road. Key sets decide; disagreeing key sets still collapse to `unknown`.
    const keysOfLiteral = (lit) => {
      const out = []; let depth = 0, buf = '';
      for (const ch of lit + ',') {
        if ('([{'.includes(ch)) depth++;
        else if (')]}'.includes(ch)) depth--;
        if (ch === ',' && depth === 0) { const k = buf.trim().split(':')[0].trim(); if (/^[A-Za-z_$][\w$]*$/.test(k)) out.push(k); buf = ''; continue; }
        buf += ch;
      }
      return [...new Set(out)].sort();
    };
    const shapes = new Set();
    for (const m2 of expr.matchAll(/\breturn\s*\{/g)) {
      const o = expr.indexOf('{', m2.index);
      let dd = 0, cc = -1;
      for (let k = o; k < expr.length; k++) {
        if (expr[k] === '{') dd++;
        else if (expr[k] === '}') { dd--; if (dd === 0) { cc = k; break; } }
      }
      if (cc > o) shapes.add(keysOfLiteral(expr.slice(o + 1, cc)).join(','));
      if (shapes.size > 1) break;
    }
    if (shapes.size > 1) return 'unknown';
    const retAt = expr.search(/\breturn\s*\{/);
    if (retAt >= 0) {
      const open = expr.indexOf('{', retAt);
      let d = 0, close = -1;
      for (let k = open; k < expr.length; k++) {
        if (expr[k] === '{') d++;
        else if (expr[k] === '}') { d--; if (d === 0) { close = k; break; } }
      }
      if (close > open) {
        const innerLit = expr.slice(open + 1, close);
        const keys = []; let depth = 0, buf = '';
        for (const ch of innerLit + ',') {
          if ('([{'.includes(ch)) depth++;
          else if (')]}'.includes(ch)) depth--;
          if (ch === ',' && depth === 0) { const k = buf.trim().split(':')[0].trim(); if (/^[A-Za-z_$][\w$]*$/.test(k)) keys.push(k); buf = ''; continue; }
          buf += ch;
        }
        const uniq = [...new Set(keys)];
        if (uniq.length && uniq.length <= 12) return `{ ${uniq.map((k) => `${k}: unknown`).join('; ')} }`;
      }
    }
    // `^\s*\{[^}]*:` was meant to catch an arrow whose body IS an object literal. It also matches every BLOCK
    // body containing a colon, which is nearly all of them — so `isPublicDnsShard` was declared
    // `Record<string, unknown>` and returns a boolean, and `axisRank` the same and returns a number. A confidently
    // WRONG type is worse than `unknown`: a consumer writes `r.whatever`, the compiler agrees, and the value is
    // undefined at runtime. The literal form is only unambiguous when there is no `return` to disagree with it.
    const isExpressionObjectBody = !/\breturn\b/.test(body) && /^\s*\{[^}]*:/.test(body);
    if (/return\s*\{/.test(body) || isExpressionObjectBody || /=>\s*\(\s*\{/.test(body)) return 'Record<string, unknown>';
    // For an EXPRESSION arrow the body already begins past the `=>`, so a pattern anchored on the arrow never
    // matches — `buildCheckpoint` is `=> buildState({…})` and stayed `unknown` until this was anchored on the
    // body's own start instead. Same correction as the brace-matching one, in the other direction.
    if (/\breturn\s+(buildState|buildTranscript)\s*\(/.test(body) || /^\s*(buildState|buildTranscript)\s*\(/.test(body)) return 'Record<string, unknown>';
    // BOOLEAN when the body IS a predicate: a comparison, a negation, or a chain of them. `isValid` is
    // `typeof r?.result === 'string' && r.result.slice(0,6) === 'VALID:'` — no literal `true` anywhere, so a
    // rule looking for one left it `unknown` while the hand-written declaration a human wrote said `boolean`.
    if (/^[^;]*(===|!==|>=|<=|&&|\|\|)[^;]*$/.test(expr) && !/\breturn\b/.test(expr) && /(===|!==|typeof |instanceof )/.test(expr)) return 'boolean';
    if (/^!/.test(expr) || /^Boolean\(/.test(expr)) return 'boolean';
    // STRING when the body delegates to a named hasher or builds one. `contentHash` is `H('ust:state', …)`,
    // whose whole job is to return a digest; the previous rule wanted a quote at the return site and missed it.
    if (/\breturn\s+['\`]/.test(body) || /\.toString\(['\`)]/.test(body)) return 'string';
    if (/^H\s*\(/.test(expr) || /^[a-zA-Z]*[Hh]ash\s*\(/.test(expr) || /\.digest\(/.test(expr)) return 'string';
    // A body that IS a call to a canonicaliser returns its string. `signedContent` is `canon({ust, state})`,
    // and inference does not follow calls — so the one primitive whose contract is "value -> canonical string"
    // is named here. Narrow on purpose: this is not general interprocedural inference and must not grow into it,
    // because each such rule is a claim about a function that could change without this file noticing.
    if (/^canon\s*\(/.test(expr)) return 'string';
    if (/\breturn\s*\[/.test(body)) return 'unknown[]';
    return 'unknown';
  })();
  return isAsync ? `Promise<${inner}>` : inner;
}

// #117 — the handful of shapes a typed consumer cannot avoid. Every key here was READ from a real value:
// a sealed genesis is `{ ust, state, sig }`, the state a builder returns is `{ id, time, data, hashes }`,
// and a verdict is `{ result, error, detail, tier }` with `id` present only when it verified. `id` is
// therefore optional and the rest are not — declaring `id` required would be the same unsoundness this
// round removed from the arity, one level along.
const SHAPES_SRC = [
  'export interface UstState { id: Record<string, unknown>; time: unknown; data: unknown; hashes: unknown }',
  'export interface UstDocument { ust: unknown; state: UstState; sig: unknown }',
  // `publisher` / `publisher_claimed` are CONDITIONAL: the core emits one or the other depending on whether the
  // name was authoritatively resolved (index.mjs — `nameAuthoritative ? { publisher } : { publisher_claimed }`).
  // Both optional, because either may be absent; declaring one required would forbid the other's world.
  'export interface UstVerdict { result: string; error: unknown; detail: unknown; tier: unknown; id?: unknown; publisher?: unknown; publisher_claimed?: unknown }',
  '',
  '// A function with two OUTCOMES is a discriminated union, not an untypeable value. Saying "these are unions,',
  '// so one interface would lie" and leaving them `unknown` was a substitution — TypeScript has unions, and the',
  '// branches below were READ from real values: the resolved branch from a corpus key-log vector, the error',
  '// branch from a rejected one. Discriminate on `error` in `res` and the compiler narrows for you.',
  'export interface UstError { error: string; detail: unknown }',
  'export interface UstKeysResolved { validKeys: unknown; active: unknown; revoked: unknown; history: unknown; roles: unknown; declaredRoles: unknown; head: string }',
  'export type UstKeyResolution = UstKeysResolved | UstError;',
  'export interface UstStreamComplete { complete: string; head?: unknown; detail?: unknown; interval?: unknown; reason?: unknown }',
  'export type UstStreamVerdict = UstStreamComplete | UstError;',
].join('\n');
const SHAPES_FOR = new Set(['ust-protocol']);
// a function whose return was MEASURED. Nothing is inferred here — the map is checked by a gate that builds
// the value and compares keys, so an entry that stops being true fails rather than quietly misleading.
const SHAPE_RETURNS = { seal: 'UstDocument', verify: 'UstVerdict', verifyJson: 'UstVerdict', resolveKeys: 'UstKeyResolution', verifyStream: 'UstStreamVerdict' };

const render = (pkg, decls) => {
  const head = [
    '// GENERATED by tools/gen-types.mjs — do not edit by hand.',
    '//',
    '// Names and ARITY come from the source and cannot drift from it: `npm run types` regenerates, and',
    '// `types-parity-gate` fails when a declaration and its export disagree. Value types are `unknown`',
    '// where nobody has refined them yet — a complete loose declaration beats a precise stale one, which',
    '// is the defect this file exists to prevent (#105).',
    '//',
    '// WHAT `unknown` MEANS HERE (#117). It is a promise we are NOT making, never a generator that gave up:',
    '// this file is derived from a JavaScript body, and a shape it cannot prove is left for you to narrow',
    '// rather than asserted. Narrowing costs a type guard and the compiler then proves the result; a',
    '// confident wrong type costs you a crash. Two return types WERE confidently wrong and are now honest',
    '// `unknown` — that direction is the fix, not a regression.',
    '//',
    '// The three shapes below are the exception, because a consumer cannot avoid them and because they are',
    '// MEASURED from real values this suite builds, not read off the specification. A gate rebuilds those',
    '// values and fails if a declared key is missing, so they cannot drift into being the stale kind.',
    `// Package: ${pkg}`,
    '',
    ...(SHAPES_FOR.has(pkg) ? [SHAPES_SRC, ''] : []),
  ];
  const body = decls.map((d) => {
    if (SHAPES_FOR.has(pkg) && d.kind === 'function' && SHAPE_RETURNS[d.name]) d = { ...d, ret: SHAPE_RETURNS[d.name] };
    // The inferred type was computed and then DISCARDED here — this line hardcoded `unknown` for every const,
    // so improving the producer changed nothing and did so silently. Read what the renderer emits, not what the
    // parser decided.
    if (d.kind === 'const') return `export const ${d.name}: ${d.type ?? 'unknown'};`;
    if (d.kind === 'class')
      return `export class ${d.name}${d.extends ? ' extends ' + d.extends : ''} { constructor(verdict?: unknown); }`;
    // TypeScript forbids a required parameter AFTER an optional one; JavaScript permits it, and our own core uses
    // it — `buildAbsence(id, time, name, reason, extra = {}, prev)` is legal JS and, transcribed literally, an
    // ILLEGAL declaration. MEASURED 2026-07-30 from a consumer: the shipped index.d.ts carried two TS1016 errors,
    // and everything declared BELOW them was lost to the compiler — `resolveKeys`, three lines past the second one,
    // read as "does not exist". A parse error in a .d.ts is not a style problem: it truncates the file silently,
    // and `skipLibCheck` does not help because it skips CHECKING, not PARSING.
    // The grammar decides the fix, not preference: optionality is contagious to the right. A caller passing every
    // argument still type-checks, so nothing true becomes unexpressible.
    let seenOptional = false;
    for (const p of d.params) { if (p.optional && !p.rest) seenOptional = true; else if (seenOptional && !p.rest) p.optional = true; }
    const ps = d.params.map((p) => `${p.rest ? '...' : ''}${p.name}${p.optional && !p.rest ? '?' : ''}: ${p.rest ? 'unknown[]' : 'unknown'}`).join(', ');
    return `export function ${d.name}(${ps}): ${d.ret ?? (d.async ? 'Promise<unknown>' : 'unknown')};`;
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
  // COMPLETENESS BY CONSTRUCTION. Patterns over source text will always miss a form — measured 2026-07-30:
  // `export { … } from` cost seven declarations, `export class` two, and `ghMirrorPublish` is reachable at runtime
  // (the regression suite calls it through the namespace) in a form four separate greps did not find. Chasing forms
  // is unwinnable; the MODULE knows its own exports. Anything the namespace has and the parser missed is declared
  // as `unknown` — an honest weak type beats a name a consumer cannot reach at all, and the gate then compares both
  // directions so the gap can never be silent again.
  const decls = declarationsFor(src, (rel) => {
    try { return readFileSync(join(root, w, rel.replace(/^\.\//, '')), 'utf8'); } catch { return null; }
  });
  try {
    const ns = await import(pathToFileURL(join(root, w, main)).href);
    for (const name of Object.keys(ns))
      if (name !== 'default' && !decls.some((d) => d.name === name)) decls.push({ kind: 'const', name, type: 'unknown' });
  } catch { /* not importable here: the source-derived set is all we can honestly claim */ }
  if (!decls.length) continue;
  writeFileSync(join(root, w, main.replace(/\.m?js$/, '.d.ts')), render(pkg.name, decls));
  wrote++; total += decls.length;
  console.log(`  ${pkg.name.padEnd(30)} ${String(decls.length).padStart(3)} declarations`);
}
console.log(`\n  ✓ ${total} declarations across ${wrote} packages — generated, never hand-written`);
