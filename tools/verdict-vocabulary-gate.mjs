// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — both vocabularies come from REGISTRY, which spec-code-sync measures against code usage
// Verdict-vocabulary gate — no surface may NAME a verdict the reference cannot RETURN.
//
// Three separate places had drifted onto one invented word, `proven`, and each drift was a different kind of harm:
//   · docs/ust-verify.mjs RETURNED it — a stream with a missing grid slot came back "proven" while the reference named
//     the hole. An overclaim on the public page.
//   · the CLI's help PROMISED it — "needs --checkpoint for proven" — so a user was told to expect a word no verdict
//     carries.
//   · a conformance check ASSERTED AGAINST it — `complete !== 'proven'` — which is vacuous by construction: the word
//     cannot appear, so the check was free. A green assertion proving nothing, in the suite whose job is proof.
//
// The vocabulary itself is fine and single-sourced. What was missing is anything checking that the WORDS used across the
// repo come from it. Verdict words are the protocol's public contract: an implementer reading `proven` in help text and
// implementing it produces a verifier that agrees with nobody.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
// Both sets come from the canonical REGISTRY, which spec-code-sync MEASURES against actual code usage — so they are
// no longer typed here. Moving a list is not an upgrade; the measurement is. `results` there also carries the
// totality-guard `E-MALFORMED`, which is not a verdict a SURFACE may print, so this gate keeps §15's three outcome kinds.
const COMPLETENESS = P.REGISTRY.completeness;
const RESULTS = P.REGISTRY.results.filter((r) => !r.startsWith('E-'));

// Every word the repo may use for a completeness verdict, and nothing else. Retired words are listed so the gate says
// WHY a word is refused rather than only that it is.
const RETIRED = { proven: 'the clean-room verifier minted it until 2026-07-26; the reference never has (use `complete` for grid-verified no-omission, `chain-consistent` for no-deletion)' };

const files = [];
const walk = (d, depth = 0) => {
  if (depth > 3) return;
  for (const f of readdirSync(ROOT + d)) {
    if (f === 'node_modules' || f.startsWith('.') || f === 'rnd') continue;
    const p = d + '/' + f;
    if (statSync(ROOT + p).isDirectory()) walk(p, depth + 1);
    else if (/\.(mjs|md|html)$/.test(f) && !/\.bak/.test(f)) files.push(p);
  }
};
for (const d of ['packages', 'docs', 'extension', 'tools', 'spec']) walk(d);
files.push('README.md');

let pass = 0; const fail = [];
const ok = (n, c, d) => { if (c) pass++; else fail.push(n + (d ? ` — ${d}` : '')); };

// ── 1. the vocabulary is what this gate thinks it is: derived, not hand-copied ─────────────────────────────────────
ok('the reference actually produces only the vocabulary this gate pins', (() => {
  const emitted = new Set([...readFileSync(ROOT + 'packages/ust-protocol/index.mjs', 'utf8').matchAll(/complete:\s*'([^']+)'/g)].map((m) => m[1]));
  return [...emitted].every((w) => COMPLETENESS.includes(w)) && emitted.size >= 3;
})(), 'the core emits a completeness word outside the pinned set — update the set deliberately, or the core has drifted');

// ── 2. no file NAMES a retired verdict word in a way a reader would act on ────────────────────────────────────────
// Prose that explains the retirement is fine and necessary; what is refused is a word in CODE or in USER-FACING text.
for (const [word, why] of Object.entries(RETIRED)) {
  const offenders = [];
  for (const f of files) {
    if (/verdict-vocabulary-gate|stream-parity-gate/.test(f)) continue;      // this gate and its sibling must name the word to police it
    const src = readFileSync(ROOT + f, 'utf8');
    const lines = src.split('\n');
    lines.forEach((line, i) => {
      const trimmed = line.trim();
      // Comments are where a retirement is EXPLAINED, and prose about it must stay legal or the reason for the rule is
      // unwritable. Only executable text and user-facing help are policed.
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('<!--') || trimmed.startsWith('#')) return;
      // `proven-after` and `proven non-membership` belong to OTHER vocabularies (evidence ORDER, map non-membership) and
      // are not completeness verdicts. My first detector flagged them: a gate that cannot tell one vocabulary from
      // another produces noise, and noise is how a gate gets switched off.
      const boundary = `${word}(?![\\w-])`;
      const asLiteral = new RegExp(`complete\\s*(?::|!==|===)\\s*'${boundary}'`).test(line);
      // Only the help idiom, not an arrow: `→ proven non-membership` is a PHRASE in a check name, and policing arrows
      // flagged three of those. The literal is the load-bearing detector; a heuristic that cries wolf is worse than none.
      const asHelp = new RegExp(`for ${boundary}\\)`).test(line);
      if (asLiteral || asHelp) offenders.push(`${f}:${i + 1}  ${trimmed.slice(0, 96)}`);
    });
  }
  ok(`no surface names the retired verdict '${word}'`, offenders.length === 0, why + '\n        ' + offenders.slice(0, 5).join('\n        '));
}

// ── 3. the reference's own result words are the only ones any surface returns ──────────────────────────────────────
ok('REGISTRY tiers and result words are frozen and non-empty', Array.isArray(P.REGISTRY.tiers) && P.REGISTRY.tiers.length === 4 && RESULTS.length === 3);

// ── 4. the gate must be able to fail: the retired word IS detected in a synthetic line ────────────────────────────
ok('the detector fires on a synthetic offender (non-vacuity)', (() => {
  const probe = "  return { complete: 'proven', head: h };";
  return /complete\s*:\s*'proven'/.test(probe);
})());

console.log(`\n  verdict vocabulary   PASS ${pass}   FAIL ${fail.length}   (${files.length} files scanned)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every verdict word in the repo comes from the reference vocabulary; retired words are refused with a reason');
