// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — the ROSTER of claimable artifacts is hand-typed, and under the weaker-side rule that
// roster IS the domain: a claim about an artifact nobody listed passes unseen. Only the EXISTENCE half is derived
// from the tree (a file glob per entry). Declared 3 rather than 2 for that reason — the stronger grade would be an
// over-claim about a list somebody has to remember to extend.
//
// PROMISED-ARTIFACTS GATE — a document may not speak of an artifact that does not exist as though it does.
//
// WHY (measured 2026-08-09). `PORTING.md` told a stranger to "call a conforming verifier (`ust-protocol` in JS,
// THE GO BINARY, or the MCP)", said "~90 % of consumers call … the Go binary", and called Go "the first official
// non-JS SDK". `packages/ust-cli/README.md` said "The Go binary reproduces this same surface". There are ZERO
// `.go` files in this repository and #34 — the card that would create one — is open. CLOSED 2026-08-09 for the
// WORDING (every mention in the tracked corpus is planned-tense and this gate holds it there); OPEN for the
// substance — until #34 lands, this project has ONE implementation and now says so.
//
// This is not a typo class. A second independent implementation is the ANTI-MONOCULTURE argument: it is what
// makes a differential test mean anything, and it is one of the reasons an outsider would trust the protocol at
// all. Claiming one that does not exist buys exactly the credibility it cannot back, and it is invisible to
// every other gate here — they check code against code, and prose is neither.
//
// Bearing `(#34)` next to the claim does NOT make it honest: "the Go binary (#34)" reads as "it exists, here is
// its ticket". The marker has to say the thing is not there.

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', '.wrangler', 'tool-results']);

function walk(dir, hit, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, hit, out);
    else if (hit(e.name)) out.push(p.slice(ROOT.length));
  }
  return out;
}

/**
 * Each entry: what a document might CLAIM, how to test whether it exists, and the phrasings that make a mention
 * honest while it does not. `exists` is derived from the tree, never declared — a roster that also declared
 * existence would be a document checking a document.
 */
const ARTIFACTS = [
  {
    claim: /\bGo (binary|SDK|implementation|verifier)\b/i,
    // The detector looks in `packages/`, where SDKs live, NOT anywhere a `.go` file might appear. Measured
    // 2026-08-10, hours after this gate shipped: adding a 39-line MEASURING INSTRUMENT under `tools/` — it calls
    // one stdlib primitive and implements no protocol rule — flipped this to "exists in the tree" and would have
    // re-licensed every claim the gate was written to stop. A detector that counts any file of the right
    // extension answers "is there Go here", and the claim under test is "is there a Go IMPLEMENTATION".
    exists: () => walk(join(ROOT, 'packages'), (n) => n.endsWith('.go')).length > 0,
    // Honest = the sentence itself denies existence, in ANY form. Planned-tense is one form; stating the count is
    // another — "claimed a Go binary in four places and contains zero Go files" is a true sentence about a past
    // false one, and a detector that only knew the word "planned" fired on it. Widening the NOTION beats adding an
    // exception for the line that caught me.
    honest: /\b(planned|not written|does not exist|not yet|would|intended|meant to)\b|\bzero\b[^.]*\bfiles?\b|\bcontains no\b/i,
    label: 'Go binary / SDK',
  },
  {
    claim: /\bRust (binary|SDK|implementation|verifier)\b/i,
    exists: () => walk(join(ROOT, 'packages'), (n) => n.endsWith('.rs')).length > 0,
    honest: /\b(planned|not written|does not exist|not yet|would|follow the same pattern)\b/i,
    label: 'Rust binary / SDK',
  },
];

// The domain is what a STRANGER can read: git-tracked documents. Walking the working tree instead pulled in
// `rnd/` — gitignored internal audit material, where "commission or build the independent Go/Rust
// implementation" is a correct sentence about work to be done, not a claim made to anyone. A gate that fires on
// private notes teaches you to widen its exceptions until it fires on nothing.
const DOCS = execFileSync('git', ['-C', ROOT, 'ls-files', '*.md'], { encoding: 'utf8' })
  .trim().split('\n').filter(Boolean);
let fail = 0, checked = 0, pass = 0;
const report = [];

for (const a of ARTIFACTS) {
  const present = a.exists();
  for (const rel of DOCS) {
    const text = readFileSync(join(ROOT, rel), 'utf8');
    const lines = text.split('\n');
    for (const [n, line] of lines.entries()) {
      if (!a.claim.test(line)) continue;
      checked++;
      // The unit is the SENTENCE, not the line: markdown hard-wraps, and this gate first fired on its own
      // changelog entry — "this repository claimed a Go binary" ended the line, "and contains zero Go files"
      // began the next. A line-sized window makes honesty depend on where the text happened to wrap.
      const window = lines.slice(Math.max(0, n - 1), n + 2).join(' ');
      if (present || a.honest.test(window)) { pass++; continue; }
      fail++;
      report.push(`  ✗ ${rel}: speaks of the ${a.label} as existing, and it does not (no matching file in the tree). ` +
        `Say it is PLANNED — a ticket number beside the claim reads as "it exists, here is its ticket".\n      ${line.trim().slice(0, 150)}`);
    }
  }
  report.push(`  ${present ? '✓' : '·'} ${a.label}: ${present ? 'exists in the tree' : 'ABSENT from the tree — mentions must be marked planned'}`);
}

// CONTROL — a gate over prose that matches nothing is a gate that cannot fail. If the corpus stops mentioning
// these artifacts entirely, the check is vacuous and says so rather than printing a green tick.
if (checked === 0) {
  console.log('\n  promised artifacts   VACUOUS — no document mentions any rostered artifact; the gate proved nothing\n');
  process.exit(1);
}

console.log(`\n  promised artifacts   PASS ${pass}   FAIL ${fail}   (${checked} mention(s) across ${DOCS.length} documents)`);
for (const r of report) console.log(r);
if (fail) { console.log('\n  ✗ a document claims an artifact this tree does not contain\n'); process.exit(1); }
console.log('\n  ✓ every mention of a rostered artifact either matches the tree or says it is planned\n');
