// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the diagnostic set is READ from the core; a supply remedy must be produced by the
// helper that can see the call, never by a literal whose correctness depends on a guard nobody related to it
//
// REMEDY GUARD (F.5.1d) — no verdict may prescribe an input the call already supplied.
//
// A SUPPLY remedy is a promise: provide `i` and the coordinate rises. A call that already holds `i` has produced
// the verdict `i` yields, so the clause is refuted by the very call that printed it. A literal inside a verdict
// branch is evaluated without reference to the options, and therefore obeys the invariant only when the branch
// CONDITION happens to imply the absence its sentence asserts — correctness by coincidence, drifting in silence.
//
// THE DOMAIN IS ENUMERATED, NOT SAMPLED. Two rosters, both read from the source:
//
//   diagnostics — every `detail:` in the core that is not inside a comment. Not a hand-list of the ones a reader
//                 recalled; that is how the 2026-08-03 instance survived three green gates.
//   option names — every `opts.<name>` the core actually reads. A hand-written vocabulary would go stale the first
//                 time an option was added, and would go stale SILENTLY, which is the same defect one level up.
//
// WHAT IT CANNOT SEE: a remedy phrased without a verb this gate knows, or one naming an option by a synonym
// ("the genesis document" rather than `genesis`). It closes the mechanical case — a literal naming a real option
// in a prescriptive sentence — and leaves the paraphrase to a reader.
//
// REPLACE clauses are deliberately NOT caught: re-fetch a stale log, rotate, re-anchor. There the slot is filled
// and the ARTEFACT is not, so the precondition is a value the branch already computed. Catching them would delete
// diagnostics that work, and a gate that deletes what works is a gate that gets switched off.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = resolve(ROOT, 'packages/ust-protocol/index.mjs');
const text = readFileSync(SRC, 'utf8');
const lines = text.split('\n');

// Roster 1 — the option vocabulary the core actually reads. TWO access shapes, and reading only the first is how
// this gate shipped blind: `resolveAuthority` DESTRUCTURES its options in a single statement, so seven names —
// keylog, nameMap, corroborated, servedNoFork, keylogFreshAsOf, keylogHeadAnchor, trust — never appear as
// `opts.<name>` anywhere. A supply clause naming one of them was already in the tree, unexamined, while the gate
// printed PASS. The gate that exists to refuse correctness-by-coincidence was itself correct by coincidence: the
// two clauses it did check happen to use the dotted form.
const OPTIONS = new Set();
for (const m of text.matchAll(/\bopts\.([A-Za-z_$][\w$]*)/g)) OPTIONS.add(m[1]);
// `= opts` and `= O` — the admitted-options snapshot is bound to a short name at several doors, and a destructured
// option is no less an option for having been renamed on the way in.
for (const m of text.matchAll(/(?:const|let)\s*\{([^}]{5,600})\}\s*=\s*(?:opts|O)\b/g))
  for (const raw of m[1].split(',')) {
    const name = raw.trim().split(/[:=]/)[0].trim();
    if (/^[A-Za-z_$][\w$]*$/.test(name)) OPTIONS.add(name);
  }

// Roster 2 — every STRING LITERAL in the core, with comments excluded by scanning rather than by pattern.
//
// The first draft read LINES containing `detail:`, and it could not fail its own control: a diagnostic assembled
// from several concatenated pieces puts the prescriptive text on a line the word `detail:` never appears on, so
// the capacity site was invisible while the gate printed PASS. Reading literals is line-independent by
// construction. Comments must be excluded by a scanner and not by a regex, because the prose in this very file
// contains the phrases being detected — a gate that trips on its own explanation teaches its reader to disable it.
const LITERALS = [];
{
  let i = 0, line = 1;
  const n = text.length;
  while (i < n) {
    const c = text[i], d = text[i + 1];
    if (c === '\n') { line++; i++; continue; }
    if (c === '/' && d === '/') { while (i < n && text[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') { i += 2; while (i < n && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') line++; i++; } i += 2; continue; }
    if (c === "'" || c === '"' || c === '`') {
      const quote = c, start = i, startLine = line;
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '\n') line++;
        i++;
      }
      i++;
      LITERALS.push({ line: startLine, start, value: text.slice(start + 1, i - 1), before: text.slice(Math.max(0, start - 90), start) });
      continue;
    }
    i++;
  }
}
const DIAGNOSTICS = LITERALS;

const fail = (msg) => { console.error('FAIL  ' + msg); process.exitCode = 1; };

// EMPTY IS NOT BLIND — but a core with no options read, or no diagnostics at all, is not a clean core: it is a
// scan that lost its target. Either roster coming back empty means this gate stopped measuring what it names.
if (OPTIONS.size === 0) fail('no `opts.<name>` reads found in the core — the option roster is empty, so every check below is vacuous');
if (DIAGNOSTICS.length === 0) fail('no `detail:` diagnostics found in the core — this gate scanned nothing and cannot report clean');

// A SUPPLY verb and the window it governs. `pass opts.x` and `supply x` are the two shapes the core uses;
// `provide`/`give` are included because they are the words a future author reaches for next.
// The window must admit `.` — the first draft excluded it to stop at a sentence end, and `pass opts.capacity`
// then truncated to `pass opts`, so the capacity site read as UNCHECKED while the gate printed PASS. A detector
// whose window ends before the noun is a detector that measures its own punctuation.
const SUPPLY = /\b(supply|provide|give|pass)\b[^;]{0,45}/gi;

let checked = 0, guarded = 0;
for (const d of DIAGNOSTICS) {
  for (const m of d.value.matchAll(SUPPLY)) {
    const clause = m[0];
    const named = [...OPTIONS].filter((o) => new RegExp('\\b' + o + '\\b').test(clause));
    if (named.length === 0) continue;
    checked++;
    // The clause must be produced by the helper that can see the call. The literal must sit in the argument
    // position of `supplyRemedy(opts, '<input>',` — read from the text immediately preceding it, so a helper call
    // several lines above a differently-named clause cannot vouch for this one.
    const wrapped = named.some((o) => new RegExp(`supplyRemedy\\(\\s*opts\\s*,\\s*['"\`]${o}['"\`]\\s*,\\s*$`).test(d.before));
    if (wrapped) { guarded++; continue; }
    fail(`${SRC.replace(ROOT + '/', '')}:${d.line} — prescribes ${named.map((n) => '`' + n + '`').join(', ')} in a supply clause that no helper guards`);
    console.error(`      clause: …${clause.trim()}…`);
    console.error('      F.5.1d: route it through supplyRemedy(opts, <input>, <clause>) so a call that already');
    console.error('      supplied it sees silence rather than a promise it can refute.');
  }
}

console.log(`remedy-guard: ${DIAGNOSTICS.length} string literal(s), ${OPTIONS.size} option name(s) read from source`);
console.log(`              ${checked} supply clause(s) naming an option · ${guarded} guarded`);

// A gate that finds nothing to check is reporting on its own blindness, not on the core. The core HAS supply
// remedies; if none is visible, the detection shape has drifted away from how they are written.
if (process.exitCode !== 1 && checked === 0)
  fail('no supply clause naming an option was found at all — the core has them, so this detector has gone blind');

// The summary line carries the ✓ and the counts the sibling gates use, so a report composed from this tree quotes
// a measurement rather than «produced no summary line» — a gate that cannot be quoted is a gate a report paraphrases.
if (process.exitCode !== 1)
  console.log(`  ✓ every supply remedy is produced by the helper that can see the call — ${checked} clause(s) over ${OPTIONS.size} option name(s) in both access shapes`);
