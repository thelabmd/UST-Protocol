// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the MARKER WORDS are the subject — matching them is the point, not a sample
//
// A RECORD OF A PAST DEFECT MUST CARRY ITS CLOSING — or a reader supplies the present tense.
//
// This repository records its own failures on purpose: a corpus in which every idea was correct on the first
// try teaches nothing and is a lie about how the work went. That discipline has a failure mode unique to it,
// and it was MEASURED on 2026-08-05 rather than imagined. STANDING — the narration form is a permanent feature
// of how this tree records itself, not a defect awaiting a fix, and this gate exists to keep it readable.
//
// An extraction agent read this tree and reported THREE LIVE DEFECTS in its checking layer: a local runner
// matching a pattern instead of the pipeline, a workflow the CI provider could not load while the local mirror
// was green, a vacuity battery that passed on an emptied manifest. All three were HISTORY — found, recorded and
// closed weeks earlier, recorded exactly as the discipline demands. The agent was not careless. The records say
// `Measured 2026-07-28: it was like this` and never say what closed them, so the reader supplies the tense.
//
// To anyone who was not there, an honest record of a fixed defect is indistinguishable from an open hole. For a
// client-facing engagement that is a liability — the document proving rigour proves negligence. So:
//
//   a record of a past defect is INCOMPLETE until it states what closed it, in the same place, where the reader
//   already is.
//
// ── WHAT THIS GATE CAN AND CANNOT SEE ────────────────────────────────────────────────────────────────────────
// It enumerates the DOMAIN — every `measured <date>` narration in the tree — and requires each to carry one of
// three markers within its own paragraph. It CANNOT judge whether the marker is TRUE; a wrong `CLOSED` is worse
// than none, and only a human or a git-history check establishes that. What it prevents is the SILENT case: a
// new defect narration landing with no disposition at all.
//
// THE PIN IS A RATCHET, NOT A FLOOR. The tree carries a backlog of unmarked records that predate the rule, and
// pretending otherwise would be the retroactive straight line this repository forbids. So the count is pinned at
// exactly what it is, and may only go DOWN: a new unmarked record fails immediately, and clearing an old one
// requires lowering the pin deliberately. A floor would let the backlog grow back invisibly.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

// The RATCHET. Lower it when records are closed; it may never rise. STANDING — this is the pin itself, a
// live count rather than a defect narration.
const PINNED_UNMARKED = 60;

// The narration form, derived from the tree rather than chosen: `Measured 2026-08-04`, `MEASURED, 2026-07-28`,
// `measured live 2026-08-03`. What makes it a DEFECT narration rather than a fact is the date — a dated
// observation is a report about a moment, and a moment passes.
const NARRATION = /\bmeasured\b[, ]+(?:live[, ]+)?(20\d{2}-\d{2}-\d{2})/i;

// The three dispositions. `CLOSED` needs a date because a closing without one is the same defect one level up.
// `STANDING` is for a measurement that reports a PROPERTY rather than a defect — a number that is still true.
// `OPEN` must carry a reference, or it is a shrug.
const MARKERS = [
  { name: 'CLOSED', re: /\bCLOSED\b[^\n]{0,60}?20\d{2}-\d{2}-\d{2}/ },
  { name: 'STANDING', re: /\bSTANDING\b/ },
  { name: 'OPEN', re: /\bSTILL OPEN\b|\bOPEN\b[^\n]{0,40}(#\d+|thelabmd\/)/ },
];

const files = execFileSync('git', ['ls-files', 'tools/*.mjs', 'packages/*/*.mjs', 'spec/*.md'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter(Boolean);

const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// A PARAGRAPH is the reader's unit — the block they are inside when they meet the sentence. Splitting on blank
// lines is right for markdown and, in these sources, for comment blocks too: a comment block separated from the
// next by a bare `//` is one paragraph, and that is exactly the span a reader takes as one thought.
const paragraphs = (text) => text.split(/\n\s*\n|\n\s*\/\/\s*\n/);

const unmarked = [];
let narrations = 0;

for (const rel of files) {
  let text;
  try { text = readFileSync(ROOT + rel, 'utf8'); } catch { continue; }
  const paras = paragraphs(text);
  for (let i = 0; i < paras.length; i++) {
    const p = paras[i];
    if (!NARRATION.test(p)) continue;
    narrations++;
    // The marker may sit in this paragraph or in the ONE that follows — an appended closing is a new paragraph
    // by construction, and requiring it inline would force rewriting the original record, which is forbidden.
    const window = p + '\n' + (paras[i + 1] ?? '');
    if (!MARKERS.some((m) => m.re.test(window))) {
      unmarked.push(`${rel} :: ${(p.match(NARRATION) || [])[0]} — ${p.replace(/\s+/g, ' ').slice(0, 90)}…`);
    }
  }
}

check(narrations >= 40, `only ${narrations} dated narration(s) found — the domain probe has gone blind and every check below would pass for free`);

// THE RATCHET, both directions. Growing fails loudly; shrinking fails too, so the pin cannot silently drift
// away from the work actually done — lowering it is a deliberate edit, which is the point.
check(unmarked.length <= PINNED_UNMARKED,
  `${unmarked.length} dated defect narration(s) carry NO disposition — above the pin of ${PINNED_UNMARKED}. A record without CLOSED/STANDING/OPEN reads to a stranger as an open hole:\n    ` + unmarked.slice(0, 8).join('\n    '));
check(unmarked.length >= PINNED_UNMARKED,
  `${unmarked.length} unmarked narration(s) — BELOW the pin of ${PINNED_UNMARKED}. Records were closed and the pin was not lowered; drop it to ${unmarked.length} so the ratchet keeps holding.`);

// The gate must DISCRIMINATE, or it is asserting against nothing.
{
  const marked = 'Measured 2026-01-01: it broke.\n\nCLOSED 2026-01-02 by the guard below.';
  const bare = 'Measured 2026-01-01: it broke.\n\nAnd nothing more was said.';
  const seen = (t) => paragraphs(t).some((p, i, a) => NARRATION.test(p) && MARKERS.some((m) => m.re.test(p + '\n' + (a[i + 1] ?? ''))));
  check(seen(marked), 'CONTROL: a narration WITH a dated closing was not recognised — the marker probe does not fire');
  check(!seen(bare), 'CONTROL: a narration with NO disposition was accepted — the gate cannot tell the two apart and proves nothing');
}

console.log(`\n  record closure   PASS ${pass}   FAIL ${fail.length}   (${narrations} dated narration(s) · ${unmarked.length} unmarked, pin ${PINNED_UNMARKED})`);
for (const f of fail) console.log('    ✗ ' + f);
console.log(fail.length ? '' : `  ✓ no dated defect narration lands without a disposition — the backlog is pinned at ${PINNED_UNMARKED} and may only shrink\n`);
process.exit(fail.length ? 1 : 0);
