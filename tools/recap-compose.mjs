// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:every number it prints is READ from a command's output or a file in this tree; the only literals are the section headings, and the FILL markers it refuses to emit
//
// Compose the measured skeleton of a report — so the numbers in it are measured BY CONSTRUCTION.
//
// MEASURED, 2026-08-03: the first recap written in this shape (#132) had every number typed by hand from a warm
// context. They were right, but right by ACCIDENT — nothing in the tree connected "5 days published", "9 of 13
// commands", "833 checks" to the artifacts that produce them. That is the defect class this repo spends most of its
// gates on, stated in printed-command-gate's own header: text ABOUT code, authored beside the code, drifting from it
// silently. A month later nobody can separate a measured number from a remembered one.
//
// CLOSED 2026-08-03 by `701e2632` — tools: compose a recap's measured skeleton instead of remembering it. In
// this tree a narration is written in the commit that fixes what it describes, and blame places this
// paragraph there; noted 2026-08-05, appended rather than rewritten.
//
// THE SPLIT, and it is deliberate. A report is two substances:
//   MEASURED  — counts, dates, versions, commits, the issue list, the sealed diary block. Mechanically derivable,
//               therefore never typed. This tool fills them.
//   JUDGMENT  — what the defect WAS, why it was invisible, the rule worth keeping. No tool writes those.
//               This tool marks them and REFUSES to let a skeleton with an unfilled mark be posted.
//
// The refusal is the load-bearing half. A generator that emits a placeholder and trusts the author to notice is the
// same shape as the four `${invocation()}` strings that reached operators verbatim: the text was right, and nobody
// ran the check that reads it. `--check` is that check.
//
// ── THREE FORMS, CUT BY THE QUESTION THEY ANSWER (2026-08-03) ─────────────────────────────────────────────────
// A form is chosen by what the CARD MEANS, never by how much there is to write. Length is a judgement made at
// composition time; a form selected by length tells a reader nothing, because the same card could have gone either
// way. These three answer different questions and cannot substitute for one another:
//
//   incident   — a defect or a gap: what broke, what it would have cost, why the defences did not see it, what proves
//                the fix. DEFAULT, because it is what most cards in this tracker are. Whether it reached a consumer
//                is NOT a second form: it is the §2 line that says so, next to the negative half that says what was
//                not affected.
//   audit      — a claim was TESTED: which obligations were examined, what each finding is CLASSED as, and — the part
//                only this form has — what the evidence does NOT establish and what the conclusion remains
//                conditional on. An audit that cannot state its own boundary is marketing.
//   delivery   — something was BUILT and handed over: what exists now, how it was verified, where its edges are.
//                No root cause, because nothing failed. Do not reach for this to avoid writing an incident.
//
// ── WHO DECIDES THE FORM ─────────────────────────────────────────────────────────────────────────────────────
// Not the author's taste, and never the length of what there is to say. THE CARD decides, through an ordered
// procedure with no ties — the same discipline §13 applies to tiers: the rules are fixed, the card is the input.
// Asked in this order, exactly one form is reachable:
//
//   1. Did something behave contrary to an obligation — the spec's, a gate's, or one we stated ourselves?
//      → INCIDENT. Asked FIRST on purpose, and *"it never reached a consumer"* is not an escape from it: that is
//        a LINE in §2 beside the negative half, not a different form. A defect caught before publication is still
//        a defect, and letting it become a delivery note is how a tree stops learning from its own near misses.
//   2. Otherwise — was the work an EXAMINATION of a claim that could have come out the other way?
//      → AUDIT. The test is falsifiability, not effort. Reading code until satisfied is not an audit, because
//        nothing was risked; if no finding could have come back NON-CONFORMING, this is not one.
//   3. Otherwise — does something exist now that did not exist before?
//      → DELIVERY.
//   4. None of the three → the card is not finished. Do not compose a report in order to discover what it was.
//
// A CARD THAT WOULD TAKE TWO FORMS IS TWO CARDS. An audit that finds a non-conformance yields an audit record AND
// a defect card: they answer different questions, and closing one does not close the other. Measured in this
// tracker — #110 and #114 are audits, and each defect they surfaced carries its own number.
//
// ── WHEN A DIAGRAM IS DRAWN ──────────────────────────────────────────────────────────────────────────────────
// A diagram is earned by a RELATION the reader would otherwise have to hold in their head — a span, a path, a
// boundary. Never by a single value: "853 checks" is a number, and a chart of one number is decoration that costs
// the reader a parse. The conditions are per form and each is DECLARED BY A FLAG, so the scaffold appears because
// the author asserted the relation exists, not because the tool guessed:
//
//   --span      (any form)  the impact has DURATION — minutes stopped, slots missed, days a defect was published.
//                           Owner's rule, 2026-08-03: a span is DRAWN, not only stated. "11 minutes, 21 slots" is a
//                           number a reader must hold; a timeline is a shape they can see, and the distance between
//                           "entered" and "closed" stops being an abstraction.
//   --collapse  (any form)  several DIFFERENT situations produced ONE observation. This project's most repeated
//                           defect shape, and the one prose cannot carry: the point is that the arrows MEET, and a
//                           reader following sentences never sees them meet.
//   --path      (any form)  the mechanism is a CHAIN — a value crossing stages, where the defect is in the crossing
//                           and not in any one stage. The witness log dropped its signed half in a derivation, not
//                           in a field.
//   --findings  (audit)     three or more findings. Below three a list reads faster than a diagram; at three the
//                           reader starts needing the CLASSES grouped rather than enumerated.
//   --boundary  (audit)     the conclusion is bounded — something is established, something is not, something stays
//                           conditional on an open gate. This is the one diagram an external reader will look at.
//   --surfaces  (delivery)  the thing built spans more than one surface or artifact, and their relation is the
//                           delivery. One command on one surface needs no picture.
//
// ── AND THE COLOURS ARE NOT A CHOICE ─────────────────────────────────────────────────────────────────────────
// Every diagram is emitted through `mermaid()` from tools/lab-palette.mjs, which carries the theme directive and
// decides classDefs from the diagram family. MEASURED on this file's own first version: the timeline scaffold was
// hand-written with a bare ```mermaid fence and shipped UNTHEMED — the palette existed, was correct, and was simply
// not called. So `--check` now REFUSES a report carrying a mermaid block without the theme directive: a rule that
// only lives in a comment is a rule the next author skips, and this one was skipped by its own author on day one.
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mermaid, mermaidInit } from './lab-palette.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const arg = (n, d = null) => { const i = process.argv.indexOf('--' + n); return i > -1 ? (process.argv[i + 1] ?? true) : d; };
const on = (n) => arg(n, null) !== null;   // a scaffold flag ASSERTS a relation; its value is never read
const sh = (cmd, args, opts = {}) => { try { return execFileSync(cmd, args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); } catch (e) { return opts.softFail ? null : `«unavailable: ${String(e.message).split('\n')[0].slice(0, 70)}»`; } };

// ── --check: the refusal. Runs against a composed file before it is posted.
const checkFile = arg('check');
if (checkFile) {
  const body = readFileSync(String(checkFile), 'utf8');
  // `[\s\S]*?` and not `[^>]*`, measured 2026-08-07: the diagram markers this same file EMITS contain an angle
  // bracket in their own instructions (`--<kind>`), so a class excluding `>` stopped there and never reached the
  // closing `>>>`. Five markers sat in a composed report while this check printed that none remained — the exact
  // failure it exists to prevent, in the tool that prevents it. CLOSED 2026-08-07 in this edit.
  const MARK = /<<<[A-Z]+:[\s\S]*?>>>/g;
  const marks = [...body.matchAll(MARK)].map((m) => m[0]);
  // CONTROL — the detector must fire on a REAL marker and stay silent on ordinary prose. The hit case now carries
  // an inner `>` and a newline, because that is the shape the generator produces; a control exercising only the
  // easy shape is how this check passed for a marker it could not see.
  const one = (t) => new RegExp(MARK.source).test(t);
  const CONTROL_HIT = one('a <<<FILL: pick a kind with --<kind>\n  and delete this>>> here');
  const CONTROL_MISS = one('an ordinary sentence about <angle brackets> and code');
  if (!CONTROL_HIT || CONTROL_MISS) { console.error('✗ CONTROL: the placeholder detector does not discriminate — this check is blind'); process.exit(1); }

  // THE PALETTE IS A GATE, NOT A CONVENTION. A mermaid block without the theme directive renders in mermaid's own
  // colours — legible, plausible, and not ours. That is the failure mode a comment cannot prevent, measured on this
  // very file: the rule was written and then broken by the same hand in the same change.
  // A NODE LABEL MUST BE QUOTED, and this is not style. A mermaid label is unquoted by default, so `{`, `(`
  // and `[` inside it are SYNTAX — `{` opens a diamond and the parse dies. Measured 2026-08-07: two of three
  // diagrams in a posted report failed to render on GitHub while this check reported all three carried the
  // theme. The theme says how it looks; nothing said whether it PARSES. CLOSED 2026-08-07 by the rule below,
  // which needs no mermaid dependency: quoting makes the whole label a string, so no character can be syntax.
  const LABEL = /^\s*([A-Za-z_]\w*)\[(.+?)\]\s*$/gm;
  const unquoted = [];
  for (const b of [...body.matchAll(/```mermaid\r?\n([\s\S]*?)```/g)].map((m) => m[1])) {
    for (const m of b.matchAll(LABEL)) {
      const label = m[2];
      if (!(label.startsWith('"') && label.endsWith('"'))) unquoted.push(`${m[1]}[${label.slice(0, 44)}`);
    }
  }
  if (unquoted.length) {
    console.error(`✗ ${unquoted.length} mermaid label(s) are UNQUOTED — a brace or bracket inside one is syntax, and the diagram will not render:`);
    for (const u of unquoted) console.error('    ' + u);
    process.exit(1);
  }
  // CONTROL — the rule must fire on the shape that actually broke, and stay silent on a quoted label.
  const labelUnquoted = (t) => { const r = new RegExp(LABEL.source, 'gm'); const m = [...t.matchAll(r)]; return m.length > 0 && !m.every((x) => x[2].startsWith('"')); };
  if (!labelUnquoted('  A[final: false, {reason}]') || labelUnquoted('  A["final: false, {reason}"]')) {
    console.error('✗ CONTROL: the label rule does not discriminate — this check is blind'); process.exit(1);
  }

  // ── every SLOTTED section decides: a diagram, or a stated refusal. An absence is neither. ──────────────
  const declared = body.match(/<!-- diagram-slots: ([\d,]*) -->/);
  if (!declared) {
    console.error('✗ the composed file declares no diagram-slot list — recompose it; a check cannot enumerate a domain the file does not carry');
    process.exit(1);
  }
  const want = declared[1] ? declared[1].split(',').map(Number) : [];
  const parts = body.split(/^## § /m).slice(1);
  const bySection = new Map(parts.map((p) => [Number(p.split(/\s/)[0]), p]));
  const undecided = [], reasons = new Map();
  for (const n of want) {
    const sec = bySection.get(n) ?? '';
    const hasDiagram = sec.includes('```mermaid');
    const refusal = sec.match(/^> \*\*no diagram\*\* — (.{25,})$/m);
    if (hasDiagram) continue;
    if (!refusal) { undecided.push(n); continue; }
    reasons.set(n, refusal[1].trim());
  }
  if (undecided.length) {
    console.error(`✗ § ${undecided.join(', § ')} — neither a diagram nor a stated refusal. Removing the slot is not deciding it:`);
    console.error('    write the diagram, or  > **no diagram** — <why no collapse, no span and no path applies here>');
    process.exit(1);
  }
  // A shrug repeated is a shrug. Distinct sections owe distinct reasons, or the author answered once and pasted.
  const seen = new Map();
  for (const [n, r] of reasons) { const k = r.toLowerCase(); if (seen.has(k)) { console.error(`✗ § ${seen.get(k)} and § ${n} give the SAME refusal — one judgement pasted twice is not two judgements`); process.exit(1); } seen.set(k, n); }

  const THEMED = /^%%\{init:/;
  const blocks = [...body.matchAll(/```mermaid\r?\n([\s\S]*?)```/g)].map((m) => m[1]);
  const bare = blocks.filter((b) => !THEMED.test(b.trimStart()));
  // CONTROL — the palette detector must read a themed block as themed and a bare one as bare.
  const P_HIT = !THEMED.test('flowchart LR\n  A --> B');
  const P_MISS = THEMED.test(mermaidInit() + '\nflowchart LR\n  A --> B');
  if (!P_HIT || !P_MISS) { console.error('✗ CONTROL: the palette detector does not discriminate — this check is blind'); process.exit(1); }
  if (bare.length) {
    console.error(`\n  ✗ ${bare.length} mermaid block(s) carry NO theme directive — they will render in mermaid's default\n    palette, which is legible, plausible and not ours. Emit through \`mermaid()\` in tools/lab-palette.mjs\n    rather than writing the fence by hand:\n`);
    for (const b of bare) console.error('    ' + b.trim().split('\n')[0].slice(0, 90));
    process.exit(1);
  }

  if (marks.length) {
    console.error(`\n  ✗ ${marks.length} section(s) still carry a FILL marker — a skeleton is not a report, and an unfilled\n    marker posted to an issue reads as the tool being broken at the moment a reader trusts it:\n`);
    for (const m of marks) console.error('    ' + m.slice(0, 110));
    process.exit(1);
  }
  console.log(`  ✓ no FILL marker remains — every judgment section was written by a person`);
  console.log(`  ✓ ${blocks.length} mermaid block(s) carry the lab theme`);
  process.exit(0);
}

const FORMS = ['incident', 'audit', 'delivery'];
const PROCEDURE = [
  '  the form follows the CARD, asked in this order — exactly one is reachable:',
  '    1. did something behave contrary to an obligation?          → incident   («it never shipped» is a §2 line, not another form)',
  '    2. else: was a claim EXAMINED, and could it have failed?     → audit      (falsifiability, not effort)',
  '    3. else: does something exist now that did not before?       → delivery',
  '    4. none of the three                                         → the card is not finished; do not compose',
  '  a card that would take two forms is TWO CARDS.',
].join('\n');
const formGiven = arg('form', null) !== null;
const form = String(arg('form', 'incident'));
const round = Number(arg('round'));
const issue = Number(arg('issue'));
if (!FORMS.includes(form) || !Number.isInteger(round) || !Number.isInteger(issue)) {
  console.error('usage: node tools/recap-compose.mjs --round <n> --issue <n> [--form incident|audit|delivery]');
  console.error('         [--since <sha>] [--symbol <name>] [--package <npm-name>] [--gates "a,b,c"]');
  console.error('       diagram scaffolds, each ASSERTING the relation exists:');
  console.error('         --span       the impact has a duration        (any form)');
  console.error('         --path       the mechanism is a chain          (any form)');
  console.error('         --findings   three or more findings            (audit)');
  console.error('         --boundary   the conclusion is bounded         (audit)');
  console.error('         --surfaces   more than one surface delivered   (delivery)');
  console.error('       node tools/recap-compose.mjs --check <composed-file>   # REFUSES a FILL marker or an unthemed diagram');
  console.error('\n' + PROCEDURE);
  if (!FORMS.includes(form)) console.error(`\n  unknown --form "${form}" — a form is chosen by the QUESTION the card answers, and this tool refuses to\n  invent a fourth: ${FORMS.join(' | ')}`);
  process.exit(1);
}
// A DEFAULT IS NOT A DECISION. `incident` is the right default because it is what most cards here are, but a form
// that arrived by omission was never chosen — so the procedure is printed and the author has to disagree with it
// on purpose. Printed to stderr, so it never reaches the composed report.
if (!formGiven) console.error(`\n  --form not given; composing as \`incident\`. That is a DEFAULT, not a decision:\n\n${PROCEDURE}\n`);
const FILL = (what) => `<<<FILL: ${what}>>>`;

// ── THE SCAFFOLDS. Every one goes through `mermaid()`, so none of them can arrive hand-coloured.
const F = (w) => `<<<FILL: ${w}>>>`;
const ganttScaffold = () => mermaid([
  'gantt', '  dateFormat YYYY-MM-DD HH:mm', '  axisFormat %H:%M',
  '  section what a consumer saw', `  ${F('label')} :crit, ${F('start')}, ${F('duration')}`,
  '  section this tree', `  ${F('label')} :done, ${F('start')}, ${F('duration')}`,
].join('\n'));
const pathScaffold = () => mermaid([
  'flowchart LR', `  A[${F('origin — where the value was correct')}]`,
  `  B[${F('the crossing — where it was rebuilt, derived or copied')}]`,
  `  C[${F('destination — what it became')}]`,
  '  A --> B --> C', '  class A valid', '  class B accent', '  class C invalid',
].join('\n'));
const findingsScaffold = () => mermaid([
  'flowchart TB', `  S[${F('obligation set examined')}]`,
  `  C1[CONFORMING · ${F('n')}]`, `  C2[NON-CONFORMING · ${F('n')}]`,
  `  C3[INDETERMINATE · ${F('n')}]`, `  C4[BY-DESIGN · ${F('n')}]`,
  '  S --> C1', '  S --> C2', '  S --> C3', '  S --> C4',
  '  class S base', '  class C1 valid', '  class C2 invalid', '  class C3 muted', '  class C4 base',
].join('\n'));
const boundaryScaffold = () => mermaid([
  'flowchart TB', `  E[establishes · ${F('the bounded conclusion')}]`,
  `  N[does NOT establish · ${F('the bounded exclusion')}]`,
  `  K[conditional on · ${F('the open gate')}]`,
  '  E -.-> K', '  N -.-> K',
  '  class E valid', '  class N invalid', '  class K muted',
].join('\n'));
// THE COLLAPSE — several distinct situations producing ONE observation. This project's most repeated defect shape
// (F.5p: absence is two facts; F.5p.2: silence is two facts; the version boundary: three situations, one verdict),
// and the one a reader cannot hold in prose because the whole point is that the arrows MEET.
const collapseScaffold = () => mermaid([
  'flowchart LR', `  A[${F('situation 1')}]`, `  B[${F('situation 2')}]`, `  C[${F('situation 3, or delete')}]`,
  `  O[${F('the ONE observation all of them produce')}]`,
  `  R[${F('what the reader concludes — and why it is wrong for some of them')}]`,
  '  A --> O', '  B --> O', '  C --> O', '  O --> R',
  '  class A valid', '  class B invalid', '  class C muted', '  class O accent', '  class R invalid',
].join('\n'));
const surfacesScaffold = () => mermaid([
  'flowchart LR', `  O[${F('what an operator runs')}]`,
  `  A1[${F('artifact / surface')}]`, `  A2[${F('artifact / surface')}]`,
  `  V[${F('what proves it landed')}]`,
  '  O --> A1 --> V', '  O --> A2 --> V',
  '  class O accent', '  class A1 base', '  class A2 base', '  class V valid',
].join('\n'));

// A scaffold appears when its relation is ASSERTED; otherwise the section carries the question, so the author
// decides once and visibly rather than forgetting the option exists.
const drawn = (flag, build, prompt) => (on(flag) ? `\n${build()}\n` : `\n${FILL(prompt)}\n`);

// ── MEASURED: the corpus this tree produces right now
const conf = sh(process.execPath, ['packages/ust-protocol/conformance.mjs']);
const checks = /PASS (\d+)\s+FAIL (\d+)/.exec(conf ?? '');
const vectors = (() => { try { return JSON.parse(readFileSync(ROOT + 'vectors/conformance-vectors.json', 'utf8')).vectors.length; } catch { return null; } })();
const ciSteps = (() => { try { return [...readFileSync(ROOT + '.github/workflows/ci.yml', 'utf8').matchAll(/^\s*run:/gm)].length; } catch { return null; } })();

// ── MEASURED: when the defect entered, from git rather than from recollection
const symbol = arg('symbol');
// A commit SUBJECT routinely carries backticks — this repo's own subjects do — and dropping one inside a
// backticked span closes the span early and renders the rest as prose. Measured on the first composition: the
// `entered` line broke exactly that way. So the subject is placed OUTSIDE the code span, and only the sha and
// date go inside it.
const entered = (() => {
  if (!symbol || symbol === true) return null;
  const line = sh('git', ['log', '-S', String(symbol), '--format=%h\t%ad\t%s', '--date=short']).split('\n').filter(Boolean).pop();
  if (!line || !line.includes('\t')) return null;
  const [sha, date, ...rest] = line.split('\t');
  return { sha, date, subject: rest.join('\t').replace(/`/g, '') };
})();

// ── MEASURED: what a stranger would fetch, asked of the registry and not of the repo
const pkg = arg('package');
const published = pkg && pkg !== true ? sh('npm', ['view', String(pkg), 'dist-tags', '--json'], { softFail: true }) : null;
const publishedLine = published ? `- published at the time of writing: ${Object.entries(JSON.parse(published)).map(([t, v]) => `\`${t}\` → \`${v}\``).join(', ')}\n` : '';

// ── MEASURED: the commits of this round, and the gates whose summaries are quoted verbatim
const since = arg('since');
const commits = since && since !== true ? sh('git', ['log', '--format=%h %s', `${since}..HEAD`]) : sh('git', ['log', '--format=%h %s', '-5']);
const gateNames = String(arg('gates', '') || '').split(',').map((s) => s.trim()).filter(Boolean);
const gateLines = gateNames.map((g) => {
  const out = sh('npm', ['run', '--silent', g], { softFail: true });
  const summary = String(out ?? '').split('\n').filter((l) => /PASS \d+|✓|✗/.test(l)).pop();
  return `- \`npm run ${g}\` — ${summary ? summary.trim() : '«produced no summary line»'}`;
});

// ── MEASURED: the diary block, rendered from the signed bytes (never typed)
const diary = existsSync(ROOT + 'tools/recap-render.mjs')
  ? (sh(process.execPath, ['tools/recap-render.mjs', '--issue', String(round)], { softFail: true }) ?? '').split('\n').slice(1).join('\n').trim()
  : '';

// ── MEASURED: what this round leaves open
const openIssues = sh('gh', ['issue', 'list', '--state', 'open', '--limit', '20', '--json', 'number,title', '-q', '.[] | "- #\\(.number) — \\(.title)"'], { softFail: true });

const conformanceLine = `- ${checks ? `${checks[1]} conformance checks, ${checks[2]} failing` : '«conformance did not report»'}${vectors !== null ? `, ${vectors} vectors` : ''}`;
const ciLine = ciSteps !== null ? `- ${ciSteps} CI steps enumerated from the workflow (\`npm run ci:local\`)\n` : '';
const commitsBlock = `<details><summary>commits</summary>

\`\`\`
${commits}
\`\`\`

</details>`;
const openBlock = `<details><summary>open issues at the time of writing (trim to the ones this report leaves)</summary>

${openIssues ?? '«gh unavailable»'}

</details>`;
const diaryBlock = `## Diary

${diary || FILL('run `node tools/recap-render.mjs --issue ' + round + '` after sealing, and paste its output below the heading — never type it')}`;


// ── THE LAB REPORT HEAD — the FORM, not just the sections ────────────────────────────────────────────────────
//
// MEASURED 2026-08-04: report R-165 came out as bare markdown headings. The sections were right and the form was
// CLOSED 2026-08-04, in this same file: the head, the full-width tables, the alerts and the per-section
// diagram slots are emitted by the generator now, so the form no longer lives in whoever writes the report.
// gone, because #132's head — the centred plate and the fielded table — was assembled BY HAND that day and the
// generator never learned it. So every later report silently lost the identity unless someone remembered, which
// is the same defect class this file exists to close: the thing lives in a person instead of in the tool.
//
// Fields that can be read ARE read (round, issue, the closing commit, the repo). The rest are FILL marks, because
// severity and the sealed coordinate are judgements and a generator that guessed them would be inventing the part
// that matters.
const HEAD_KIND = { incident: 'INCIDENT REPORT', audit: 'AUDIT RECORD', delivery: 'DELIVERY NOTE' };
const cell = (v) => `\n\n${v}\n\n`;
const head = () => `# THE LAB<br>${HEAD_KIND[form]}

<table width="100%">
<tr><td valign="top">${cell('**REPORT**')}</td><td valign="top">${cell('`R-' + round + '`')}</td><td valign="top">${cell('**SUBJECT**')}</td><td valign="top">${cell(FILL('one line — what this report is about'))}</td></tr>
<tr><td valign="top">${cell('**OPENED**')}</td><td valign="top">${cell(FILL('`YYYY-MM-DD HH:MMZ` — when the issue was filed'))}</td><td valign="top">${cell('**CLOSED**')}</td><td valign="top">${cell(FILL('`YYYY-MM-DD HH:MMZ` and the elapsed time, or `open`'))}</td></tr>
<tr><td valign="top">${cell('**SEVERITY**')}</td><td valign="top">${cell(FILL('what the blast radius WAS — shipped to registry / caught before publication / latent'))}</td><td valign="top">${cell('**STATUS**')}</td><td valign="top">${cell(FILL('`🟢 CLOSED` or `🟡 OPEN`, and the CI sha it is green on'))}</td></tr>
<tr><td valign="top">${cell('**SEALED**')}</td><td valign="top">${cell(FILL('the diary `ust:` coordinate, or `—` while unsealed'))}</td><td valign="top">${cell('**ISSUE**')}</td><td valign="top">${cell('#' + issue)}</td></tr>
<tr><td valign="top">${cell('**RECORDED**')}</td><td valign="top">${cell(FILL('`contemporaneous`, or `retro — written YYYY-MM-DD about an event closed YYYY-MM-DD`'))}</td><td valign="top">${cell('**DIARY**')}</td><td valign="top">${cell(FILL('the sealed entry, or `none — retro closings carry no diary` (a diary written afterwards is a retelling, not a conclusion)'))}</td></tr>
<tr><td colspan="4" valign="top">${cell('<sub>' + FILL('one sentence a stranger can read first — what happened and who was affected') + '</sub>')}</td></tr>
</table>

`;


// ── THE FORM'S OWN ELEMENTS ──────────────────────────────────────────────────────────────────────────────────
// Measured against R-131/132/133: SIX full-width tables, THREE alerts, TWO-to-THREE diagrams each. R-165's first
// draft had one table, one diagram and no alerts — the sections were right and the FORM was gone, because it
// lived in whoever wrote the previous report.
//
// TABLES ARE HTML AND FULL WIDTH. A markdown table shrinks to its content and reads like a draft beside the ones
// before it; a comparison the reader must scan needs the page, not a column.
const td = (v) => `<td valign="top">\n\n${v}\n\n</td>`;
const tbl = (rows) => `<table width="100%">\n${rows.map((r) => '<tr>' + r.map(td).join('') + '</tr>').join('\n')}\n</table>`;
const alert = (kind, body) => `> [!${kind}]\n> ${body}`;

// ── A DIAGRAM IS DERIVED, NOT POSITIONED ─────────────────────────────────────────────────────────────────────
// Owner's rule, 2026-08-04: *not one or two in fixed sections — wherever a USEFUL one can be drawn, never for
// show. It is a derived part of the report: maybe every section, maybe one. If there is meaning, there is a
// diagram.*
//
// So the slot stands in EVERY section, and the flag names the SECTION it belongs in: `--collapse 1 --span 2
// --path 4`, in any combination or none. A generator that fixed the kinds to sections would be deciding, for the
// author, where meaning is — which is the one judgement it has no way to make.
const KINDS = { collapse: () => collapseScaffold(), span: () => ganttScaffold(), path: () => pathScaffold(), boundary: () => boundaryScaffold(), surfaces: () => surfacesScaffold(), findings: () => findingsScaffold() };
// WHICH SECTIONS WERE OFFERED A SLOT is recorded HERE, by the generator, and written into the composed file.
// Measured 2026-08-07: `--check` refused a marker that REMAINED and accepted one that was DELETED — and
// deleting is the cheaper path. Five diagram slots were removed from one report with a single blanket
// sentence, and the check reported that every judgment section had been written by a person. A gate that a
// deletion satisfies is a gate that teaches deletion. CLOSED 2026-08-07 by this list plus the decision rule
// in --check: a slotted section must carry a diagram or a stated refusal, and an absence is neither.
const SLOTTED = [];
const slot = (section) => {
  SLOTTED.push(Number(section));
  const here = Object.keys(KINDS).filter((k) => String(arg(k, '')) === String(section));
  if (here.length) return '\n' + here.map((k) => KINDS[k]()).join('\n\n') + '\n';
  return `\n${FILL(`a diagram for § ${section} IF a relation here is worth drawing — collapse (several situations, one observation) · span (a duration) · path (a value crossing stages) · boundary (what is and is not established) · surfaces (more than one artifact). Scaffold with --<kind> ${section}. Delete this line if nothing here earns one`)}\n`;
};

const BODIES = {
  incident: () => `${alert('CAUTION', FILL('one sentence naming the blast radius and who was exposed — what a reader sees before any section'))}

## § 1 &nbsp; Recap

${FILL('what broke, where it was visible, and for how long — a few sentences')}
${slot(1)}
## § 2 &nbsp; Measured impact

${tbl([
  ['**FOUND**', FILL('how it surfaced — a run, a gate, a report'), '**ISSUE**', '#' + issue],
  ['**ENTERED**', entered ? `\`${entered.sha}\` on ${entered.date} — ${entered.subject}` : FILL('when the defect entered, or `unknown` with why'), '**PUBLISHED**', published ? Object.entries(JSON.parse(published)).map(([t, v]) => `\`${t}\` → \`${v}\``).join(' · ') : FILL('what a stranger would have fetched, or `not published`')],
  ['**BLAST RADIUS**', FILL('what was affected — and in the same cell what was NOT: the negative half is the honest half'), '**REACHED A CONSUMER**', FILL('yes/no, and if NOT, WHY — the barrier that held is evidence, not luck')],
  ['**PUBLISHED ARTIFACTS**', FILL('whether any published document, signature or verdict is affected'), '**RECOVERABLE**', FILL('what can still be undone, and what is permanent')],
])}
${slot(2)}
## § 3 &nbsp; Root cause

${tbl([
  ['**1**', FILL('the MECHANISM — why was this invisible? never a restatement of the symptom')],
  ['**2**', FILL('the second mechanism, or delete this row')],
  ['**3**', FILL('the third, or delete this row')],
])}
${slot(3)}
## § 4 &nbsp; Resolution

- [x] ${FILL('what shipped — structural first, the patch never')}
${slot(4)}
## § 5 &nbsp; Verification

${tbl([
  ['**CONFORMANCE**', checks ? `${checks[1]} checks, ${checks[2]} failing${vectors !== null ? `, ${vectors} vectors` : ''}` : '«conformance did not report»', '**CI**', ciSteps !== null ? `${ciSteps} steps (\`npm run ci:local\`)` : FILL('CI state')],
  ['**CAN THE CHECK FAIL**', FILL('revert the fix and name exactly what goes red — with its own message, not a neighbour\'s'), '**CONTROL**', FILL('the detector fires on the real defect and stays silent on correct code')],
  ...(gateLines.length ? [['**GATES**', gateLines.join('<br>'), '**NOTE**', FILL('anything a gate reported that a reader should not skip')]] : []),
])}
${slot(5)}
<details><summary>commits</summary>

\`\`\`
${commits}
\`\`\`

</details>

## § 6 &nbsp; Follow-ups

${alert('NOTE', FILL('the PROCEDURAL follow-up, if this round exposed one about how the work is done'))}

${tbl([
  // FOUR fates, not two. A round disposes of things in four ways and the two that were missing are the two a
  // reader silently misreads: work that LANDED reads as still pending when nothing says otherwise, and work
  // that MOVED reads as abandoned. `none` is a legitimate value for any row; an absent row is not.
  ['**DONE**', FILL('what this round actually closed — the disposition, not a repeat of § 4')],
  ['**MOVED**', FILL('what left this round for another issue, and WHICH — a pointer, never a promise')],
  ['**OPEN**', FILL('what this round leaves open, and where it is tracked')],
  ['**BLOCKED**', FILL('what cannot proceed and on what — or `none`')],
])}

<details><summary>open issues at the time of writing (trim to the ones this round leaves)</summary>

${openIssues ?? '«gh unavailable»'}

</details>

## § 7 &nbsp; The rule worth keeping

${alert('IMPORTANT', FILL('one sentence a future reader can apply without this issue in front of them'))}

## § 8 &nbsp; Diary

${diary || FILL('run `node tools/recap-render.mjs --issue ' + round + '` after sealing and paste its output — never type it; or state that the diary is the owner\'s to call')}
`,

  audit: () => `## Audit subject

${FILL('the exact document, implementation, release or claim under audit — a version and a commit, never "the protocol"')}

## Audit question

${FILL('the precise question this audit answers, phrased so a NO is possible')}

## Scope

**Included**

- ${FILL('specification sections, packages, commands, vector sets, evidence sources')}

**Excluded**

- ${FILL('what this record must NOT be read as proving — the exclusion is load-bearing, not a disclaimer')}

## Normative basis

- ${FILL('`reference` — the obligation, quoted closely enough that a reader can check it')}

## Method

1. ${FILL('static inspection')}
2. ${FILL('execution or reproduction')}
3. ${FILL('independent verification — by a DIFFERENT implementation, or say plainly that there was none')}
4. ${FILL('negative control or mutation: break the thing and watch THIS check go red')}

## Findings

### F-01 · ${FILL('title')}

**Class:** \`CONFORMING | NON-CONFORMING | INDETERMINATE | BY-DESIGN | DOCUMENTATION\`

**Obligation** — ${FILL('what was required')}

**Observation** — ${FILL('what was actually found')}

**Evidence** — ${FILL('command, file, vector or artifact a reader can re-run')}

**Disposition** — ${FILL('fixed, accepted, deferred, or retained by design — and under which issue')}
${drawn('findings', findingsScaffold, 'a CLASS BREAKDOWN if there are three or more findings — below three a list reads faster. Pass --findings to scaffold one, or delete this line')}
## Measured result

${conformanceLine}
${ciLine}${gateLines.length ? gateLines.join('\n') + '\n' : ''}- obligations examined: ${FILL('n')} · conforming ${FILL('n')} · non-conforming ${FILL('n')} · indeterminate ${FILL('n')} · by design ${FILL('n')}
- independent implementations used: ${FILL('n — and 0 is an honest answer that changes the conclusion below')}

## Resolution

- [x] ${FILL('closed finding or implemented correction')}
- [ ] ${FILL('open obligation or ship gate')}

## Audit conclusion

${FILL('one short paragraph stating exactly what the evidence supports — no more')}

- **does establish:** ${FILL('the bounded conclusion')}
- **does not establish:** ${FILL('the bounded exclusion')}
- **remains conditional on:** ${FILL('the open gate or dependency')}
${drawn('boundary', boundaryScaffold, 'a BOUNDARY diagram — the one picture an external reader will actually look at. Pass --boundary to scaffold one, or delete this line')}
## Residual risk

- ${FILL('known limitation, unreviewed surface, unsupported environment, evidence that remains unavailable')}

${commitsBlock}

## Follow-ups

- ${FILL('the issue carrying remaining work, and the one carrying a deliberately deferred question')}

${openBlock}

${diaryBlock}
`,

  delivery: () => `## Delivered

${FILL('one sentence: what exists now that did not exist before')}

## What it is

- ${FILL('the concrete resulting state — a command, an artifact, a surface, a version')}
${publishedLine}- ${FILL('what an operator or consumer can now do that they could not')}
${drawn('surfaces', surfacesScaffold, 'a SURFACE map if this spans more than one artifact and their relation IS the delivery. Pass --surfaces to scaffold one, or delete this line if it is one thing in one place')}
## Scope

- **Affected:** ${FILL('the surface this touches')}
- **Not affected:** ${FILL('what a reader might reasonably fear was touched and was not — say it even when obvious')}

## Verification

${conformanceLine}
${ciLine}${gateLines.length ? gateLines.join('\n') + '\n' : ''}- ${FILL('the check that would FAIL if this were built wrong — a delivery verified only by its own success proves nothing')}

${commitsBlock}

## Follow-ups

- ${FILL('what this delivery deliberately leaves open, and where it is tracked')}

${openBlock}

${diaryBlock}
`,
};

const out = head() + BODIES[form]();

console.log(out + `\n<!-- diagram-slots: ${[...new Set(SLOTTED)].sort((a, b) => a - b).join(',')} -->\n`);
console.error(`\n  composed ${form} report, round ${round} → #${issue}. Every number above is read from a command or a file in this tree.`);
const drawnCount = [...out.matchAll(/```mermaid/g)].length;
console.error(`  ${[...out.matchAll(/<<<FILL:/g)].length} judgment section(s) are yours; ${drawnCount} diagram(s) scaffolded through the lab palette.`);
console.error(`  Then:  node tools/recap-compose.mjs --check <file>`);
