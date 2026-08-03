// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:every number it prints is READ from a command's output or a file in this tree; the only literals are the section headings, and the FILL markers it refuses to emit
//
// Compose the measured skeleton of a round's recap — so the numbers in it are measured BY CONSTRUCTION.
//
// MEASURED, 2026-08-03: the first recap written in this shape (#132) had every number typed by hand from a warm
// context. They were right, but right by ACCIDENT — nothing in the tree connected "5 days published", "9 of 13
// commands", "833 checks" to the artifacts that produce them. That is the defect class this repo spends most of its
// gates on, stated in printed-command-gate's own header: text ABOUT code, authored beside the code, drifting from it
// silently. A month later nobody can separate a measured number from a remembered one.
//
// THE SPLIT, and it is deliberate. A recap is two substances:
//   MEASURED  — counts, dates, versions, commits, the issue list, the sealed diary block. Mechanically derivable,
//               therefore never typed. This tool fills them.
//   JUDGMENT  — what the incident WAS, why it was invisible, the rule worth keeping. No tool writes those.
//               This tool marks them and REFUSES to let a skeleton with an unfilled mark be posted.
//
// The refusal is the load-bearing half. A generator that emits a placeholder and trusts the author to notice is the
// same shape as the four `${invocation()}` strings that reached operators verbatim: the text was right, and nobody
// ran the check that reads it. `--check` is that check.
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const arg = (n, d = null) => { const i = process.argv.indexOf('--' + n); return i > -1 ? (process.argv[i + 1] ?? true) : d; };
const sh = (cmd, args, opts = {}) => { try { return execFileSync(cmd, args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); } catch (e) { return opts.softFail ? null : `«unavailable: ${String(e.message).split('\n')[0].slice(0, 70)}»`; } };

// ── --check: the refusal. Runs against a composed file before it is posted.
const checkFile = arg('check');
if (checkFile) {
  const body = readFileSync(String(checkFile), 'utf8');
  const marks = [...body.matchAll(/<<<[A-Z]+:[^>]*>>>/g)].map((m) => m[0]);
  // CONTROL — the detector must fire on a real marker and stay silent on ordinary prose, or a green run means nothing.
  const CONTROL_HIT = /<<<[A-Z]+:[^>]*>>>/.test('a <<<FILL: something>>> here');
  const CONTROL_MISS = /<<<[A-Z]+:[^>]*>>>/.test('an ordinary sentence about <angle brackets> and code');
  if (!CONTROL_HIT || CONTROL_MISS) { console.error('✗ CONTROL: the placeholder detector does not discriminate — this check is blind'); process.exit(1); }
  if (marks.length) {
    console.error(`\n  ✗ ${marks.length} section(s) still carry a FILL marker — a skeleton is not a recap, and an unfilled\n    marker posted to an issue reads as the tool being broken at the moment a reader trusts it:\n`);
    for (const m of marks) console.error('    ' + m.slice(0, 110));
    process.exit(1);
  }
  console.log('  ✓ no FILL marker remains — every judgment section was written by a person');
  process.exit(0);
}

const round = Number(arg('round'));
const issue = Number(arg('issue'));
if (!Number.isInteger(round) || !Number.isInteger(issue)) {
  console.error('usage: node tools/recap-compose.mjs --round <n> --issue <n> [--since <sha>] [--symbol <name>] [--package <npm-name>] [--gates "a,b,c"]');
  console.error('       node tools/recap-compose.mjs --check <composed-file>     # REFUSES any remaining FILL marker');
  process.exit(1);
}
const FILL = (what) => `<<<FILL: ${what}>>>`;

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

const out = `## Recap

${FILL('what broke, where it was visible, and for how long — a few sentences')}

## Measured impact

${entered ? `- entered \`${entered.sha}\` on ${entered.date} — ${entered.subject}\n` : ''}- found and closed under #${issue}
${published ? `- published at the time of writing: ${Object.entries(JSON.parse(published)).map(([t, v]) => `\`${t}\` → \`${v}\``).join(', ')}\n` : ''}- ${FILL('what was affected — and, in the same list, what was NOT: the negative half is the honest half')}
- ${FILL('whether any published document, signature or verdict is affected')}

## Root cause

${FILL('numbered MECHANISMS, each answering "why was this invisible", never restating the symptom')}

## Resolution

- [x] ${FILL('what shipped — structural first, the patch never')}

## Verification

- ${checks ? `${checks[1]} conformance checks, ${checks[2]} failing` : '«conformance did not report»'}${vectors !== null ? `, ${vectors} vectors` : ''}
${ciSteps !== null ? `- ${ciSteps} CI steps enumerated from the workflow (\`npm run ci:local\`)\n` : ''}${gateLines.length ? gateLines.join('\n') + '\n' : ''}- ${FILL('the proof the check CAN fail — revert the fix and name exactly what goes red')}
- ${FILL('controls: the detector fires on the real defect and stays silent on correct code')}

<details><summary>commits</summary>

\`\`\`
${commits}
\`\`\`

</details>

## Follow-ups

- ${FILL('the PROCEDURAL follow-up, if this round exposed one about how I work')}

<details><summary>open issues at the time of writing (trim to the ones this round leaves)</summary>

${openIssues ?? '«gh unavailable»'}

</details>

## The rule worth keeping

${FILL('one sentence a future reader can apply without this issue in front of them')}

## Diary

${diary || FILL('run `node tools/recap-render.mjs --issue ' + round + '` after sealing, and paste its output below the heading — never type it')}
`;

console.log(out);
console.error(`\n  composed round ${round} → #${issue}. Every number above is read from a command or a file in this tree.`);
console.error(`  ${[...out.matchAll(/<<<FILL:/g)].length} judgment section(s) are yours. Then:  node tools/recap-compose.mjs --check <file>`);
