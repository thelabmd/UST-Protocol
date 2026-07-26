#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// diarium — a task closes, the agent writes what it learned, the entry is sealed as a UST and chained into diarium/.
//
// The crypto is not here: it is `ust-protocol`, and this tool calls five functions from it. What lives here is the
// DISCIPLINE the library cannot hold — prev taken from the head of the chain rather than the last filename, the entry
// verified before it is stored, the cap enforced, one closure one entry, and a refusal to extend a broken store. Those
// are exactly the invariants an agent re-deriving them each session gets wrong.
//
// Everything is relative to the directory you run it in, so the store lands next to your code and the tool itself can
// live in node_modules.
import * as P from 'ust-protocol';
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';

const CWD = process.cwd();
const STORE = join(CWD, 'diarium');
const PENDING = join(STORE, '.pending');
const RULES = join(STORE, 'rules.md');
const SETTINGS = join(STORE, 'settings.json');
const ENV = join(CWD, '.env');

// rules.md is PROSE and it is the agent's prompt — yours to rewrite, and the tool does not care how you word it.
// Only `cap` is parsed and enforced; the rest it can ask for, which is honest as long as asking is not presented as
// enforcement. settings.json is STRUCTURE, read by code: a typo there fails loudly instead of being ignored.
const DEFAULT_RULES = `# Rules

Yours to rewrite. The tool reads this file before every entry and enforces \`cap\`; the rest it can only ask for.

cap: 560

- Write what you UNDERSTOOD and what you LEARNED from the task that just closed. Not what you did — git already keeps that.
- Write the failures too. A task that went wrong, a fix that did not hold, a call you got wrong. Never dress a loss up as a win.
- One entry, one thing. If it does not fit the cap, cut it; do not split it.
- No performed feelings. If it reads like marketing, delete it and write what actually happened.
- Do NOT reconstruct. If you no longer hold the task, say so and stop — reading the issue and the diff to manufacture an
  insight produces a summary, and git already keeps summaries better than you will. Read enough to RECOGNISE whether you
  remember it; never enough to invent it.
- "Nothing to learn" is a real entry. Absence of a result is a result. Write it plainly and pass --nothing-learned.
- Nobody reviews this before it lands. The discipline is the trigger, not review: you do not choose when to write.
`;

const args = process.argv.slice(2);
const cmd = args[0];
const flag = (n, d) => { const i = args.indexOf('--' + n); return i > 0 && args[i + 1] ? args[i + 1] : d; };
const die = (m) => { console.error('✗ ' + m); process.exit(1); };

// First run detects the trackers this repo actually has rather than asking you to describe them.
function detectSources() {
  const out = [];
  if (existsSync(join(CWD, '.beads'))) out.push({ type: 'bd', cwd: '.' });
  try {
    const url = execSync('git remote get-url origin', { cwd: CWD, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const m = /[:/]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(url);
    if (m) out.push({ type: 'github', repo: `${m[1]}/${m[2]}` });
  } catch { /* no remote: leave it out rather than guess */ }
  return out;
}

// The seed is generated at INIT, not lazily on the first entry: the developer must see the "gitignore this" warning
// while installing, not in the middle of writing. A leaked seed lets someone else write entries as you.
function ignored() {
  try { execSync('git check-ignore -q .env', { cwd: CWD, stdio: 'ignore' }); return true; } catch { return false; }
}

function ensure() {
  mkdirSync(PENDING, { recursive: true });
  if (!existsSync(RULES)) writeFileSync(RULES, DEFAULT_RULES);
  if (!existsSync(SETTINGS)) {
    const sources = detectSources();
    writeFileSync(SETTINGS, JSON.stringify({ sources, cursors: {} }, null, 2) + '\n');
    console.log(`  · created ${STORE.replace(CWD + '/', '')}/ with ${sources.length} detected tracker(s): ${sources.map((s) => s.type).join(', ') || 'none — add them to settings.json'}`);
  }
  key();
  if (!ignored()) console.log('  ! .env is NOT gitignored — add it now. The seed in there is the identity of this store;\n    anyone who has it can write entries as you, and every one of them will verify.');
}
const cap = () => { const m = (existsSync(RULES) ? readFileSync(RULES, 'utf8') : DEFAULT_RULES).match(/^cap:\s*(\d+)/m); return m ? Number(m[1]) : 560; };
const files = () => (existsSync(STORE) ? readdirSync(STORE).filter((f) => f.endsWith('.ust.json')).sort() : []);
const load = (f) => JSON.parse(readFileSync(join(STORE, f), 'utf8'));

// Order comes from the CHAIN, never from the filesystem: filenames are cosmetic and renaming every file must change
// nothing. Deriving order from `prev` also sees forks and orphans, which a filename sort never can.
function chain() {
  const docs = files().map((f) => ({ f, d: load(f) }));
  const problems = [];
  if (!docs.length) return { ordered: [], problems };
  const hashOf = (x) => P.contentHash(x.d);
  const prevOf = (x) => x.d.state.provenance?.prev;
  const byHash = new Map(docs.map((x) => [hashOf(x), x]));

  const genesis = docs.filter((x) => !prevOf(x));
  if (!genesis.length) problems.push('no genesis: every entry carries a prev, so the oldest one is missing');
  if (genesis.length > 1) problems.push(`${genesis.length} entries carry no prev — a stream has exactly one genesis: ${genesis.map((x) => x.f).join(', ')}`);

  const claimed = new Map();
  for (const x of docs) {
    const p = prevOf(x); if (!p) continue;
    if (!byHash.has(p)) problems.push(`${x.f}: prev ${p.slice(0, 20)}… resolves to no entry here — a gap, or the chain leaves this store`);
    claimed.set(p, (claimed.get(p) || []).concat(x.f));
  }
  for (const [p, fs2] of claimed) if (fs2.length > 1) problems.push(`FORK: ${fs2.length} entries claim the same prev ${p.slice(0, 20)}… — ${fs2.join(', ')}`);

  const heads = docs.filter((x) => !claimed.has(hashOf(x)));
  if (heads.length > 1) problems.push(`${heads.length} heads — nothing follows any of: ${heads.map((x) => x.f).join(', ')}`);

  const ordered = []; const seen = new Set();
  let cur = heads[0], guard = docs.length + 1;
  while (cur && guard-- > 0) {
    if (seen.has(cur.f)) { problems.push(`cycle detected at ${cur.f}`); break; }
    seen.add(cur.f); ordered.unshift(cur);
    const p = prevOf(cur); cur = p ? byHash.get(p) : null;
  }
  for (const x of docs) if (!seen.has(x.f)) problems.push(`${x.f}: unreachable from the head — an orphan the chain does not include`);
  return { ordered, problems };
}

function key() {
  const env = existsSync(ENV) ? readFileSync(ENV, 'utf8') : '';
  let m = env.match(/^DIARIUM_SEED=(\S+)/m);
  if (!m) {
    const seed = randomBytes(32).toString('base64url');
    appendFileSync(ENV, `${env.endsWith('\n') || !env ? '' : '\n'}DIARIUM_SEED=${seed}\n`);
    m = [null, seed];
    console.log('  · generated a signing key into .env — gitignore it. The seed is never printed, not even here.');
  }
  const seed = Buffer.from(m[1], 'base64url');
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
  return { priv, pub, kid: P.keyId(pub) };
}

// A task reference is a PATH and paths go stale: rename or transfer the repo and the reference inside an already-sealed
// entry is unresolvable, unfixable because the seal is immutable. So the seal carries the readable ref AND the id that
// survives a rename. Where no global id exists that is RECORDED, never implied, and nothing is invented on failure.
function resolveTask(ref) {
  const m = /^(?:([\w.-]+)\/([\w.-]+))?#?(\d+)$/.exec(String(ref).trim());
  if (!m) return { ref, source: /^[A-Za-z][\w.-]*-[a-z0-9]+$/.test(ref) ? 'tracker-local' : 'raw' };
  let [, owner, repo, num] = m;
  if (!owner || !repo) {
    try {
      const url = execSync('git remote get-url origin', { cwd: CWD, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      const rm = /[:/]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(url);
      if (rm) { owner = rm[1]; repo = rm[2]; }
    } catch { /* stay unqualified rather than guess */ }
  }
  if (!owner || !repo) return { ref, source: 'raw' };
  const qualified = `${owner}/${repo}#${num}`;
  try {
    const j = JSON.parse(execSync(`gh api repos/${owner}/${repo}/issues/${num} --jq '{id:.id,node_id:.node_id}'`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
    return { ref: qualified, id: String(j.id), node_id: j.node_id, source: 'github' };
  } catch { return { ref: qualified, source: 'github-unresolved' }; }
}
const field = (s) => String(s).replace(/_/g, '-').replace(/[^\w.-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
const slug = (t) => { const m = /^(?:[\w.-]+\/)?([\w.-]+)#(\d+)$/.exec(t.ref); return m ? `${field(m[1])}_${field(m[2])}` : field(t.ref); };
const pendingPath = (ref) => join(PENDING, String(ref).replace(/[^\w.-]/g, '_') + '.json');

// ── scan ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Every source answers ONE question — what closed after this cursor — so a new tracker is an adapter, not an
// integration. Polling is what makes the trigger real: measured on a live day, it caught every closure while a
// commit-keyword hook caught none, because the closures went through `gh issue close` and the commits said "Refs #90".
if (cmd === 'scan') {
  ensure();
  let cfg; try { cfg = JSON.parse(readFileSync(SETTINGS, 'utf8')); } catch (e) { die(`settings.json does not parse — a typo there fails loudly on purpose: ${e.message}`); }
  cfg.cursors = cfg.cursors || {};
  let found = 0;
  for (const s of (cfg.sources || []).filter((x) => x.enabled !== false)) {
    const id = `${s.type}:${s.repo || s.cwd || '.'}`;
    const cold = !cfg.cursors[id];
    const since = cfg.cursors[id] || '1970-01-01T00:00:00Z';
    let rows = [];
    try {
      if (s.type === 'github') {
        rows = JSON.parse(execSync(`gh issue list -R ${s.repo} --state closed --limit 100 --json number,closedAt,title`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }))
          .filter((x) => x.closedAt > since).map((x) => ({ ref: `${s.repo}#${x.number}`, at: x.closedAt, title: x.title }));
      } else if (s.type === 'bd') {
        rows = JSON.parse(execSync('bd list --status=closed --limit 400 --json', { cwd: join(CWD, s.cwd || '.'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }))
          .filter((x) => (x.closed_at || '') > since).map((x) => ({ ref: x.id, at: x.closed_at, title: x.title }));
      } else { console.log(`  ? ${id}: unknown source type — skipped, never guessed`); continue; }
    } catch (e) {
      // The CAUSE lives in stderr; e.message only repeats the command back, which is the least informative line there is.
      const why = (String(e.stderr || '').split('\n').filter(Boolean)[0] || String(e.message).split('\n')[1] || 'no output').trim();
      console.log(`  ! ${id}: unreachable — cursor untouched, so nothing is skipped quietly\n      ${why.slice(0, 120)}`); continue;
    }

    // A cold start sets a BASELINE, not a backlog. Asking an agent to write dozens of entries about work it does not
    // remember manufactures recollection, and a corpus of invented memories is worse than an empty one.
    if (cold) {
      cfg.cursors[id] = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      console.log(`  ${id}: BASELINE set — ${rows.length} historical closure(s) skipped (a memory you did not live is an invention, not a memory)`);
      continue;
    }
    for (const r of rows.sort((a, b) => a.at.localeCompare(b.at))) {
      if (!existsSync(pendingPath(r.ref))) { writeFileSync(pendingPath(r.ref), JSON.stringify({ ref: r.ref, kind: 'done', title: r.title || '', at: r.at }, null, 2) + '\n'); found++; }
      if (r.at > (cfg.cursors[id] || '')) cfg.cursors[id] = r.at;
    }
    console.log(`  ${id}: ${rows.length} closure(s) since ${since.slice(0, 16)}`);
  }
  writeFileSync(SETTINGS, JSON.stringify(cfg, null, 2) + '\n');
  console.log(found ? `\n  ${found} new obligation(s) — run: diarium status` : '\n  nothing new');
  process.exit(0);
}

if (cmd === 'closed') {
  const ref = args[1]; if (!ref) die('usage: diarium closed <ref> [--kind done|cancelled] [--title "..."]');
  ensure();
  if (existsSync(pendingPath(ref))) { console.log(`· ${ref} already owes an entry`); process.exit(0); }
  writeFileSync(pendingPath(ref), JSON.stringify({ ref, kind: flag('kind', 'done'), title: flag('title', ''), at: new Date().toISOString() }, null, 2) + '\n');
  console.log(`· ${ref} closed — an entry is owed:  diarium write ${ref} <file>`);
  process.exit(0);
}

// ── status: the gate. A closure without an entry is the thing this catches, so it exits non-zero while any is owed.
if (cmd === 'status') {
  ensure();
  const owed = readdirSync(PENDING).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(PENDING, f), 'utf8')));
  console.log(`  store: ${files().length} entries  ·  cap ${cap()}  ·  diarium/`);
  if (!owed.length) { console.log('  ✓ no closure is waiting for an entry'); process.exit(0); }
  console.log(`  ✗ ${owed.length} closure(s) owe an entry:`);
  for (const o of owed.sort((a, b) => a.at.localeCompare(b.at))) console.log(`    ${String(o.ref).padEnd(16)} ${o.kind.padEnd(9)} ${o.at.slice(0, 16)}  ${(o.title || '').slice(0, 60)}`);
  process.exit(1);
}

if (cmd === 'write') {
  const ref = args[1], bodyPath = args[2];
  if (!ref || !bodyPath || !existsSync(bodyPath)) die('usage: diarium write <task-ref> <file> [--nothing-learned]');
  ensure();
  const body = readFileSync(bodyPath, 'utf8').trim();
  if (!body) die('empty entry');
  const limit = cap();
  if (body.length > limit) die(`entry is ${body.length} characters — the cap declared in diarium/rules.md is ${limit}. Cut it, do not split it.`);
  // "Nothing to learn" is first-class and recorded STRUCTURALLY so it can be counted: a corpus that is mostly this is
  // telling you something, and that signal is lost if the fact hides inside a sentence.
  const nothing = args.includes('--nothing-learned');

  const task = resolveTask(ref);
  // The closure time travels into the seal so the closure→entry INTERVAL is observable: an entry written minutes after
  // the closure was lived, one written days later was reconstructed. Nobody declares which — declaring your own
  // reliability is the self-asserted assurance this design refuses everywhere else.
  if (existsSync(pendingPath(ref))) { try { task.closed_at = JSON.parse(readFileSync(pendingPath(ref), 'utf8')).at; } catch { /* keep going without it */ } }

  const { ordered, problems } = chain();
  if (problems.length) { console.error('✗ refusing to extend a broken store — fix it first:'); for (const p of problems) console.error('   • ' + p); process.exit(1); }
  const prev = ordered.length ? P.contentHash(ordered[ordered.length - 1].d) : undefined;

  const { priv, pub, kid } = key();
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const ust_id = `ust:${now.slice(0, 4)}${now.slice(5, 7)}${now.slice(8, 10)}.${now.slice(11, 13)}${now.slice(14, 16)}${now.slice(17, 19)}`;
  const state = P.buildState({ domain_shard: kid, ust_id, key_id: kid, class: 'observation' },
    { generated_at: now, valid_from: now, valid_to: now },
    { entry: { kind: 'captured', value: nothing ? { text: body, task, learned: 'none' } : { text: body, task } } },
    prev ? { prev } : undefined);
  const doc = P.seal(state, priv, pub);
  const v = P.verify(doc, { context: 'data' });
  if (v.result !== 'VALID:LIGHT') die(`entry did not seal VALID:LIGHT: ${v.result || v.error}`);

  // Underscore separates fields, hyphen lives inside them: repo names carry hyphens, and a separator that can also
  // appear in the data is not a separator. No `ust:` prefix — a colon cannot be checked out on Windows. The name
  // carries no meaning; order is the chain's and identity is the content_hash.
  const name = `${ust_id.slice(4)}_${slug(task)}_${P.contentHash(doc).slice(7, 15)}.ust.json`;
  writeFileSync(join(STORE, name), JSON.stringify(doc) + '\n');
  if (existsSync(pendingPath(ref))) unlinkSync(pendingPath(ref));
  console.log('✓ entry sealed + stored');
  console.log('  file        :', name);
  if (nothing) console.log('  learned     : none (recorded as such, and countable)');
  console.log('  task        :', task.ref, `(${task.source}${task.id ? ', id ' + task.id : ''})`);
  console.log('  content_hash:', P.contentHash(doc));
  console.log('  prev        :', prev || '(genesis)');
  process.exit(0);
}

if (cmd === 'read') {
  const rawDepth = flag('depth', '3');
  const { ordered, problems } = chain();
  const depth = rawDepth === 'all' ? ordered.length : Number(rawDepth);
  // --json emits the ordered DOCUMENTS so a caller can render its own view without re-deriving the chain. Without it,
  // anyone wanting a different presentation writes a second chain walk, which is the duplication this tool exists to avoid.
  if (args.includes('--json')) {
    if (problems.length) { console.error('✗ refusing to emit an order derived from a broken store:'); for (const p of problems) console.error('   • ' + p); process.exit(1); }
    console.log(JSON.stringify(ordered.slice(-depth).map((x) => x.d)));
    process.exit(0);
  }
  if (!ordered.length) { console.log('  (no entries yet)'); process.exit(0); }
  if (problems.length) console.log(`  ! ${problems.length} structural problem(s) — run: diarium verify\n`);
  console.log(`  walking back ${depth} hop(s) from the head of ${ordered.length} entries\n`);
  for (const { f, d } of ordered.slice(-depth).reverse()) {
    const st = d.state, v = st.data.entry?.value ?? {};
    console.log(`  ── ${st.id.ust_id}  ·  task ${v.task?.ref ?? v.task ?? '?'}${v.learned === 'none' ? '  ·  learned: none' : ''}`);
    console.log('  ' + String(v.text ?? '').split('\n').join('\n  ') + '\n');
  }
  process.exit(0);
}

if (cmd === 'verify') {
  const { ordered, problems } = chain();
  const present = files();
  if (!present.length) { console.log('  (no entries yet)'); process.exit(0); }
  // Every file PRESENT, not just the chain-reachable ones: a tampered entry falls out of the chain, and verifying only
  // what is reachable would leave its broken seal unreported.
  const broken = [];
  for (const f of present) {
    let d; try { d = load(f); } catch { broken.push(`${f}: not parseable JSON`); continue; }
    const v = P.verify(d, { context: 'data' });
    if (v.result !== 'VALID:LIGHT') broken.push(`${f}: seal does NOT verify — ${v.result || v.error}`);
  }
  // Broken seals lead. A tampered entry is the FINDING; the orphans and extra heads it produces are consequences, and
  // printing them first buries the one line that says what actually happened.
  const fails = [...broken, ...problems];
  if (fails.length) {
    console.error(`✗ verify FAILED (${ordered.length} in chain, ${present.length} file(s) present):`);
    for (const x of broken) console.error('   • ' + x);
    if (broken.length && problems.length) console.error('   — and the structural consequences of that:');
    for (const x of problems) console.error('   • ' + x);
    process.exit(1);
  }
  console.log(`✓ ${ordered.length} entries: every seal verifies, one genesis, one head, no fork, no orphan (order from the chain — filenames are cosmetic)`);
  process.exit(0);
}

if (cmd === 'render') {
  for (const { f, d } of chain().ordered) {
    const st = d.state, v = st.data.entry?.value ?? {};
    console.log(`${v.text}\n\n<sub>${f} · task ${v.task?.ref ?? v.task} · ${st.time.generated_at}</sub>\n\n---\n`);
  }
  process.exit(0);
}

console.log(`diarium — a task closes, you write what you learned, it is sealed and chained

  diarium scan                      what closed since last time (first run sets a baseline)
  diarium status                    closures owing an entry (exit 1 while any is owed)
  diarium write <ref> <file>        seal + chain + store   [--nothing-learned]
  diarium read [--depth N]          walk the chain N hops back from the head
  diarium verify                    every seal, one genesis, one head, no fork, no orphan
  diarium render                    markdown to stdout, derived, never stored

The store is ./diarium/ — rules.md is prose you may rewrite, settings.json is structure.`);
