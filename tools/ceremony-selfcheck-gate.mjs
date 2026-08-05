// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the three RESOLVER entries are a judgement — which call answers a world question cannot be read off anything — while the RUNG half is derived from the core's identity ladder
// Ceremony self-check gate (rev95) — a ceremony's self-check must assert the invariant the ceremony PRESERVES,
// never a property of the WORLD it does not determine.
//
// The defect it exists for [measured 2026-07-27]: `ust rotate` asked
// `resolveAuthority(...).strength === 'authoritative'` while supplying only `noForkConfirmed`, which yields
// `consumer-override` — the value #98 had HARDENED the protocol to withhold that same day, precisely so a caller's
// boolean cannot name a canonical. The ceremony therefore demanded of a flag a property the protocol had just
// decided that flag may not confer, and it died on its own check EVERY time. Rotation is the only recovery from
// key compromise, so the recovery path was unavailable and nothing said so.
//
// CLOSED 2026-08-03 — the same day by that sweep, 2026-08-03 (round 156): `ensureOutDir` is one exported helper
// and all five ceremonies call it at entry, which is what the legs below hold shut. Written here afterwards —
// the paragraph records only what was measured. Noted 2026-08-05, appended rather than rewritten.
//
// CLOSED 2026-07-27 — in the same commit that added this gate, 2026-07-27 (rev95, round 61): the rotation
// self-check now asserts F.5e membership — the new key is ACTIVE in the grown log — instead of asking
// `resolveAuthority`, so the recovery path runs. Noted 2026-08-05, appended rather
// than rewritten.
//
// The other two ceremonies asked correctly — and that was LUCK. Nothing stated the rule and nothing stopped a
// fourth from copying the wrong one. This gate is what turns three lucky cases into one invariant.
//
// WORLD-PROPERTY VOCABULARY: name authority, witness confirmation, network reachability. A ceremony holds a cold
// key, a fetched log and a declared parameter — it cannot determine any of those, so asking about them either
// fails always or passes vacuously, and both read to an operator as the other.
import { readFileSync } from 'node:fs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// The DOMAIN is every self-check in the ceremony surface, read out of the source — a new one enters this set by
// existing, which is what makes the rule survive the next ceremony.
const lines = SRC.split('\n');
const sites = [];
lines.forEach((l, i) => { if (/self-check FAILED/.test(l)) sites.push({ line: i + 1, text: l }); });
check(sites.length >= 4, `only ${sites.length} self-check sites found — the probe has gone blind`);

// A self-check may not condition on a world property. These are the resolver calls that ANSWER a world question.
// The RESOLVER half is a judgement — which calls answer a world question cannot be read off anything, so these three
// are named with their reasons. The RUNG half is DERIVED, and it had to be: this list named `'authoritative'` and left
// `corroborated` and `self-asserted` out, so a self-check conditioning on either would have passed. Neither appears in
// the CLI today [measured], so nothing was broken — the gap was in the watching, which is the third time that sentence
// has been written this week. The ladder is read from the core, so a NEW rung is forbidden the moment it exists.
const CORE = readFileSync(new URL('../packages/ust-protocol/index.mjs', import.meta.url), 'utf8');
const ladder = (CORE.match(/identity:\s*\[([^\]]+)\]/) ?? [, ''])[1].match(/'([a-z-]+)'/g) ?? [];
check(ladder.length >= 3, `the identity ladder read from the core has ${ladder.length} rung(s) — the derivation has gone blind and the rung half of WORLD would be empty`);
const WORLD = [
  ['resolveAuthority', 'name authority — depends on witness evidence a ceremony neither holds nor should'],
  ['noForkConfirmed', 'a caller no-fork assertion — #98 hardened the protocol so this can never confer authority'],
  ['acceptConsumerOverride', 'a consumer opt-in — the ceremony is not the consumer'],
  ...ladder.map((r) => [r, `the ${r.replace(/'/g, '')} rung is a property of the WORLD, not of what the ceremony produced — derived from the core's ladder, so this list cannot fall behind it`]),
];
// CONTROL — the derivation must actually reach the ladder, and must not swallow prose.
check(WORLD.some(([n]) => n === "'corroborated'"), 'the rung half of WORLD did not pick up `corroborated` — the ladder derivation is not in use');
check(!WORLD.some(([n]) => n === "'nosuchrung'"), 'the ladder derivation accepts a rung that does not exist');
for (const s of sites) {
  // the whole statement, not just the line: a check may span the two lines above it
  // the window must INCLUDE the matched line: the condition and its exit live ON it. The first version excluded
  // it and the gate was vacuous — the mutation test caught that, a reading of the code would not have.
  const stmt = lines.slice(Math.max(0, s.line - 4), s.line + 1).join(' ');
  for (const [needle, why] of WORLD) {
    check(!stmt.includes(needle),
      `ceremony self-check at ust-cli/index.mjs:${s.line} conditions on ${needle} — ${why}. Assert what the ceremony PRESERVES instead (rev95).`);
  }
}

// and every self-check must EXIT — a check whose failure branch cannot run is not a check. The rotation branch
// called a bare rl.close() where its three neighbours use rl?.close(), and `rl` is built lazily since rc.43, so
// the failure threw a TypeError BEFORE printing its diagnosis: the operator saw a stack, not the reason.
for (const s of sites) {
  const stmt = lines.slice(Math.max(0, s.line - 4), s.line + 1).join(' ');
  if (!/\brl\b/.test(stmt)) continue;
  check(!/[^?]\brl\.close\(\)/.test(stmt),
    `ceremony self-check at ust-cli/index.mjs:${s.line} calls a bare rl.close() — rl is built LAZILY, so the failure branch throws before it can report. Use rl?.close().`);
}

// the pin must be able to fail
check(WORLD.length >= 4 && sites.length >= 4, 'the vocabulary or the site set shrank — the gate would pass vacuously');

// ── A CONDITION CHECKABLE AT ENTRY MUST NOT BE DISCOVERED AT EXIT ────────────────────────────────────────────────
//
// MEASURED on the reference operator's live re-rooting, 2026-08-03. The ceremony ran to completion: twelve
// acceptance legs green, both cold-key passphrases typed, a fresh crown minted in memory — and then `writeFileSync`
// threw ENOENT, because `--out` named a directory that did not exist and `writeFileSync` does not create parents.
// The minted identity was discarded. Nothing was published, so nothing was lost but the operator's session with a
// key out of cold storage, which is the scarcest thing a ceremony spends.
//
// FOUR of the five ceremonies had it, and the sweep found them rather than the incident: only the command being
// debugged had been fixed. The domain is every command that asks for a secret — each must have proven its output
// target writable BEFORE the question, because everything after it is work the operator cannot redo.
{
  const fns = [];
  let cur = null;
  lines.forEach((l, i) => {
    const m = /^(?:export )?(?:async )?function (cmd\w+)/.exec(l);
    if (m) { cur = { name: m[1], start: i, out: null, ask: null }; fns.push(cur); }
    if (!cur) return;
    if (/ensureOutDir\(/.test(l) && !/export function/.test(l) && cur.out === null) cur.out = i;
    if (/askHidden\(/.test(l) && cur.ask === null) cur.ask = i;
  });
  // THE RULE IS ABOUT WORK THAT MUST BE SAVED, not about asking a secret. `ust key check` decrypts a cold backup to
  // answer one question and writes nothing — demanding an output directory of it was the gate reading its own
  // wording rather than its reason. So the domain is commands that WRITE AFTER they ask.
  fns.forEach((f, i) => {
    const end = i + 1 < fns.length ? fns[i + 1].start : lines.length;
    f.writesAfterAsk = f.ask !== null && lines.slice(f.ask, end).some((l) => /write(FileSync|Secret|Public)\(/.test(l));
  });
  const withSecret = fns.filter((f) => f.ask !== null && f.writesAfterAsk);
  check(fns.some((f) => f.ask !== null && !f.writesAfterAsk), 'no read-only secret command found — the write/no-write split is untested and would pass vacuously');
  check(withSecret.length >= 4, `only ${withSecret.length} ceremony command(s) ask for a secret — the probe has gone blind`);
  for (const f of withSecret)
    check(f.out !== null && f.out < f.ask,
      `${f.name} asks for a passphrase at :${f.ask + 1} without having proven its output directory writable first (ensureOutDir at :${f.out === null ? 'nowhere' : f.out + 1}). A ceremony that mints a key and THEN cannot write it has spent a cold-key session for nothing — measured live on 2026-08-03.`);
  check(/export function ensureOutDir/.test(SRC), 'ensureOutDir is gone — each command would grow its own copy of the check, or none');
  check(/mkdirSync\(dir, \{ recursive: true \}\)/.test(SRC) && /write-probe/.test(SRC),
    'ensureOutDir no longer CREATES the directory and PROBES a write — an existing but unwritable path would still fail at exit');
}

// ── A CEREMONY PROVES THE FILE IT WROTE, NOT THE VALUE IT HELD ───────────────────────────────────────────────────
//
// MEASURED live, 2026-08-03. Every acceptance leg a ceremony runs inspects values in MEMORY. A crown was written
// through a path that encoded it differently from every other ceremony: the file encrypted and decrypted perfectly
// and then would not parse. Nothing noticed, because nothing read it back — and a FILE is what the operator carries
// to cold storage. They found out with the network on and the passphrase no longer in hand.
//
// CLOSED 2026-08-03 by `5c2542e` — cli: a ceremony proves the FILE it wrote, not the value it held. The guard
// this paragraph explains landed with it; noted 2026-08-05, appended rather than rewritten.
//
// The owner's rule when it happened: check it in the tool, right after the ceremony, while the client is still
// offline. So every command that WRITES a key must READ IT BACK and prove it against what the documents say.
{
  const writers = [];
  let cur = null;
  lines.forEach((l, i) => {
    const m = /^(?:export )?(?:async )?function (cmd\w+)/.exec(l);
    if (m) { cur = { name: m[1], start: i, writes: [], proves: [] }; writers.push(cur); }
    if (!cur) return;
    if (/(write(FileSync|Secret)|secret)\(.*-?key.*\.b64|secret\(crownName|secret\(caName/.test(l)) cur.writes.push(i);
    if (/proveWrittenKey\(/.test(l)) cur.proves.push(i);
  });
  const keyWriters = writers.filter((w) => w.writes.length);
  check(keyWriters.length >= 3, `only ${keyWriters.length} command(s) found writing a key file — the probe has gone blind`);
  for (const w of keyWriters)
    check(w.proves.length > 0,
      `${w.name} writes a key file at :${w.writes[0] + 1} and never reads it back — a ceremony must prove the FILE, not the value it held. Measured live: a crown that encrypts and decrypts perfectly can still be unparseable, and the operator finds out in cold storage.`);
  check(/export function proveWrittenKey/.test(SRC), 'proveWrittenKey is gone — each command would grow its own read-back, or none');
}

// ── askHidden must OWN stdin, and the roster is ENUMERATED rather than claimed ────────────────────────────────────
//
// `askHidden` reads a passphrase in raw mode so it never echoes. A readline interface opened BEFORE it takes stdin
// over and echoes the line itself — the secret prints while the code looks correct. A guard was added on 2026-07-27
// after the owner watched a root passphrase print, and its comment stated: "Every caller now builds its readline
// LAZILY, and this guard makes a future eager one loud instead of silent."
//
// THE CLAIM WAS FALSE WHEN WRITTEN. `cmdGenesis` still opened its interface eagerly, so from rc.43 the guard REFUSED
// every silver and gold genesis ceremony — the tool that mints a name's identity, broken at the two profiles an
// operator actually uses, and unnoticed because no gate performs a passphrase ceremony. That is the difference
// between asserting a property over a domain and enumerating the domain: the sentence "every caller" was the bug.
{
  const callers = [];
  for (const m of SRC.matchAll(/askHidden\(/g)) {
    const line = SRC.slice(0, m.index).split('\n').length;
    if (/export async function askHidden/.test(lines[line - 1] || '')) continue;   // the definition itself
    // walk back to the enclosing function
    let fn = -1;
    for (let i = line - 1; i >= 0; i--) if (/^(export )?(async )?function \w+|^async function \w+/.test(lines[i])) { fn = i; break; }
    if (fn >= 0) callers.push({ line, fn, name: (lines[fn].match(/function (\w+)/) || [, '?'])[1] });
  }
  check(callers.length >= 3, `only ${callers.length} askHidden call sites found — the roster probe has gone blind and this whole section would pass vacuously`);

  for (const c of callers) {
    // the enclosing function's readline must be created LAZILY, on first use, not at entry
    const body = lines.slice(c.fn, c.line).join('\n');
    const eager = /^\s*const rl = createInterface\(/m.test(body);
    const lazy = /rl \?\?= openReader\(/.test(body);
    check(!eager, `${c.name} opens its readline EAGERLY (ust-cli/index.mjs) and then calls askHidden at :${c.line} — the open interface owns stdin and echoes the passphrase, so askHidden's guard refuses and the whole ceremony dies. Build it lazily: \`let rl = null; const ask = (q) => { rl ??= createInterface(...); return rl.question(q); };\``);
    check(lazy, `${c.name} calls askHidden at :${c.line} but no lazy \`rl ??= createInterface(\` is visible above it — the roster is enumerated, so a new caller must adopt the pattern rather than inherit a claim about it`);
    // a lazy rl means every close must be null-safe, or the failure path throws instead of reporting
    const after = lines.slice(c.fn, c.fn + 400).join('\n');
    const bare = (after.match(/(?<!\?)\brl\.close\(\)/g) || []).length;
    check(bare === 0, `${c.name} contains ${bare} bare rl.close() call(s) while its rl is lazy — a failure before the first prompt throws a TypeError instead of printing why`);
  }
}


// ── askHidden must OWN stdin AT THE MOMENT IT RUNS, not merely have been built lazily ─────────────────────────────
//
// Lazy construction was necessary and NOT sufficient, and the gap cost the owner a failed ceremony on a machine
// deliberately cut off from the network. By the time the passphrase is asked, the ceremony has already asked several
// questions, so the interface EXISTS — lazily built, but open — and askHidden's guard refuses one step before the
// files are written. The tool was correct and the ceremony still died.
//
// So the caller must hand stdin BACK: close the interface and null the handle immediately before each attempt, and
// let the lazy getter re-create it for whatever is asked next. Inside the loop, not once before it — askHidden's own
// no-tty fallback delegates to `ask`, which re-opens the interface, so a second attempt met an open reader again.
//
// And the retry must be BOUNDED: unbounded, it spins forever the moment stdin cannot answer.
{
  for (const m of SRC.matchAll(/askHidden\(/g)) {
    const line = SRC.slice(0, m.index).split('\n').length;
    if (/export async function askHidden/.test(lines[line - 1] || '')) continue;
    // FIVE LINES OF CODE, not of text. A comment block between the hand-back and the prompt pushed a correct call
    // out of the window and reported a defect that was not there — measured 2026-08-03, while fixing a credential
    // prompt that really did echo. A comment opens no reader, so it cannot be what breaks this property.
    const codeBefore = lines.slice(0, line).filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l));
    const before = codeBefore.slice(Math.max(0, codeBefore.length - 6)).join('\n');
    check(/rl = closeReader\(rl\);/.test(before),
      `the askHidden call at ust-cli/index.mjs:${line} does not hand stdin back first (\`rl?.close(); rl = null;\` within the five lines above it). Building the interface lazily is not enough — by this point earlier questions have opened it, and the guard will refuse one step before the ceremony writes anything.`);
    // PROXIMITY IS NOT CONTAINMENT. This read "a `while`/`for` within the eight lines above", which flagged a
    // one-line `for (const l of legs) console.log(…)` that had already CLOSED before the call — a printing loop, not
    // a retry loop. Measured 2026-08-03 on `ust reroot`. A loop only retries the question if it still ENCLOSES it, so
    // the test is brace depth: from the loop header to the call, depth must stay above zero.
    const encloses = (() => {
      for (let i = line - 2; i >= Math.max(0, line - 12); i--) {
        if (!/\b(while|for)\s*\(/.test(lines[i] || '')) continue;
        let depth = 0;
        for (const l of lines.slice(i, line - 1)) for (const ch of l) { if (ch === '{') depth++; else if (ch === '}') depth--; }
        if (depth > 0) return lines.slice(i, line + 2).join('\n');       // still open at the call ⇒ it wraps it
      }
      return null;
    })();
    if (encloses) {
      check(/tries|attempts|max|>\s*\d/.test(encloses),
        `the askHidden call at :${line} retries in an UNBOUNDED loop — an exhausted pipe or a detached terminal makes it spin forever, printing the same prompt on a machine that may have nobody watching`);
    }
  }
}


// ── the reader lifecycle, and the two things a pipe cannot show you ───────────────────────────────────────────────
//
// Both were measured on a real pty AFTER a piped rehearsal had reported success, and neither is visible under a pipe:
//
// 1. `rl.close()` is not enough. With `terminal: true` — what stdin gets in an actual terminal — readline attaches a
//    'data' AND a 'keypress' listener, and close() removes only the keypress one. The 'data' listener SURVIVES, so
//    askHidden's guard keeps refusing after a correct close. Under a pipe `terminal` is false and close() does drop
//    it, which is why the rehearsal passed and the operator's run did not.
// 2. A data event is a CHUNK, not a keystroke. A pasted passphrase — how anyone enters a strong one — arrives whole,
//    matches no terminator, is pushed as a single "character", and the prompt never returns. The ceremony hung.
{
  check(/export function openReader/.test(SRC) && /export function closeReader/.test(SRC),
    'the reader lifecycle is gone — close() alone leaves a live stdin listener on a terminal, and every askHidden after it will be refused');
  check(!/createInterface\(\{ input: process\.stdin/.test(SRC.replace(/export function openReader[\s\S]*?\n}/, '')),
    'a readline interface is created outside openReader — its listeners will not be undone, so the next secret prompt is refused');
  const cr = SRC.slice(SRC.indexOf('export function closeReader'));
  check(/removeListener/.test(cr.slice(0, 600)), 'closeReader no longer removes the listeners readline added — close() does not on a terminal');
  check(/before\[ev\]\.includes/.test(cr.slice(0, 600)), 'closeReader no longer preserves foreign listeners — it must undo only what it added');
  const ah = SRC.slice(SRC.indexOf('export async function askHidden'));
  // ANCHORED ON THE PROPERTY, NOT THE SPELLING. This read `for (const c of b.toString` and went red when the loop
  // was refactored to keep the chunk in a named variable — the property was intact and the anchor had moved. Two
  // independent marks now, both about what the code DOES: the chunk becomes text, and it is walked by code point.
  const body = ah.slice(0, 4000);
  check(/b\.toString\('utf8'\)/.test(body) && /for \(const c of \w/.test(body),
    'askHidden reads a data event as ONE character again — a pasted passphrase arrives as a chunk, matches no terminator, and the prompt never returns');
  // THE REMAINDER. MEASURED 2026-08-03: on the terminator the loop resolved and DISCARDED the rest of the chunk, so
  // a SECOND askHidden waited forever for input already delivered. Reproduced under a pipe and under a real pty, so
  // it is a race an interactive human hides by typing slowly. `ust reroot` is the first command needing two secrets
  // and it hung on the second. A reader that consumes a chunk owes back what it did not use.
  check(/HIDDEN_PENDING = /.test(body) && /HIDDEN_PENDING/.test(body.slice(0, 1500)),
    'askHidden no longer hands back the UNUSED remainder of a data chunk — a second secret prompt in the same command will hang');
  check(/if \(c < ' '\) continue;/.test(body),
    'askHidden accepts C0 control characters into a secret again — an operator sees an asterisk, cannot see what was accepted, and can never reproduce the passphrase');
}


// ── a command that finishes must EXIT ─────────────────────────────────────────────────────────────────────────────
//
// The air-gapped ceremony completed correctly — eight files, every document verified, the whole handoff printed — and
// then hung. `askHidden` resumes stdin to read in raw mode and never paused it again, and a resumed stdin with no
// reader holds the event loop open. The shell never returned a prompt, and the operator's next command was typed
// into a dead process. Nothing in the output said anything was wrong, because nothing WAS wrong except that it would
// not end.
//
// Checked structurally here (the runtime proof is the pty rehearsal): whatever resumes stdin must restore the state
// it found, and the reader lifecycle must pause a stream nobody is left reading.
{
  const ah = SRC.slice(SRC.indexOf('export async function askHidden'));
  const body = ah.slice(0, 3000);
  check(/stdin\.resume\(\)/.test(body), 'askHidden no longer resumes stdin — the raw read would never receive anything');
  check(/const wasPaused = stdin\.isPaused\(\)/.test(body),
    'askHidden resumes stdin without recording whether it was paused — it cannot restore what it found, so the process never exits');
  check(/if \(wasPaused\) stdin\.pause\(\)/.test(body),
    'askHidden does not restore the paused state on the way out — a resumed stdin with no reader holds the event loop open and the command hangs after finishing');
  const cr = SRC.slice(SRC.indexOf('export function closeReader'), SRC.indexOf('export async function askHidden'));
  check(/process\.stdin\.pause\(\)/.test(cr),
    'closeReader does not pause a stream nobody is reading — the process stays alive after the last question');
  check(/listenerCount\('data'\) === 0/.test(cr),
    'closeReader pauses unconditionally — it must only do so when no reader is left, or it would starve a concurrent one');
}


console.log(`\n  ceremony self-check   PASS ${pass}   FAIL ${fail.length}   (${sites.length} self-check sites × ${WORLD.length} world properties)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every ceremony self-check asserts what the ceremony preserves, and every failure branch can report');
