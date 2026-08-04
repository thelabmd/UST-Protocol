// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the command set is DERIVED from the source (every body that parses positionals) and the flag classification is checked against it both ways
// Stream CONSUMPTION gate — the dual of `discovery-serving-gate`. That one asks whether an artifact a ceremony
// PRODUCES has somewhere to be served; this one asks whether it has somewhere to be CONSUMED, and whether the
// command that consumes it can tell an argument from a filename.
//
// Three measured defects, one class, all in commands that take positionals AND flags:
//   1. `argv.slice(3).filter(a => !a.startsWith('--'))` dropped flag NAMES and kept their VALUES. `arg()` reads a
//      value as argv[i+1], so a value-flag owns TWO slots. Proved: `ust stream --genesis <g> <f>` opened <g> as a
//      frame — and a <g> that VERIFIES was silently admitted into the range, so a completeness verdict was computed
//      over a set the operator never described. The same line existed in `cmdForkChoice`; fixing only the reported
//      one is how a defect class survives its own fix.
//   2. `--keylog` could not take the SERVED ARRAY — the file `ust rotate` writes, and the bytes at
//      /.well-known/ust-keylog.
//   3. `--cadence-log` could not take it either — the file `ust cadence` writes. (Measured: a single entry verified
//      VALID:LIGHT, the array INVALID E-MALFORMED. The verification CONTEXT was my first hypothesis and the
//      measurement disproved it — the shape was the whole defect.)
//
// So the gate pins: no command parses positionals by prefix · every usage flag is CLASSIFIED · every flag a command
// READS is promised in its usage · and every served-log artifact is actually accepted. (rev92)
import { readFileSync } from 'node:fs';
import { STREAM_VALUE_FLAGS, FORKCHOICE_VALUE_FLAGS, FORKCHOICE_BOOL_FLAGS, NAMES_VALUE_FLAGS, positionals, parseLogRaw, buildCeremony } from '../packages/ust-cli/index.mjs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// The commands under this gate, with their DECLARED classification. The claim that used to stand here — "adding a
// positional-taking command without a row here fails leg 1" — was FALSE: leg 1 pins the `--`-prefix pattern, and
// nothing enumerated this set at all, so a third command parsing positionals would simply not be looked at while the
// gate reported over "2 positional-taking commands". The set is now DERIVED from the CLI source (leg 0b below) and
// these rows are the classification, which legs 2 and 3 already check against the source in both directions.
const COMMANDS = [
  { fn: 'cmdStream', value: STREAM_VALUE_FLAGS, bool: new Set() },
  { fn: 'cmdForkChoice', value: FORKCHOICE_VALUE_FLAGS, bool: FORKCHOICE_BOOL_FLAGS },
  { fn: 'cmdNames', value: NAMES_VALUE_FLAGS, bool: new Set() },   // F.5t-a — paths only today; classified anyway, so the first flag added cannot silently reintroduce the prefix sweep
];

// The reader helpers whose literal argument names a flag. `arg()` is the direct reader; `rd()` is cmdStream's local
// wrapper. Named here because the scan below cannot see through a rename — so leg 0 asserts they still EXIST, and
// this gate's blind spot is written down instead of merely being absent.
const READERS = ['arg', 'rd'];
for (const r of READERS) check(new RegExp(`\\b${r}\\(`).test(SRC), `the flag scan looks for \`${r}(\` and the source no longer contains it — the scan has gone blind and every later leg is measuring nothing`);

// ── 1. nobody parses positionals by prefix any more. This is the defect itself, pinned as a SET over the file.
const byPrefix = [...SRC.matchAll(/process\.argv\.slice\(\d+\)\.filter\(/g)];
check(byPrefix.length === 0, `${byPrefix.length} site(s) still split positionals by the \`--\` prefix — a flag VALUE will be read as a positional there`);

const bodyOf = (fn) => {
  const start = SRC.indexOf(`function ${fn}(`);
  if (start < 0) return null;
  const end = SRC.indexOf('\n}\n', start);
  return end < 0 ? SRC.slice(start) : SRC.slice(start, end);
};

// ── 0b. THE DOMAIN, enumerated from the source: every command whose body parses positionals must have a row above.
// A classification is only as good as the set it classifies, and this set was the one thing nobody checked.
{
  const found = [...SRC.matchAll(/function (cmd\w+)\(/g)].map((m) => m[1])
    .filter((fn) => { const b = bodyOf(fn); return b && /positionals\(process\.argv\.slice\(/.test(b); });
  const declared = new Set(COMMANDS.map((c) => c.fn));
  for (const fn of found) check(declared.has(fn), `${fn} parses positionals and has no row in COMMANDS — it is not classified, so positionals() cannot know which of its flags take a value`);
  for (const fn of declared) check(found.includes(fn), `COMMANDS classifies ${fn} and no such command parses positionals any more — a stale row reads as coverage`);
  // CONTROL — the scan must discriminate, or the enumeration is a list of everything or of nothing.
  check(found.length >= 2, `the positional-command scan found ${found.length} — it has gone blind and this leg would pass vacuously`);
  check(!found.includes('cmdThatCannotExist'), 'the scan accepts a command that does not exist');
}


for (const { fn, value, bool } of COMMANDS) {
  const body = bodyOf(fn);
  check(body !== null && body.length > 100, `${fn}: body not found — the gate cannot speak for it`);
  if (!body) continue;

  // ── 2. it must use the declared-set parser, not a prefix filter
  check(/positionals\(process\.argv\.slice\(\d+\), [A-Z_]+\)/.test(body), `${fn} does not parse positionals against a DECLARED flag set`);

  // ── 3. every flag the command READS is classified, and is PROMISED in its usage line. `--keylog` was read by
  //      cmdStream and appeared in no usage text — an operator could not discover the flag that makes HIGH
  //      resolution work, and nothing said so.
  const read = new Set([...body.matchAll(new RegExp(`\\b(?:${READERS.join('|')})\\('([a-z-]+)'`, 'g'))].map((m) => m[1]));
  // A command that DECLARES flags and reads none has a stale declaration, and the scan saying so is the point.
  // A command that declares NONE and reads none is not vacuous — it is consistent, and demanding a flag here
  // would be surface invented to satisfy a gate. Nothing is lost: reading an undeclared flag still fails below,
  // and declaring one that is never read still fails at the end of this loop, so both directions stay closed.
  const declaresNothing = value.size === 0 && bool.size === 0;
  check(read.size > 0 || declaresNothing, `${fn}: the flag scan found no flags at all while ${value.size + bool.size} are declared — vacuous`);
  const usage = body.match(/usage: [^'`]*/);
  const promised = new Set([...(usage ? usage[0] : '').matchAll(/--([a-z-]+)/g)].map((m) => m[1]));
  for (const f of read) {
    check(value.has(f) || bool.has(f), `${fn} reads --${f} but it is classified neither value-taking nor boolean — positionals() cannot know whether to skip its next token`);
    check(promised.has(f), `${fn} reads --${f} and never promises it in its usage line — an undiscoverable flag`);
  }
  for (const f of [...value, ...bool]) check(read.has(f), `${fn} classifies --${f} but never reads it — a stale declaration drifts into a wrong skip`);
}

// ── 4. positionals() BEHAVES: a value-flag's value is never a positional, a boolean's successor always is.
check(JSON.stringify(positionals(['--genesis', 'g.json', 'f1.json'], STREAM_VALUE_FLAGS)) === '["f1.json"]', 'a value-flag\'s value is still swept into the positionals');
check(JSON.stringify(positionals(['f1.json', '--genesis', 'g.json', 'f2.json'], STREAM_VALUE_FLAGS)) === '["f1.json","f2.json"]', 'positionals around a value-flag are not both kept');
check(JSON.stringify(positionals(['--offline', 'a.json'], FORKCHOICE_VALUE_FLAGS)) === '["a.json"]', 'a BOOLEAN flag ate the positional after it — the value/bool split is not honoured');
check(JSON.stringify(positionals(['--genesis'], STREAM_VALUE_FLAGS)) === '[]', 'a value-flag with no value at the end of argv is mishandled');

// ── 5. the SERVED shapes are accepted. Built from a real ceremony, because the whole defect was that the shape our
//      own tooling writes was the shape our own reader refused.
const cer = await buildCeremony({ domain: 'x.example', profile: 'silver' });
const served = JSON.stringify([cer.keylog0], null, 2) + '\n';
const parsed = parseLogRaw(served, '--keylog');
check(!parsed.err && parsed.entries.length === 1, `the served key-log array (what \`ust genesis\`/\`ust rotate\` write) is refused: ${parsed.err}`);
check(parseLogRaw(JSON.stringify(cer.keylog0), '--keylog').err !== undefined, 'a SINGLE entry is being accepted by the array parser — the two shapes must stay distinguishable, or the byte-router cannot route');

// ── 6. the pin must be able to FAIL.
check(JSON.stringify(positionals(['--nosuchflag', 'x.json'], STREAM_VALUE_FLAGS)) === '["x.json"]', 'an UNDECLARED flag is being treated as value-taking — undeclared must mean boolean, or a typo silently swallows a frame');
check(parseLogRaw('{"not":"an array"}', '--keylog').err !== undefined, 'the array parser accepts a non-array — leg 5 would pass for anything');
check(parseLogRaw('[{"ust":"1.0"}]', '--keylog').err !== undefined, 'the array parser accepts an array of non-verifying entries — leg 5 proves nothing');

console.log(`\n  stream consumption   PASS ${pass}   FAIL ${fail.length}   (${COMMANDS.length} positional-taking commands)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ no command splits positionals by prefix; every flag is classified and promised; the served log shapes our ceremonies write are accepted');
