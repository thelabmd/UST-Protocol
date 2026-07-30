// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:NETWORK_BY_DESIGN names the one callee that IS the network, whose call site the guarded/unguarded legs already govern — the callee set itself is DERIVED from what the command calls before the cut
// Offline-ceremony gate — the air-gapped half must be unable to reach the network, by POSITION, not by intention.
//
// The whole value of an air-gapped ceremony is one sentence an operator gets to say afterwards: "the crown key was
// generated on a machine with no network, so it never left over one." That sentence is worth exactly as much as the
// code behind it. A single stray call — a probe, a readback, a telemetry ping — and it becomes false, while every
// output still looks correct.
//
// So this does not check that the offline path AVOIDS the network. It checks that the offline path RETURNS before
// the network section begins: the early return is a cut, and everything that reaches out lives after it. A future
// call added below the cut cannot break the claim, and one added above it fails here.
import { readFileSync } from 'node:fs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const start = SRC.indexOf('async function cmdGenesis');
check(start > 0, 'cmdGenesis not found — the gate would be vacuous');
const body = SRC.slice(start, SRC.indexOf('\nasync function ', start + 10) > 0 ? SRC.indexOf('\nasync function ', start + 10) : undefined);

// the flag must be declared before it is read — a temporal dead zone killed the whole command on its first run
const decl = body.indexOf("const offline = !!arg('offline'");
const firstUse = body.indexOf('if (offline)');
check(decl > 0, 'the ceremony no longer takes --offline');
check(decl < firstUse, '`offline` is used before it is declared — a temporal dead zone, which is how this shipped broken the first time');

// THE CUT: the early return that ends the offline half
const cut = body.indexOf('offlineHandoff(');
check(cut > 0, 'the offline handoff is gone — an air-gapped operator would be left without the second half');

// every network reach in this command must live AFTER the cut
const NET = /\b(fetch\(|remintProbe\(|dohLookup|cfApi|wranglerDeploy\(|cfPublish\(|liveGate)/g;
const reaches = [...body.matchAll(NET)].map((m) => ({ at: m.index, what: m[1] }));
check(reaches.length >= 3, `only ${reaches.length} network reaches found in the ceremony — the probe has gone blind`);

const before = reaches.filter((r) => r.at < cut);
// the remint probe is the one reach that sits before the files, and it is BRANCHED: offline takes the other arm.
// So a reach before the cut is only acceptable if it is inside the `else` of the offline branch.
// Guarded means: the nearest preceding `if (offline) {` is followed by an `} else {` that this call sits inside.
// A fixed look-back window is the wrong instrument — the offline arm is prose-heavy and grows, and a window sized to
// today's text silently stops reaching tomorrow's. Measured: 725 characters were needed and 700 were allowed, so the
// gate reported the correctly-guarded probe as a breach. Anchor on the structure instead of on a distance.
const guarded = before.filter((r) => {
  const io = body.lastIndexOf('if (offline) {', r.at);
  if (io < 0) return false;
  const ie = body.indexOf('} else {', io);
  return ie > io && ie < r.at;
});
const unguarded = before.filter((r) => !guarded.includes(r));
check(unguarded.length === 0,
  `${unguarded.length} network call(s) sit before the offline cut and outside its guard — the air-gapped half would touch the network: ${unguarded.map((r) => r.what).join(', ')}`);

// THE COMMAND IS NOT THE WHOLE OFFLINE HALF. cmdGenesis delegates the actual work — key generation, sealing, the
// self-check — to other functions, and a network call in one of those breaks the air gap just as completely. The
// first version of this gate scanned only cmdGenesis; a mutation placed a `fetch` inside `buildCeremony` and it
// stayed green. So the callees that run before the cut are scanned too, and there the rule is stricter: NO network
// at all, because they have no offline branch to take.
// THE CALLEE SET IS DERIVED, and the hand-typed version was covering less than half of it. MEASURED 2026-07-30:
// thirteen names are called before the cut; four were listed. `openReader`, `ceremonyMap`, `resolveDnsToken`,
// `closeReader` and `askHidden` run inside the air gap and nothing was scanning them — the same shape as the
// `buildCeremony` miss recorded above, which is what this list was created for in the first place.
//
// Two distinctions the derivation has to make, and both were found by getting them wrong first:
//   · LOCAL vs TOP-LEVEL. `writeSecret`, `askOr` and sixty others are declared INSIDE cmdGenesis, so the positional
//     cut already governs them; scanning them as separate functions made the extractor run to the end of the file and
//     report the command's own network section as theirs.
//   · a `const` is not a function. `CADENCE` matched at column 0 — inside a TEMPLATE STRING the ceremony emits into a
//     worker. The declaration must be a function or an arrow, or the set fills with text.
const NETWORK_BY_DESIGN = {
  remintProbe: 'it IS the network reach — a re-mint probe against the live name. Its CALL SITE before the cut is what matters, and the guarded/unguarded legs above already require it to sit inside the `else` of the offline branch.',
};
const preCut = body.slice(0, cut);
const topLevel = (fn) => {
  const m = new RegExp('^(export )?(async )?(function ' + fn + '\\b|const ' + fn + '\\s*=\\s*(async\\s*)?\\()', 'm').exec(SRC);
  if (!m) return null;
  const from = m.index, rest = SRC.slice(from + m[0].length);
  const nx = rest.search(/^(export )?(async )?(function \w|const \w+\s*=\s*(\(|async))/m);
  return { at: from, src: SRC.slice(from, nx > 0 ? from + m[0].length + nx : undefined) };
};
const OFFLINE_CALLEES = [...new Set([...preCut.matchAll(/\b([a-zA-Z][A-Za-z0-9]{3,})\s*\(/g)].map((m) => m[1]))]
  .filter((n) => n !== 'cmdGenesis' && topLevel(n) && !Object.hasOwn(NETWORK_BY_DESIGN, n))
  .concat(['offlineHandoff']);   // the cut itself: it runs LAST in the offline half, so it is not "before" it
check(OFFLINE_CALLEES.length >= 6, `only ${OFFLINE_CALLEES.length} offline callees derived — the scan has gone blind and this leg would pass vacuously`);
check(!OFFLINE_CALLEES.includes('callThatCannotExist'), 'the callee derivation accepts a name that does not exist');
for (const [fn, why] of Object.entries(NETWORK_BY_DESIGN)) check(String(why).length >= 60, `${fn} is exempted with a reason too short to be one`);

for (const fn of OFFLINE_CALLEES) {
  const t = topLevel(fn);
  check(!!t, `${fn} is called in the offline half and has no top-level declaration the probe can bound`);
  if (!t) continue;
  // CONTROL for the extractor itself: a body that runs to the end of the file means the bound was not found, and
  // that is how a local helper was once reported as reaching the network — the command's own section, attributed to it.
  check(t.src.length < SRC.length / 3, `${fn}: the body extraction did not find its end (${t.src.length} of ${SRC.length} chars) — it would report a neighbour's network reach as this function's`);
  const hits = [...t.src.matchAll(NET)].map((m) => m[1]);
  check(hits.length === 0,
    `${fn} runs in the OFFLINE half and reaches the network (${[...new Set(hits)].join(', ')}) — the air gap is broken inside a callee, where the command's own cut cannot see it`);
}

// and the handoff must tell the operator what NOT to carry out — the crown leaving is the failure this prevents
const handoff = SRC.slice(SRC.indexOf('export function offlineHandoff'), SRC.indexOf('export function ceremonySummary'));
check(/DO NOT CARRY OUT/.test(handoff), 'the handoff no longer separates what travels from what stays — the crown key is the whole point');
check(/genesis-key/.test(handoff) && /recovery-key/.test(handoff), 'the handoff no longer names the keys that must not travel');
check(/(ust|invocation\(\)\}) publish/.test(handoff), 'the handoff no longer names the online half, so an operator is left holding files with no next step');

// each leg must be able to fail
check(!/\bnonexistentNetworkCall\(/.test(body), 'the network probe matches a call the source lacks');

console.log(`\n  offline ceremony   PASS ${pass}   FAIL ${fail.length}   (${reaches.length} network reaches · ${before.length} before the cut, all guarded)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ the air-gapped half returns before the network section — the claim is positional, not intentional');
