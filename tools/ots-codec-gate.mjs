// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — the import roster is DERIVED from the package sources, so a new dependency fails by
// being new rather than by being recognised; the round-trip is an equality on real calendar output, and the
// mutation leg proves the equality is evaluated rather than assumed.
// The Bitcoin substrate path carries no third-party code, and reads a real proof byte-for-byte.
//
// Two properties, and the first is the one that regresses silently. Removing a dependency is an afternoon;
// keeping it removed is a gate. A future contributor reaching for `opentimestamps` to add one feature would
// hand every consumer of an anchored document a tree with two critical advisories in it again — and nothing
// in a passing test suite would say so, because the tests would keep passing.
//
// THE IMPORT ROSTER IS DERIVED FROM SOURCE, never listed here. A hand-written list of forbidden modules is a
// sample: it forbids what someone remembered. This enumerates every import the package actually has and
// admits only the ones resolvable inside Node or inside this package — so a NEW dependency fails by being
// new, not by being recognised.
//
// The second property is the codec's contract. A parser can drop a branch or misread a length in ways no
// field assertion catches, and each of those changes the message the rest of the proof is computed over.
// Serializing back and demanding byte equality asks the question that covers them all: was every byte
// accounted for? The fixture is real calendar output — a hand-built proof would test the encoder's idea of
// the format rather than the format.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseOts, serializeOts, isComplete, bitcoinAttestations } from '../packages/ust-ots-verify/ots-codec.mjs';

const PKG_DIR = 'packages/ust-ots-verify';
const fails = [];
const check = (ok, msg) => { if (!ok) fails.push(msg); };

// ── 1. the manifest declares nothing ────────────────────────────────────────────────────────────────
const pkg = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8'));
for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
  const names = Object.keys(pkg[field] ?? {});
  check(names.length === 0, `${PKG_DIR}/package.json declares ${field}: ${names.join(', ')} — the substrate path is meant to carry none`);
}

// ── 2. no source file imports anything foreign ──────────────────────────────────────────────────────
const sources = readdirSync(PKG_DIR).filter((f) => f.endsWith('.mjs'));
check(sources.length > 0, `${PKG_DIR} has no .mjs sources — an empty enumeration is not a pass`);

const IMPORT = /(?:^|\n)\s*(?:import\b[^;\n]*?from\s*|import\s*|export\b[^;\n]*?from\s*)['"]([^'"]+)['"]/g;
const DYNAMIC = /\bimport\(\s*['"]([^'"]+)['"]\s*\)|\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;
let scanned = 0;
for (const f of sources) {
  const src = readFileSync(join(PKG_DIR, f), 'utf8');
  const specs = [
    ...[...src.matchAll(IMPORT)].map((m) => m[1]),
    ...[...src.matchAll(DYNAMIC)].map((m) => m[1] ?? m[2]),
  ];
  scanned += specs.length;
  for (const spec of specs) {
    const ok = spec.startsWith('node:') || spec.startsWith('./') || spec.startsWith('../');
    check(ok, `${PKG_DIR}/${f} imports "${spec}" — a third party on the substrate path`);
  }
}
check(scanned > 0, 'no import specifiers were found at all — the roster is derived from source, and an empty derivation is a broken gate');

// ── 3. the codec round-trips real calendar output ───────────────────────────────────────────────────
// The same bytes the package test pins, kept here too on purpose: this gate must be able to fail ALONE,
// without depending on which other suite happened to run.
const PENDING = Buffer.from(readFileSync(join(PKG_DIR, 'ots-codec.test.mjs'), 'utf8')
  .match(/const PENDING_HEX =\s*([\s\S]*?);/)[1]
  .replace(/[^0-9a-f]/g, ''), 'hex');

check(PENDING.length > 64, 'the fixture did not load — a gate that verifies nothing reports green');

let parsed;
try { parsed = parseOts(PENDING); } catch (e) { fails.push(`the real fixture does not parse: ${e.message}`); }
if (parsed) {
  check(serializeOts(parsed).equals(PENDING), 'round trip is NOT byte-identical — the parser did not account for every byte');
  check(isComplete(parsed) === false, 'a pending proof reports complete — pending is a true answer, not a lesser final');
  check(bitcoinAttestations(parsed).length === 0, 'a pending proof yields a Bitcoin attestation');
}

// ── 4. the gate can fail ────────────────────────────────────────────────────────────────────────────
// Without this leg the three checks above would report green over a parser that never ran.
const mutated = Buffer.from(PENDING); mutated[mutated.length - 1] ^= 0xff;
let mutationCaught = false;
try { mutationCaught = !serializeOts(parseOts(mutated)).equals(PENDING); } catch { mutationCaught = true; }
check(mutationCaught, 'a mutated proof round-tripped to the original — the equality is not being evaluated');

console.log(`  ots codec   ${sources.length} source(s), ${scanned} import(s), fixture ${PENDING.length} b`);
if (fails.length) {
  for (const f of fails) console.error(`::error::${f}`);
  console.error(`\n✗ ots-codec gate FAILED — ${fails.length} problem(s)`);
  process.exit(1);
}
console.log('  ✓ the substrate path carries no third-party code, and a real proof round-trips byte-for-byte');
