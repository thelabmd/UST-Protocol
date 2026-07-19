// SPDX-License-Identifier: Apache-2.0
// Conformance badge — a STATIC shields.io badge whose NUMBERS are generated from the real, drift-gated counts, NEVER
// hand-typed. Earlier this was a shields `endpoint` badge reading .github/badge-conformance.json over
// raw.githubusercontent — a fragile DYNAMIC chain (shields' dynamic backend + a second network fetch) that broke while
// the STATIC shields badges (the license badges) kept rendering. So the badge is now a plain STATIC shields URL — the
// same mechanism the license badges use — with the counts baked into the URL and REGENERATED here, then written into the
// README. `test:spec-sync` git-diff on README.md gates it, so the numbers can never silently drift (measured, not
// estimated). `vectors` = the language-neutral corpora (byte + arc); `fuzz` = the reference-checker probe count MEASURED
// from the runner's own report.
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const byte = JSON.parse(readFileSync(new URL('../vectors/checker-byte-vectors.json', import.meta.url), 'utf8'));
const arc = JSON.parse(readFileSync(new URL('../vectors/arc-vectors.json', import.meta.url), 'utf8'));
if (!Array.isArray(byte.vectors) || !Array.isArray(arc.vectors)) { console.error('  ✗ vector corpora missing a .vectors array'); process.exit(1); }
const vectors = byte.vectors.length + arc.vectors.length;   // language-neutral conformance vectors (byte + arc)

// MEASURE the fuzz probe count from the runner's own deterministic report — not a constant.
const fuzzPath = fileURLToPath(new URL('../packages/ust-protocol/reference-checker.fuzz.mjs', import.meta.url));
const fuzzOut = execSync('node ' + JSON.stringify(fuzzPath), { encoding: 'utf8' });
const m = fuzzOut.match(/\((\d+) probes\)/);
if (!m) { console.error('  ✗ could not read the fuzz probe count from the runner output'); process.exit(1); }
const fuzz = Number(m[1]);

const message = `${vectors} vectors · ${fuzz} fuzz`;
// STATIC shields badge encoding: `-`→`--`, `_`→`__`, then percent-encode (spaces → %20, `·` → %C2%B7).
const enc = (s) => encodeURIComponent(s.replace(/-/g, '--').replace(/_/g, '__'));
const url = `https://img.shields.io/badge/conformance-${enc(message)}-brightgreen`;

const readmePath = new URL('../README.md', import.meta.url);
let readme = readFileSync(readmePath, 'utf8');
const re = /!\[conformance\]\(https:\/\/img\.shields\.io[^)]*\)/;
if (!re.test(readme)) { console.error('  ✗ README has no ![conformance](https://img.shields.io…) badge tag'); process.exit(1); }
readme = readme.replace(re, `![conformance](${url})`);
writeFileSync(readmePath, readme);
console.log(`  ✓ README conformance badge → static shields "${message}" (${byte.vectors.length} byte + ${arc.vectors.length} arc vectors, fuzz measured)`);
