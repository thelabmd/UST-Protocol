// SPDX-License-Identifier: Apache-2.0
// Derive every light-theme illustration from its dark original. The light files are DERIVED artefacts — never edited
// by hand — so this runs in the same pipeline as the panel and status generators, and light-variant-gate re-runs the
// derivation to prove none has drifted.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { toLight, unmappedColours, lightName, isDarkOnly } from './lib/readme-image.mjs';

const DIR = new URL('../.github/', import.meta.url);
// dark-only panels are excluded WITH their reason: a TUI panel is dark on a light page too (see readme-image.mjs).
const darks = readdirSync(DIR).filter((f) => f.endsWith('.svg') && !f.endsWith('-light.svg') && !isDarkOnly(f.replace(/\.svg$/, '')));

let unmapped = 0;
for (const f of darks) {
  const src = readFileSync(new URL(f, DIR), 'utf8');
  const missing = unmappedColours(src);
  if (missing.length) { console.error(`  ✗ ${f} uses colours the palette does not map: ${missing.join(' ')}`); unmapped++; }
  writeFileSync(new URL(lightName(f.replace(/\.svg$/, '')) + '.svg', DIR), toLight(src));
}
if (unmapped) process.exit(1);
console.log(`  ✓ ${darks.length} light variants derived — palette-mapped from the dark originals, never hand-edited`);
