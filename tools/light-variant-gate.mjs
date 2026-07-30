// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes — light panels compared against the dark originals they derive from
// Light-variant gate — every `.github/<panel>-light.svg` must equal the palette map applied to its dark original.
//
// The light files exist because the diagrams were authored in GitHub's dark palette and rendered as a black block on
// a white page. They are DERIVED, so the failure mode is not "wrong colour" but DRIFT: someone edits a dark panel and
// the light one silently keeps yesterday's picture, or edits a light file by hand and the next generator run discards
// it. Re-running the derivation is the only check that closes both.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { toLight, unmappedColours, lightName, imageRe, altOf, isDarkOnly, DARK_ONLY } from './lib/readme-image.mjs';

const DIR = new URL('../.github/', import.meta.url);
const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const all = readdirSync(DIR).filter((f) => f.endsWith('.svg') && !f.endsWith('-light.svg'));
const darks = all.filter((f) => !isDarkOnly(f.replace(/\.svg$/, '')));
// a dark-only panel must stay ONE artifact: no derived light file, no <picture> fork to drift out of step
for (const name of DARK_ONLY) {
  check(!existsSync(new URL(lightName(name) + '.svg', DIR)), name + ' is dark-on-both-themes by design (a TUI panel is dark on a light page too) yet a derived light file exists — delete it, or drop it from DARK_ONLY with a reason');
  check(!/<picture>[\s\S]{0,400}\.github\/' + name + '\.svg/.test(README), name + ' is dark-only yet sits in a <picture> block');
}
check(darks.length > 0, 'no dark panels found — the gate would pass vacuously');

for (const f of darks) {
  const base = f.replace(/\.svg$/, '');
  const lp = new URL(lightName(base) + '.svg', DIR);
  check(existsSync(lp), `${base} has no light variant — run tools/gen-light-svgs.mjs`);
  if (!existsSync(lp)) continue;
  const dark = readFileSync(new URL(f, DIR), 'utf8');
  check(unmappedColours(dark).length === 0, `${base} uses colours outside the palette: ${unmappedColours(dark).join(' ')} — the derivation would leave them dark on a white page`);
  check(readFileSync(lp, 'utf8') === toLight(dark), `${base}-light.svg is NOT the derivation of ${base}.svg — either the dark panel changed without regenerating, or the light file was hand-edited. Run tools/gen-light-svgs.mjs.`);
}

// every panel referenced by the README must go through the <picture> block, or a reader on a white page gets the
// dark artwork back — the exact defect this closes
for (const f of darks) {
  const base = f.replace(/\.svg$/, '');
  if (!new RegExp('\\.github/' + base.replace(/[-.]/g, '\\$&') + '\\.svg').test(README)) continue;
  check(imageRe(base).test(README), `README references ${base}.svg outside a <picture> block — a light-theme reader would get the dark artwork`);
  check(typeof altOf(README, base) === 'string' && altOf(README, base).length > 40, `${base}'s image block carries no substantial alt text — agents read the alt, not the SVG`);
}

// each leg must be able to fail
check(!imageRe('nonexistent-panel').test(README), 'the block probe matches a panel the README lacks');
check(toLight('#0d1117') === '#ffffff', 'the derivation no longer maps the dark canvas — light variants would keep a black background');
check(unmappedColours('#123456').length === 1, 'the unmapped-colour probe reports nothing for an unknown colour');

console.log(`\n  light variants   PASS ${pass}   FAIL ${fail.length}   (${darks.length} panels)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every light panel is the derivation of its dark original, and every README image goes through <picture>');
