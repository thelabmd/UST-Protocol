// SPDX-License-Identifier: Apache-2.0
// README status panel — a TUI-style (btop/lazygit) SVG generated from the CANONICAL `VERSION.spec`, the same one
// version source the README alt-text and root package.json track (gen-readme-version.mjs). Deterministic (a pure
// function of VERSION.spec — no dates, no randomness), so `git diff --exit-code .github/status.svg` gates drift the
// same way the spec registry is gated. Dark terminal palette by design: a terminal panel is dark on BOTH GitHub
// themes — no prefers-color-scheme forks, one artifact. Borders are VECTOR lines (crisp at any scale), not box-drawing
// glyphs, so the panel survives mobile widths where an ASCII box in a code block wraps and tears.
import { readFileSync, writeFileSync } from 'node:fs';
import { VERSION } from '../packages/ust-protocol/index.mjs';

const W = 880;
const PAD = 28;                       // left text margin
const COL = 214;                      // value column for label:value rows
const BG = '#0d1117', BORDER = '#3d444d', SEP = '#30363d';
const TITLE = '#58a6ff', TEXT = '#c9d1da', LABEL = '#8b949e', VALUE = '#79c0ff';
const OK = '#3fb950', WARN = '#d29922';
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');   // MUST escape quotes: the alt goes into aria-label="…" (ust:"1.0" would break the attribute → XML error)
const parts = [];
let y = 0;
const row = (dy) => (y += dy, y);
const text = (x, yy, s, fill, extra = '') => parts.push(`  <text x="${x}" y="${yy}" fill="${fill}" ${extra}>${esc(s)}</text>`);
const section = (label) => {                                     // ── LABEL ──────── separator with the title cut into it
  const yy = row(34);
  parts.push(`  <line x1="${PAD - 12}" y1="${yy - 4}" x2="${W - 16}" y2="${yy - 4}" stroke="${SEP}" stroke-width="1"/>`);
  parts.push(`  <rect x="${PAD - 4}" y="${yy - 13}" width="${label.length * 8.2 + 14}" height="17" fill="${BG}"/>`);
  text(PAD + 2, yy, label, TITLE, `font-size="12" font-weight="600" letter-spacing="2"`);
};
const kv = (label, value, vfill) => {                            // Label : value
  const yy = row(26);
  text(PAD + 14, yy, label, LABEL);
  text(COL - 22, yy, ':', LABEL);
  text(COL, yy, value, vfill);
};
const mark = (glyph, gfill, s) => {                              // ✓ / ○ status line
  const yy = row(26);
  text(PAD + 14, yy, glyph, gfill, `font-weight="600"`);
  text(PAD + 38, yy, s, TEXT);
};
const bullet = (s) => { const yy = row(26); text(PAD + 14, yy, '•', LABEL); text(PAD + 38, yy, s, TEXT); };

// ── panel content (mirrors the README status block; version is the ONE interpolated token) ──
row(40); text(PAD, y, 'UST Protocol', TITLE, `font-size="17" font-weight="600"`);
row(30); text(PAD, y, 'Verify machine-readable state without trusting whoever handed it to you.', TEXT);
row(6);
section('RELEASE STATUS');
kv('Version', VERSION.spec, VALUE);
kv('Stage', 'RELEASE CANDIDATE', WARN);
kv('Final 1.0?', 'No', TEXT);
row(6);
section('ASSESSMENT');
mark('✓', OK, 'Multiple external AI reviews incorporated structurally');
mark('○', WARN, 'Independent human cryptographic audit — pending');
mark('✓', OK, 'Suitable for evaluation and integration testing');
row(6);
section('COMPATIBILITY');
kv('Wire format', 'ust: "1.0"', VALUE);
kv('Stability', 'stable across all 1.0 release candidates', TEXT);
row(6);
section('RECOMMENDATION');
bullet('Pin exact dependency versions.');
bullet('Do not treat RC builds as production-final.');
const H = y + 26;

// a CURATED, READABLE alt (agents read the alt, not the SVG) — the version stays the FIRST backtick token so the machine
// status-line remains greppable; the prose mirrors the panel's meaning.
const alt = 'UST status: `' + VERSION.spec + '` — a release candidate, not a final 1.0. Verify machine-readable state without trusting whoever handed it to you. Multiple external AI reviews incorporated structurally; an independent human cryptographic audit is pending; suitable for evaluation and integration testing. The wire format ust:"1.0" is stable across all release candidates; pin exact versions.';
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(alt.replace(/`/g, ''))}">
<title>${esc(alt.replace(/`/g, ''))}</title>
<g font-family="${MONO}" font-size="15">
  <rect x="1.5" y="1.5" width="${W - 3}" height="${H - 3}" rx="10" fill="${BG}" stroke="${BORDER}" stroke-width="1.5"/>
${parts.join('\n')}
</g>
</svg>
`;
writeFileSync(new URL('../.github/status.svg', import.meta.url), svg);
// sync the README status image ALT to this content (agents read the alt); the version token is preserved for the machine grep.
const readmePath = new URL('../README.md', import.meta.url);
let readme = readFileSync(readmePath, 'utf8');
const re = /!\[UST status:[^\]]*\]\(\.github\/status\.svg\)/;
if (!re.test(readme)) { console.error('  ✗ README has no "![UST status: …](.github/status.svg)" image tag'); process.exit(1); }
writeFileSync(readmePath, readme.replace(re, '![' + alt.replace(/\]/g, ')') + '](.github/status.svg)'));
console.log(`  ✓ .github/status.svg + README alt → ${VERSION.spec} (TUI status panel, deterministic from VERSION.spec)`);
