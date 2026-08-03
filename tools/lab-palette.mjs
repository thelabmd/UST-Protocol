// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the hex literals ARE the design system; `--check` proves every colour emitted
// downstream is drawn from this table and none was invented at a call site
//
// THE LAB · operator colour system, owned once.
//
// Source: `THE LAB Operator.dc.html` — two modes, light acts (I, II, III·1, V, VI) and dark insets (III·2, IV, the
// hero terminal, full-bleed banners). Recorded here rather than pasted into each diagram for the ordinary reason:
// a palette copied into N places is N places to drift, and a diagram whose colours were typed from memory is the
// same defect as a recap whose numbers were.
//
// A NOTE ON GITHUB, stated rather than discovered later: a `%%{init}%%` block pins the diagram's own background, so
// a reader in dark mode sees a LIGHT diagram. That is deliberate — the block is self-contained, like a figure on a
// page, and a diagram that half-inherits a host theme is the one that reads broken. The dark tokens below are for
// the panels INSIDE a figure (clusters, terminals, verdict cards), not for following the reader's setting.
export const TOKENS = {
  // ── light
  paper:        '#f4f2ec',   // page background
  ink:          '#1e1c1a',   // body text, headings
  ink2:         '#6f6b63',   // secondary text
  ink3:         '#a8a39a',   // tertiary — arrows, labels, inactive
  line:         '#d6d2c9',   // borders / rules
  line2:        '#e7e3da',   // lighter borders, plates
  accent:       '#0c7c78',   // teal accent on light — links, marks
  // ── dark panels
  bgPanel:      '#141312',   // dark sections
  bgDeep:       '#0d0c0b',   // deepest background (full-bleed)
  bgTerminal:   '#0f0e0d',   // hero terminal
  bgCard:       '#0b0a09',   // nested cards on dark
  borderDark:   '#2b2926',
  borderDark2:  '#302e2b',
  borderCard:   '#4a463f',
  textDark:     '#e8e4d8',
  textDark2:    '#b8b3a6',
  textDark3:    '#8f8a7e',
  textDark4:    '#57534a',
  alight:       '#5fb0ac',   // teal accent on dark
  // ── semantics
  valid:        '#5fb0ac',   // verified — on dark
  validLight:   '#0c7c78',   // verified — on light
  invalid:      '#c98a5e',   // error / refusal
};
const T = TOKENS;
export const MONO = 'IBM Plex Mono, ui-monospace, monospace';
export const SERIF = "'IBM Plex Serif', Georgia, serif";

/** The init directive. Goes on the FIRST line of a mermaid block, before any diagram keyword. */
export const mermaidInit = () => `%%{init: {'theme':'base','themeVariables':{`
  + `'background':'${T.paper}','primaryColor':'${T.line2}','primaryTextColor':'${T.ink}',`
  + `'primaryBorderColor':'${T.line}','secondaryColor':'${T.paper}','tertiaryColor':'${T.paper}',`
  + `'lineColor':'${T.ink3}','textColor':'${T.ink}','mainBkg':'${T.line2}','nodeBorder':'${T.line}',`
  + `'clusterBkg':'${T.bgPanel}','clusterBorder':'${T.borderCard}','edgeLabelBackground':'${T.paper}',`
  + `'fontFamily':'${MONO}'}}}%%`;

/** The class palette. Emit once per diagram, after the nodes; apply with `class A,B accent`. */
export const mermaidClassDefs = () => [
  `classDef base fill:${T.line2},stroke:${T.line},color:${T.ink};`,
  `classDef accent fill:${T.accent},stroke:${T.accent},color:${T.paper};`,
  `classDef muted fill:${T.paper},stroke:${T.line},color:${T.ink2},stroke-dasharray: 2 2;`,
  `classDef dark fill:${T.bgPanel},stroke:${T.borderCard},color:${T.textDark};`,
  `classDef darkCard fill:${T.bgCard},stroke:${T.borderCard},color:${T.textDark};`,
  `classDef darkAccent fill:${T.bgCard},stroke:${T.alight},color:${T.alight};`,
  `classDef valid fill:${T.bgPanel},stroke:${T.valid},color:${T.valid};`,
  `classDef invalid fill:${T.bgPanel},stroke:${T.invalid},color:${T.invalid};`,
  `linkStyle default stroke:${T.ink3},stroke-width:1px;`,
].join('\n');

/** Wrap diagram source in a fenced mermaid block carrying the theme and the classes. */
export const mermaid = (source) => '```mermaid\n' + mermaidInit() + '\n' + source.trim() + '\n' + mermaidClassDefs() + '\n```';

// ── `--check`: every colour this module EMITS must come from TOKENS. A hex typed at a call site is exactly the
// drift this file exists to prevent, and a palette nobody checks is a second place to be wrong.
if (process.argv[1] && process.argv[1].endsWith('lab-palette.mjs') && process.argv.includes('--check')) {
  const known = new Set(Object.values(TOKENS).map((h) => h.toLowerCase()));
  const emitted = [...`${mermaidInit()}\n${mermaidClassDefs()}`.matchAll(/#[0-9a-fA-F]{6}\b/g)].map((m) => m[0].toLowerCase());
  const stray = [...new Set(emitted)].filter((h) => !known.has(h));
  const controlHit = !known.has('#ff00ff');            // a colour NOT in the table must read as stray
  const controlMiss = known.has(TOKENS.accent.toLowerCase());
  let bad = 0;
  if (!controlHit || !controlMiss) { console.error('✗ CONTROL: the token membership test does not discriminate'); bad++; }
  if (stray.length) { console.error(`✗ ${stray.length} colour(s) emitted that are not in TOKENS: ${stray.join(', ')}`); bad++; }
  if (!emitted.length) { console.error('✗ nothing emitted — the sweep is blind'); bad++; }
  if (bad) process.exit(1);
  console.log(`  ✓ lab palette: ${Object.keys(TOKENS).length} tokens, ${new Set(emitted).size} distinct colours emitted, none invented`);
}
