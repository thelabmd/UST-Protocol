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
// page, and a diagram that half-inherits a host theme is the one that reads broken.
//
// AND THE LIMIT THAT MAKES IT MORE THAN A PREFERENCE: a fenced mermaid block on GitHub CANNOT follow the reader's
// theme. The `<picture>` + `prefers-color-scheme` trick works for SVG and PNG, which are images the browser
// selects between; a mermaid block is rendered client-side from source, and a media query has no place to live
// inside `%%{init}%%`. Emitting two blocks would show BOTH. So on GitHub the choice is one appearance for every
// reader, and we choose the light one — a printed figure, legible in either host theme.
//
// MODE is therefore for surfaces that DO follow a theme (theme-aware artifact pages, the operator site), not for
// GitHub. Same tokens, two bindings; `light` stays the default so nothing that renders on GitHub can drift into
// the dark set by omission.
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

// The two bindings. Same token table, and every value below is a lookup — a hex typed here would defeat `--check`.
const BIND = {
  light: { bg: T.paper, node: T.line2, nodeBorder: T.line, text: T.ink, line: T.ink3, cluster: T.bgPanel, clusterBorder: T.borderCard, accent: T.accent, onAccent: T.paper, ok: T.validLight, plate: T.paper, plateAlt: T.line2, second: T.ink2 },
  dark:  { bg: T.bgPanel, node: T.bgCard, nodeBorder: T.borderCard, text: T.textDark, line: T.textDark3, cluster: T.bgDeep, clusterBorder: T.borderCard, accent: T.alight, onAccent: T.bgCard, ok: T.valid, plate: T.bgPanel, plateAlt: T.bgCard, second: T.textDark2 },
};
const bind = (mode) => BIND[mode] ?? BIND.light;

/** The init directive. Goes on the FIRST line of a mermaid block, before any diagram keyword. */
export const mermaidInit = (mode = 'light') => { const B = bind(mode); return `%%{init: {'theme':'base','themeVariables':{`
  + `'background':'${B.bg}','primaryColor':'${B.node}','primaryTextColor':'${B.text}',`
  + `'primaryBorderColor':'${B.nodeBorder}','secondaryColor':'${B.bg}','tertiaryColor':'${B.bg}',`
  + `'lineColor':'${B.line}','textColor':'${B.text}','mainBkg':'${B.node}','nodeBorder':'${B.nodeBorder}',`
  + `'clusterBkg':'${B.cluster}','clusterBorder':'${B.clusterBorder}','edgeLabelBackground':'${B.bg}',`
  // gantt takes NO classDef, so its colours have to arrive through themeVariables or not at all
  + `'sectionBkgColor':'${B.plate}','altSectionBkgColor':'${B.plateAlt}','sectionBkgColor2':'${B.plateAlt}',`
  + `'taskBkgColor':'${B.node}','taskBorderColor':'${B.nodeBorder}','taskTextColor':'${B.text}',`
  + `'taskTextOutsideColor':'${B.second}','taskTextDarkColor':'${B.text}','activeTaskBkgColor':'${B.accent}',`
  + `'activeTaskBorderColor':'${B.accent}','doneTaskBkgColor':'${B.ok}','doneTaskBorderColor':'${B.ok}',`
  + `'critBkgColor':'${T.invalid}','critBorderColor':'${T.invalid}','gridColor':'${B.nodeBorder}','todayLineColor':'${T.invalid}',`
  + `'fontFamily':'${MONO}'}}}%%`; };

/** The class palette. Emit once per diagram, after the nodes; apply with `class A,B accent`. */
export const mermaidClassDefs = (mode = 'light') => { const B = bind(mode); return [
  `classDef base fill:${B.node},stroke:${B.nodeBorder},color:${B.text};`,
  `classDef accent fill:${mode === 'dark' ? B.node : B.accent},stroke:${B.accent},color:${mode === 'dark' ? B.accent : B.onAccent};`,
  `classDef muted fill:${B.bg},stroke:${B.nodeBorder},color:${B.second},stroke-dasharray: 2 2;`,
  `classDef dark fill:${T.bgPanel},stroke:${T.borderCard},color:${T.textDark};`,
  `classDef darkCard fill:${T.bgCard},stroke:${T.borderCard},color:${T.textDark};`,
  `classDef darkAccent fill:${T.bgCard},stroke:${T.alight},color:${T.alight};`,
  `classDef valid fill:${mode === 'dark' ? T.bgCard : T.bgPanel},stroke:${T.valid},color:${T.valid};`,
  `classDef invalid fill:${mode === 'dark' ? T.bgCard : T.bgPanel},stroke:${T.invalid},color:${T.invalid};`,
  `linkStyle default stroke:${B.line},stroke-width:1px;`,
].join('\n'); };

// `classDef` and `linkStyle` belong to the FLOWCHART family and to no other diagram. MEASURED 2026-08-03: the first
// version of this wrapper appended them unconditionally, and GitHub answered a gantt with
// `Parse error … Expecting 'taskData', got ':'` — a wrapper that is wrong for a whole class of inputs, discovered by
// the rendered page rather than by anything here. So the family is DECIDED FROM THE SOURCE, and everything outside it
// gets the theme alone; its colours arrive through themeVariables, which is why the init above carries the gantt keys.
//
// CLOSED 2026-08-03 by `f09c6f86` — tools(palette): classDef belongs to the flowchart family and to no other
// diagram. In this tree a narration is written in the commit that fixes what it describes, and blame places
// this paragraph there; noted 2026-08-05, appended rather than rewritten.
const CLASSDEF_FAMILY = /^\s*(flowchart|graph|classDiagram|stateDiagram(-v2)?|erDiagram)\b/;
export const takesClassDefs = (source) => CLASSDEF_FAMILY.test(String(source ?? ''));

/** Wrap diagram source in a fenced mermaid block carrying the theme, and the classes when the family accepts them. */
export const mermaid = (source, mode = 'light') => {
  const body = String(source ?? '').trim();
  return '```mermaid\n' + mermaidInit(mode) + '\n' + body + (takesClassDefs(body) ? '\n' + mermaidClassDefs(mode) : '') + '\n```';
};

// ── `--check`: every colour this module EMITS must come from TOKENS. A hex typed at a call site is exactly the
// drift this file exists to prevent, and a palette nobody checks is a second place to be wrong.
if (process.argv[1] && process.argv[1].endsWith('lab-palette.mjs') && process.argv.includes('--check')) {
  const known = new Set(Object.values(TOKENS).map((h) => h.toLowerCase()));
  // BOTH bindings, enumerated from the map rather than named here: a mode added later and not listed would ship
  // unchecked, which is the same shape as a gate that names one instance where the obligation quantifies.
  const MODES = Object.keys(BIND);
  const emitted = MODES.flatMap((m) => [...`${mermaidInit(m)}\n${mermaidClassDefs(m)}`.matchAll(/#[0-9a-fA-F]{6}\b/g)].map((x) => x[0].toLowerCase()));
  const stray = [...new Set(emitted)].filter((h) => !known.has(h));
  const controlHit = !known.has('#ff00ff');            // a colour NOT in the table must read as stray
  const controlMiss = known.has(TOKENS.accent.toLowerCase());
  let bad = 0;
  if (!controlHit || !controlMiss) { console.error('✗ CONTROL: the token membership test does not discriminate'); bad++; }
  if (stray.length) { console.error(`✗ ${stray.length} colour(s) emitted that are not in TOKENS: ${stray.join(', ')}`); bad++; }
  if (!emitted.length) { console.error('✗ nothing emitted — the sweep is blind'); bad++; }
  // the family rule, both directions — a gantt that receives classDefs does not render at all
  const ganttOut = mermaid('gantt\n  dateFormat YYYY-MM-DD\n  section s\n  t :done, 2026-01-01, 1d');
  const flowOut = mermaid('flowchart TB\n  A --> B');
  if (/classDef|linkStyle/.test(ganttOut)) { console.error('✗ a gantt received classDef/linkStyle — mermaid refuses to parse it'); bad++; }
  if (!/classDef/.test(flowOut)) { console.error('✗ a flowchart received NO classDef — the palette would never apply'); bad++; }
  for (const kind of ['pie', 'sequenceDiagram', 'gitGraph', 'journey', 'timeline', 'mindmap'])
    if (/classDef|linkStyle/.test(mermaid(kind + '\n  x'))) { console.error(`✗ ${kind} received classDef/linkStyle`); bad++; }
  // The two modes must actually DIFFER, and the default must be the light one. A `mode` argument that silently
  // fell through to one binding would pass every check above while making the parameter a decoration.
  if (mermaidInit('dark') === mermaidInit('light')) { console.error('✗ dark and light emit identical themes — the mode argument does nothing'); bad++; }
  if (mermaidInit() !== mermaidInit('light')) { console.error('✗ the default mode is not light — GitHub would receive the dark binding by omission'); bad++; }
  if (mermaidInit('nonsense') !== mermaidInit('light')) { console.error('✗ an unknown mode does not fall back to light'); bad++; }
  if (bad) process.exit(1);
  console.log(`  ✓ lab palette: ${Object.keys(TOKENS).length} tokens, ${MODES.length} modes (${MODES.join('/')}), ${new Set(emitted).size} distinct colours emitted, none invented`);
}
