// SPDX-License-Identifier: Apache-2.0
// README illustration panels — TUI-style (btop/lazygit) SVGs, the same visual language as .github/status.svg
// (gen-status-svg.mjs). Five panels: anatomy (what a transcript IS), tiers (what each verdict adds), chain (layered
// shards / graduated visibility), time (the shared ust:ID axis), map (the repository). Deterministic pure functions
// (no dates, no randomness) gated by `git diff --exit-code` in test:spec-sync, exactly like the status panel — the
// prose stays in the README; these panels replace only the ASCII diagrams that wrap and tear on mobile.
import { writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const W = 880;
const BG = '#0d1117', BORDER = '#3d444d', SEP = '#30363d';
const TITLE = '#58a6ff', TEXT = '#c9d1da', LABEL = '#8b949e', VALUE = '#79c0ff';
const OK = '#3fb950', WARN = '#d29922', PURPLE = '#bc8cff', GREEN = '#7ee787';
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function panel(name, title, build, titleStyle) {                 // shared frame: rounded border + panel title row; titleStyle overrides the default for long titles
  const parts = [];
  const P = {
    y: 46,
    t: (x, y, s, fill, extra = '') => parts.push(`  <text x="${x}" y="${y}" fill="${fill}" ${extra}>${esc(s)}</text>`),
    line: (x1, y1, x2, y2, stroke = SEP, wd = 1) => parts.push(`  <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="${wd}"/>`),
    rect: (x, y, w, h, opts = '') => parts.push(`  <rect x="${x}" y="${y}" width="${w}" height="${h}" ${opts}/>`),
    chip: (x, y, s, color) => {                                  // small rounded status chip, returns its width
      const w = Math.round(s.length * 7.3 + 18);
      parts.push(`  <rect x="${x}" y="${y - 13}" width="${w}" height="19" rx="9.5" fill="none" stroke="${color}" stroke-width="1"/>`);
      parts.push(`  <text x="${x + w / 2}" y="${y + 1}" fill="${color}" font-size="12" text-anchor="middle">${esc(s)}</text>`);
      return w;
    },
    row: (dy) => (P.y += dy, P.y),
  };
  P.t(28, 34, title, TITLE, titleStyle || 'font-size="13" font-weight="600" letter-spacing="2"');
  build(P);
  const H = P.y + 26;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">
<title>${esc(title)}</title>
<g font-family="${MONO}" font-size="15" xml:space="preserve">
  <rect x="1.5" y="1.5" width="${W - 3}" height="${H - 3}" rx="10" fill="${BG}" stroke="${BORDER}" stroke-width="1.5"/>
  <line x1="16" y1="46" x2="${W - 16}" y2="46" stroke="${SEP}" stroke-width="1"/>
${parts.join('\n')}
</g>
</svg>
`;
  writeFileSync(new URL(`../.github/${name}.svg`, import.meta.url), svg);
  console.log(`  ✓ .github/${name}.svg`);
}

// ── 1. ANATOMY — what a transcript IS (JSON skeleton + inline annotations + the seal→store→verify pipeline) ──
panel('ust-anatomy', 'A TRANSCRIPT — SELF-CONTAINED, VERIFIES ANYWHERE', (P) => {
  const CODE = 36, ANN = 520, CH = 8.43;   // 14px mono ≈ 8.43px/char — the JSON column ends < 500, annotations at 520
  const codeLine = (x, y, s) => {          // colored JSON line: key blue · string value green · rest text-gray
    const m = s.match(/^(\s*)"([^"]+)"(\s*:\s*)(.*)$/);
    if (!m) { const lead = (s.match(/^\s*/) || [''])[0].length; P.t(x + lead * CH, y, s.trim(), TEXT, 'font-size="14"'); return; }   // indent via explicit x — never via collapsible spaces
    const [, ind, key, colon, rest] = m;
    const kx = x + ind.length * CH;
    P.t(kx, y, `"${key}"`, VALUE, 'font-size="14"');
    const rx = kx + (key.length + 2) * CH;
    P.t(rx, y, colon, LABEL, 'font-size="14"');
    P.t(rx + colon.length * CH, y, rest, /^"/.test(rest) ? GREEN : TEXT, 'font-size="14"');
  };
  const j = (s, ann) => {
    const y = P.row(25);
    codeLine(CODE, y, s);
    if (ann) { P.t(ANN - 18, y, '←', TITLE); P.t(ANN, y, ann, LABEL, 'font-size="13"'); }
  };
  j('{');
  j('  "ust": "1.0",', 'wire format — stable across all rc’s');
  j('  "state": {');
  j('    "id": {');
  j('      "domain_shard": "example.org",', 'WHO — a name, or a self-certifying key-id');
  j('      "ust_id": "ust:20260710.1429",', 'WHEN — an address on one shared UTC axis');
  j('      "key_id": "sha256:…", "class": "observation"');
  j('    },');
  j('    "time": { generated_at · valid_from · valid_to },', 'the claimed frame');
  j('    "data": { … partitions … },', 'captured / computed / blinded / encrypted');
  j('    "hashes": { one per partition },', 'domain-separated — bind data to id + frame');
  j('    "provenance": { based_on[] · prev · seed }', 'lineage — chains, streams, derivations');
  j('  },');
  j('  "sig": { "alg": "Ed25519", key_id · pub · sig }', 'travels WITH the data — not with the channel');
  j('}');
  P.row(14); P.line(16, P.y, W - 16, P.y); P.row(30);
  const y = P.y;
  P.t(36, y, 'SEAL at creation', OK, 'font-weight="600"');
  P.t(196, y, '──▶', LABEL);
  P.t(244, y, 'STORE anywhere', VALUE, 'font-weight="600"');
  P.t(388, y, '──▶', LABEL);
  P.t(436, y, 'VERIFY offline — one call · no blockchain', TEXT, 'font-weight="600"');
  P.row(24);
  P.t(36, P.y, 'TLS secures the pipe — UST secures the payload: cache, mirror, file or chat paste — the same verdict', LABEL, 'font-size="13"');
});

// ── 2. TIERS — the verdict ladder (each rung EARNED, the verdict carries its tier) ──
panel('ust-tiers', 'TRUST IS GRADUATED, AND THE VERDICT CARRIES ITS TIER — A CONFORMING VERIFIER NEVER SAYS A BARE VALID:', (P) => {
  const cols = [
    { x: 24, top: 150, chip: 'VALID:LIGHT', c: TEXT, name: 'the floor — a key, canonical form, a signature', rows: ['exact bytes · signing key', 'claimed time frame', 'no infra · no fees'] },
    { x: 312, top: 110, chip: 'VALID:HIGH', c: VALUE, name: '+ the NAME is provably bound to the key', rows: ['genesis + key log ceremony', 'rotation / revocation', 'corroborated|authoritative'] },
    { x: 600, top: 70, chip: 'VALID:TOP', c: OK, name: '+ existed BY a real point in time', rows: ['anchor inclusion proof', 'Bitcoin/OTS · Rekor opt-in', 'completeness: range verdict'] },
  ];
  const BOT = 320, CW = 256;
  for (const col of cols) {
    P.rect(col.x, col.top, CW, BOT - col.top, `rx="8" fill="none" stroke="${SEP}" stroke-width="1.2"`);
    P.chip(col.x + 14, col.top + 26, col.chip, col.c);
    // name wraps to two lines max — greedy ≤27 chars INCLUDING the joining space (13px mono ≈ 7.83px/char → 27ch = 212px < the 228px inner width)
    const words = col.name.split(' '); let l1 = '', l2 = '';
    for (const w2 of words) ((l1.length + (l1 ? 1 : 0) + w2.length) <= 27 && !l2 ? l1 += (l1 ? ' ' : '') + w2 : l2 += (l2 ? ' ' : '') + w2);
    P.t(col.x + 14, col.top + 56, l1, TEXT, 'font-size="13"');
    if (l2) P.t(col.x + 14, col.top + 74, l2, TEXT, 'font-size="13"');
    col.rows.forEach((r, i) => { P.t(col.x + 14, col.top + 100 + i * 22, '·', LABEL, 'font-size="13"'); P.t(col.x + 28, col.top + 100 + i * 22, r, LABEL, 'font-size="13"'); });
  }
  P.t(288, 200, '▶', TITLE, 'font-size="17"'); P.t(576, 160, '▶', TITLE, 'font-size="17"');
  P.y = BOT + 8; P.row(28);
  P.t(28, P.y, 'INVALID', '#f85149', 'font-size="13" font-weight="600"');
  P.t(96, P.y, '= a definite failure (E-*)', LABEL, 'font-size="13"');
  P.t(330, P.y, 'INDETERMINATE', WARN, 'font-size="13" font-weight="600"');
  P.t(456, P.y, '= cannot decide — never conflated with forged', LABEL, 'font-size="13"');
  P.row(22);
  P.t(28, P.y, 'a tier is EARNED per verification — there is NO field a producer can set to claim it', TEXT, 'font-size="13"');
}, 'font-size="11.5" font-weight="600" letter-spacing="0.8"');   // 102-char title — fitted, same voice

// ── 3. CHAIN — one state, graduated visibility (the L1..L4 ladder, hash-linked) ──
panel('ust-chain', 'ONE STATE — GRADUATED VISIBILITY', (P) => {
  const layers = [
    { tag: 'L1', name: 'public observation', ex: '"geomagnetic activity: elevated"', chip: 'anyone verifies', c: OK },
    { tag: 'L2', name: 'blinded commitment', ex: 'value fixed — hidden until reveal', chip: 'existence is public', c: WARN },
    { tag: 'L3', name: 'encrypted shard', ex: 'AEAD ciphertext + commitment', chip: 'key holders read & verify', c: VALUE },
    { tag: 'L4', name: 'partner’s derived shard', ex: 'another publisher, own key', chip: 'cross-party lineage', c: PURPLE },
  ];
  let y = 64;
  for (const [i, L] of layers.entries()) {
    P.rect(24, y, 566, 54, `rx="8" fill="none" stroke="${L.c}" stroke-opacity="0.55" stroke-width="1.2"`);
    P.t(40, y + 24, L.tag, L.c, 'font-weight="600"');
    P.t(76, y + 24, L.name, TEXT, 'font-weight="600"');
    P.t(76, y + 43, L.ex, LABEL, 'font-size="13"');
    P.chip(614, y + 30, L.chip, L.c);
    if (i < layers.length - 1) {
      P.line(56, y + 54, 56, y + 78, SEP, 1.2);
      P.t(66, y + 72, '▲ based_on: sha256(content) + seed — order & lineage publicly provable', LABEL, 'font-size="12.5"');
    }
    y += 78;
  }
  P.y = y - 12; P.row(30);
  P.t(28, P.y, 'public sees L1 · client L1–L2 · partner L1–L3 · auditor walks ALL — each layer verifies on its own,', TEXT, 'font-size="13"');
  P.row(20);
  P.t(28, P.y, 'trust composes but is never inherited. Payloads deletable; “existed, in this order” stays provable.', TEXT, 'font-size="13"');
});

// ── 4. TIME — the shared axis (containment IS string prefixing) ──
panel('ust-time', 'ONE TIME AXIS — EVERY PUBLISHER, BY CONSTRUCTION (UTC)', (P) => {
  const boxes = [                                                // explicitly nested: hour ⊃ minute ⊃ second
    { x: 24, y: 64, w: 832, h: 172, label: 'ust:20260710.14', tail: 'the hour frame', c: SEP, lc: TEXT },
    { x: 48, y: 104, w: 620, h: 108, label: 'ust:20260710.1429', tail: 'the minute', c: VALUE, lc: VALUE },
    { x: 72, y: 146, w: 400, h: 44, label: 'ust:20260710.142900', tail: 'the second', c: OK, lc: OK },
  ];
  for (const b of boxes) {
    P.rect(b.x, b.y, b.w, b.h, `rx="8" fill="none" stroke="${b.c}" stroke-width="1.2"`);
    P.t(b.x + 16, b.y + 27, b.label, b.lc, 'font-weight="600"');
    P.t(b.x + 16 + b.label.length * 9.03 + 12, b.y + 27, '— ' + b.tail, LABEL, 'font-size="13"');
  }
  P.y = 64 + 172; P.row(30);
  P.t(28, P.y, 'containment is literal string prefixing — roll-ups are prefix scans · sortable = streamable', LABEL, 'font-size="13"');
  P.row(22);
  P.t(28, P.y, '“what was the world doing at 14:29Z?” is a query — same coordinate ⇒ same moment, joinable after the fact', TEXT, 'font-size="13"');
});

// ── 5. MAP — the repository at a glance ──
panel('ust-map', 'REPOSITORY MAP', (P) => {
  const rows = [
    ['UST-Protocol/', '', TEXT, true],
    ['├── spec/', 'UST-1.0.md (normative) · formal model (measure-theoretic semantics)', VALUE],
    ['├── vectors/', 'language-neutral conformance + byte corpus — the cross-impl arbiter', VALUE],
    ['├── packages/', '', VALUE],
    ['│   ├── ust-protocol', 'reference verifier + producer — zero-dep, stateless', GREEN],
    ['│   ├── ust-cli', 'the ust command — verify · canon · HIGH genesis ceremony · witness', GREEN],
    ['│   ├── ust-mcp', 'MCP server — agents verify natively', GREEN],
    ['│   ├── ust-lite', 'minimal subset — byte-identical verdicts', TEXT],
    ['│   ├── ust-web-signer', 'WebCrypto browser signing (non-extractable keys)', GREEN],
    ['│   └── ust-{ots,rekor}-verify', 'opt-in anchor substrates — Bitcoin/OTS · Sigstore Rekor', GREEN],
    ['├── docs/', 'web verifier (GitHub Pages) · zero-dependency single-file verifiers', VALUE],
    ['├── examples/ · extension/', 'sample docs (valid + tampered) · “Make it UST” Chrome demo', VALUE],
    ['└── tools/', 'drift gates: spec == code == vectors == README == these panels', VALUE],
  ];
  for (const [tree, desc, c, bold] of rows) {
    const y = P.row(25);
    P.t(36, y, tree.replace(/ /g, ' '), c, bold ? 'font-weight="600"' : '');   // NBSP — tree indentation survives every whitespace-collapsing renderer
    if (desc) P.t(320, y, desc, LABEL, 'font-size="13"');
  }
  P.row(10);
});
// ── 6. CLI — the command surface, derived from the REAL binary (`$ ust` help), never hand-copied ──
// Run the CLI with no args: it prints its own command table to stderr and exits 0. Parse `  ust <cmd> …  <desc>` rows.
// If a command is added/renamed in the dispatcher, this panel regenerates differently → the spec-sync git-diff gate fails.
{
  const cli = fileURLToPath(new URL('../packages/ust-cli/index.mjs', import.meta.url));
  const out = spawnSync(process.execPath, [cli], { encoding: 'utf8' });
  if (out.status !== 0) throw new Error('ust CLI no-arg help exited ' + out.status);
  const rows = out.stderr.split('\n').filter((l) => /^\s+ust /.test(l)).map((l) => {
    // the help aligns columns with 2+ spaces — including INSIDE a usage ("ust canon  <file|->"), so split on runs
    // and absorb leading arg-shaped parts (<…> / --…) into the usage; the first prose part starts the description.
    const parts = l.trim().split(/\s{2,}/);
    let usage = parts[0], i = 1;
    while (i < parts.length && /^(<|--)/.test(parts[i])) usage += ' ' + parts[i++];
    return { usage, desc: parts.slice(i).join(' ') };
  });
  if (rows.length < 8) throw new Error('parsed only ' + rows.length + ' CLI commands — help format changed, update the parser');
  panel('ust-cli', 'THE ust CLI — ONE ENTRYPOINT, THE WHOLE SURFACE', (P) => {
    let y = P.row(28);
    P.t(36, y, '$', OK, 'font-weight="600"'); P.t(54, y, 'npm i -g @ust-protocol/cli', TEXT, 'font-weight="600"');
    P.t(300, y, '# installs the ust command', LABEL, 'font-size="13"');
    y = P.row(24);
    P.t(36, y, '$', OK, 'font-weight="600"'); P.t(54, y, 'ust', TEXT, 'font-weight="600"');
    P.t(300, y, `# ${rows.length} subcommands — this table is parsed from the real help`, LABEL, 'font-size="13"');
    P.row(8);
    for (const r of rows) {
      y = P.row(24);
      const sub = r.usage.split(' ')[1];                                     // `verify` from `ust verify <file|->`
      P.t(48, y, 'ust', LABEL, 'font-size="13"');
      P.t(48 + 4 * 7.83, y, sub, GREEN, 'font-size="13" font-weight="600"');
      P.t(48 + (4 + sub.length + 1) * 7.83, y, r.usage.split(' ').slice(2).join(' '), VALUE, 'font-size="13"');
      y = P.row(19);
      P.t(76, y, r.desc, LABEL, 'font-size="12.5"');
    }
    P.row(12); P.line(16, P.y, W - 16, P.y); P.row(26);
    P.t(36, P.y, 'exit 0 = VALID (tier in the verdict) · 1 = not · the ceremony self-verifies its outputs — fail-closed', TEXT, 'font-size="13"');
  });
}
console.log('  (6 README panels regenerated — deterministic; the CLI panel is parsed from the real `$ ust` help)');
