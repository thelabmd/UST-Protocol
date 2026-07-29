#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// CLI mascot renderer — packages/ust-cli/seal_mini_square.svg → the half-block art for the CLI's first screen.
//
// NOT wired into CI: rasterising the SVG needs macOS Quick Look (`qlmanage`), which a Linux runner does not have.
// The committed .txt is a source artifact, and this script is how it is re-derived rather than redrawn by hand.
//
// Usage:  node tools/gen-cli-mascot.mjs [height]      (default 21)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodePNG } from './lib/png-decode.mjs';

const ROOT = new URL('../', import.meta.url).pathname;
// The SOURCE lives in art/, not in the package: the package ships only what it READS at runtime (the .txt),
// and .github/ is the README-panel pipeline, where every svg is enumerated for a palette-mapped light twin —
// which a mascot that appears in no README does not want.
const SVG = ROOT + 'art/seal_mini_square.svg';
const OUT = ROOT + 'packages/ust-cli/seal_mini_square.txt';
const H = Number(process.argv[2] ?? 21);

const tmp = mkdtempSync(join(tmpdir(), 'ust-mascot-'));
try {
  execFileSync('qlmanage', ['-t', '-s', '1024', '-o', tmp, SVG], { stdio: 'ignore' });
  const png = join(tmp, readdirSync(tmp).find((f) => f.endsWith('.png')));
  const { w, h, ink } = decodePNG(png);
  let x0 = w, y0 = h, x1 = -1, y1 = -1;
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) if (ink(x, y)) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
  const bw = x1 - x0 + 1, bh = y1 - y0 + 1;
  const cols = Math.round(H * (bw / bh));
  const cell = (cx, cy) => {                       // area coverage, thresholded — the art is an OUTLINE, so a
    const sx = x0 + cx * bw / cols, ex = x0 + (cx + 1) * bw / cols;   // single-pixel stroke must survive
    const sy = y0 + cy * bh / H, ey = y0 + (cy + 1) * bh / H;
    let on = 0, tot = 0;
    for (let y = Math.floor(sy); y < Math.ceil(ey); y++) for (let x = Math.floor(sx); x < Math.ceil(ex); x++) { tot++; if (x < w && y < h && ink(x, y)) on++; }
    return tot ? on / tot : 0;
  };
  const g = [];
  for (let r = 0; r < H; r++) { const row = []; for (let c = 0; c < cols; c++) row.push(cell(c, r) >= 0.5); g.push(row); }
  const lines = [];
  for (let r = 0; r < H; r += 2) {                 // two art rows per terminal row: ▀ upper, ▄ lower, █ both
    let s = '';
    for (let c = 0; c < cols; c++) { const t = g[r][c], b = g[r + 1]?.[c]; s += t && b ? '█' : t ? '▀' : b ? '▄' : ' '; }
    lines.push(s.replace(/\s+$/, ''));
  }
  writeFileSync(OUT, lines.join('\n') + '\n');
  console.log(`  ✓ ${cols} × ${H} art-px → ${lines.length} terminal rows → packages/ust-cli/seal_mini_square.txt`);
} finally { rmSync(tmp, { recursive: true, force: true }); }
