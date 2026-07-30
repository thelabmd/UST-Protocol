#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// @assurance 1a canfail:no — the SIGNED store decides, read through the package that verifies the chain
// diarium.md renderer — the repo-specific SUPERSTRUCTURE over the ordinary `diarium` package.
//
// The package is the base and runs here exactly as it runs for anyone: `diarium scan | status | write | verify`, a
// sealed file per entry under diarium/. This file owns one thing the package has no business knowing — how THIS
// repository likes to show a diary: the prose, then a collapsed <details> block carrying the transcript that proves it.
//
// It contains NO chain logic, deliberately. The order comes from `diarium read --json`, so there is exactly one
// implementation of "what follows what" in the tree. Re-deriving the order here would recreate the second
// implementation this migration existed to delete.
//
// diarium.md is therefore a GENERATED VIEW, not the source. The store is the source: one signed file per entry, each
// verifiable on its own. Sealing into both a store file and an embedded block would put the same signed bytes in two
// places under an obligation to agree — the drift class this repository is built to refuse. `npm run test:diary`
// regenerates and diffs, so the view can never quietly disagree with what was signed.
//
// Usage:  node tools/diarium-render.mjs [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MD = ROOT + 'diarium.md';
const CLI = ROOT + 'node_modules/.bin/diarium';
const SEP = '\n---\n\n';

// The header is the agent's PROMPT — the rules it reads before writing. It is hand-written and this renderer must never
// author it, so everything above the first entry is carried through untouched.
const current = readFileSync(MD, 'utf8');
const firstEntry = current.indexOf('\n## ');
if (firstEntry < 0) { console.error('✗ diarium.md has no entries — refusing to guess where the header ends'); process.exit(1); }
const header = current.slice(0, current.lastIndexOf(SEP, firstEntry) + SEP.length);

let docs;
try { docs = JSON.parse(execFileSync(CLI, ['read', '--depth', 'all', '--json'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })); }
catch (e) { console.error('✗ the store would not yield an order: ' + String(e.stderr || e.message).trim()); process.exit(1); }
if (!docs.length) { console.error('✗ no entries in the store'); process.exit(1); }

const rendered = header + docs.map((d) => {
  const st = d.state;
  const text = st.data.entry?.value?.text;
  if (typeof text !== 'string') throw new Error(`entry ${st.id.ust_id} carries no text — the store holds something this view cannot show`);
  // The hash in the summary is recomputed from the signed bytes, never copied from a field, so the visible proof line
  // cannot drift from the document it claims to describe.
  const prev = st.provenance?.prev;
  const ch = P.contentHash(d);
  const lineage = prev ? `prev <code>${prev}</code>` : 'genesis (no prev)';
  return `${text}\n\n<details>\n<summary>🔒 sealed · <code>${st.id.ust_id}</code> · <code>${ch}</code> · ${lineage}</summary>\n\n\`\`\`json\n${JSON.stringify(d)}\n\`\`\`\n\n</details>\n`;
}).join(SEP);

if (process.argv.includes('--check')) {
  if (rendered === current) { console.log(`  ✓ diarium.md matches the store (${docs.length} entries, order from the chain)`); process.exit(0); }
  console.error('✗ diarium.md does not match the store — regenerate it: node tools/diarium-render.mjs');
  process.exit(1);
}
writeFileSync(MD, rendered);
console.log(`  ✓ diarium.md rendered from ${docs.length} store entries`);
