// SPDX-License-Identifier: Apache-2.0
// Qualified-checkpoint gate — the word names two different chains, so it may not stand alone.
//
// UST has TWO checkpoints and they answer different questions:
//   · a STREAM checkpoint (§11.3 M5) is a point in the DATA chain — {head, frame_count, from, to},
//     prev-linked, and it answers "between these two moments nothing was dropped and nothing removed";
//   · an AUTHORITY checkpoint (§12.3) is a point in the AUTHORITY chain — sequence, previous_checkpoint,
//     genesis_epoch — and it answers "which key set was valid at that time".
//
// Both are honestly checkpoints. The defect is the UNQUALIFIED word: read "the checkpoint" and you cannot
// tell which chain is meant until you reconstruct the context. Measured 2026-07-29: 109 bare uses against
// 46 qualified ones — the ambiguous form was the majority. It confused the author of the explanation and
// the owner reading it, in the same conversation, about the same paragraph.
//
// The owner first decided to RENAME the authority object to "epoch". Reading §12.3 showed that would be
// worse: the object carries `sequence` and `previous_checkpoint`, so it is a POINT in an epoch, and the
// spec already uses "epoch" correctly for the PERIOD one genesis is active. Two words beat one rename.
//
// A third meaning exists and is not ours: Rekor's `checkpoint` is a signed tree head. Left alone.
import { readFileSync } from 'node:fs';

// The residual that a qualifying pass could not decide from the line alone — mostly Appendix B revision
// history, where the entry's subject lives in a paragraph rather than a sentence. Pinned so it may only
// SHRINK: a new bare use fails, closing an old one is free.
const PIN = 16;

const src = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8');
const bare = [];
src.split('\n').forEach((l, i) => {
  const re = /\bcheckpoint\b/gi;
  let m;
  while ((m = re.exec(l))) {
    const pre = l.slice(0, m.index), post = l.slice(m.index + m[0].length);
    if (/authority[- ]|stream |hour /i.test(pre.slice(-12))) continue;   // already qualified
    if (/^[-_]/.test(post) || /[-_:]$/.test(pre)) continue;              // compound identifier
    if ((pre.match(/`/g) || []).length % 2 === 1) continue;              // inside code ticks — a field name
    if (/rekor|sigstore|logIndex|treeSize/i.test(l)) continue;           // a third party's term
    bare.push(`${i + 1}: ${l.trim().slice(0, 100)}`);
  }
});

const ok = bare.length <= PIN;
console.log(`\n  checkpoint qualified   ${ok ? 'PASS' : 'FAIL'}   (${bare.length} bare in prose, pinned at ${PIN})`);
if (!ok) {
  console.log('    ✗ a NEW unqualified `checkpoint` entered the spec. Say which chain it belongs to:');
  console.log('      stream checkpoint (§11.3, the data chain) or authority checkpoint (§12.3, the key chain).');
  bare.slice(PIN).forEach((b) => console.log('      ' + b));
  process.exit(1);
}
if (bare.length < PIN) console.log(`    · residual shrank to ${bare.length} — lower PIN to match`);
console.log('  ✓ no new bare `checkpoint`: a reader can tell which chain is meant without reconstructing context');
