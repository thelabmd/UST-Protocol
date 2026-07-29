// SPDX-License-Identifier: Apache-2.0
// Ambiguous-term gate — a word that names two mechanisms may not stand alone in the spec.
//
// This generalizes the single-word checkpoint gate, and it exists because the failure repeated. Three
// collisions were found in ONE day (2026-07-29), each after it had already caused a wrong edit:
//
//   · `checkpoint`  — a STREAM checkpoint (§11.3) is a point in the DATA chain and answers "nothing was
//     dropped between these moments"; an AUTHORITY checkpoint (§12.3) is a point in the AUTHORITY chain and
//     answers "which key set was valid then". 109 bare uses against 46 qualified when first measured. It
//     confused the author and the reader in the same conversation about the same paragraph.
//
//   · `rotation`    — the key-log `rotate` OPERATION (§12.2, removed rev97) versus authority-checkpoint
//     rotation (§12.3.2, alive), which names a successor in-band. Removing the first nearly took prose
//     belonging to the second with it; six stale references survived the first sweep.
//
// A THIRD case was examined and deliberately NOT registered, because registering it would have been the
// wrong fix. `recovery` names exactly ONE mechanism: the genesis-rooted threshold that re-authorizes the
// AUTHORITY CHECKPOINT chain (§12.3.2). A draft of §F.5e.3 admitted recovery keys as key-log mutators — not
// because the word was ambiguous, but because I extended its SCOPE to a chain it never touched. Enumerating
// all 36 uses showed them consistent; a bare-use pin would have forced 26 edits and prevented nothing.
//
// So the two defects are kept apart. AMBIGUITY is a property of the word and a prose gate can hold it.
// OVER-EXTENDED SCOPE is a property of a claim, and what caught it was a VECTOR that failed — §12.3.2 now
// states the scope negatively ("does not authorize key-log mutation") so the next reader inherits the answer.
//
// The rule the owner set after the second collision: introduce the qualified pair BEFORE the ambiguity does
// damage, because the damage lands on the foundation and is found late. This gate makes that mechanical — each
// term carries the qualifiers that disambiguate it, and its bare count is PINNED so it may only shrink.
//
// A pin is not a target. It is the residual a qualifying pass could not decide from the line alone (mostly
// Appendix B revision history, where the subject lives in the paragraph). Closing one is free; adding one fails.
import { readFileSync } from 'node:fs';

const TERMS = [
  { word: 'checkpoint', pin: 16, qualifiers: /authority[- ]|stream |hour /i,
    thirdParty: /rekor|sigstore|logIndex|treeSize/i },
  { word: 'rotation',   pin: 12, qualifiers: /authority[- ]|checkpoint |key[- ]|operational[- ]|hygienic |normal /i,
    thirdParty: /null/ },
];

const src = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8');
const lines = src.split('\n');
let failed = false;

for (const t of TERMS) {
  const bare = [];
  lines.forEach((l, i) => {
    const re = new RegExp(`\\b${t.word}\\b`, 'gi');
    let m;
    while ((m = re.exec(l))) {
      const pre = l.slice(0, m.index), post = l.slice(m.index + m[0].length);
      if (t.qualifiers.test(pre.slice(-14))) continue;                    // already qualified
      if (/^[-_]/.test(post) || /[-_:]$/.test(pre)) continue;             // compound identifier
      if ((pre.match(/`/g) || []).length % 2 === 1) continue;             // inside code ticks — a field name
      if (t.thirdParty.test(l)) continue;                                 // a third party's term
      bare.push(`${i + 1}: ${l.trim().slice(0, 96)}`);
    }
  });
  const verb = bare.length > t.pin ? '✗' : '·';
  console.log(`  ${verb} ${t.word}: ${bare.length} bare (pin ${t.pin})`);
  if (bare.length > t.pin) {
    failed = true;
    bare.slice(0, 6).forEach((b) => console.log(`      ${b}`));
    console.log(`    A bare \`${t.word}\` names two mechanisms. Qualify it, or if the pin is genuinely`);
    console.log(`    unreachable say so in the row — do not raise it to make the gate quiet.`);
  }
}

if (failed) { console.log('\n✗ ambiguous-term gate'); process.exit(1); }
console.log(`✓ ambiguous-term gate: ${TERMS.length} known collisions, every bare use within its pin`);
