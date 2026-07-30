// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — the terms and their counts are pinned by hand and cannot be derived: WHICH word names two mechanisms is a judgement, and the pin is a measured residual rather than a rule
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
//   · `recovery`    — GENESIS-RECOVERY (§12.1 P2) re-roots the name through DOMAIN CONTROL, the arbiter that
//     sits above the key log; CHECKPOINT-RECOVERY (§12.3.2, §F.5l) is a dormant genesis-fixed threshold that
//     re-authorizes the AUTHORITY CHECKPOINT chain. Different roots of trust, different documents, different
//     failure they answer. A draft of §F.5e.3 admitted checkpoint-recovery keys as key-log mutators on the
//     strength of the shared word — widening an authority set in text that reads as a clarification. Worse,
//     the first attempt to fix it swept the word blindly and CONFLATED the two, turning "Genesis recovery —
//     re-rooted in domain control" into a checkpoint mechanism. The word had to be split, not counted.
//
//     Note the pattern in all three: the WIRE was already right. `ust:checkpoint-authority-recovery`,
//     `verifyCheckpointRecovery`, and the two distinct checkpoint shapes all carried the qualifier. Only the
//     prose dropped it, and reasoning happens in prose.
//
// The rule the owner set after the second collision: introduce the qualified pair BEFORE the ambiguity does
// damage, because the damage lands on the foundation and is found late. This gate makes that mechanical — each
// term carries the qualifiers that disambiguate it, and its bare count is PINNED so it may only shrink.
//
// A pin is not a target. It is the residual a qualifying pass could not decide FROM THE LINE ALONE, and after the
// rev97 pass it is three things, all legitimate: Appendix B revision history (the subject lives in the paragraph,
// not the sentence); the generic English activity ("the once-a-year rotation its tooling warns about"), which
// names no mechanism; and text that discusses the ambiguity ITSELF and must therefore reference both mechanisms
// collectively. Closing one is free; adding one fails.
//
// The pins below are the MEASURED residual over BOTH documents after that pass, not a target chosen in advance.
// They moved once, when the gate's domain grew from one document to two — a domain change, stated here rather
// than quietly absorbed, because raising a pin to silence a gate is the failure this file exists to prevent.
import { readFileSync } from 'node:fs';

const TERMS = [
  { word: 'checkpoint', pin: 24, qualifiers: /authority[- ]|stream |hour /i,
    thirdParty: /rekor|sigstore|logIndex|treeSize/i },
  { word: 'rotation',   pin: 22, qualifiers: /authority[- ]|checkpoint |key[- ]|operational[- ]|hygienic |normal /i,
    thirdParty: /null/ },
  { word: 'recovery',   pin: 17,  qualifiers: /genesis-|checkpoint-|Keys|Threshold|Claim|brute-force |key-|nonce-reuse |private |disaster /i,
    thirdParty: /brute-force|nonce-reuse|low-entropy/i },
];

// BOTH documents: the formal model is where the reasoning happens, so an ambiguous term does the most damage
// there. Checking only the spec would have missed every use that produced the §F.5e.3 error.
const lines = [
  ...readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8').split('\n'),
  ...readFileSync(new URL('../spec/UST-1.0-formal-model.md', import.meta.url), 'utf8').split('\n'),
];
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

// ── CONTROLS. A count-pin gate has exactly two ways to be worthless: the counter never counts, or the qualifier
// swallows everything. Both are checked against a SYNTHETIC line rather than against the documents, so the controls
// cannot drift with the prose they guard.
{
  const probe = (line, t) => {
    const re = new RegExp(`\\b${t.word}\\b`, 'gi'); let n = 0, m;
    while ((m = re.exec(line))) {
      const pre = line.slice(0, m.index), post = line.slice(m.index + m[0].length);
      if (t.qualifiers.test(pre.slice(-14))) continue;
      if (/^[-_]/.test(post) || /[-_:]$/.test(pre)) continue;
      if ((pre.match(/`/g) || []).length % 2 === 1) continue;
      if (t.thirdParty.test(line)) continue;
      n++;
    }
    return n;
  };
  const t = TERMS[0];
  const ctl = [
    [`a bare ${t.word} in a sentence must COUNT as bare`, probe(`the ${t.word} is verified`, t) === 1],
    [`a qualified ${t.word} must NOT count`, probe(`the authority ${t.word} is verified`, t) === 0],
    ['the counter must not count a word that is absent', probe('nothing ambiguous here at all', t) === 0],
  ];
  for (const [name, ok] of ctl) if (!ok) { failed = true; console.log(`  ✗ CONTROL: ${name}`); }
  if (!failed) console.log(`  ✓ CONTROL: the counter discriminates bare from qualified from absent (${ctl.length} legs)`);
}

// ── SCOPE, stated because it is a decision and not an oversight. This gate reads the spec and the formal model: the
// collision does its damage in PROSE, because reasoning happens there. It does NOT read code — and the API surface has
// the same collision, MEASURED 2026-07-30: `buildCheckpoint` builds a STREAM checkpoint while `buildAuthorityCheckpoint`
// sits beside it, so one export names its chain and the other does not. Renaming a public export is a breaking change,
// so it is a decision rather than a defect this gate can fix: thelabmd/UST-Protocol#112.
if (failed) { console.log('\n✗ ambiguous-term gate'); process.exit(1); }
console.log(`✓ ambiguous-term gate: ${TERMS.length} known collisions, every bare use within its pin`);
