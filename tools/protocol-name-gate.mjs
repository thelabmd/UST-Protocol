// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the label itself is the subject — matching it is the point, not a sample
//
// F.5t — THE NAME IS A CLAIM. An artifact carrying this protocol's name tells a machine to apply this
// protocol's verifier. If it then fails, the consumer sees the observation reserved for a corrupt or forged
// document: a benign file emits an attack's signal, and the only remedy is a private exception list — which
// is the divergence the protocol exists to remove.
//
// Measured 2026-08-02: the reference operator's own outage records carried `"protocol": "UST"` with no
// version, no state and NO SIGNATURE. Nobody noticed for as long as they existed, because nothing looked.
// This looks — at every artifact in this tree that wears the name.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as P from '../packages/ust-protocol/index.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const fail = [];
let pass = 0, checked = 0;
const corpora = [];
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

const files = execFileSync('git', ['ls-files', '*.json'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);
const CLAIMS = /"protocol"\s*:\s*"UST"|"ust"\s*:\s*"1\./;

for (const rel of files) {
  let raw;
  try { raw = readFileSync(ROOT + rel, 'utf8'); } catch { continue; }
  if (!CLAIMS.test(raw.slice(0, 4000))) continue;
  checked++;
  let doc;
  try { doc = JSON.parse(raw); } catch {
    check(false, `${rel} carries the protocol name and is not parseable JSON — a consumer applying the verifier sees the signal of a truncated or tampered document`);
    continue;
  }
  // THE SUBJECT IS THE DOCUMENT SHAPE, not a directory list — a directory list would be a sample again.
  // A corpus that DESCRIBES documents is not one; it is judged separately below, because carrying the name
  // at the top level of a non-document is its own, smaller version of the same defect.
  //
  // The predicate is the PACKAGE's (F.5t-a), not this gate's. It was written here first and was the only copy
  // in the tree, which is precisely the corollary: an operator bound by the rule held no procedure. Calling the
  // export keeps this gate and every operator's own sweep deciding the same question the same way.
  const isDocument = P.classifyNamed(raw).status === 'document';
  if (!isDocument) { checked--; corpora.push(rel); continue; }

  // A NEGATIVE sample legitimately wears the name — a TAMPERED document is a document of this protocol that
  // fails, which is the theorem's own example. The expectation is READ from the sibling recipe, where it is
  // already written for humans, rather than from a list inside this gate: a gate carrying its own exception
  // list is the private knowledge F.5t is about.
  let negative = false;
  for (const suffix of ['-recipe.md', '.recipe.md']) {
    try { negative = /verification MUST fail|Expected: it does NOT verify/i.test(readFileSync(ROOT + rel.replace(/\.json$/, suffix), 'utf8')); } catch { /* no recipe */ }
    if (negative) break;
  }
  // The class decides the context: a genesis verified as `data` answers E-MALFORMED, which would have been
  // read as a violation. Measured while writing this gate — my own first version reported it.
  const cls = doc.state?.id?.class;
  const context = cls === 'genesis' || cls === 'key' ? 'genesis' : 'data';
  const v = P.verify(doc, { context });
  const valid = typeof v.result === 'string' && (v.result.slice(0, 6) === 'VALID:' || v.result === 'INDETERMINATE');
  if (negative) {
    check(!valid, `${rel} is declared a NEGATIVE sample ("verification MUST fail") and it VERIFIES — the declaration and the artifact disagree`);
  } else {
    check(valid, `${rel} wears the protocol name and does NOT verify under it (${v.result}${v.error ? ': ' + v.error : ''}) — either it IS a document of this protocol or it must not carry the name (F.5t)`);
  }
}

// A NON-DOCUMENT carrying the name at its TOP LEVEL is the same defect one size down: a machine reading
// `"protocol": "UST"` applies the verifier and fails. A corpus may be ABOUT the protocol without claiming to
// be a document of it.
for (const rel of corpora) {
  const top = JSON.parse(readFileSync(ROOT + rel, 'utf8'));
  check(!(top && typeof top === 'object' && top.protocol === 'UST'),
    `${rel} is not a document and carries \`"protocol": "UST"\` at its top level — a machine reading that applies the verifier and gets the signal of a corrupt document (F.5t)`);
}

check(checked >= 20, `only ${checked} artifact(s) claiming the name were examined — the roster has gone blind and every check above would pass for free`);

// The gate must be able to FAIL: prove it against a planted artifact that wears the name and is not a document.
{
  const planted = { protocol: 'UST', kind: 'outage-proof', detected_at: '2026-08-01T04:18:54.694Z', hash: 'sha256:' + 'c2'.repeat(32) };
  const v = P.verify(planted, { context: 'data' });
  check(!(typeof v.result === 'string' && v.result.slice(0, 6) === 'VALID:'),
    'CONTROL: an unsigned artifact wearing the name verified — the gate cannot tell a document from a label and proves nothing');
}

console.log(`\n  protocol name   PASS ${pass}   FAIL ${fail.length}   (${checked} artifact(s) claim the name · verified, not sampled)`);
for (const f of fail) console.log('    ✗ ' + f);
console.log(fail.length ? '' : '  ✓ every artifact wearing the protocol name verifies under it — the label is an instruction, not a decoration\n');
process.exit(fail.length ? 1 : 0);
