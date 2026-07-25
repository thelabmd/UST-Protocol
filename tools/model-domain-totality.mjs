// SPDX-License-Identifier: Apache-2.0
// MODEL-DOMAIN TOTALITY GATE — the missing DOMAIN of the model↔code lockstep.
//
// Every existing gate keys on a population something DELIBERATELY joined:
//   • `model-correspondence.mjs` — sections that chose to CITE a check label.
//   • `model-lockstep-gate.mjs`  — `**Realization` notes that carry a rev tag or cite a check; and it exempts, by
//                                  construction, "a representation note that cites NOTHING".
//   • `spec-code-sync.mjs` / `rule-lockstep.mjs` — the canonical REGISTRY sets and the §14 rule set.
// Each proves ITS population consistent. None enumerates the population of model SECTIONS. So a section that cites
// nothing and carries no Realization note is invisible to ALL of them SIMULTANEOUSLY — it can assert any property with
// zero code obligation, and every board stays green. That is the shape the whole rc.37 arc kept re-discovering: a gate
// over a declared population is a LOWER BOUND; the missing step is enumerating the DOMAIN and requiring membership.
//
// This gate enumerates the domain FROM the document and requires every section to be BOUND by one of three sources —
// two of them pre-existing (no new hand-maintained table is introduced):
//   (1) a cited conformance label that RAN AND PASSED in the executed manifest (strictly stronger than a source
//       substring — a renamed or disabled check no longer counts);
//   (2) a `lockstep-registry.json` record whose `model_locus` LOCATES inside the section (derived, not declared);
//   (3) an EXPLICIT machine-readable marker, reason drawn from a CLOSED set:
//         **Binding: none — definitional.**              (a definition/framing/disclaimer: no code obligation exists)
//         **Binding: none — numbers-normative-in-§13.**   (the obligation lives in the normative bounds section)
//         **Binding: pending — <tracker ref>.**           (a real obligation, not yet realized — reported, never silent)
// Silence fails. An unknown reason fails. `pending` without a reference fails. A section that is BOTH bound and marked
// `none` fails (a contradiction hides whichever is stale). `pending` sections are PRINTED as named residuals on a green
// run, so a deferral can never read as coverage.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const MODEL_PATH = '../spec/UST-1.0-formal-model.md';
const MODEL = readFileSync(new URL(MODEL_PATH, import.meta.url), 'utf8');
const REG = JSON.parse(readFileSync(new URL('./lockstep-registry.json', import.meta.url), 'utf8'));
const MANIFEST = JSON.parse(readFileSync(new URL('../vectors/conformance-checks.json', import.meta.url), 'utf8'));

const failures = [];

// the executed manifest must be BOUND to the source it came from — same staleness rule the lockstep gate applies, so
// this gate cannot be fooled by an old manifest either.
const srcHash = (rel) => createHash('sha256').update(readFileSync(new URL(rel, import.meta.url))).digest('hex');
const cur = {
  conformance: srcHash('../packages/ust-protocol/conformance.mjs'),
  index: srcHash('../packages/ust-protocol/index.mjs'),
};
if (!MANIFEST.source || MANIFEST.source.conformance !== cur.conformance || MANIFEST.source.index !== cur.index)
  failures.push('the executed manifest is STALE — regenerate it before trusting any binding in this gate');
const EXECUTED = Array.isArray(MANIFEST.checks) ? MANIFEST.checks : [];
const EXECUTED_SET = new Set(EXECUTED);

// ── the DOMAIN: every section of the formal model, enumerated from the document itself ────────────────────────────
const heads = [...MODEL.matchAll(/\n(#{2,4}) (F\.[0-9a-z.]+[^\n]*)/g)].map((m) => ({ pos: m.index, title: m[2].trim() }));
const bounds = heads.map((h) => h.pos).concat(MODEL.length);
// The domain's own SIZE is pinned (the primitive rev82 used for the module seam). A floor like ">= 20" would let a
// section silently LEAVE the domain — renamed to a non-`F.x` heading, it would simply stop being enumerated and this
// gate would still pass. That is the very defect class this gate exists to close, so the count is exact and any change
// to the section inventory must be a deliberate edit here.
const EXPECTED_SECTIONS = 34;
if (heads.length !== EXPECTED_SECTIONS)
  failures.push(`the enumerated DOMAIN changed: ${heads.length} sections found, ${EXPECTED_SECTIONS} pinned. A section was added, removed, or renamed out of the \`F.x\` convention — update EXPECTED_SECTIONS deliberately (a floor check would let a section leave the domain unnoticed)`);
const sectionId = (t) => t.match(/^(F\.[0-9a-z.]+)/)[1];

// a cited label counts only if it RAN AND PASSED. Citations may elide a shared prefix with "..."; resolve the longest
// verbatim fragment against the executed labels (same fragment rule as model-correspondence, stronger target).
const citationExecuted = (cite) => {
  if (EXECUTED_SET.has(cite)) return true;
  const frag = cite.split('...').map((s) => s.trim()).filter((s) => s.length >= 12).sort((a, b) => b.length - a.length)[0];
  return frag ? EXECUTED.some((label) => label.includes(frag)) : false;
};

// registry records localised to their enclosing section, using the SAME verbatim rule the lockstep gate enforces
const enclosing = (pos) => {
  for (let i = 0; i < heads.length; i++) if (pos >= heads[i].pos && pos < bounds[i + 1]) return sectionId(heads[i].title);
  return null;
};
const registryCovered = new Set();
for (const r of REG.records || []) {
  if (!r.model_locus) continue;
  const at = MODEL.indexOf(r.model_locus);
  if (at < 0) continue;                      // the lockstep gate already fails on a locus that no longer appears
  const s = enclosing(at);
  if (s) registryCovered.add(s);
}

// CLOSED set. Each reason names WHO bears the obligation — that is why it is not an escape hatch:
//   definitional              — a definition/framing/disclaimer; no party owes code for it.
//   numbers-normative-in-§13  — the obligation is the normative bounds section, realized by the bounds checks.
//   substrate-assumption      — the property is REQUIRED OF the substrate profile (§17) and probed through
//                               `substrateVerify`; the checker cannot enforce it, so claiming a checker binding
//                               would be the overclaim, not the honesty.
const REASONS = new Set(['definitional', 'numbers-normative-in-§13', 'substrate-assumption']);
const MARKER = /\*\*Binding:\s*(none|pending)\s*—\s*([^.*]+?)\.?\*\*/;

const rows = [];
for (let i = 0; i < heads.length; i++) {
  const id = sectionId(heads[i].title);
  const body = MODEL.slice(heads[i].pos, bounds[i + 1]);
  const cites = [...body.matchAll(/\*"([^"]+)"\*/g)].map((m) => m[1]);
  const executedCites = cites.filter(citationExecuted);
  const byRegistry = registryCovered.has(id);
  const m = body.match(MARKER);

  let marker = null;
  if (m) {
    const kind = m[1], reason = m[2].trim();
    if (kind === 'none' && !REASONS.has(reason))
      failures.push(`[${id}] **Binding: none — ${reason}** uses a reason outside the closed set {${[...REASONS].join(', ')}} — an unknown reason is not a licence to be unbound`);
    if (kind === 'pending' && reason.length < 3)
      failures.push(`[${id}] **Binding: pending** carries no tracker reference — a deferral must be attributable`);
    marker = { kind, reason };
  }

  const bound = executedCites.length > 0 || byRegistry;
  if (bound && marker && marker.kind === 'none')
    failures.push(`[${id}] is BOUND (${executedCites.length} executed citation(s)${byRegistry ? ' + registry' : ''}) yet also marked **Binding: none — ${marker.reason}** — remove whichever is stale; a contradiction hides one of them`);
  if (!bound && !marker)
    failures.push(`[${id}] "${heads[i].title.split('—')[0].trim()}" is UNBOUND and UNMARKED — it states properties with no code obligation and no gate can see it. Cite a check that runs, or declare **Binding: none — <${[...REASONS].join('|')}>** / **Binding: pending — <ref>**`);
  if (!bound && cites.length > 0 && executedCites.length === 0)
    failures.push(`[${id}] cites ${cites.length} check label(s), NONE of which ran+passed in the executed manifest — a renamed or disabled check is not a binding`);

  rows.push({ id, bound, byRegistry, nCites: executedCites.length, marker });
}

if (failures.length) {
  console.error(`✗ model-domain totality FAILED — ${failures.length} finding(s) over ${rows.length} enumerated sections:`);
  for (const f of failures) console.error('   • ' + f);
  process.exit(1);
}

const boundRows = rows.filter((r) => r.bound);
const pending = rows.filter((r) => r.marker?.kind === 'pending');
const declared = rows.filter((r) => r.marker?.kind === 'none');
console.log(`✓ model-domain totality: ${rows.length}/${rows.length} enumerated sections accounted for — ${boundRows.length} bound by an EXECUTED check or a registry record, ${declared.length} declared non-realizable with a closed-set reason, ${pending.length} pending`);
if (pending.length) {
  console.log(`  named residuals (a deferral is reported, never silent):`);
  for (const p of pending) console.log(`    ${p.id} — pending: ${p.marker.reason}`);
}
