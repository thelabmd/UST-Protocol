// SPDX-License-Identifier: Apache-2.0
// THE MUTATION CORPUS — one definition per deliberate break, shared by the two things that observe them.
//
// A mutation is a single, reversible edit that breaks something on purpose. Two different gates ask two different
// questions about the SAME edit, and until rev89 each kept its own copy of the edit:
//   • `drift-guards.test.mjs` asks "does the GATE that guards this reject it?" — fail-closed proof for the gate.
//   • `vacuity-battery.mjs`   asks "which registered CHECKS notice?" — non-vacuity proof for the checks.
// Two copies of one edit is the drift class this repo exists to eliminate: `new function export` was written twice,
// once per file, and nothing would have caught the two drifting apart. One corpus, two observations.
//
// `observe` declares which channels a mutation is worth running on, and it is a claim about REACHABILITY, not effort:
//   gate         — a gate command must exit non-zero. Every mutation carries this.
//   conformance   — the suite loads the mutated module, so registered checks can notice. Only code the suite imports
//                   qualifies: a prose edit to the spec or the formal model cannot change conformance behaviour, so
//                   running it there would burn a suite execution to observe a guaranteed zero.
//   byte-vectors  — the language-neutral corpus, the only channel that reaches the reference checker's own verdicts.
// `mustDetect` marks the verdict-seam mutations the battery treats as hard requirements; the rest are harvest — a hit
// lowers the unproven residual, a miss is covered by the gate channel and is not a failure.
export const MUTATIONS = [
  // rev93 third case — the C3 NEUTRALIZATION. A strength label whose status is not `verified` must contribute the
  // FLOOR, never its own rung. Broken, a caller-shaped or unresolved label lifts the identity coordinate straight
  // into the assurance tuple, which is the forgery this seam exists to close — and the reason an inert label is
  // merely misleading in the report but catastrophic in the derivation.
  {
    id: 'bare-label-earns-its-rung', mustDetect: true, observe: ['conformance'],
    why: 'the C3 neutralization. Broken, a strength label with no verified status earns its own rung — an unresolved or caller-supplied name binds.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  const idStr = !verified ? 'self-asserted'",
    to: "  const idStr = !verified ? (identity?.strength ?? 'self-asserted') /* mutant */",
  },
  // rev92 — the axis seam. An UNDECLARED grid is the one case where nothing signed says how many slots there
  // should be, so no-omission is not merely unproven but undecidable. Minting `complete` there would let a publisher
  // reach the strongest range verdict by declaring LESS, which inverts the incentive the whole grid exists to create.
  {
    id: 'undeclared-grid-mints-complete', mustDetect: true, observe: ['conformance'],
    why: 'the no-grid ceiling. Broken, a stream with no signed cadence reports no-omission — the completeness axis starts paying for silence.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    return { complete: 'chain-consistent', head: prevHash, ...(a.from !== undefined && a.to !== undefined ? { interval: { from: a.from, to: a.to } } : {}) };",
    to: "    return { complete: 'complete', head: prevHash, ...(a.from !== undefined && a.to !== undefined ? { interval: { from: a.from, to: a.to } } : {}) };",
  },
  // ── verdict seams: the battery's hard requirements ────────────────────────────────────────────────────────────
  {
    id: 'verifier-stops-refusing', mustDetect: true, observe: ['conformance'],
    why: 'the single seam that constructs a refusal. Broken, the verifier accepts everything it should reject — every check whose evidence is "the attack is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "function bad(code, detail, fields) { return { result: 'INVALID', error: code, detail, ...(fields || null) }; }",
    to: "function bad(code, detail, fields) { return { result: 'VALID', tier: 'LIGHT' }; }",
  },
  {
    id: 'signature-always-verifies', mustDetect: true, observe: ['conformance'],
    why: 'the Ed25519 leaf. Broken, every forged or tampered signature passes — checks whose evidence is "a bad signature is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'export function edVerifyStrict(pubB64url, msgUtf8, sigB64url) {',
    to: 'export function edVerifyStrict(pubB64url, msgUtf8, sigB64url) { return true; /* mutant */',
  },
  // ── #95 the anchor INCLUSION seam. Delegating the tree opens exactly four forgery surfaces (F.5c.1 rev86); one
  // mutant per surface, so each closure is shown CAPABLE of going red rather than merely being green today.
  // MEASURED, not assumed: a mutant for the doc-borne surface was written and REMOVED. The insertion point is
  // reachable (diagnostically confirmed), but `admitDeep` STRIPS every field the verifier does not declare, so a
  // publisher's `inclusionVerify` — function or inert look-alike — never arrives for the mutant to honour. The surface is
  // closed by admission, one layer above the seam; a mutant there would be decorative, which this corpus does not keep.
  {
    id: 'inclusion-connector-leaf-not-typed', mustDetect: true, observe: ['conformance'],
    why: 'the CLOSED TYPED leaf. Broken, any truthy connector return mints inclusion — the string "yes" would anchor a document.',
    file: 'packages/ust-protocol/index.mjs',
    // The anchor moved when the router's `null` = not-claimed branch landed (#95 finish), so it is now the `else if`.
    // The battery REFUSED to run until this was updated rather than silently matching something else — which is the point.
    from: '      else if (inc !== true && inc !== false)',
    to: '      else if (false) /* mutant: truthy accepted */',
  },
  {
    id: 'inclusion-seam-not-total', mustDetect: true, observe: ['conformance'],
    why: 'the not-ours door (UST-5tm). Broken, a hostile connector throws THROUGH the verifier instead of becoming a structured verdict.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      return { inclusion: false, time: 'unproven', status: 'unavailable', detail: 'inclusion seam is not-ours (UST-5tm): a hostile connector return/throw is a structured reject, never a host throw' };",
    to: '      throw new Error("mutant: hostile connector rethrown");',
  },
  {
    id: 'inclusion-connector-mints-time', mustDetect: true, observe: ['conformance'],
    why: 'the rung separation (C3). Broken, delegating inclusion also delegates anchored TIME — a connector answering true would forge the substrate half.',
    file: 'packages/ust-protocol/index.mjs',
    // Same anchor drift as its sibling: the router branch made this `else inclusion = inc;`.
    from: '      else inclusion = inc;',
    to: "      else { inclusion = inc; if (inc) return { inclusion: true, time: 'anchored', status: 'verified', anchorTime: '2027-01-01T00:00:00Z', detail: 'mutant: connector minted time' }; }",
  },
  {
    id: 'tier-always-top', mustDetect: true, observe: ['conformance'],
    why: 'the tier projection. Broken, every document reads as the strongest tier — checks whose evidence is "this evidence does NOT earn TOP/authoritative" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'export function projectTier(state) {',
    to: "export function projectTier(state) { return 'TOP'; /* mutant */",
  },
  {
    id: 'tcb-stops-refusing', mustDetect: true, observe: ['conformance', 'byte-vectors'],
    why: 'the refusal seam inside the reference checker — the normative TCB. Broken, `checkAuthorityProofBytes` accepts every package it should reject, so the language-neutral byte corpus must go red.',
    file: 'packages/ust-protocol/reference-checker.mjs',
    from: "  const INVALID = (reason) => ({ result: 'INVALID', reason });",
    to: "  const INVALID = (reason) => ({ result: 'VALID', tier: 'LIGHT' });",
  },

  // ── extension vectors: a gate must reject them; the suite may also notice (harvest) ───────────────────────────
  {
    // rev89: this edit used to exist TWICE — as the battery's `unclassified-export` and as drift-guards' first probe.
    id: 'unclassified-export', mustDetect: true, observe: ['conformance'],
    why: 'the from-code partition. A new export that no one classified must fail the roster checks — the family whose evidence is "a new surface cannot ship silently".',
    file: 'packages/ust-protocol/index.mjs',
    append: '\nexport function __mutationProbeExport(x) { return x; }\n',
    gate: 'node tools/capability-parity.mjs',
    gateName: 'new function export → capability-parity',
  },
  {
    // rev89 MEASURED: run on the conformance channel it caught ZERO registered checks, so it is gate-only. The #91
    // hypothesis — "computing the union of the drift-guard and battery populations should lower the unproven residual
    // without writing a new check" — is FALSIFIED for this mutation: registry records describe adversarial closures in
    // the verifier's BEHAVIOUR, while this breaks registry HYGIENE, which only its own gate reads. Kept gate-only so the
    // battery does not burn a suite execution to re-observe a measured zero.
    id: 'unregistered-error-code', observe: [],
    why: 'a new L1-checker error code that no registry declares.',
    file: 'packages/ust-protocol/reference-checker.mjs',
    append: "\nconst __mutationProbeCode = 'E-DRIFT-PROBE';\n",
    gate: 'node tools/spec-code-sync.mjs',
    gateName: 'new checker error code → spec-code-sync',
  },
  {
    // rev89 MEASURED: zero registered checks on the conformance channel — same finding as `unregistered-error-code`.
    id: 'sixteenth-inference-rule', observe: [],
    why: 'a 16th rule in a decision relation frozen at 15.',
    file: 'packages/ust-protocol/reference-checker.mjs',
    from: 'RULE_CONTRACTS = deepFreeze(Object.assign(Object.create(null), {',
    to: 'RULE_CONTRACTS = deepFreeze(Object.assign(Object.create(null), {\n  __DriftRule16: 1,',
    gate: 'node tools/rule-lockstep.mjs',
    gateName: 'new inference rule (16th RULE_CONTRACTS key) → rule-lockstep',
  },

  // ── gate-only: conformance cannot reach these, so the battery does not burn a run on them ─────────────────────
  {
    id: 'bmc-denominator-shrunk', observe: [],
    why: 'an interpreter rule dropped from the BMC coverage denominator.',
    file: 'packages/ust-protocol/bmc.mjs',
    from: "NameBound: ['Genesis'], ", to: '',
    gate: 'node packages/ust-protocol/bmc.mjs',
    gateName: 'interpreter rule dropped from CHILD_SIG → BMC',
  },
  {
    id: 'unregistered-realization', observe: [],
    why: 'a model enforcement Realization with no registry record.',
    file: 'spec/UST-1.0-formal-model.md',
    append: '\n**Realization (rev99 — drift probe).** A fake enforcement claim with no registry record.\n',
    gate: 'node tools/model-lockstep-gate.mjs',
    gateName: 'model Realization without a registry record → model-lockstep',
  },
  {
    id: 'unbound-model-section', observe: [],
    why: 'a new model section that binds nothing — silence used to be invisible to every gate at once.',
    file: 'spec/UST-1.0-formal-model.md',
    append: '\n## F.99 Drift probe — a section that binds nothing\n\nIt asserts a property and cites no check.\n',
    gate: 'node tools/model-domain-totality.mjs',
    gateName: 'new UNBOUND model section → model-domain totality',
  },
  {
    id: 'binding-reason-outside-closed-set', observe: [],
    why: 'a Binding reason outside the closed set — an unknown reason is not a licence.',
    file: 'spec/UST-1.0-formal-model.md',
    from: '**Binding: none — definitional.** It fixes the ambient objects',
    to: '**Binding: none — because-i-said-so.** It fixes the ambient objects',
    gate: 'node tools/model-domain-totality.mjs',
    gateName: 'Binding reason outside the closed set → model-domain totality',
  },
  {
    id: 'retired-mechanism-respecified', observe: [],
    why: 'an abandoned path walking back into the spec under its own name.',
    file: 'spec/UST-1.0.md',
    append: '\n\nThe key log MAY instead be committed as a positioned SMT keyed by `H(index)`.\n',
    gate: 'node tools/retired-mechanisms-gate.mjs',
    gateName: 'retired mechanism re-specified → retired-mechanisms',
  },
];

// Apply a mutation to source text. Returns the mutated text, or null when the anchor is absent — an absent anchor means
// the source moved and the mutation is stale, which every consumer must treat as a failure, never as a pass.
export function applyMutation(m, source) {
  if (m.append) return source + m.append;
  const occurrences = source.split(m.from).length - 1;
  if (occurrences !== 1) return null;        // 0 = anchor moved; >1 = ambiguous, would mutate the wrong site
  return source.replace(m.from, m.to);
}
