// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the EXCLUSIONS live in the model itself as `**Binding: none|pending — …**` markers drawn from a CLOSED reason set, and `pending` without a tracker reference already fails, so an exclusion cannot be invented here — the sections are computed from the document and EXPECTED_SECTIONS is an exact-equality pin that fails when wrong rather than a bound that tolerates more
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
const EXPECTED_SECTIONS = 53;   // 52 → 53: F.5p.1 (rev101) — a profile BINDS and DESCRIBES, and one extension rule
// cannot serve both: a verifier meeting an unknown key cannot evaluate `bind(k)`, because the spec version it
// implements is precisely what does not define k. The partition must be POSITIONAL — a naming convention would let
// the publisher choose whether its own statement binds it. 51 → 52: F.5z (rev99) — суперсессия есть ТЕРМИНАЛЬНЫЙ акт кей-лога, и носитель
// ВЫНУЖДЕН, а не выбран: подписывает старый корень, а корень под объявленным режимом допускает ровно
// {genesis, key, cadence}, из которых два исключаются по существу. 50 → 51: F.5y (rev98) — перекоренение есть ПЕРЕСЕЧЕНИЕ каждой укоренённой в
// генезисе структуры, которую издатель инстанциировал, а не одно событие; пять осей перечислены из чтений
// самого верификатора, и три из них нашлись только потому, что домен перечисляли, а не выбирали образец.
// 49 → 50: F.7c (rev90) — нормативное утверждение ОПРЕДЕЛЕНО, иначе оно не
//   закончено: место, где ответ зависит от того, КОГО спросили, — не свобода, а ненайденное правило.
//    // 48 → 49: F.5x (rev90) — авторизация читает ДОКУМЕНТ, поэтому `class`
//   не одна ось из нескольких, а единственная имеющаяся: тира в координатах состояния нет, он
//   восстанавливается только проходом по цепи. И два сервиса под ОДНИМ именем ролью не разделяются.
//    // 47 → 48: F.5w (rev87) — у предиката есть ОБЛАСТЬ, на которой он
//   нетривиален, и key-form — та область, где привязка ключа тождественно истинна. Поднято НАВЕРХ из
//   раунда 145, где математика была объявлена исключённой ошибочно.
// 46 → 47: F.5v (rev86) — покрытие слота НЕ ЕСТЬ наблюдение: запись о
//   разрыве это собственное подписанное заявление издателя, что кадра он не произвёл, поэтому она обязана
//   ослаблять отрицательное утверждение, а не подкреплять его. Композиционный отказ: оба механизма верны
//   по отдельности.
// 45 → 46: F.5u (rev84) — корень публикуется ДВАЖДЫ, и перечислить может
//   только одна из двух публикаций: печать (`set`) перечисляет, пакетное обязательство — нет. Перечисление
//   не является входом предиката включения §11.2 и выдаёт оракул членства, поэтому требовать его ради
//   публикации корня значит выгонять честного оператора за пределы протокола.
// 44 → 45: F.5t (rev83) — имя протокола есть ИНСТРУКЦИЯ машине: артефакт,
//   носящий имя и не проходящий проверку, отдаёт наблюдение, зарезервированное за повреждённым или
//   подделанным документом. Замерено на собственных записях об аварии оператора.
// 39 → 40: F.5e.4 added (#97/tlx, round 78) — the verification ROLE is a partition of classes, and it had been enforced on one side only
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

// ── THE NORMATIVE SPEC (rev87) ─────────────────────────────────────────────────────────────────────────────────────
// The appendix above is non-normative; `spec/UST-1.0.md` is the document third parties implement, and it had NO
// traceability convention at all. Note carefully what is and is not being claimed: the wire format IS tested — the
// conformance vectors exercise it and `spec-code-sync` generates whole regions FROM code. What is missing is a
// machine-verifiable link from a normative STATEMENT to the check that realizes it. So this block does NOT force a
// marker onto 49 sections (that would manufacture paperwork and call it coverage). It enumerates the domain, counts
// what is genuinely bound, and PINS the unbound remainder so the number can be driven down deliberately and can never
// drift up unnoticed. Binding sources: a generated `spec-sync:` region, an executed citation, a named existing gate,
// or the same explicit marker the appendix uses.
const SPEC = readFileSync(new URL('../spec/UST-1.0.md', import.meta.url), 'utf8');
// A section covered by a DIFFERENT existing gate — declared, because the coverage lives in that gate, not here.
const GATE_COVERAGE = { '14.': 'rule-lockstep (the §14 decision relation is frozen: case labels == RULE_CONTRACTS keys, both directions)' };
const PINNED_SPEC_UNBOUND = 48;

const specHeads = [...SPEC.matchAll(/\n#{2,3} ([^\n]+)/g)].map((m) => ({ pos: m.index, title: m[1].trim() }));
const specBounds = specHeads.map((h) => h.pos).concat(SPEC.length);
if (specHeads.length < 40) failures.push(`spec section extraction broke — only ${specHeads.length} sections found`);
const specUnbound = [];
for (let i = 0; i < specHeads.length; i++) {
  const title = specHeads[i].title, body = SPEC.slice(specHeads[i].pos, specBounds[i + 1]);
  const generated = body.includes('spec-sync:');
  const cited = [...body.matchAll(/\*"([^"]+)"\*/g)].map((m) => m[1]).some(citationExecuted);
  const byGate = Object.keys(GATE_COVERAGE).some((k) => title.startsWith(k));
  const marked = MARKER.test(body);
  if (!(generated || cited || byGate || marked)) specUnbound.push(title.split('—')[0].trim().slice(0, 54));
}
if (specUnbound.length > PINNED_SPEC_UNBOUND)
  failures.push(`the NORMATIVE SPEC untraced remainder grew: ${specUnbound.length} sections have no machine-verifiable link to a check, pinned at ${PINNED_SPEC_UNBOUND}. Bind the new section (cite an executed check, generate its region, or declare it) — this number may only go down`);

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
console.log(`  normative spec: ${specHeads.length - specUnbound.length}/${specHeads.length} sections traceable to a check (generated region, executed citation, named gate, or declaration); ${specUnbound.length} untraced (pinned ≤ ${PINNED_SPEC_UNBOUND}) — the wire format IS tested by the vectors, what is pinned here is the missing STATEMENT→check link:`);
for (const s of specUnbound.slice(0, 8)) console.log(`    ${s}`);
if (specUnbound.length > 8) console.log(`    … and ${specUnbound.length - 8} more`);
{
}

// ── CONTROLS. This gate rests on two mechanisms, and each has one way to be worthless: the heading scanner never
// finds a section, or the binding test accepts a citation that resolves against nothing. Both are checked against
// SYNTHETIC input rather than against the model, so a control cannot drift with the document it guards.
{
  const ctl = [
    ['the heading scanner finds a synthetic F-section',
      [...'\n## F.9.9 a fabricated section that exists only in this control\n'.matchAll(/\n(#{2,4}) (F\.[0-9a-z.]+[^\n]*)/g)].length === 1],
    ['the heading scanner finds nothing in text that has no F-section',
      [...'\n## Appendix B history\n'.matchAll(/\n(#{2,4}) (F\.[0-9a-z.]+[^\n]*)/g)].length === 0],
    ['the executed manifest does NOT contain a check name that cannot exist',
      !EXECUTED_SET.has('a check name that cannot exist — control')],
    ['the manifest is not empty, so binding against it is not vacuous', EXECUTED.length > 100],
    ['the section pin matches what was measured, so the pin is not decoration', heads.length === EXPECTED_SECTIONS],
  ];
  const bad = ctl.filter(([, ok]) => !ok).map(([n]) => n);
  if (bad.length) { bad.forEach((n) => console.error('  ✗ CONTROL: ' + n)); process.exit(1); }
  console.log(`  ✓ CONTROL: the heading scanner and the binding test both discriminate (${ctl.length} legs, synthetic input)`);
}
