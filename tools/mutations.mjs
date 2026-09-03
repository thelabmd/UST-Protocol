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
  // round 95 — THE HAND-WRITTEN SUITES. Five CI steps sat in the weakest quadrant of thelabmd/UST-Protocol#110 for one
  // reason: their only honest negative control is a MUTANT of the surface they test, and this corpus reached none of
  // those surfaces. Adding a leg to each suite would have been the appearance of coverage; adding entries HERE gives
  // each one an adversary the `drift-guards` observer already knows how to run — one corpus, the same two observations.
  {
    id: 'name-map-root-self-admitted', gate: 'node packages/ust-protocol/security-regression.mjs',
    why: 'the #42 consumer-admission of a name-map root. Broken, ANY root counts as admitted, so a self-supplied name-map root earns identity=authoritative — the P0-01a reproduction expects exactly that refusal.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (Array.isArray(trust?.mapRoots) && trust.mapRoots.includes(root)) return { basis: 'consumer-asserted' };",
    to: "  if (true) return { basis: 'consumer-asserted' }; /* mutant */",
  },
  {
    id: 'silence-reads-as-independence', gate: 'node packages/ust-protocol/conformance.mjs',
    why: 'F.5a.1 clause 2 — independence is CONSUMER-owned, so an unassigned trust domain is UNESTABLISHED, never independent. Broken, silence satisfies the floor: a consumer that asked for an independent authority and configured none is told it has one, which is the self-declared independence the clause exists to forbid, arriving through an omission instead of a field.',
    file: 'packages/ust-protocol/index.mjs',
    from: '      if (vouchDomain === undefined || vouchDomain === st.id.domain_shard)',
    to: '      if (vouchDomain === st.id.domain_shard) /* mutant */',
  },
  {
    id: 'minted-map-token-cloned-away', gate: 'node packages/ust-protocol/conformance.mjs',
    why: '#42 — a minted token is preserved BY IDENTITY through admission. Broken, `admitDeep` clones it like any plain record, the WeakSet no longer recognises it, and the anchored-authority branch is simply never taken: the consumer that did everything right silently drops back to the per-epoch pinned root. Found the hard way while building it — the branch looked dead and the token was the reason.',
    file: 'packages/ust-protocol/index.mjs',
    from: '|| VERIFIED_MAP_ROOT.has(v)) return v;',
    to: ') return v; /* mutant */',
  },
  {
    id: 'map-authority-self-admitted', gate: 'node packages/ust-protocol/conformance.mjs',
    why: '#42 / F.5a.1 clause 2 — admission of a map authority is the CONSUMER\'s and never the statement\'s. Broken, any well-formed signed root mints, so an impostor runs its own map, signs its own root, anchors it, and earns `authoritative` for a name it does not hold.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (!admitted) return { ok: false, detail: 'map authority not in the consumer mapAuthorities",
    to: "  if (false) return { ok: false, detail: 'map authority not in the consumer mapAuthorities",
  },
  {
    id: 'publisher-chain-establishes-the-floor', gate: 'node packages/ust-protocol/conformance.mjs',
    why: 'formal model F.5s-c — the floor is ESTABLISHED only when root-ness comes from outside the publisher. Broken, a publisher-supplied chain establishes it, and since the chain\'s completeness is the publisher\'s to withhold, an operator hides its earliest transitions and every gap before the later floor is reclassified as a period in which nothing was owed. This is the one coordinate where suppression FORGES instead of lowering.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (!(Array.isArray(c.trust?.streamRoots) && c.trust.streamRoots.includes(rh)))",
    to: "  if (false) /* mutant */",
  },
  {
    id: 'refusal-drops-its-facts', gate: 'node packages/ust-protocol/conformance.mjs',
    why: 'formal model F.5.1f — the ONE seam that gives every INDETERMINATE exit its shape. Broken, a refusal goes back to naming no vocabulary and no absent input, which is the state measured before round 217: five fields against the answer\'s nine, on precisely the branch where the reader must decide what to bring.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'return { ...facts, absent: absentInputs(opts, doc), verifier: VERSION, registry_digest: registryDigest() };',
    to: 'return { ...facts }; /* mutant */',
  },
  {
    id: 'map-root-currency-unlabelled', gate: 'node packages/ust-protocol/conformance.mjs',
    why: 'formal model F.5a.2b — a pinned root supplies CURRENCY by axiom, and an axiom the verdict does not label reads as an evidence fact. Broken, the map rung ships with no currency coordinate, which is exactly the silence this round removed: the verdict says a superseded binding is active and offers nothing to refuse on.',
    file: 'packages/ust-protocol/index.mjs',
    from: 'map_root: nm.map_root, map_root_currency: nmCur.basis,',
    to: 'map_root: nm.map_root,',
  },
  {
    id: 'diary-cap-not-enforced', gate: 'node --test packages/diarium/test/store.test.mjs',
    why: 'the cap the diary declares in its own rules.md. Broken, an entry over the cap is stored, so "one entry, one thing" stops being enforced by the tool and becomes a request.',
    file: 'packages/diarium/bin/diarium.mjs',
    from: '  if (body.length > limit) die(',
    to: '  if (false && body.length > limit) die(',
  },
  {
    id: 'authority-sequence-skip-admitted', gate: 'node packages/ust-protocol/run-arc-vectors.mjs',
    why: 'the §12.3 authority-checkpoint sequence rule. Broken, sequence stops having to be prev+1, so a chain with a SKIPPED checkpoint verifies — the `ac-sequence-skip` arc vector expects a refusal and would get a pass.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      if (b.sequence !== String(BigInt(prev.sequence) + 1n)) return { result: 'INVALID', error: 'E-SEQ', detail: 'sequence is not prev+1' };",
    to: "      if (false) return { result: 'INVALID', error: 'E-SEQ', detail: 'sequence is not prev+1' }; /* mutant */",
  },
  {
    id: 'ssrf-private-range-opened', gate: 'node packages/ust-protocol/ssrf.test.mjs',
    why: 'the SSRF door. Broken, no address is private, so a resolved host in 127/8 or 10/8 is fetched.',
    file: 'packages/ust-protocol/ssrf.mjs',
    from: 'export function isPrivateIp(ip) {\n  const v = net.isIP(ip);',
    to: 'export function isPrivateIp(ip) {\n  if (true) return false; /* mutant */\n  const v = net.isIP(ip);',
  },
  {
    id: 'cadence-root-conjunct-removed-discovery', gate: 'node tools/cadence-discovery-gate.mjs',
    why: 'the §F.5e.3 cadence conjunct, observed THROUGH discovery rather than through the reducer: an operational key moves the grid and the served contract still reports a declared cadence.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    if (sKid !== gKid) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' cadence mutation requires the GENESIS ROOT",
    to: "    if (false && sKid !== gKid) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' cadence mutation requires the GENESIS ROOT",
  },
  {
    id: 'keyadd-role-obligation-dropped', gate: 'node packages/ust-cli/regression.mjs',
    why: 'the §12.2 role obligation in the CLI core (round 84). Broken, a DECLARING genesis stops requiring a role, so a parallel key is added with none and the entry is E-KEY when served.',
    file: 'packages/ust-cli/index.mjs',
    from: '  if (declares && !role) throw new Error(',
    to: '  if (false && declares && !role) throw new Error(',
  },

  // round 131 (#120) — F.5q-a. Broken, ANY silent declared leg reads as dark, so a single dropped substrate
  // raises a full outage: `exists` reported as `for all`, which is the mistake the theorem exists to forbid.
  {
    id: 'one-silent-leg-reads-as-dark', mustDetect: true, observe: ['conformance'],
    why: 'the roll-up. Broken, one silent declared substrate is reported as a dark publisher.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    : silent.length === declared.length ? 'dark'            // nothing on ANY substrate it promised",
    to: "    : silent.length > 0 ? 'dark' /* mutant */",
  },
  // round 131 (#120) — F.5q admissibility. Broken, an anchor on an UNDECLARED substrate stops counting, so a
  // profile that names nothing hides evidence that is plainly there.
  {
    id: 'undeclared-anchor-stops-counting', mustDetect: true, observe: ['conformance'],
    why: 'the anchored row. Broken, evidence on a substrate the profile omits is discarded.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  for (const s of new Set([...declared, ...Object.keys(observed)]))",
    to: "  for (const s of new Set([...declared])) /* mutant */",
  },
  // round 133 (#122) — цепь перестаёт ловить оборванный prev. Тогда «ветвь поодиночке верифицируется
  // чисто» перестаёт что-либо значить: чисто проходило бы всё, и асимметрия видимости стала бы
  // непроверяемой — а именно она обосновывает, почему отказ обязан жить у производителя.
  {
    id: 'chain-stops-catching-dangling-prev', mustDetect: true, observe: ['conformance'],
    why: 'асимметрия видимости. Сломано: одна ветвь тоже перестаёт проходить, и условность обнаружения не проверить.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    else if (p !== prevHash) return { error: 'E-PREV', detail: 'frame ' + i + ' prev dangling (broken chain)' };",
    to: "    else if (false) return { error: 'E-PREV', detail: 'unreachable' }; /* mutant */",
  },
  // round 99 (#102) — F.5p relocation closure. Broken, a profile-named location for a standard surface is accepted
  // instead of refused, so a verifier could read the trust chain from a place the audited host itself chose.
  {
    id: 'profile-relocation-admitted', mustDetect: true, observe: ['conformance'],
    why: 'the relocation refusal. Broken, a standard surface may be resolved at a location the profile names.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (!standardLocation) throw Object.assign(new Error(`E-DISCOVERY: '${surface}' resolves at its §20.1 well-known location and only there; a profile locator is an ADDITIONAL copy compared by content_hash (F.5o), never a substitute (F.5p)`), { code: 'E-DISCOVERY' });",
    to: "  if (false) throw new Error('unreachable'); /* mutant */",
  },
  // round 99 (#102) — F.5p's "silence cannot hide evidence". Broken, the PRESENT row consults the declaration, so
  // an operator serving a witness while declaring nothing has that evidence ignored — the profile would become a
  // filter on what a verifier is allowed to see, which is the opposite of a locator.
  {
    id: 'present-surface-consults-declaration', mustDetect: true, observe: ['conformance'],
    why: 'the present row. Broken, a served surface is only attested when the profile also names it.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (observed === 'present') return deepFreeze({ surface, status: 'attested', reason: 'served' });",
    to: "  if (observed === 'present') return deepFreeze({ surface, status: declared ? 'attested' : 'not-offered', reason: 'served' }); /* mutant */",
  },
  // round 99 (#102) — F.5p's monotonicity. Broken, an UNDECLARED absent surface reads as attested, so an operator
  // that declares nothing gets every optional property for free — silence would become the strongest claim.
  {
    id: 'undeclared-absence-reads-attested', mustDetect: true, observe: ['conformance'],
    why: 'the 2x2 itself. Broken, an absent surface nobody declared is reported as attested.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    : deepFreeze({ surface, status: 'not-offered', reason: 'undeclared-and-absent' });   // settled, not a transient",
    to: "    : deepFreeze({ surface, status: 'attested', reason: 'undeclared-and-absent' }); /* mutant */",
  },
  // round 98 (#102) — the SERVING axis of "independence is never self-declared" (F.5o). Broken, the core stops
  // REFUSING a caller-supplied independence coordinate and just drops it, so a publisher naming its own copies
  // can hand the verifier a property no fetch can decide and nothing objects. The refusal is the whole mechanism:
  // silently ignoring the field looks identical from the outside right up until some surface starts reading it.
  {
    id: 'serving-independence-self-declared-admitted', mustDetect: true, observe: ['conformance'],
    why: 'the serving-axis independence closure. Broken, a self-declared independence coordinate is ignored instead of refused.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    if (k in rest) throw Object.assign(new Error(`E-REPLICATION: byte-agreement is decidable from bytes; '${k}' is not (F.5o) — independence enters from consumer configuration or external evidence, never from the locator list`), { code: 'E-REPLICATION' });",
    to: "    if (false && k in rest) throw new Error('unreachable'); /* mutant */",
  },
  // round 98 (#102) — byte-agreement must FAIL on a copy that differs. Broken, disagreement is recorded but the
  // verdict still reads attested, so a copy serving a DIFFERENT genesis passes the one check that would catch it.
  {
    id: 'replication-disagreement-still-attested', mustDetect: true, observe: ['conformance'],
    why: 'byte-agreement itself. Broken, a copy carrying a different content_hash no longer fails the property.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  return deepFreeze({ property: 'byte-agreement', expected, agreed, disagreed, attested: copies.length > 0 && disagreed.length === 0 });",
    to: "  return deepFreeze({ property: 'byte-agreement', expected, agreed, disagreed, attested: copies.length > 0 }); /* mutant */",
  },
  // round 79 (#106) — role INHERITANCE down a lineage. Broken, `add(k, supersedes=s)` no longer carries `s`'s role,
  // so replacing a roled key becomes impossible without restating the role by hand — and the asymmetry the whole
  // derivation rests on ("propagates, never introduces") stops being observable at all.
  {
    id: 'role-inheritance-dropped', mustDetect: true, observe: ['conformance'],
    why: 'role propagation. Broken, a successor key loses the role of the key it supersedes.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      const inherited = op.supersedes !== undefined ? roles.get(op.supersedes) : undefined;",
    to: "      const inherited = undefined; /* mutant */",
  },
  // round 79 (#106) — key ROLES under a DECLARED genesis. Broken, a missing role stops being refused: every key a
  // publisher adds is again indistinguishable from every other, so a leak of one signs everything and revocation
  // is all-or-nothing. This is the fail-CLOSED direction — a missing field must never be the strongest claim.
  {
    id: 'role-missing-not-refused', mustDetect: true, observe: ['conformance'],
    why: 'the declared-role requirement. Broken, an unroled key is admitted under a genesis that declared separation.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        if (r === undefined) return { error: 'E-KEY', detail: 'entry ' + i + ' has no `role` and inherits none",
    to: "        if (false /* mutant */) return { error: 'E-KEY', detail: 'entry ' + i + ' has no `role` and inherits none",
  },
  // round 78 (#97/tlx) — the class↔role PARTITION, one-sided. Broken, the `key` role admits every class again:
  // a data document verifies as a trust-layer document, and the shared served-log reader takes it as a log entry
  // while reporting that it VERIFIED it. This mutant is what proves the role matrix is not asserting against an
  // impossible literal — remove the key-side conjunct and the 12 class-role vectors must go red.
  {
    id: 'class-role-one-sided', mustDetect: true, observe: ['conformance'],
    why: 'the role partition. Broken, a data class passes as an authority document in the key role.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    if (opts.context === 'key' && !AUTHORITY_CLASSES.has(st.id.class)) return bad('E-MALFORMED',",
    to: "    if (false /* mutant */ && !AUTHORITY_CLASSES.has(st.id.class)) return bad('E-MALFORMED',",
  },
  // round 76 (#107) — the cadence ROOT conjunct. Broken, an operational key that is legitimately `active` may re-declare
  // the stream cadence, and with it what the operator's own COMPLETENESS claim means: a widening inside one precision
  // class (30s->90s) turns a stream with empty slots into `complete` without adding a frame. This mutant is what proves
  // the #107 checks are not asserting against an impossible literal — remove the conjunct and they must go red.
  {
    id: 'cadence-mutation-not-root-only', mustDetect: true, observe: ['conformance'],
    why: 'the cadence root conjunct. Broken, the most exposed key rewrites the grid that defines `complete`.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    if (sKid !== gKid) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' cadence mutation requires the GENESIS ROOT",
    to: "    if (false /* mutant */) return { error: 'E-KEY', detail: 'cadence entry ' + i + ' cadence mutation requires the GENESIS ROOT",
  },
  // rev95 — the rung a caller boolean may NOT earn. Broken, a consumer's own assertion becomes name authority,
  // which is the forgery #98 hardened against and the property `ust rotate` was wrongly demanding of that flag.
  {
    id: 'override-earns-authoritative', mustDetect: true, observe: ['conformance'],
    why: 'the override ceiling. Broken, consumer-override derives authoritative — a caller boolean names a canonical.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    : identity.strength === 'corroborated' ? 'corroborated'",
    to: "    : identity.strength === 'consumer-override' ? 'authoritative' /* mutant */ : identity.strength === 'corroborated' ? 'corroborated'",
  },
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
    from: "    return { complete: 'chain-consistent', head: prevHash, ...(bounded ? { interval: { from: a.from, to: a.to } } : {}),",
    to: "    return { complete: 'complete', head: prevHash, ...(bounded ? { interval: { from: a.from, to: a.to } } : {}),",
  },
  // #169 / round-233 — the SCOPE of a refusal. This break makes a coordinate the identity verdict never reads withhold
  // that verdict anyway, which is how it shipped: every step correct, the blast radius wrong. It is the one direction a
  // verdict-comparing check catches only if it compares against the SIBLING transport answer rather than a named value.
  {
    id: 'unknown-cadence-withholds-identity', mustDetect: true, observe: ['conformance'],
    why: 'the scope of a refusal. Broken, an unreadable cadence log withholds the whole discovery resolution — identity, capacity and no-fork are never derived — although the cadence enters no single-document verdict; a browser then reads every document of a publisher that serves no cadence log as INDETERMINATE.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        cadenceUnknown = { reason: /ceiling|§13/.test(e.message || '') ? 'resource_limit' : 'unavailable', detail: 'cadence-log present but unreadable: ' + (e && e.message || e) };",
    to: "        return { verdict: base, resolution: { status: 'INDETERMINATE', reason: /ceiling|§13/.test(e.message || '') ? 'resource_limit' : 'unavailable', error: 'cadence-log present but unreadable: ' + (e && e.message || e) } };",
  },
  // #169 / round-233 — the opposite direction, and it must be a SEPARATE mutant: collapsing the unknown into the
  // publisher's `null` leaves identity intact, so the scope check above stays green and only the substitution check
  // moves. Two mutants because the two checks discriminate, and one mutant would let either of them rot unnoticed.
  {
    id: 'unknown-cadence-collapses-into-declared-none', mustDetect: true, observe: ['conformance'],
    why: 'the third state. Broken, "the surface could not be read" is reported as "this publisher declares no grid" — a transient transport fact printed as a permanent property of the publisher, and the one substitution the F.4 closure forbids.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    ...(cadenceUnknown ? { cadence_unknown: cadenceUnknown } : { cadence: cadRes.cadence === null ? null : String(cadRes.cadence) }),",
    to: "    cadence: cadenceUnknown ? null : (cadRes.cadence === null ? null : String(cadRes.cadence)),",
  },
  // #172 / round-235 — the SAME scope defect on the TIME axis, and it needs its own pair for the same reason the
  // cadence one did. Broken, an inclusion construction this build cannot compute withholds the DOCUMENT's verdict,
  // although membership-in-a-committed-root enters no identity coordinate. Sharper than #169's: the input that
  // triggers it is a CORRECT proof, so attaching true evidence made a document verify worse than attaching none.
  {
    id: 'unreadable-construction-withholds-identity', mustDetect: true, observe: ['conformance'],
    why: 'the scope of a refusal, on the anchor axis. Broken, a proof whose construction is unclaimed collapses the whole verdict to INDETERMINATE before name authority is resolved — identity, capacity, no-fork and the witness result are never derived, and a publisher that starts attaching proofs makes every consumer without that connector strictly worse off.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        timeField = { strength: 'unproven', status: a.status ?? 'unavailable', unknown: { reason: a.reason ?? 'unavailable', ...(a.detail ? { detail: a.detail } : {}) } };",
    to: "        return { result: 'INDETERMINATE', reason: a.reason ?? 'unavailable', detail: a.detail || 'embedded proof could not be evaluated', verifier: VERSION, registry_digest: registryDigest() };",
  },
  // #172 / round-235 — the opposite direction, and SEPARATE for the same reason: collapsing the unreadable state into
  // the absent one leaves identity intact, so the scope check stays green and only the third-state check moves.
  {
    id: 'unreadable-construction-collapses-into-no-proof', mustDetect: true, observe: ['conformance'],
    why: 'the third state, on the anchor axis. Broken, "this build cannot read the proof offered" is reported as "no proof was offered" — the two are repaired by different parties, and only the first is fixed by installing a connector.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        timeField = { strength: 'unproven', status: a.status ?? 'unavailable', unknown: { reason: a.reason ?? 'unavailable', ...(a.detail ? { detail: a.detail } : {}) } };",
    to: "        timeField = { strength: 'unproven', status: 'none' };",
  },
  // #173 / round-236 — the SYNC door's answer to a promise. Broken, a connector the caller could not be observed in
  // this mode is reported as a refusal of the DOCUMENT, and verify() turns that into INVALID: a document called forged
  // because the reader's own connector was async. Every browser connector is async by construction, so this is a whole
  // host family, not a case.
  {
    id: 'async-connector-refuses-the-document', mustDetect: true, observe: ['conformance'],
    why: 'inability reported as guilt, on the inclusion seam. Broken, a promise from the caller\'s connector becomes `inclusion: false`, which verify() reads as a proof that does not reach its root — INVALID for a correct document.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        return { time: 'unproven', status: 'unavailable', reason: 'unsupported_construction', detail: 'inclusion connector is ASYNC and this is the SYNCHRONOUS door",
    to: "        return { inclusion: false, time: 'unproven', status: 'unavailable', reason: 'unsupported_construction', detail: 'inclusion connector is ASYNC and this is the SYNCHRONOUS door",
  },
  // #173 / round-236 — the ASYNC door, and it must be SEPARATE: dropping the pre-resolution leaves the sync door's
  // withholding intact, so the check above stays green and only the equality-between-doors check moves.
  {
    id: 'async-door-does-not-resolve-the-inclusion-seam', mustDetect: true, observe: ['conformance'],
    why: 'the remedy the refusal names. Broken, verifyAsync stops pre-resolving the inclusion connector, so both doors lead back to the synchronous call and an async connector can never reach `anchored` — the caller is told to use a door that does not open.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    if (capCH !== undefined) { try { incReceipt = await opts.inclusionVerify(capCH, capP); } catch { incReceipt = null; } }",
    to: "    /* mutant: the seam is not pre-resolved */",
  },
  // #173 / round-236 — the ASYMMETRY the repair must not swallow. Broken, a connector that COMPUTED and returned
  // `false` is treated as if it had merely been unobservable, so a proof that genuinely misses its root is withheld
  // instead of refused: the mirror of the defect the round fixed, and the direction that LOSES a real refusal.
  {
    id: 'a-computed-refusal-is-treated-as-unobservable', mustDetect: true, observe: ['conformance'],
    why: 'the asymmetry. Broken, `inclusionVerify` returning false stops being a verdict about the proof and becomes a withheld answer — a document whose path does not reach its root would no longer be refused for it.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      if (inc === null || inc === undefined) { inclusion = undefined; }",
    to: "      if (inc === null || inc === undefined || inc === false) { inclusion = undefined; } /* mutant */",
  },
  // #171 / round-237 — the SKIP. Broken, a caller assertion suppresses the witness probe again: the observation is
  // never made, so the earned `corroborated` is unreachable and an added TRUE premise LOWERS the verdict — and the
  // fork refusal, which lives only on that branch, becomes unreachable with it.
  {
    id: 'a-caller-assertion-suppresses-the-witness-probe', mustDetect: true, observe: ['conformance'],
    why: 'an axiom treated as an answer. Broken, asserting no-fork stops the verifier asking the witness, so a consumer that adds a true premise is charged a lower strength than one that says nothing, and the rival-genesis search it asserted about is switched off.',
    file: 'packages/ust-protocol/index.mjs',
    from: "  if (!opts.offline) {\n    const w = await witnessNoFork(shard, genesisHash,",
    to: "  if (!callerNoFork && !opts.offline) {\n    const w = await witnessNoFork(shard, genesisHash,",
  },
  // #171 / round-237 — the JOIN, and SEPARATE because it fails the other way: with the probe running, dropping the
  // axiom from the earned result leaves monotonicity intact and costs the consumer only the lift it asked for.
  {
    id: 'the-earned-basis-drops-the-callers-axiom', mustDetect: true, observe: ['conformance'],
    why: 'the join. Broken, a served-list corroboration reports itself alone and the caller\'s explicit axiom is discarded, so `acceptConsumerOverride` has nothing liftable and a consumer that was ALSO corroborated can no longer reach the tier it consciously opted into.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      ...((ncf === true || cor === true) ? { override_liftable: true, independently_verified: false, axiom: 'caller-asserted',",
    to: "      ...(false ? { override_liftable: true, independently_verified: false, axiom: 'caller-asserted',",
  },
  // #161 — a shortfall that says nothing. The verdict is UNCHANGED by this break (still `provisional`), which is
  // exactly why it needs its own mutant: no verdict-comparing check can see it, and the defect it reproduces sat in
  // the tree until someone read the returned object field by field.
  {
    id: 'shortfall-refuses-without-naming', mustDetect: true, observe: ['conformance'],
    why: 'the shortfall vocabulary. Broken, an absent checkpoint answers a bare word and the consumer cannot tell WHICH input would move it — the F.5.1e defect, one layer down from the verdict.',
    file: 'packages/ust-protocol/index.mjs',
    from: "    reason: genesis\n      ? 'open-tail: no checkpoint, so the observed set has no declared extent — the chain proves no-deletion BETWEEN the frames held, never that they are all of them'\n      : 'unbounded: neither a genesis nor a checkpoint — the origin is unbound and the extent undeclared; the chain proves no-deletion between the frames held and nothing about either end' };",
    to: "  };",
  },
  // ── verdict seams: the battery's hard requirements ────────────────────────────────────────────────────────────
  {
    id: 'verifier-stops-refusing', mustDetect: true, observe: ['conformance'],
    why: 'the single seam that constructs a refusal. Broken, the verifier accepts everything it should reject — every check whose evidence is "the attack is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "function bad(code, detail, fields) { return { result: 'INVALID', error: code, detail: quoteSafe(detail), ...(fields || null) }; }",
    to: "function bad(code, detail, fields) { return { result: 'VALID', tier: 'LIGHT' }; }",
  },
  {
    id: 'identifier-may-forge-structure', mustDetect: true, observe: ['conformance'],
    why: 'the §6 identifier seam. A partition name and an `enc.key_id` travel INTO the verdict, so a publisher writes part of what the reader sees. Broken, a newline in either composes a line of the verifier\'s own report — measured 2026-09-01 as a fabricated `tier : [TOP] anchored in Bitcoin` printed above the real `[LIGHT]` one, and CLOSED 2026-09-01 by the admission rule this mutant removes. Every check whose evidence is "an identifier the verdict quotes cannot forge structure" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "      if (FORGES_STRUCTURE.test(name)) return bad('E-MALFORMED', 'partition name carries a control or bidi-override character",
    to: "      if (false) return bad('E-MALFORMED', 'partition name carries a control or bidi-override character",
  },
  {
    id: 'blinded-may-carry-a-ciphertext', mustDetect: true, observe: ['conformance'],
    why: 'the admission seam for §4.4\'s two private productions. Broken, a partition declared `blinded` may ship an `enc` block, and the AEAD branch — keyed on the MODE — never runs: the ciphertext is signed, published and examined by nobody while the verdict says every declared channel was checked. Measured as a working exploit on 2026-09-01 before this refusal existed. Every check whose evidence is "a channel outside the declared mode is refused" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "        if (part.privacy === 'blinded' && part.enc !== undefined)",
    to: "        if (false)   /* mutant: the pre-fix grammar — `enc` optional for BOTH private modes */",
  },
  {
    id: 'partial-disclosure-reported-as-whole', mustDetect: true, observe: ['conformance'],
    why: 'the per-channel seam (§14.8, model F.7a.1 per-channel corollary). An `encrypted` partition has two channels opened by different secrets; a reader holding only the disclosure checked ONE. Broken, that reader is handed the same word as one who checked both — and on the divergence vectors, where the two channels contradict each other, "disclosed" would name a state nobody verified. Every check whose evidence is "the report does not outrun the check" must go red.',
    file: 'packages/ust-protocol/index.mjs',
    from: "          disclosedPartial.push({ partition: name, checked: 'commit', unchecked: 'aead', needs_key_id: part.enc.key_id });",
    to: "          disclosed.push(name);   /* mutant: the pre-#177 behaviour — one channel reported as all of them */",
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
    // AUDIT #114 — the OTS half of the same lesson. A disagreeing explorer is the ONLY thing standing between a
    // forged block claim and finality, and the suite asserts exactly that. Break it and those assertions go true.
    id: 'ots-explorer-conflict-ignored', gate: 'node packages/ust-ots-verify/index.test.mjs',
    why: 'the §17 explorer-conflict rule. Ignored, a single lying explorer is enough to call a claim anchored.',
    file: 'packages/ust-ots-verify/index.mjs',
    from: 'if (blk.merkle_root !== wantMerkle) { conflict = true; continue; }',
    to: 'if (blk.merkle_root !== wantMerkle) { continue; }',
    observe: [],
  },
  {
    // AUDIT #114, second look. The connector suites had no can-fail demonstration at all, and my first answer was to
    // WIDEN the vocabulary that looks for one — a gate refused my claim, so I moved the gate. The two SSRF suites
    // already show the right shape: they do not ARGUE they can fail, they CITE a mutant that makes them fail. This is
    // that mutant for Rekor. Break the tree-head signature check and the suite's `final: false` assertions go true.
    id: 'rekor-treehead-signature-unchecked', gate: 'node packages/ust-rekor-verify/index.test.mjs',
    why: "the LOG's signature over its tree head. Unchecked, ANY checkpoint reads as signed by Rekor, which is the one thing that binds a root to the log rather than to itself.",
    file: 'packages/ust-rekor-verify/index.mjs',
    from: "if (edVerify('sha256', body, pubKey, sig.subarray(4))) return true;",
    to: "if (edVerify('sha256', body, pubKey, sig.subarray(4)) || true) return true;",
    observe: [],
  },
  {
    // AUDIT #114 MEASURED 2026-07-30: the assurance roster silently held 57 of 58 steps for as long as it existed —
    // `connector receipts (OTS + Rekor)` carries a comment between `- name:` and `run:`, and the old parser required
    // them adjacent. It vanished, and the gate reported the remaining 57 as "every CI step". Nothing in the corpus
    // held that class, so this mutant does: a step whose command the gate cannot read must FAIL, never disappear.
//
// CLOSED 2026-07-30 by `2e89945f` — audit(#114): the roster held 57 of 58 steps in silence, and the missing
// one was the anchor. In this tree a narration is written in the commit that fixes what it describes, and
// blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
    id: 'unreadable-ci-step', observe: [],
    why: 'a CI step the assurance roster cannot parse — the shape that used to leave the domain in silence.',
    file: '.github/workflows/ci.yml',
    from: '      - name: web-signer cross-verification',
    to: '      - name: drift step with no readable command\n        uses: ./nonexistent\n      - name: web-signer cross-verification',
    gate: 'node tools/assurance-map-gate.mjs',
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
    // The sentinel was `rev99` until 2026-07-31, when a round registered records AT rev99 and silently
    // DISABLED this probe: rule 2 found a record for the rev and passed. A sentinel that can collide with a
    // real value is not a sentinel. `rev0` cannot occur (revisions are 1-based and monotone), and the note now
    // also CITES a check nobody registered, so rule 3 catches it even if rule 2 is ever satisfied by accident.
    append: '\n**Realization (rev0 — drift probe).** A fake enforcement claim with no registry record, citing *"DRIFT PROBE: a check no registry records"*.\n',
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
