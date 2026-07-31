// SPDX-License-Identifier: Apache-2.0
// @assurance 3 canfail:yes — the CLASSIFICATION is hand-typed and a misclassified export still passes; the DOMAIN is live (every core export triaged, both directions)
// Capability parity gate (UST-kdb) — the FORCING FUNCTION so a spec capability can NEVER silently lag a surface
// (the UST-3dj class: an agent/CLI surface that resolves/verifies but quietly drops a capability the core added).
//
// Single source below: CAPS (every user-meaningful core capability → the core exports that realize it) and SURFACES
// (each surface's DECLARED stance per capability: full | subset | na). The gate asserts three things:
//   (1) COVERAGE — every capability-bearing core export is triaged: bucketed in CAPS or listed in PRIMITIVES. A NEW
//       core export fails until someone puts it under a capability (or declares it a primitive). No silent capability.
//   (2) NO PHANTOM — every core name CAPS references actually exists in ust-protocol (catches a renamed/removed export).
//   (3) REALITY — a declared full/subset is genuinely EXPOSED by that surface (export / MCP tool / CLI flag / forwarded
//       FIELD). This is what catches UST-3dj: `no-fork-evidence` is its own capability probed by the FIELD name, so a
//       tool that exists but drops the field flips the cell red. `na` is honest-absence and needs a reason.
//
// Granularity is deliberate: capabilities that live as a FIELD inside an existing tool/command (no-fork-evidence,
// trust-roots) are separate units with field-level probes — coarse tool-presence checks would miss a dropped field.
import * as P from '../packages/ust-protocol/index.mjs';
import * as LITE from '../packages/ust-light/index.mjs';
import * as WEB from '../packages/ust-web-signer/index.mjs';
import * as OTS from '../packages/ust-ots-verify/index.mjs';
import * as REKOR from '../packages/ust-rekor-verify/index.mjs';
import * as MCP from '../packages/ust-mcp/index.mjs';
import { readFileSync } from 'node:fs';

const cliSrc = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const mcpSrc = readFileSync(new URL('../packages/ust-mcp/index.mjs', import.meta.url), 'utf8');
const mcpTools = new Set(MCP.listTools().map((t) => t.name));

// ── CAPS — the capability units. `core` = the ust-protocol exports that realize the capability. `mcp`/`cli` = the
//    probe token (a tool name / forwarded field for MCP; a flag / command for CLI) proving that surface EXPOSES it.

// ── STANCE (owner 2026-07-27) — a capability exposed by NO surface must say WHY, or the gate's own green is empty.
// The parity checks below compare DECLARED against ACTUAL and therefore pass forever on a capability honestly
// declared as nowhere: they answer "does the tree match itself", never "is the declaration right". The owner asked
// exactly that question — "did we update everything in the tools that we made ourselves" — and the matrix could not
// answer it. Same shape as the ladder registry shipped this morning: an exclusion is legitimate, an ABSENCE is not.
//
// 'decided'  — deliberately internal or deliberately deferred, with the reason.
// 'undecided'— nobody has ruled. Written down as such rather than passing silently; this is the queue.
const MIN_REASON = 50;
const STANCE = {
  'evidence-receipt':    ['undecided', 'the receipt is the paid signing axis in the product plan, so exposing it on a free surface is a COMMERCIAL decision and not mine to make. Queued for the owner.'],
  'assurance-lattice':   ['decided',   'internal algebra: deriveAssurance/assuranceState/projectTier are how a verdict is COMPUTED. A surface that let a caller assemble a tuple directly would be the forgery oracle round-25 closed at the type level.'],
  'verified-handle':     ['decided',   'the branded-handle machinery is the mechanism that makes the above unforgeable. Exposing the brand IS the vulnerability; it can have no public surface by construction.'],
  'authority-bundle':    ['undecided', 'the #76/#77 authority-checkpoint family is built in core and reachable from no tool. It belongs to the TOP work (UST-48p) and should get its surface there, not before.'],
  'recovery':            ['undecided', 'N-of-M genesis-authorized recovery exists in core. A surface for it is a CEREMONY, and ceremonies live on the CLI — but the owner has not ruled whether recovery is operator-facing or support-only.'],
  'epoch-transition':    ['undecided', 'same family as authority-bundle; same answer — it lands with TOP or not at all.'],
  'uniqueness-attest':   ['undecided', 'part of the checkpoint/uniqueness cluster. No tool consumes it yet, and inventing a surface before a consumer exists is how unused surface becomes permanent.'],
  'verifiable-map':      ['undecided', 'the anchored name-map is the independent path to authoritative. It has no operator today because no map substrate is registered; the surface should follow the substrate, not precede it.'],
  'disclosure':          ['decided',   'private-partition disclosure is a PUBLISHER-side act on data the tool never holds — the verifier receives {nonce, value} from whoever discloses. There is nothing for a tool of ours to do.'],
  'negative-observation':['decided',   'a negative observation is built with the ordinary transcript builders and carries no distinct operation; it is a USAGE of build-transcript, not a capability needing its own surface.'],
};

const CAPS = {
  'canon':              { core: ['canon'], mcp: 'ust_canon', cli: 'canon' },
  'content-address':    { core: ['contentHash', 'signedContent', 'partitionHash', 'seed', 'merkleRoot', 'keyId'], mcp: 'ust_key_id', cli: 'contentHash' },
  'build-transcript':   { core: ['buildState', 'buildAttestation', 'buildDerivation', 'buildGenesis', 'buildKeyLogEntry', 'buildCheckpoint', 'buildStreamCheckpoint', 'buildGap'], mcp: 'ust_build_observation', cli: 'buildState' },
  'sign':               { core: ['seal'], cli: 'seal' },
  'verify':             { core: ['verify', 'verifyJson', 'verifyAsync', 'isValid', 'checkBounds', 'assertValid', 'verifyOrThrow'], mcp: 'ust_verify', cli: 'verifyRaw' },
  'resolve-authority':  { core: ['resolveAuthority', 'resolveKeys', 'resolveKeysBytes', 'resolveByDiscovery'], mcp: 'ust_resolve', cli: '--genesis' },
  'no-fork-evidence':   { core: ['noForkClaim', 'buildNoForkEvidence', 'verifyNoForkEvidence', 'witnessNoFork'], mcp: 'noForkEvidence', cli: '--witness' },
  'consumer-trust-root':{ core: ['quorumTrustDomains'], mcp: 'trustRoots', cli: '--trust-root' },
  'anchor-verify':      { core: ['verifyAnchor'], mcp: 'ust_anchor_verify', cli: '--require-anchored' },
  'fork-choice':        { core: ['forkChoice'], mcp: 'ust_fork_choice' },
  'stream-verify':      { core: ['verifyStream'], mcp: 'ust_verify_stream', cli: 'verifyStream' },
  'typed-evidence':     { core: ['verifiedEvidence', 'evidenceClass', 'evidenceCaps', 'compareEvidenceOrder', 'EVIDENCE_CAPS_UNIVERSE'] },
  // M3 (UST-6vj C2) — provenance-bearing evidence: a SIGNED connector receipt verified against consumer-admitted
  // connectors is the ONLY way external facts reach a strong rung (closes the rc.35 round-2 verifiedEvidence-forge).
  'evidence-receipt':   { core: ['evidenceReceiptClaim', 'buildEvidenceReceipt', 'evidenceReceiptId', 'verifyEvidenceReceipt'] },
  'assurance-lattice':  { core: ['ASSURANCE_AXES', 'axisRank', 'assuranceState', 'assuranceLE', 'meetAssurance', 'joinAssurance', 'projectTier', 'TIER_RANK', 'capAssurance', 'deriveAssurance', 'provePredicates'] },
  // K3 (UST-znh) — the opaque-handle brand: consumers may TEST provenance (image-membership), never MINT it.
  'verified-handle':    { core: ['isVerifiedHandle'] },
  // K4 (UST-znh) — the ONE public authority entrypoint: raw inputs + config in, single verdict + derivation trace out.
  // K4 → Closed Proof Kernel: the ONE public authority verdict is prover ∘ check_C (reference-checker.mjs).
  'authority-bundle':   { core: ['verifyAuthorityBundle', 'buildAuthorityProof', 'checkAuthorityProof', 'checkAuthorityProofBytes'] },
  'checkpoint-chain':   { core: ['buildAuthorityCheckpoint', 'sealAuthorityCheckpoint', 'authorityCheckpointId', 'verifyAuthorityCheckpointChain', 'resolveCheckpointRoots', 'deriveCheckpointFreshness', 'verifiedGenesisContext', 'genesisEpoch', 'authorityScopeId'], cli: 'buildCeremony' },
  // §12.1 is 'recovery/supersession' — one section, one capability. witnessSuccessor BUILDS the successor witness
  // log when a name re-roots; witnessNoShrink is the rule it must satisfy, shared with any mirror that ingests it.
  'recovery':           { core: ['checkpointRecoveryClaim', 'buildRecoveryStatement', 'verifyCheckpointRecovery', 'witnessSuccessor', 'witnessNoShrink'] },
  'epoch-transition':   { core: ['epochTransitionClaim', 'buildEpochTransition', 'verifyEpochTransition'] },
  'uniqueness-attest':  { core: ['checkpointUniquenessClaim', 'buildUniquenessAttestation', 'verifyCheckpointUniqueness'] },
  'verifiable-map':     { core: ['buildVerifiableMap', 'checkpointMapLeaf', 'nameMapLeaf', 'verifyCheckpointMapUniqueness', 'verifyActiveGenesisUniqueness'] },
  'keylog-commitment':  { core: ['keylogLeaf', 'buildKeylogCommitment', 'verifyKeylogTerminality'], cli: 'rotateKeylog' },
  'cadence-grid':       { core: ['ustGrid', 'resolveCadence', 'resolveCadenceBytes'], mcp: 'ust_resolve_cadence', cli: 'cadence' },
  // Split OUT of build-transcript (2026-07-27): that capability bundles eight builders behind ONE representative probe
  // (`ust_build_observation`), so `buildCadenceEntry` having no surface at all read as full. A capability whose probe
  // cannot see its own members is the coarse-probe failure this file's own header warns about.
  'cadence-declare':    { core: ['buildCadenceEntry'], mcp: 'ust_build_cadence', cli: 'cmdCadence' },
  'substrate-registry': { core: ['combineSubstrates', 'combineInclusion'] },   // #95 — finality AND membership route by substrate name, one pattern
  'discovery-shard':    { core: ['isPublicDnsShard'], cli: 'attestDiscovery' },
  'disclosure':         { core: ['blindedCommit', 'blindPartition'] },
  'negative-observation':{ core: ['buildAbsence', 'noEventBacking'] },   // #39 — a normative absence assertion + the no-event↔completeness tie; core-only for now, no surface exposes it yet
};

// Internal primitives — not user-capability units (raw hash, encoders, error types, the registry itself).
// PRIMITIVES was a bare Set and therefore an UNJUSTIFIED ESCAPE HATCH: an export dropped in here vanishes from the
// capability matrix and nothing asks why. Two of its twenty entries were MEASURED DEAD on 2026-07-30 — `noFraudProof`
// and `REFERENCE_CHECKER_ERROR_CODES` name exports the core does not have — because COVERAGE was ONE-SIDED: it asked
// that every export be triaged and never that every triaged name still exist. Same class as round 78's one-sided
// role partition. So each entry now carries its reason, and the partition is checked in BOTH directions.
const PRIMITIVES = {
  VERSION: 'the wire/spec/revision triple a report stamps itself with — it describes the implementation, not something a consumer can DO',
  STABILITY: 'per-rung stability labels the surfaces read; a property OF the capabilities rather than one of them',
  REFERENCE_CHECKER_VERSION: 'the L1 build identity a conformance report must name — an instrument label, and naming the instrument is not a capability',
  REFERENCE_CHECKER_RULES: 'the checker\'s own rule vocabulary, exported so gates ENUMERATE it from source instead of typing a copy',
  RULE_CONTRACTS: 'the §14 decision-relation contracts, exported for the same reason: rule-lockstep reads them rather than restating them',
  REGISTRY: 'the canonical string sets, exported so spec-code-sync can measure code usage AGAINST them rather than against a typed list',
  registryDigest: 'the digest a verdict carries for attribution, derived FROM REGISTRY — a stamp on an answer, not an answer',
  H: 'a domain-separated hash leaf used by EVERY capability; bucketing it under one would make that one capability\'s cell lie',
  Hbytes: 'the byte-input twin of H, and the same argument: shared by every path, owned by none',
  edVerifyStrict: 'the signature primitive underneath every verify path — shared by all of them, so it belongs to no single one',
  strictB64url: 'the base64url admission leaf at the byte boundary; an input-admission primitive rather than a user-meaningful act',
  parseCadenceInt: 'the canonical positive-integer-STRING leaf (§11.3) — an admission primitive that no surface exposes on its own',
  admitUtf8: 'the shared Unicode byte-admission leaf (round-19 P1-01), reached by every canonicalisation rather than by one capability',
  anyLoneSurrogate: 'the other half of that same admission leaf, exported so the refusal is testable from outside the kernel',
  admitDeep: 'THE input-boundary primitive (canon-transparent inert snapshot, round-27), exported so its transparency can be tested',
  snapshotBytes: 'THE byte-admission door (round-48 P0-01): exact native Uint8Array to immutable copy, shared by the kernel and both resolvers',
  UstInvalid: 'a verdict CARRIER — a typed throw. A surface cannot expose it as a capability; it is the shape an answer arrives in',
  UstIndeterminate: 'the other verdict carrier, and the same argument: it transports a verdict rather than being one',
};

// A connector exposes the substrate seam (verifyAnchor delegate + typed evidence emit), not core names.
const connector = (X) => (cap) => ['anchor-verify', 'typed-evidence', 'substrate-registry'].includes(cap) && typeof X.substrateVerify !== 'undefined' && typeof X.toVerifiedEvidence === 'function';
// round-51 P1-03 (owner: set-COMPLETE predicate, not `some`) — a `full` stance means EVERY core export of the capability is
// exposed; `some`-intersection wrongly certified a surface as full when it had ONE of many (GPT round-51: lite declared full for
// build-transcript with only buildState, missing buildAttestation/…). `full` ⇒ every; a genuine reduced surface declares `subset`.
const exportIntersect = (X) => (cap, stance) => (stance === 'full' ? CAPS[cap].core.every((n) => n in X) : CAPS[cap].core.some((n) => n in X));
const mcpProbe = (cap) => { const tok = CAPS[cap].mcp; return !!tok && (mcpTools.has(tok) || mcpSrc.includes(tok)); };
const cliProbe = (cap) => { const tok = CAPS[cap].cli; return !!tok && cliSrc.includes(tok); };

// ── SURFACES — each surface's DECLARED stance. `full` = exposes the capability; `subset` = a documented reduced form;
//    everything else defaults to `na` with the surface's `naReason` (a specific override lives in `naSpecific`). This
//    encodes the owner's decisions: cli grows to full authoritative; mcp stays agent-facing (operator caps na).
const SURFACES = {
  'ust-light':         { probe: exportIntersect(LITE), full: ['canon', 'sign'], subset: ['content-address', 'build-transcript', 'verify'], naReason: 'outside the standalone zero-dependency LIGHT floor — lite is a documented SUBSET (round-51 P1-03: build-transcript = buildState/seal for class:observation, WITH provenance (prev/based_on+seed) since UST-jls, but not the full builder family; verify = the WHOLE LIGHT floor including every §14a provenance obligation — UST-jls closed 14 lite-VALID/core-INVALID shapes — but not the HIGH/TOP verifiers; content-address = the partition/content/seed hashes it needs)' },
  'ust-web-signer':   { probe: exportIntersect(WEB), full: ['canon', 'sign'], subset: ['content-address', 'build-transcript'], naReason: 'producer-only surface — a documented SUBSET (round-51 P1-03: browser signer builds+signs a state, not the full builder family)', naSpecific: { 'verify': 'by design: the private key never enters a verifier — verification is ust-protocol / ust-light (README)' } },
  'ust-ots-verify':   { probe: connector(OTS), full: ['anchor-verify', 'typed-evidence', 'substrate-registry'], subset: [], naReason: 'a Bitcoin/OTS substrate connector (plugs into verifyAnchor via substrateVerify), not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts (buildEvidenceReceipt with its own key) instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  'ust-rekor-verify': { probe: connector(REKOR), full: ['anchor-verify', 'typed-evidence', 'substrate-registry'], subset: [], naReason: 'a Rekor transparency-log substrate connector, not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  // Agent MCP TARGET (owner, 2026-07-15) = full for EVERY non-operator capability + the single conditionally-operator
  // touch: reaching TOP (mint/attach an anchor), planned for noosphere, not yet built. `na` here means the capability
  // is deferred to the PLANNED operator MCP over @ust-protocol/operator (key creation, checkpoint/recovery/epoch/uniqueness/map
  // ceremonies) so a human explicitly grants agent rights — NOT 'stays core+CLI forever'. NOTE: no-fork-evidence /
  // anchor-verify are marked full on the CONSUME side; a produce/consume axis split is the honest refinement (UST-<top>).
  'ust-mcp':          { probe: mcpProbe, full: ['canon', 'content-address', 'build-transcript', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'fork-choice', 'stream-verify', 'cadence-grid', 'cadence-declare'], subset: [], naReason: 'deferred to the planned operator MCP over @ust-protocol/operator (privilege-separation: a human explicitly grants agent rights) — NOT core+CLI-forever; TOP-produce is the one agent touch still to be built for noosphere', naSpecific: { 'sign': 'the agent signs with its OWN key; build tools return signing_input, the MCP never holds a private key', 'negative-observation': 'agent-appropriate (a normal negative observation, NOT operator) — new per #39; an MCP absence verb is planned, not yet built' } },
  'ust-cli':          { probe: cliProbe, full: ['canon', 'content-address', 'build-transcript', 'sign', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'stream-verify', 'checkpoint-chain', 'keylog-commitment', 'discovery-shard', 'cadence-grid', 'cadence-declare'], subset: [], naReason: 'not exposed by the reference operator CLI', naSpecific: { 'negative-observation': 'new per #39; a `ust absence` command is planned, not yet built' } },
};

const capIds = Object.keys(CAPS);
const surfaceIds = Object.keys(SURFACES);
let fail = 0; const report = [];
const stanceOf = (s, cap) => SURFACES[s].full.includes(cap) ? 'full' : SURFACES[s].subset.includes(cap) ? 'subset' : 'na';

// (1) COVERAGE — every capability-bearing core export is triaged (in a CAP or a PRIMITIVE).
const covered = new Set(Object.values(CAPS).flatMap((c) => c.core));
const untriaged = Object.keys(P).filter((k) => !covered.has(k) && !Object.hasOwn(PRIMITIVES, k));
// ── the OTHER direction, which was missing and cost two dead entries: every TRIAGED name must still be a live
// export. A triage list that outlives what it triaged reads as coverage while covering nothing.
{
  const live = new Set(Object.keys(P));
  const deadPrim = Object.keys(PRIMITIVES).filter((n) => !live.has(n));
  const deadCaps = [...new Set(capIds.flatMap((c) => CAPS[c].core.filter((n) => !live.has(n))))];
  const thin = Object.entries(PRIMITIVES).filter(([, why]) => String(why).trim().length < MIN_REASON).map(([n]) => n);
  if (deadPrim.length) { fail++; report.push(`  ✗ COVERAGE (reverse): PRIMITIVES names ${deadPrim.length} export(s) the core does not have: [${deadPrim.join(', ')}] — a triage list that outlives its subject reads as coverage`); }
  if (deadCaps.length) { fail++; report.push(`  ✗ COVERAGE (reverse): CAPS names ${deadCaps.length} export(s) the core does not have: [${deadCaps.join(', ')}]`); }
  if (thin.length) { fail++; report.push(`  ✗ PRIMITIVES reason under ${MIN_REASON} chars (a placeholder, not a decision): ${thin.join(', ')}`); }
  if (!deadPrim.length && !deadCaps.length && !thin.length)
    report.push(`  ✓ COVERAGE (reverse): every triaged name is a live export, and all ${Object.keys(PRIMITIVES).length} PRIMITIVES carry a stated reason`);
  // CONTROLS — both directions must be able to fail, or neither is checking anything.
  if (live.has('ghostExportThatCannotExist')) { fail++; report.push('  ✗ CONTROL: the live-export set accepts a name that cannot exist'); }
  if (!Object.keys({ ...PRIMITIVES, ghostTriagedNameThatCannotExist: 'x' }).filter((n) => !live.has(n)).length) { fail++; report.push('  ✗ CONTROL: the reverse detector does not flag a triaged name that is not exported'); }
}
if (untriaged.length) { fail++; report.push(`  ✗ COVERAGE: ${untriaged.length} core export(s) not triaged — add to a CAP or PRIMITIVES: [${untriaged.join(', ')}]`); }
else report.push(`  ✓ COVERAGE: all ${Object.keys(P).length} core exports triaged (${covered.size} in ${capIds.length} capabilities, ${Object.keys(PRIMITIVES).length} primitives)`);

// (2) NO PHANTOM — CAPS never names a core export that does not exist.
const phantom = [...covered].filter((n) => !(n in P));
if (phantom.length) { fail++; report.push(`  ✗ PHANTOM: CAPS reference non-existent core exports: [${phantom.join(', ')}]`); }
else report.push(`  ✓ PHANTOM: every core name in CAPS resolves to a real ust-protocol export`);

// (3) REALITY — every declared full/subset is genuinely exposed; every na has a reason.
let cells = 0, drift = 0;
for (const s of surfaceIds) {
  const def = SURFACES[s];
  for (const cap of capIds) {
    cells++;
    const stance = stanceOf(s, cap);
    const real = def.probe(cap, stance);   // round-51 P1-03 — stance-aware: full ⇒ EVERY export, subset ⇒ some
    if (stance !== 'na' && !real) { fail++; drift++; report.push(`  ✗ REALITY: ${s} declares ${cap}=${stance} but does NOT expose it (dropped/renamed? UST-3dj-class regression)`); }
    if (stance === 'na' && real) { fail++; drift++; report.push(`  ✗ REALITY: ${s} exposes ${cap} but the matrix says na — promote to full/subset (under-declared)`); }
    if (stance === 'na' && !def.naReason && !(def.naSpecific && def.naSpecific[cap])) { fail++; report.push(`  ✗ ${s}/${cap}=na has no reason`); }
  }
}
if (!drift) report.push(`  ✓ REALITY: all ${cells} surface×capability cells match what the surface actually exposes`);

// ── human-readable matrix
const mark = { full: ' ✅', subset: ' 🟅', na: ' ·' };
const short = (s) => s.replace('ust-', '');
const pad = (x, n) => (x + ' '.repeat(n)).slice(0, n);
console.log('\n  UST capability parity — surface × capability (✅ full · 🟅 subset · · n/a)\n');
console.log('  ' + pad('capability', 20) + surfaceIds.map((s) => pad(short(s), 12)).join(''));
for (const cap of capIds) console.log('  ' + pad(cap, 20) + surfaceIds.map((s) => pad(mark[stanceOf(s, cap)], 12)).join(''));


// ── every zero-surface capability must carry a stance, and every stance must name a real capability
{
  // the authoritative domain is SURFACES — each surface DECLARES the capabilities it exposes. My first version
  // read key names off CAPS and reported two capabilities as surfaceless that the matrix shows with a full ✅; the
  // detector was pointed at the wrong object, and the gate caught its own author on the first run.
  const exposed = new Set(Object.values(SURFACES).flatMap((s) => [...(s.full ?? []), ...(s.subset ?? [])]));
  const zero = Object.keys(CAPS).filter((n) => !exposed.has(n));
  const missing = zero.filter((n) => !STANCE[n]);
  const thin = zero.filter((n) => STANCE[n] && String(STANCE[n][1]).trim().length < MIN_REASON);
  const phantom = Object.keys(STANCE).filter((n) => !CAPS[n]);
  if (missing.length || thin.length || phantom.length) {
    if (missing.length) console.error('  ✗ capability exposed by NO surface and carrying no stance: ' + missing.join(', '));
    if (thin.length) console.error('  ✗ stance shorter than ' + MIN_REASON + ' chars (a placeholder, not a decision): ' + thin.join(', '));
    if (phantom.length) console.error('  ✗ stance names a capability that does not exist: ' + phantom.join(', '));
    process.exit(1);
  }
  const undecided = zero.filter((n) => STANCE[n][0] === 'undecided');
  console.log('  ✓ STANCE: all ' + zero.length + ' zero-surface capabilities declare a reason (' + undecided.length + ' undecided — the queue: ' + undecided.join(', ') + ')');
}
console.log('\n  capability parity gate (UST-kdb):');
report.forEach((r) => console.log(r));
console.log(fail ? `\n  ✗ ${fail} parity failure(s) — a surface diverged from the spec's capability set` : `\n  ✓ every surface's capabilities match its declared, spec-derived stance — no silent drift`);
process.exit(fail ? 1 : 0);
