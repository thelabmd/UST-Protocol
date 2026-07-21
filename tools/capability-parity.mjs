// SPDX-License-Identifier: Apache-2.0
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
import * as LITE from '../packages/ust-lite/index.mjs';
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
const CAPS = {
  'canon':              { core: ['canon'], mcp: 'ust_canon', cli: 'canon' },
  'content-address':    { core: ['contentHash', 'signedContent', 'partitionHash', 'seed', 'merkleRoot', 'keyId'], mcp: 'ust_key_id', cli: 'contentHash' },
  'build-transcript':   { core: ['buildState', 'buildAttestation', 'buildDerivation', 'buildGenesis', 'buildKeyLogEntry', 'buildCheckpoint', 'buildGap', 'buildCadenceEntry'], mcp: 'ust_build_observation', cli: 'buildState' },
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
  'recovery':           { core: ['checkpointRecoveryClaim', 'buildRecoveryStatement', 'verifyCheckpointRecovery'] },
  'epoch-transition':   { core: ['epochTransitionClaim', 'buildEpochTransition', 'verifyEpochTransition'] },
  'uniqueness-attest':  { core: ['checkpointUniquenessClaim', 'buildUniquenessAttestation', 'verifyCheckpointUniqueness'] },
  'verifiable-map':     { core: ['buildVerifiableMap', 'checkpointMapLeaf', 'nameMapLeaf', 'verifyCheckpointMapUniqueness', 'verifyActiveGenesisUniqueness'] },
  'keylog-commitment':  { core: ['keylogLeaf', 'buildKeylogCommitment', 'verifyKeylogTerminality'], cli: 'rotateKeylog' },
  'cadence-grid':       { core: ['ustGrid', 'resolveCadence', 'resolveCadenceBytes'] },
  'substrate-registry': { core: ['combineSubstrates'] },
  'discovery-shard':    { core: ['isPublicDnsShard'], cli: 'attestDiscovery' },
  'disclosure':         { core: ['blindedCommit', 'blindPartition'] },
  'negative-observation':{ core: ['buildAbsence', 'noEventBacking'] },   // #39 — a normative absence assertion + the no-event↔completeness tie; core-only for now, no surface exposes it yet
};

// Internal primitives — not user-capability units (raw hash, encoders, error types, the registry itself).
const PRIMITIVES = new Set(['VERSION', 'STABILITY', 'REFERENCE_CHECKER_VERSION', 'REFERENCE_CHECKER_RULES', 'REFERENCE_CHECKER_ERROR_CODES', 'RULE_CONTRACTS', 'H', 'Hbytes', 'edVerifyStrict', 'strictB64url', 'parseCadenceInt', 'UstInvalid', 'UstIndeterminate', 'REGISTRY', 'noFraudProof', 'admitUtf8', 'anyLoneSurrogate', 'admitDeep', 'snapshotBytes']);   // round-19 P1-01 — shared Unicode byte-admission leaf; round-27 (3) — admitDeep, THE input-boundary primitive (canon-transparent inert snapshot), exported so its transparency is testable; round-48 P0-01 — snapshotBytes, THE byte-admission door (exact native Uint8Array → immutable copy), shared by the kernel + the two resolvers

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
  'ust-lite':         { probe: exportIntersect(LITE), full: ['canon', 'sign'], subset: ['content-address', 'build-transcript', 'verify'], naReason: 'outside the standalone zero-dependency LIGHT floor — lite is a documented SUBSET (round-51 P1-03: build-transcript = buildState/seal only, not the full builder family; verify = the LIGHT floor, not the HIGH/TOP verifiers; content-address = the partition/content hashes it needs)' },
  'ust-web-signer':   { probe: exportIntersect(WEB), full: ['canon', 'sign'], subset: ['content-address', 'build-transcript'], naReason: 'producer-only surface — a documented SUBSET (round-51 P1-03: browser signer builds+signs a state, not the full builder family)', naSpecific: { 'verify': 'by design: the private key never enters a verifier — verification is ust-protocol / ust-lite (README)' } },
  'ust-ots-verify':   { probe: connector(OTS), full: ['anchor-verify', 'typed-evidence', 'substrate-registry'], subset: [], naReason: 'a Bitcoin/OTS substrate connector (plugs into verifyAnchor via substrateVerify), not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts (buildEvidenceReceipt with its own key) instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  'ust-rekor-verify': { probe: connector(REKOR), full: ['anchor-verify', 'typed-evidence', 'substrate-registry'], subset: [], naReason: 'a Rekor transparency-log substrate connector, not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  // Agent MCP TARGET (owner, 2026-07-15) = full for EVERY non-operator capability + the single conditionally-operator
  // touch: reaching TOP (mint/attach an anchor), planned for noosphere, not yet built. `na` here means the capability
  // is deferred to the PLANNED operator MCP over ustate (key creation, checkpoint/recovery/epoch/uniqueness/map
  // ceremonies) so a human explicitly grants agent rights — NOT 'stays core+CLI forever'. NOTE: no-fork-evidence /
  // anchor-verify are marked full on the CONSUME side; a produce/consume axis split is the honest refinement (UST-<top>).
  'ust-mcp':          { probe: mcpProbe, full: ['canon', 'content-address', 'build-transcript', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'fork-choice', 'stream-verify'], subset: [], naReason: 'deferred to the planned operator MCP over ustate (privilege-separation: a human explicitly grants agent rights) — NOT core+CLI-forever; TOP-produce is the one agent touch still to be built for noosphere', naSpecific: { 'sign': 'the agent signs with its OWN key; build tools return signing_input, the MCP never holds a private key', 'negative-observation': 'agent-appropriate (a normal negative observation, NOT operator) — new per #39; an MCP absence verb is planned, not yet built' } },
  'ust-cli':          { probe: cliProbe, full: ['canon', 'content-address', 'build-transcript', 'sign', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'stream-verify', 'checkpoint-chain', 'keylog-commitment', 'discovery-shard'], subset: [], naReason: 'not exposed by the reference operator CLI', naSpecific: { 'negative-observation': 'new per #39; a `ust absence` command is planned, not yet built' } },
};

const capIds = Object.keys(CAPS);
const surfaceIds = Object.keys(SURFACES);
let fail = 0; const report = [];
const stanceOf = (s, cap) => SURFACES[s].full.includes(cap) ? 'full' : SURFACES[s].subset.includes(cap) ? 'subset' : 'na';

// (1) COVERAGE — every capability-bearing core export is triaged (in a CAP or a PRIMITIVE).
const covered = new Set(Object.values(CAPS).flatMap((c) => c.core));
const untriaged = Object.keys(P).filter((k) => !covered.has(k) && !PRIMITIVES.has(k));
if (untriaged.length) { fail++; report.push(`  ✗ COVERAGE: ${untriaged.length} core export(s) not triaged — add to a CAP or PRIMITIVES: [${untriaged.join(', ')}]`); }
else report.push(`  ✓ COVERAGE: all ${Object.keys(P).length} core exports triaged (${covered.size} in ${capIds.length} capabilities, ${PRIMITIVES.size} primitives)`);

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

console.log('\n  capability parity gate (UST-kdb):');
report.forEach((r) => console.log(r));
console.log(fail ? `\n  ✗ ${fail} parity failure(s) — a surface diverged from the spec's capability set` : `\n  ✓ every surface's capabilities match its declared, spec-derived stance — no silent drift`);
process.exit(fail ? 1 : 0);
