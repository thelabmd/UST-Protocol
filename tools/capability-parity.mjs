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
import * as RFC from '../packages/ust-rfc6962-verify/index.mjs';   // #178 — a real package that was in no column
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
  // THREE STANCES LEFT THIS REGISTER in round 270, for the same reason two dispositions did: a stance explains why
  // a capability is on NO surface, and all three had one. `disclosure-produce` reached `ust sign` (#177),
  // `ladder-report` had been `ust explain` since round 137, `name-obligation` is `ust names`. Each had turned into
  // a historical note without ceasing to be a record of an absence, and the leg below now refuses that.
  //
  // `name-obligation`'s text also argued the MCP absence was DELIBERATE — "handing an agent a filesystem sweep of
  // arbitrary paths is a capability about the host" — while the ORDERING register classifies it `lagging`, which
  // owes NO justification. Two registers, one absence, opposite answers, and nothing compared them. The argument
  // does not survive its own premise: `nameSetReport` takes DOCUMENTS, so an agent-side tool would accept an array
  // and touch no filesystem at all. It was an argument against a badly-shaped tool, read as an argument against the
  // capability — which is how it sat in the quiet register while the loud one called it debt.
  'evidence-receipt':    ['undecided', 'the receipt is the paid signing axis in the product plan, so exposing it on a free surface is a COMMERCIAL decision and not mine to make. Queued for the owner.'],
  'assurance-lattice':   ['decided',   'internal algebra: deriveAssurance/assuranceState/projectTier are how a verdict is COMPUTED. A surface that let a caller assemble a tuple directly would be the forgery oracle round-25 closed at the type level.'],
  'verified-handle':     ['decided',   'the branded-handle machinery is the mechanism that makes the above unforgeable. Exposing the brand IS the vulnerability; it can have no public surface by construction.'],
  'authority-bundle':    ['undecided', 'the #76/#77 authority-checkpoint family is built in core and reachable from no tool. It belongs to the TOP work (UST-48p) and should get its surface there, not before.'],
  'recovery':            ['undecided', 'N-of-M genesis-authorized recovery exists in core. A surface for it is a CEREMONY, and ceremonies live on the CLI — but the owner has not ruled whether recovery is operator-facing or support-only.'],
  'epoch-transition':    ['undecided', 'same family as authority-bundle; same answer — it lands with TOP or not at all.'],
  'uniqueness-attest':   ['undecided', 'part of the checkpoint/uniqueness cluster. No tool consumes it yet, and inventing a surface before a consumer exists is how unused surface becomes permanent.'],
  'verifiable-map':      ['undecided', 'the anchored name-map is the independent path to authoritative. It has no operator today because no map substrate is registered; the surface should follow the substrate, not precede it.'],
  'negative-observation':['decided',   'a negative observation is built with the ordinary transcript builders and carries no distinct operation; it is a USAGE of build-transcript, not a capability needing its own surface.'],
  'commitment-windows':  ['decided',   'F.5q-c: the CORE lands before any surface, deliberately. Coverage and gaps are measurable in the commitment chain alone, and the vectors pin what that answer may and may not be — an empty chain answers `unknown` rather than `uncovered`, adjacent windows are not a gap — BEFORE a CLI shape fixes those answers by accident. The present-tense half (F.5q-d) needs a verifier-owned clock and is not built, so a surface now would expose half a question.'],
};

const CAPS = {
  'canon':              { core: ['canon'], mcp: 'tool:ust_canon', cli: 'cmd:canon' },
  'content-address':    { core: ['contentHash', 'signedContent', 'partitionHash', 'seed', 'merkleRoot', 'keyId'], mcp: 'tool:ust_key_id', cli: 'cmd:canon' },
  'build-transcript':   { core: ['buildState', 'buildAttestation', 'buildDerivation', 'buildGenesis', 'buildKeyLogEntry', 'buildCheckpoint', 'buildStreamCheckpoint', 'buildGap', 'buildAnchorCommitment'], mcp: ['tool:ust_build_observation', 'tool:ust_build_genesis', 'tool:ust_build_key_log', 'tool:ust_combine_derivation', 'tool:ust_combine_attestation'], cli: ['cmd:sign', 'cmd:genesis', 'cmd:key'] },
  // Two operations, one name — the third time this shape has surfaced across #177/#178 (after `disclosure` and
  // `build-transcript`). `seal` SIGNS and ASSEMBLES; `attachSignature` only assembles, from a signature made
  // elsewhere, and needs no key. A surface that must never hold a key can own the second half honestly, so the
  // capability names both and a surface exposing one of them is a SUBSET rather than absent.
  'sign':               { core: ['seal', 'attachSignature'], cli: 'cmd:sign', mcp: 'tool:ust_seal' },
  'verify':             { core: ['verify', 'verifyJson', 'verifyAsync', 'isValid', 'cannotDecide', 'admitEd25519Point', 'checkBounds', 'assertValid', 'verifyOrThrow'], mcp: 'tool:ust_verify', cli: 'cmd:verify' },
  'resolve-authority':  { core: ['resolveAuthority', 'resolveKeys', 'resolveKeysBytes', 'resolveByDiscovery', 'resolveSupersession'], mcp: 'tool:ust_resolve', cli: 'flag:genesis' },
  'no-fork-evidence':   { core: ['noForkClaim', 'buildNoForkEvidence', 'verifyNoForkEvidence', 'witnessNoFork'], mcp: 'arg:ust_verify.noForkEvidence', cli: 'flag:witness' },
  'consumer-trust-root':{ core: ['quorumTrustDomains'], mcp: 'arg:ust_verify.trustRoots', cli: 'flag:trust-root' },
  'anchor-verify':      { core: ['verifyAnchor'], mcp: 'tool:ust_anchor_verify', cli: 'flag:require-anchored' },
  'fork-choice':        { core: ['forkChoice'], mcp: 'tool:ust_fork_choice' },
  // #102 / F.5o — the SERVING axis. A consumer-meaningful act (do the copies a publisher named agree byte for
  // byte?) whose whole discipline is what it REFUSES to answer: independence is not decidable from the bytes,
  // so it is not in this capability and no surface may report it. `ust discovery --mirror` is the CLI face.
  // #135 / F.5p.1 — `parseProfile` belongs HERE and not to a capability of its own: it does not answer a question,
  // it reads the DECLARATION the three below are evaluated against. Before it, a copy the publisher named was
  // invisible to this capability and its staleness unmeasurable; the CLI face is now the profile itself, with
  // `--mirror` remaining the CONSUMER's own locator rather than a substitute for it.
  'byte-agreement':     { core: ['replicationAgreement', 'surfaceVerdict', 'anchorRollup', 'parseProfile'], cli: 'flag:mirror', mcp: ['tool:ust_profile_declares', 'tool:ust_replication_agreement', 'tool:ust_serving_verdict', 'tool:ust_anchor_rollup'] },   // #178 round 273 — the last inversion; the F.5o refusals travel with it
  'name-obligation':    { core: ['classifyNamed', 'nameSetReport'], cli: 'cmd:names', mcp: 'tool:ust_name_report' },   // #178 round 271 — the agent hands the set as an ARRAY; the filesystem sweep was how the CLI COLLECTS it, never what the capability is
  'commitment-windows': { core: ['commitmentCoverage'] },
  // #137 / F.5.1 + F.5p.2 — REPORTING the ladder is its own capability, not a facet of verification. It answers a
  // different question: not *is this valid for me*, but *what stands between it and the next rung, and whose is
  // that to move*. It is a function OF the decision relation and never an input to it (F.5.1b), so it can never
  // raise a verdict — which is why it is admissible as a capability at all.
  'ladder-report':      { core: ['explainLadder'], cli: 'cmd:explain', mcp: 'tool:ust_explain' },
  'stream-verify':      { core: ['verifyStream'], mcp: 'tool:ust_verify_stream', cli: 'cmd:stream' },
  'typed-evidence':     { core: ['verifiedEvidence', 'evidenceClass', 'evidenceCaps', 'compareEvidenceOrder', 'EVIDENCE_CAPS_UNIVERSE'], mcp: ['tool:ust_evidence_kind', 'tool:ust_evidence_record', 'tool:ust_evidence_order'] },   // #178 round 275 — the last asymmetry; `verifiedEvidence` GRANTS nothing (its output is not branded), so what travels with it is the facts-only refusal
  // M3 (UST-6vj C2) — provenance-bearing evidence: a SIGNED connector receipt verified against consumer-admitted
  // connectors is the ONLY way external facts reach a strong rung (closes the rc.35 round-2 verifiedEvidence-forge).
  'evidence-receipt':   { core: ['evidenceReceiptClaim', 'buildEvidenceReceipt', 'evidenceReceiptId', 'verifyEvidenceReceipt'] },
  'assurance-lattice':  { core: ['ASSURANCE_AXES', 'axisRank', 'assuranceState', 'assuranceLE', 'meetAssurance', 'joinAssurance', 'projectTier', 'TIER_RANK', 'capAssurance', 'deriveAssurance', 'provePredicates'] },
  // K3 (UST-znh) — the opaque-handle brand: consumers may TEST provenance (image-membership), never MINT it.
  'verified-handle':    { core: ['isVerifiedHandle'] },
  // K4 (UST-znh) — the ONE public authority entrypoint: raw inputs + config in, single verdict + derivation trace out.
  // K4 → Closed Proof Kernel: the ONE public authority verdict is prover ∘ check_C (reference-checker.mjs).
  'authority-bundle':   { core: ['verifyAuthorityBundle', 'buildAuthorityProof', 'checkAuthorityProof', 'checkAuthorityProofBytes'] },
  'checkpoint-chain':   { core: ['buildAuthorityCheckpoint', 'sealAuthorityCheckpoint', 'authorityCheckpointId', 'verifyAuthorityCheckpointChain', 'resolveCheckpointRoots', 'deriveCheckpointFreshness', 'verifiedGenesisContext', 'genesisEpoch', 'authorityScopeId'], cli: 'api:buildCeremony' },
  // §12.1 is 'recovery/supersession' — one section, one capability. witnessSuccessor BUILDS the successor witness
  // log when a name re-roots; witnessNoShrink is the rule it must satisfy, shared with any mirror that ingests it.
  'recovery':           { core: ['checkpointRecoveryClaim', 'buildRecoveryStatement', 'verifyCheckpointRecovery', 'witnessSuccessor', 'witnessNoShrink'] },
  'epoch-transition':   { core: ['epochTransitionClaim', 'buildEpochTransition', 'verifyEpochTransition', 'deriveStreamFloor'] },   // F.5s — the floor is read OFF the epoch chain, so it belongs to the capability that owns the chain, not to a second one
  'uniqueness-attest':  { core: ['checkpointUniquenessClaim', 'buildUniquenessAttestation', 'verifyCheckpointUniqueness'] },
  'verifiable-map':     { core: ['buildVerifiableMap', 'checkpointMapLeaf', 'nameMapLeaf', 'verifyCheckpointMapUniqueness', 'verifyActiveGenesisUniqueness', 'nameMapRootClaim', 'buildNameMapRoot', 'verifyNameMapRoot', 'proveMapRootAnchor'] },   // #42 — the ROOT half of the same capability: carrying, admitting and anchor-proving the root a map proof is checked against
  'keylog-commitment':  { core: ['keylogLeaf', 'buildKeylogCommitment', 'verifyKeylogTerminality'], cli: 'cmd:rotate', mcp: ['tool:ust_keylog_commitment', 'tool:ust_keylog_terminality'] },   // #178 round 272 — pure, key-free, and absent from the principal surface for no stated reason
  'cadence-grid':       { core: ['ustGrid', 'resolveCadence', 'resolveCadenceBytes'], mcp: 'tool:ust_resolve_cadence', cli: 'flag:cadence-log' },
  // Split OUT of build-transcript (2026-07-27): that capability bundles eight builders behind ONE representative probe
  // (`ust_build_observation`), so `buildCadenceEntry` having no surface at all read as full. A capability whose probe
  // cannot see its own members is the coarse-probe failure this file's own header warns about.
  'cadence-declare':    { core: ['buildCadenceEntry'], mcp: 'tool:ust_build_cadence', cli: 'cmd:cadence' },
  'substrate-registry': { core: ['combineSubstrates', 'combineInclusion'], cli: 'flag:require-anchored', mcp: 'arg:ust_verify.proof' },   // #95 — finality AND membership route by substrate name, one pattern
  'discovery-shard':    { core: ['isPublicDnsShard'], cli: 'cmd:discovery', mcp: 'tool:ust_shard_check' },   // #178 round 272 — the publisher's question BEFORE it publishes: is /.well-known the route to me at all
  // PRODUCE, and the name now says so. Its core set is three PRODUCERS, and the blanket reason that kept it `na`
  // everywhere — "a publisher-side act on data the tool never holds" — was true of CONSUMING a disclosure and
  // false of MAKING one: `encryptPartition` works on exactly the data a publisher does hold. One sentence covered
  // two operations, so the produce half stayed unowned until `ust sign` was written (#177). CONSUMPTION is not a
  // separate capability: it is `verify` with `disclosures`/`decKeys`, and it is scored there.
  'disclosure-produce': { core: ['blindedCommit', 'blindPartition', 'encryptPartition', 'sealingRequest', 'attachEncryption'], cli: 'cmd:sign', mcp: ['arg:ust_build_observation.data', 'tool:ust_sealing_request', 'tool:ust_attach_encryption'] },
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
  ROLE_CLASSES: 'the §12.2 class-set per operating role — the table `admits(k, c)` is evaluated against. Exported so a consumer and a second implementation READ the relation from source instead of re-typing it; it is a vocabulary the verifier consults, not an action a caller performs',
  PREV_ONLY_SUBTYPES: 'the §11.3 C2 subtype vocabulary, exported so the conformance corpus and any second implementation ENUMERATE it from source instead of re-typing three names; a vocabulary a verifier reads, not an action a consumer takes',
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
  REPO_URL: 'the contact address a labelled request carries (#43) — an attribute of this implementation, like VERSION, and not a protocol act; a second implementation would carry its own',
  userAgent: 'builds the wire label `ust/<wire> (<component>/<version>; +<repo>)`. It answers "who is calling", never a question about a document, so it decides no verdict and belongs to no capability',
  labelledFetch: 'wraps a transport so outbound calls carry that label. Deliberately NOT a capability: a capability cell claims a surface implements a protocol act, and every surface here would read `full` for something that changes no answer. The cross-surface agreement it does owe is held by `tools/user-agent-gate.mjs`, which reads each package version rather than accepting a stance',
};

// A connector exposes the substrate seam (verifyAnchor delegate + typed evidence emit), not core names.
// round-193 (measured 2026-08-10) — `substrate-registry` is TWO halves, and this probe accepted one as both.
// Its core set is `combineSubstrates` (finality) AND `combineInclusion` (membership); the comment beside it says so:
// "finality AND membership route by substrate name". The probe asked only for `substrateVerify`, so `ust-ots-verify`
// — which has no `inclusionVerify` at all — was certified `full` on a capability it implements half of. Green with
// nothing behind the other half, which is the shape round-51 introduced this predicate to stop ("`full` ⇒ every").
// CLOSED 2026-08-10 (round 194): the probe splits the halves and ots-verify declares the membership half `na` with a
// physical reason — an OTS proof shows a root existed by a time, never that a leaf is in it.
const connector = (X) => (cap) => {
  if (!['anchor-verify', 'typed-evidence', 'substrate-registry'].includes(cap)) return false;
  const finality = typeof X.substrateVerify !== 'undefined' && typeof X.toVerifiedEvidence === 'function';
  if (cap !== 'substrate-registry') return finality;
  return finality && typeof X.inclusionVerify === 'function';   // membership half — absent in a finality-only connector
};
// round-51 P1-03 (owner: set-COMPLETE predicate, not `some`) — a `full` stance means EVERY core export of the capability is
// exposed; `some`-intersection wrongly certified a surface as full when it had ONE of many (GPT round-51: lite declared full for
// build-transcript with only buildState, missing buildAttestation/…). `full` ⇒ every; a genuine reduced surface declares `subset`.
const exportIntersect = (X) => (cap, stance) => (stance === 'full' ? CAPS[cap].core.every((n) => n in X) : CAPS[cap].core.some((n) => n in X));
// round-246 — THE PROBE MUST ASK THE SURFACE, NOT THE SOURCE TEXT.
//
// Measured 2026-08-31 (#177) — CLOSED 2026-08-31 by the typed tokens below and their controls: `cliProbe` was
// `cliSrc.includes(tok)` and `mcpProbe` fell back to `mcpSrc.includes(tok)`.
// A substring of the implementation file certified a capability as exposed. So `ust-cli` was declared **full** for
// `sign` (token `seal`, 18 occurrences — every one inside a ceremony: genesis signs itself, rotation builds a probe
// document to prove the new key works) and for `build-transcript` (token `buildState`, twice, same place). The user
// has no command that signs a document at all. Two false declarations, and the mechanism is that the probe could not
// tell a USER-FACING surface from internal code that happens to mention the same word.
//
// A token now DECLARES which surface it belongs to, and the probe checks that surface and nothing else:
//   cmd:<name>   a command in the CLI's dispatch table — what a user types
//   flag:<name>  an option the argument parser actually reads
//   api:<name>   an export of the package — a caller's surface, not a terminal user's
//   tool:<name>  an MCP tool the server registers
//   arg:<tool>.<name>  an input property of that tool's schema
// A token that names none of these resolves to false, so a typo cannot pass as a capability.
//
// And the predicate matches `exportIntersect`, which round-51 already fixed for the library surfaces: `full` ⇒ EVERY
// token present, `subset` ⇒ some. Listing one token where a capability has nine parts is how `full` came to mean
// "there is at least one of these" on the two surfaces whose probe was never given the same treatment.
const CLI_CMDS = new Set((cliSrc.match(/const run = \{([^}]*)\}/) || [, ''])[1].split(',').map((x) => x.trim().split(':')[0]).filter(Boolean));
const CLI_FLAGS = new Set([...cliSrc.matchAll(/\barg\(\s*['"`]([a-z0-9-]+)['"`]/g)].map((m) => m[1]));
const CLI_EXPORTS = new Set([...cliSrc.matchAll(/export (?:async )?(?:function|const) (\w+)/g)].map((m) => m[1]));
const MCP_TOOL_ARGS = (() => {
  const out = new Map();
  for (const m of mcpSrc.matchAll(/name: '(ust_[a-z_]+)'/g)) {
    const seg = mcpSrc.slice(m.index, mcpSrc.indexOf('handler:', m.index));
    out.set(m[1], new Set([...seg.matchAll(/(\w+): \{ type:/g)].map((x) => x[1])));
  }
  return out;
})();
const resolves = (tok) => {
  const [what, rest] = String(tok).split(':');
  if (what === 'cmd') return CLI_CMDS.has(rest);
  if (what === 'flag') return CLI_FLAGS.has(rest);
  if (what === 'api') return CLI_EXPORTS.has(rest);
  if (what === 'tool') return mcpTools.has(rest);
  if (what === 'arg') { const [tool, prop] = String(rest).split('.'); return !!MCP_TOOL_ARGS.get(tool)?.has(prop); }
  return false;                                                    // an unrecognised form is NOT a pass
};
// round-267 — A TOKEN NAMED THE RIGHT SURFACE AND THE WRONG CAPABILITY, and `resolves` cannot see the difference.
//
// Measured 2026-09-03 (#178) — CLOSED 2026-09-03 by `exercises` below. `discovery-shard` declared `cmd:discovery`. The token
// RESOLVES: `ust discovery` is a real command in the dispatch table. The command never called `isPublicDnsShard`,
// the one export the capability is made of — it built `https://${domain}/…` from argv and fetched. So the grid
// reported the capability present on the CLI for two months on the strength of a command that does not perform it.
//
// Why that is worse than an ordinary miscount: the ORDERING axis (#178) measures the human/agent inversion THROUGH
// these tokens. A token that resolves while doing nothing is FALSE PRESENCE on the human side, and a real inversion
// then reads as a two-sided absence — the quietest cell on the grid, the one nobody audits. Round 266 found exactly
// that shape hiding `ladder-report` for 129 rounds. One idle token can manufacture it.
//
// THE RULE IS PER TOKEN KIND, and the distinction is not decoration:
//   cmd: / tool:  the surface PERFORMS the capability ⇒ it must CALL one of the capability's core exports.
//   flag: / arg:  the surface FEEDS the capability into another core call ⇒ the value is consumed inside the core
//                 and no direct call exists or should. `--trust-root` reaches `quorumTrustDomains` through
//                 `P.verify`; demanding a direct call here would be demanding the surface duplicate the core.
//   api:          the export IS the surface.
//
// That split was MEASURED, not assumed, and it is the correction of my own first probe: requiring a direct call of
// every kind flagged SIX declarations, and five were my harness being wrong — `no-fork-evidence`, `consumer-trust-root`
// and `anchor-verify` all forward their flag into `P.resolveAuthority`/`P.verify` opts, which is the honest shape for
// a consumer faculty. Reading only the first result would have "fixed" three correct declarations.
//
// Domain, not sample: all 25 cmd/tool declarations across both surfaces are checked, and exactly one was idle.
// The probe reads CODE, never prose. Without this it would repeat the defect it exists to catch one level up: a
// file that DISCUSSES `P.isPublicDnsShard` in a comment would certify the command as performing it, which is the
// mention-for-use substitution that made `cliSrc.includes(tok)` wrong in round 246. Full-line and block comments
// are dropped; a trailing `//` is left alone because a line's code precedes it.
const codeOf = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
const CODE = { cli: codeOf(cliSrc), mcp: codeOf(mcpSrc) };
const exercisesCore = (which, core) => core.some((fn) => new RegExp('P\\.' + fn + '\\b').test(CODE[which]));
const exercises = (which) => (cap) => exercisesCore(which, CAPS[cap].core);
const tokenProbe = (which) => (cap, stance) => {
  const toks = [].concat(CAPS[cap][which] ?? []);
  if (!toks.length) return false;
  const acts = toks.filter((t) => t.startsWith('cmd:') || t.startsWith('tool:'));
  if (acts.length && !exercises(which)(cap)) return false;          // the surface names the act and does not perform it
  return stance === 'full' ? toks.every(resolves) : toks.some(resolves);
};
const mcpProbe = tokenProbe('mcp');
const cliProbe = tokenProbe('cli');

// ── THE AGENT SURFACE IS THE PRINCIPAL ONE, so its absences are classified rather than merely reasoned (#178).
//
// Owner, 2026-09-02: the agent is not a first-class publisher among others — it is the protocol's principal
// audience. A human at a terminal has a shell, a filesystem and the package; when a tool lacks something they
// write six lines. An agent has EXACTLY what is exposed as a tool. So the same absence is an inconvenience on
// one surface and a wall on the other, and the two may not be recorded in the same words.
//
// THE TEST, and it is the owner's: **would this still need a human if we trusted the agent completely?**
//   YES ⇒ `deferred` — the requirement is a property of the ACT, not a restriction we impose. Minting an
//         identity, rotating a root key, re-rooting a chain: no amount of trust removes the person, because the
//         act IS a human decision. A deferred cell owes a claim about the act, checkable by reading it.
//   NO  ⇒ `lagging` — our own unfinished work, sitting where the principal audience reaches for it. It owes NO
//         justification, because none exists. It is counted, and the count may only shrink.
//
// Writing a rationale under a `lagging` cell is the defect this whole classification exists to stop: absence
// wearing the vocabulary of intent, which is how `disclosure-produce` sat unowned for two months behind a
// sentence that defended a risk that was not present.
// THREE classifications, not two (owner, 2026-09-03: "человек" is wider than "signs" — merging them would sew
// distinct things together, and we would lose the difference later).
//
// The two-way split of round 256 was wrong twice over, and the measurement says how:
//   · every genuinely key-bound function in the six I called `deferred` SIGNS — `sealAuthorityCheckpoint`,
//     `buildRecoveryStatement`, `buildEpochTransition`, `buildUniquenessAttestation`, `buildNameMapRoot`;
//   · `keylog-commitment` has NO key-bound function at all — all three of its exports only compute;
//   · and NONE of those eight functions is called by the CLI either. They are not a human-first inversion; they
//     are exposed by no surface at all.
// So a capability can be absent from the agent surface for three unrelated reasons, and one word for all three
// hides which. The three obligations differ, and that difference is the point:
//
//   'ceremony'  — the act is a HUMAN DECISION and stays one however much an agent is trusted. This is a property
//                 of an operator WORKFLOW (the CLI carries 34 interactive prompts), never of a core function:
//                 `buildAuthorityCheckpoint` computes an artifact, and what needs a person is deciding to stand
//                 behind it. Owes a claim about the act. PERMANENT.
//   'key-bound' — the function SIGNS, and a private key may not cross into an agent's context. NOT a wall: the
//                 split (rounds 258, 261) is how an agent participates — it produces what is signed and assembles
//                 what comes back. Owes the signing function's name. SOLVED SHAPE.
//   'lagging'   — nobody built the surface. Owes NOTHING but its place in the count, because a justification
//                 written under debt is absence wearing the vocabulary of intent. DEBT.
const MCP_DISPOSITION = {
  // TEN ENTRIES LEFT THIS REGISTER in round 274, and none was reclassified in STATUS. Each is on NO surface at
  // all, so the ordering relation has no second term for it: `STANCE` answers why it is nowhere, and
  // `ACKNOWLEDGED_MIXED` answers what a split capability's halves are. What remains here is the ASYMMETRY —
  // a capability some non-core surface has while the agent does not — which is the only shape the rule speaks
  // about. `recovery`, `epoch-transition`, `uniqueness-attest` and `verifiable-map` kept their key-bound
  // arguments in ACKNOWLEDGED_MIXED, where the halves were already written out.
  // ── key-bound: the signing half stays outside; the agent reaches the rest through the split
  // `sign` and `disclosure-produce` LEFT this register in round 270. They are not absences: the splits of rounds
  // 258 and 261 put `attachSignature`, `sealingRequest` and `attachEncryption` on the agent surface, so `ust-mcp`
  // scores SUBSET for both. What their halves are is recorded in ACKNOWLEDGED_MIXED, which is where a capability
  // split on key-taking belongs; a disposition would say the agent lacks something it has.
  'checkpoint-chain':   ['key-bound', 'sealAuthorityCheckpoint signs; its eight other functions only compute. The computing half is LAGGING and is counted as such below — this entry names only why the signing one is out.'],

  // ── ceremony: nothing here yet, and that is a finding rather than an omission. Ceremony is a property of a
  // WORKFLOW — `ust genesis`, `ust reroot` walk an operator through DNS, publication and confirmation — and the
  // capability map is over core FUNCTIONS, which compute artifacts that are inert until someone signs them.

  // ── lagging: debt, and nothing is written under any of them
};
const PINNED_LAGGING = 0;   // 1 → 0 (round 275): the ordering axis is CLEAR. Every capability another surface exposes is on the agent surface too — the rule still binds for whatever arrives next, and the register now reports an empty domain as the goal rather than failing on it   // 7 → 1 (round 274): NOT progress. The counter stopped counting ten capabilities NOBODY exposes, for which the ordering relation was never defined — six of them held substantive STANCE reasons, two saying a surface would be a security hole   // 8 → 7 (round 273): `byte-agreement` reached the agent surface WITH its refusals — a surface that softened F.5o would let a publisher's own independence claim ride into a consumer's reasoning   // 10 → 8 (round 272): `keylog-commitment` and `discovery-shard` reached the agent surface. Every function of both is PURE — no key, no filesystem, no network — which is what `lagging` means: nobody decided against them, nobody built them   // 11 → 10 (round 271): `name-obligation` reached the agent surface as `ust_name_report`. Paid, not reclassified — the register it left is the one that owes no justification   // 12 → 13 (round 262): `keylog-commitment` moved OUT of a false deferral into debt — none of its three functions takes a key or asks a person, so the claim that kept it out was never true of it   // 14 → 13 (round 257, `disclosure-produce`) → 12 (round 258, `sign`: the ASSEMBLY half reached the agent surface, and the signing half stays outside because a key in an argument list is a claim about the ACT, not about agents)

// ── SURFACES — each surface's DECLARED stance. `full` = exposes the capability; `subset` = a documented reduced form;
//    everything else defaults to `na` with the surface's `naReason` (a specific override lives in `naSpecific`). This
//    encodes the owner's decisions: cli grows to full authoritative; mcp stays agent-facing (operator caps na).
const SURFACES = {
  // #178 (owner, 2026-09-03): the columns are ORDERED, and the order is an argument. The core comes first because
  // it says what EXISTS; `ust-mcp` next because the agent is the principal audience and a reader should meet its
  // row before the human one; `ust-cli` after it; then the standalone packages; then the connectors LAST, because
  // their number grows and a growing family at the front would push the surfaces that matter off the eye.
  //
  // `ust-protocol` is itself a column now. Without it the grid showed six exposures of a set nobody could see,
  // and `ust-rfc6962-verify` — a real published package — was in no column at all.
  'ust-protocol':     { probe: exportIntersect(P), full: Object.keys(CAPS), subset: [], naReason: 'the reference implementation defines the capability set; a cell that is not full here means the capability names an export the core does not have, which the PHANTOM check already refuses' },
  'ust-mcp':          { probe: mcpProbe, full: ['canon', 'content-address', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'fork-choice', 'stream-verify', 'cadence-grid', 'cadence-declare', 'substrate-registry', 'ladder-report', 'name-obligation', 'keylog-commitment', 'discovery-shard', 'byte-agreement', 'typed-evidence'], subset: ['build-transcript', 'disclosure-produce', 'sign'], naReason: 'deferred to the planned operator MCP over @ust-protocol/operator (privilege-separation: a human explicitly grants agent rights) — NOT core+CLI-forever; TOP-produce is the one agent touch still to be built for noosphere', naSpecific: { 'sign': 'the agent signs with its OWN key; build tools return signing_input, the MCP never holds a private key', 'negative-observation': 'agent-appropriate (a normal negative observation, NOT operator) — new per #39; an MCP absence verb is planned, not yet built' } },
  'ust-cli':          { probe: cliProbe, full: ['canon', 'content-address', 'verify', 'resolve-authority', 'no-fork-evidence', 'consumer-trust-root', 'anchor-verify', 'stream-verify', 'checkpoint-chain', 'keylog-commitment', 'discovery-shard', 'cadence-grid', 'cadence-declare', 'byte-agreement', 'name-obligation', 'sign', 'disclosure-produce', 'ladder-report', 'substrate-registry'], subset: ['build-transcript'], naReason: 'not exposed by the reference operator CLI', naSpecific: { 'negative-observation': 'new per #39; a `ust absence` command is planned, not yet built', 'build-transcript': 'CLOSED 2026-09-02 by `ust sign` (#177) — but SUBSET, not full: this surface builds a STATE (`ust sign`) and a genesis/key-log (the ceremonies), and nothing here builds an attestation, a derivation, a checkpoint, a gap or an anchor commitment. Declaring full would be the same overclaim round 246 removed, one command later.' } },
  'ust-light':         { probe: exportIntersect(LITE), full: ['canon'], subset: ['content-address', 'build-transcript', 'verify', 'disclosure-produce', 'sign'], naReason: 'outside the standalone zero-dependency LIGHT floor — lite is a documented SUBSET (round-51 P1-03: build-transcript = buildState/seal for class:observation, WITH provenance (prev/based_on+seed) since UST-jls, but not the full builder family; verify = the WHOLE LIGHT floor including every §14a provenance obligation — UST-jls closed 14 lite-VALID/core-INVALID shapes — but not the HIGH/TOP verifiers; content-address = the partition/content/seed hashes it needs)' },
  'ust-web-signer':   { probe: exportIntersect(WEB), full: ['canon'], subset: ['content-address', 'build-transcript', 'sign'], naReason: 'producer-only surface — a documented SUBSET (round-51 P1-03: browser signer builds+signs a state, not the full builder family)', naSpecific: { 'verify': 'by design: the private key never enters a verifier — verification is ust-protocol / ust-light (README)' } },
  // Agent MCP TARGET (owner, 2026-07-15) = full for EVERY non-operator capability + the single conditionally-operator
  // touch: reaching TOP (mint/attach an anchor), planned for noosphere, not yet built. `na` here means the capability
  // is deferred to the PLANNED operator MCP over @ust-protocol/operator (key creation, checkpoint/recovery/epoch/uniqueness/map
  // ceremonies) so a human explicitly grants agent rights — NOT 'stays core+CLI forever'. NOTE: no-fork-evidence /
  // anchor-verify are marked full on the CONSUME side; a produce/consume axis split is the honest refinement (UST-<top>).
  'ust-ots-verify':   { probe: connector(OTS), full: ['anchor-verify', 'typed-evidence'], subset: [], naReason: 'CLOSED 2026-08-10 (round 194). substrate-registry is NA here, not subset: its core set is combineSubstrates (finality) AND combineInclusion (membership), and this connector implements finality only — it has no inclusionVerify, because an OTS timestamp proves a root existed by a time, never that a leaf is in that root. Rekor carries the membership half. Measured 2026-08-10, round 193. Originally: a Bitcoin/OTS substrate connector (plugs into verifyAnchor via substrateVerify), not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts (buildEvidenceReceipt with its own key) instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  'ust-rekor-verify': { probe: connector(REKOR), full: ['anchor-verify', 'typed-evidence', 'substrate-registry'], subset: [], naReason: 'a Rekor transparency-log substrate connector, not a general surface', naSpecific: { 'evidence-receipt': 'THE connector job per M3 — emit signed receipts instead of raw verifiedEvidence facts; planned follow-up, tracked under UST-6vj C4/legacy' } },
  'ust-rfc6962-verify': { probe: connector(RFC), full: [], subset: [], naReason: 'an RFC 6962 inclusion verifier — it answers membership in a Merkle tree and nothing else, so it carries the `substrate-registry` membership half through `inclusionVerify` and no protocol capability of its own' },
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

// CONTROLS for the token probe — it must be able to say NO, and it must not accept a mention. Proven here rather
// than asserted in the comment above, because the defect this replaces was a probe that could only say yes.
{
  const ghost = [
    ['cmd:thisCommandCannotExist', 'a command not in the dispatch table'],
    ['flag:this-flag-cannot-exist', 'a flag the parser never reads'],
    ['api:thisExportCannotExist', 'an export the package does not have'],
    ['tool:ust_this_tool_cannot_exist', 'an MCP tool that is not registered'],
    ['arg:ust_verify.thisPropertyCannotExist', 'an input property the schema lacks'],
    ['seal', 'a BARE name — the old substring form, which must no longer resolve at all'],
    ['buildState', 'the other bare name that produced a false `full` for two years of cells'],
  ];
  for (const [tok, why] of ghost) {
    if (resolves(tok)) { fail++; report.push(`  ✗ CONTROL: the token probe accepted ${tok} — ${why}`); }
  }
  // …and it must still say YES to each real form, or every cell above passes for a different wrong reason.
  const real = ['cmd:verify', 'flag:genesis', 'api:buildCeremony', 'tool:ust_verify', 'arg:ust_verify.disclosures'];
  for (const tok of real) if (!resolves(tok)) { fail++; report.push(`  ✗ CONTROL: the token probe rejected ${tok}, which IS present — the surfaces were parsed wrong`); }
  // …and the EXERCISE half, which is the round-267 addition: a command that names an act it does not perform must
  // be refused, and prose must not stand in for the act. Both directions, because a detector that can only say yes
  // is what let `cmd:discovery` certify a capability the command never called.
  if (exercisesCore('cli', ['thisCoreExportCannotExist'])) { fail++; report.push('  ✗ CONTROL: the exercise probe accepted a core name that does not exist — an idle declaration would pass'); }
  if (exercisesCore('cli', ['keyId']) === false) { fail++; report.push('  ✗ CONTROL: the exercise probe missed a call the CLI plainly makes — the source was parsed wrong'); }
  // Fed a REAL input rather than asserted against an impossible literal, which would pass for free (vacuity).
  if (/P\.x\b/.test(codeOf('// P.x is discussed here\n/* and P.x here */\nconst y = 1;'))) { fail++; report.push('  ✗ CONTROL: comment text survives into the code view — prose about a call would certify the act'); }
  if (!/P\.x\b/.test(codeOf('const z = P.x(1);   // trailing prose'))) { fail++; report.push('  ✗ CONTROL: the code view dropped a real call — every exercise verdict below is unfounded'); }
  if (!fail) report.push(`  ✓ CONTROL: the probe resolves each surface form and refuses ${ghost.length} tokens that name nothing, and a cmd/tool token must be EXERCISED — prose about a call is not a call`);
}

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

// Reads the PARAMETER LIST, not the first line. Measured 2026-09-03 (#178), CLOSED 2026-09-03 by this form: the first-line version counted
// `checkpointMapLeaf` and `nameMapLeaf` as key-bound because an arrow function's BODY is on that line and both
// RETURN `{ key: … }` — a map key, not key material. A probe that cannot tell what a function takes from what it
// returns inflates the very set this axis exists to bound.
const takesKey = (fn) => {
  const f = P[fn];
  if (typeof f !== 'function') return false;
  const src = f.toString();
  const open = src.indexOf('('), close = (() => { let d = 0; for (let i = open; i < src.length; i++) { if (src[i] === '(') d++; else if (src[i] === ')' && --d === 0) return i; } return -1; })();
  const params = (open < 0 || close < 0 ? '' : src.slice(open + 1, close)).replace(/key_id/g, '');   // key_id is a NAME
  return /\bkey\b|\bpriv|privKeyObj|decKeys/.test(params);
};

// (4) THE ORDERING AXIS (#178) — every absence on the PRINCIPAL surface is classified, and the debt may only shrink.
//
// ITS DOMAIN IS THE ASYMMETRY, and for four rounds it was not. The rule is the owner's and it is a relation
// between two surfaces: *any capability the protocol gives a publisher appears on the agent surface NOT LATER
// THAN ON THE HUMAN ONE*. A capability NOBODY exposes has no second term — the relation is not false for it, it
// is undefined, and asking it there is a domain error rather than a strict reading.
//
// Measured 2026-09-03, CLOSED 2026-09-03 (#178), and the measurement is what decides that this is structural
// rather than a convenient re-slice: `STANCE` is wholly CONTAINED in `MCP_DISPOSITION` — every one of its ten
// zero-surface entries also carried a disposition, while genuine asymmetries numbered TWO. A containment is not
// an overlap. One register's question was being asked across the whole of another's domain, systematically.
//
// What that cost: six capabilities counted as `lagging` — debt, which by this register's own rule owes NO
// justification — while STANCE held substantive reasons for each. Two of those reasons say a surface would be a
// SECURITY HOLE (`assurance-lattice`: a caller assembling a tuple directly is the forgery oracle round 25 closed
// at the type level; `verified-handle`: exposing the brand IS the vulnerability). The register's rule is that a
// justification under debt is ABSENCE WEARING THE VOCABULARY OF INTENT. This was the inverse — intent wearing the
// vocabulary of debt — and the number, driven down for four rounds, was pointing at two tools nobody may build.
//
// NOTHING IS RECLASSIFIED IN STATUS. The ten leave a register whose question does not apply to them and stay in
// the ones that answer them: `STANCE` for why they are on no surface, `ACKNOWLEDGED_MIXED` for what a split
// capability's halves are. The debt count falls 7 → 1 because the counter stopped counting what it never
// measured, which is a correction and NOT progress.
{
  // A surface holding EVERY capability cannot witness exposure (the same tautology the STANCE leg excludes).
  const capTotal = capIds.length;
  const witnessSurfaces = surfaceIds.filter((sf) => sf !== 'ust-mcp' && capIds.filter((c) => stanceOf(sf, c) !== 'na').length < capTotal);
  const exposedElsewhere = new Set(witnessSurfaces.flatMap((sf) => capIds.filter((c) => stanceOf(sf, c) !== 'na')));
  const mcpNa = capIds.filter((c) => stanceOf('ust-mcp', c) === 'na' && exposedElsewhere.has(c));
  const nowhere = capIds.filter((c) => stanceOf('ust-mcp', c) === 'na' && !exposedElsewhere.has(c));

  // THE TWO REGISTERS ANSWER DIFFERENT QUESTIONS AND MUST NOT OVERLAP. Round 270 found this shape for ONE
  // capability (`name-obligation`: a stance calling the agent absence deliberate while ORDERING called it debt),
  // fixed that instance, and did not enumerate the domain — which is the rule this file states about gates and
  // which its own author then broke one round later. Both directions, so neither register can absorb the other.
  const inBoth = Object.keys(MCP_DISPOSITION).filter((c) => STANCE[c]);
  if (inBoth.length) { fail++; report.push(`  ✗ ORDERING: [${inBoth.join(', ')}] are answered by BOTH registers — STANCE says why a capability is on no surface, ORDERING why the AGENT lacks one the human has, and a capability nobody exposes has no ordering to be judged by`); }
  // The OTHER half of the partition — every capability on no surface carries a stance — is already the STANCE
  // leg's own `missing` check, over the same set computed the same way. Adding it here would be a second
  // derivation of one set, which is the defect this file spent four rounds removing from elsewhere. Named rather
  // than duplicated: narrowing this axis drops nothing, because that leg still covers `nowhere` entirely.
  void nowhere;
  // AN EMPTY DOMAIN HAS TWO CAUSES AND THEY ARE OPPOSITE. This leg was written in round 274 to stop a green
  // standing over an empty set — and as written it fired at the moment the axis SUCCEEDS, because paying the last
  // asymmetry is exactly what empties the domain. Third time in three rounds that a guard of mine turned red on
  // its own success (round 273's control naming its subject, round 274's generator demanding a non-empty debt).
  // The distinction it actually needs: empty because the agent surface now holds everything another surface
  // holds, or empty because the surfaces could not be read at all.
  if (!exposedElsewhere.size) { fail++; report.push('  ✗ ORDERING: NO capability is exposed by any non-core surface — the surface declarations could not be read, and an empty asymmetry domain here means a broken parse, not a paid debt'); }
  else if (!mcpNa.length) report.push(`  ✓ ORDERING: the asymmetry domain is EMPTY and that is the goal — every one of the ${exposedElsewhere.size} capability(ies) another surface exposes is on the agent surface too. The rule still binds: whichever surface receives the next one first, the agent surface may not be later`);

  const undecided = mcpNa.filter((c) => !MCP_DISPOSITION[c]);
  if (undecided.length) { fail++; report.push(`  ✗ ORDERING: ${undecided.length} capability(ies) absent from the agent surface with NO disposition: [${undecided.join(', ')}] — an unclassified absence is how one sat unowned behind a sentence that defended a risk that was not present (#177)`); }

  // THE OTHER DIRECTION, and it was missing for two rounds. A disposition CLASSIFIES AN ABSENCE. When the split
  // put `attachSignature` and `sealingRequest`/`attachEncryption` on the agent surface (rounds 258, 261) the
  // absences ended — and the entries recording them kept standing, still counted as current. Their own texts said
  // so outright ("`ust-mcp` scores subset here, not na"), so each had become a historical note without ceasing to
  // be a classification, and nothing asked whether the subject of a classification still existed.
  //
  // Measured 2026-09-03, CLOSED 2026-09-03 (#178): the register held 18 entries and only 16 were absences, so the
  // gate printed 5 key-bound (it filters by `mcpNa`) while SUPPORT.md printed 7 (it reads the register). TWO COUNTS
  // OF ONE SET, disagreeing in public, under a heading that says every absence is classified. With this leg the two
  // derivations are equal as SETS and any consumer may read either — which is what makes the generator's unfiltered
  // read correct rather than lucky. The history is not lost: `ACKNOWLEDGED_MIXED` is where a split capability
  // belongs, and it already carried both, with the rounds.
  const overPresence = Object.keys(MCP_DISPOSITION).filter((c) => !mcpNa.includes(c));
  if (overPresence.length) { fail++; report.push(`  ✗ ORDERING: ${overPresence.length} disposition(s) classify an absence the agent surface no longer has: [${overPresence.join(', ')}] — a capability that ARRIVED leaves the register; its halves are recorded in ACKNOWLEDGED_MIXED, and a classification laid over presence is stale by construction`); }

  // A `deferred` cell owes a CLAIM ABOUT THE ACT; a `lagging` cell owes nothing but the count. Enforcing the
  // reason on `deferred` only is the point: requiring one on `lagging` would invite exactly the rationalisation
  // this classification exists to stop.
  const KINDS = ['ceremony', 'key-bound', 'lagging'];
  const wrongKind = mcpNa.filter((c) => MCP_DISPOSITION[c] && !KINDS.includes(MCP_DISPOSITION[c][0]));
  if (wrongKind.length) { fail++; report.push(`  ✗ ORDERING: unknown classification on [${wrongKind.join(', ')}] — the three are ${KINDS.join(' / ')}, and a fourth word would be a category nobody agreed to`); }
  // `ceremony` and `key-bound` each owe an argument; they differ in WHAT they argue, and both are checked for
  // presence rather than for truth. `lagging` owes nothing — see below.
  const thin = mcpNa.filter((c) => ['ceremony', 'key-bound'].includes(MCP_DISPOSITION[c]?.[0]) && String(MCP_DISPOSITION[c][1] ?? '').trim().length < MIN_REASON);
  if (thin.length) { fail++; report.push(`  ✗ ORDERING: ${thin.join(', ')} classified without an argument (under ${MIN_REASON} chars) — "it needs a human" and "it holds a key" are conclusions, not arguments`); }
  // A `key-bound` claim is REFUTABLE by measurement, and refuting it is the whole reason this classification is
  // separate: if no function of the capability signs, the claim is about something that is not there.
  // The predicate is TAKES KEY MATERIAL, not "signs" — and the distinction cost two false readings in one probe.
  // A first version matched `sign(`, which also matches `Object.assign(`, so `byte-agreement` would have passed a
  // key-bound claim it has no basis for. And it refuted `disclosure-produce`, whose hazard is a SYMMETRIC key:
  // `encryptPartition` seals with AEAD and signs nothing. One word over two mechanisms, in the detector written
  // to catch exactly that — the third time today. `takesKey` reads the parameter list and covers both.
  const unfounded = mcpNa.filter((c) => MCP_DISPOSITION[c]?.[0] === 'key-bound' && !(CAPS[c]?.core ?? []).some(takesKey));
  if (unfounded.length) { fail++; report.push(`  ✗ ORDERING: [${unfounded.join(', ')}] claim key-bound and NO function of theirs signs — that is how \`keylog-commitment\` sat outside on a claim about a key it never touches`); }
  const rationalised = mcpNa.filter((c) => MCP_DISPOSITION[c]?.[0] === 'lagging' && MCP_DISPOSITION[c].length > 1);
  if (rationalised.length) { fail++; report.push(`  ✗ ORDERING: a LAGGING cell carries a justification: ${rationalised.join(', ')} — debt owes a date, never a reason; a reason here is absence wearing the vocabulary of intent`); }

  const lagging = mcpNa.filter((c) => MCP_DISPOSITION[c]?.[0] === 'lagging');
  const inverted = lagging.filter((c) => stanceOf('ust-cli', c) !== 'na');
  if (lagging.length > PINNED_LAGGING) { fail++; report.push(`  ✗ ORDERING: the agent surface fell FURTHER behind — ${lagging.length} lagging capabilities, pinned at ${PINNED_LAGGING}. A capability reaching the human surface first is the rule this axis exists to hold: not "parity eventually", but "no wider than today"`); }
  else if (lagging.length < PINNED_LAGGING) { fail++; report.push(`  ✗ ORDERING: the debt SHRANK to ${lagging.length} (pinned ${PINNED_LAGGING}) — lower the pin in the same commit, so the improvement is recorded rather than absorbed`); }
  else { const cer = mcpNa.filter((c) => MCP_DISPOSITION[c]?.[0] === 'ceremony').length, kb = mcpNa.filter((c) => MCP_DISPOSITION[c]?.[0] === 'key-bound').length;
    report.push(`  ✓ ORDERING: every absence on the agent surface is classified — ${cer} ceremony (a human decision, permanent), ${kb} key-bound (the signing half only; the split is how an agent takes part), ${lagging.length} lagging (debt, pinned, ${inverted.length} of them reachable from the CLI today)`); }

  // CONTROL — the classifier must be able to say NO in both registers, proven rather than asserted.
  const probe = { ...MCP_DISPOSITION, __ghost: ['lagging'] };
  if (!Object.keys(probe).filter((c) => probe[c][0] === 'lagging').includes('__ghost')) { fail++; report.push('  ✗ CONTROL: the lagging counter cannot see a new entry — the ratchet would never trip'); }
  if (MCP_DISPOSITION['checkpoint-chain']?.[0] !== 'key-bound') { fail++; report.push('  ✗ CONTROL: the signing capability is not classified key-bound — the registers have collapsed'); }
  // THE CONTROL NAMED AN INSTANCE AND THE INSTANCE GOT PAID. It read `MCP_DISPOSITION['byte-agreement'] ===
  // 'lagging'`, so round 273 — which put byte-agreement ON the agent surface, exactly what the register exists to
  // encourage — turned the control red. A check pinned to a literal defends the defect it was written against and
  // fails at the moment it succeeds. Stated as a PROPERTY instead, it now covers every pure capability rather than
  // the one I happened to be looking at, and it survives being satisfied.
  const pureAbsent = mcpNa.filter((c) => (CAPS[c]?.core ?? []).length && CAPS[c].core.every((n) => !takesKey(n)));
  const misdressed = pureAbsent.filter((c) => MCP_DISPOSITION[c]?.[0] !== 'lagging');
  if (misdressed.length) { fail++; report.push(`  ✗ CONTROL: [${misdressed.join(', ')}] hold no key material and are absent from the agent surface, yet are not classified lagging — debt dressed as a boundary`); }
  // …and the domain is REPORTED, because a control over an empty set passes for free and reads as coverage. When
  // the debt is finally cleared this line will say 0, which is a fact worth seeing rather than a silence.
  else report.push(`  ✓ CONTROL: all ${pureAbsent.length} key-free capability(ies) absent from the agent surface are classified lagging — no debt is wearing the vocabulary of a boundary`);
}

// (5) A CAPABILITY WHOSE PARTS SPLIT ON KEY-TAKING MUST BE ACKNOWLEDGED AS TWO (#178, owner 2026-09-02).
//
// The owner proposed a gate asking "is the hazard even present on this surface?". Measured before building it:
// that question PASSES the defect it was aimed at — `ust_verify` has carried `decKeys` since round 247, so
// "key material does not belong in an agent's argument list" is TRUE of the MCP interface today, and it was still
// the wrong reason for `disclosure-produce`.
//
// My first replacement scanned reasons for a hazard word and required every core function to carry that hazard.
// It fired on `verify` at `ust-web-signer` — "the private key never enters a verifier" — where the hazard is a
// descriptive aside, not the justification. That version read a WORD as an INTENT, which is precisely the error
// it was written to catch. Prose cannot be judged here honestly, so this axis judges no prose at all.
//
// THE RULE, stated because a mechanism is not a rule: **a capability whose name is a VERB is worth splitting
// before it is scored — a surface not owed all of it may still owe part.** A stance is placed on a NAME, so when
// one verb covers two operations with different access costs, any reason about the expensive half silently
// withholds the cheap one, and the reason reads as true because it IS true — just not of everything it covers.
//
// WHAT THIS AXIS MECHANISES, AND WHAT IT DOES NOT. It knows ONE split axis: key-taking. That catches
// `disclosure-produce` and `sign`, and it does NOT catch `build-transcript`, whose nine functions are all
// key-free and which split on a different axis entirely — what a human ceremony owns. The rule is broader than
// its detector, and pretending otherwise would be the third version of the same mistake in one round.
//
// THE STRUCTURAL FACT INSTEAD. Partition a capability's core functions by whether they take key material. If both
// halves are non-empty the capability is MIXED — one name over two operations, only one of which is key-bound —
// and every recorded instance of this repository's most repeated surface defect has that shape:
//   `disclosure-produce`  blindedCommit·blindPartition (no key) + encryptPartition (key)   → two months unowned
//   `sign`                attachSignature (no key)   + seal (key)                          → agents publishing off-surface
//   `build-transcript`    buildState (no key)        + ceremonies                          → declared full on a substring
// A mixed capability scored `na` withholds its key-free half on the strength of the other's risk, whatever the
// reason says. So the set of mixed capabilities is PINNED: a new one fails the build until it is split, or
// acknowledged here with what its halves are.
// Seven, not the two I knew about — and FIVE of them are capabilities I classified `deferred` in round 256 on a
// claim about the ACT. The claim was true of the key-bound function and false of the rest: `checkpoint-chain` is
// ONE key-bound `sealAuthorityCheckpoint` against EIGHT key-free ones including `verifyAuthorityCheckpointChain`,
// which needs no human by any reading. I applied the owner's test to the capability's NAME instead of to each
// operation, and the name covers both — the same mistake, one level deeper than the one it was meant to fix.
// Each entry below states the halves and what the key-free half is owed; splitting them properly is debt on #178.
const ACKNOWLEDGED_MIXED = {
  'sign': 'seal SIGNS (key) · attachSignature ASSEMBLES (none). A surface that must never hold a key owns the second half honestly — `ust-mcp` scores subset here, not na (round 258).',
  'disclosure-produce': 'encryptPartition needs a key · blindedCommit, blindPartition, sealingRequest and attachEncryption need none. Both `blinded` and the two key-free halves of `encrypted` are on the agent surface (rounds 257, 261); only the sealing itself stays with whoever owns the key.',
  'no-fork-evidence': 'buildNoForkEvidence issues (key) · noForkClaim, verifyNoForkEvidence, witnessNoFork read (none). CONSUMING no-fork evidence is already on the agent surface; the issuing half is the operator\'s.',
  'evidence-receipt': 'buildEvidenceReceipt issues (key) · evidenceReceiptClaim, evidenceReceiptId, verifyEvidenceReceipt read (none). The reading half is owed to the agent surface and is currently withheld with it.',
  'checkpoint-chain': 'sealAuthorityCheckpoint mints (key) · EIGHT key-free functions read, including verifyAuthorityCheckpointChain and deriveCheckpointFreshness. The deferral in round 256 was argued about MINTING and applied to reading — the reading half needs no human at all.',
  'recovery': 'buildRecoveryStatement asserts (key) · checkpointRecoveryClaim, verifyCheckpointRecovery, witnessSuccessor, witnessNoShrink read (none). Same over-coverage as checkpoint-chain.',
  'epoch-transition': 'buildEpochTransition commits an identity forward (key) · epochTransitionClaim, verifyEpochTransition, deriveStreamFloor read (none). The deferral holds for the first and not the rest.',
  'uniqueness-attest': 'buildUniquenessAttestation swears (key) · checkpointUniquenessClaim, verifyCheckpointUniqueness read (none). Round 256 already said an agent may CHECK such an attestation — and then withheld the checking half with the swearing one.',
  'verifiable-map': 'checkpointMapLeaf, nameMapLeaf, buildNameMapRoot publish (key) · buildVerifiableMap, verifyCheckpointMapUniqueness, verifyActiveGenesisUniqueness, nameMapRootClaim, verifyNameMapRoot, proveMapRootAnchor read (none).',
};
{
  const mixed = capIds.filter((c) => {
    const core = CAPS[c]?.core ?? [];
    const withKey = core.filter(takesKey), without = core.filter((n) => !takesKey(n));
    return withKey.length && without.length;
  });
  const unacknowledged = mixed.filter((c) => !ACKNOWLEDGED_MIXED[c]);
  if (unacknowledged.length) { fail++; report.push(`  ✗ MIXED: ${unacknowledged.length} capability(ies) split on key-taking and are recorded as one: [${unacknowledged.join(', ')}]. A surface scoring such a capability \`na\` withholds its key-free half on the strength of the other half's risk — split it, or acknowledge the halves here. Three instances of this shape have already cost this repository a defect each.`); }
  const stale = Object.keys(ACKNOWLEDGED_MIXED).filter((c) => !mixed.includes(c));
  if (stale.length) { fail++; report.push(`  ✗ MIXED: acknowledged but no longer mixed: [${stale.join(', ')}] — the split happened, so remove the acknowledgement rather than leaving a note nobody re-derived`); }
  if (!unacknowledged.length && !stale.length) report.push(`  ✓ MIXED: ${mixed.length} capability(ies) split on key-taking, each acknowledged with what its halves are — the shape that cost three defects is now pinned`);

  // CONTROLS — both directions, because a detector that cannot see the historical cases is watching nothing.
  if (!takesKey('seal') || takesKey('attachSignature')) { fail++; report.push('  ✗ CONTROL: the key-taking probe misreads `seal`/`attachSignature` — the one pair this axis was built from'); }
  if (takesKey('canon') || takesKey('contentHash')) { fail++; report.push('  ✗ CONTROL: the probe reports key material in a pure function — every capability would read as mixed'); }
}

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
  // A SURFACE THAT EXPOSES EVERYTHING WITNESSES NOTHING. The core declares `full: Object.keys(CAPS)` — every
  // capability lives in the library by definition — so counting it as evidence of exposure makes "which capability
  // is on NO surface" unanswerable: the answer is always none.
  //
  // Measured 2026-09-03, CLOSED 2026-09-03 (#178): that is exactly what happened. Round 264 added the core column
  // the owner asked for, and this leg's domain went to ZERO in the same edit. It printed `all 0 zero-surface
  // capabilities declare a reason` on every run since — a sentence whose own number says the domain is empty, read
  // as green by me for six rounds. My fix removed the subject from my own detector, and the three stances that
  // rotted underneath it (`disclosure-produce`, `ladder-report`, `name-obligation`) are what the silence cost.
  //
  // The test is structural rather than a named exception: any surface holding EVERY capability is a tautology here,
  // so a second such surface would be excluded for the same reason without an edit.
  const capCount = Object.keys(CAPS).length;
  const witnesses = Object.entries(SURFACES).filter(([, s]) => new Set([...(s.full ?? []), ...(s.subset ?? [])]).size < capCount);
  const exposed = new Set(witnesses.flatMap(([, s]) => [...(s.full ?? []), ...(s.subset ?? [])]));
  const zero = Object.keys(CAPS).filter((n) => !exposed.has(n));
  // THE DOMAIN ITSELF IS ASSERTED. A leg that measures an empty set reports success for free, and this one did.
  if (!zero.length) { console.error('  ✗ STANCE: the zero-surface domain is EMPTY — every capability is claimed by some surface, so this leg is asserting nothing (a green over an empty domain is what hid three stale stances)'); process.exit(1); }
  if (witnesses.length === Object.keys(SURFACES).length) { console.error('  ✗ CONTROL: no surface was recognised as exposing everything — the tautology filter is inert, and the core would be counted as evidence again'); process.exit(1); }
  // THE OTHER DIRECTION, the same class the ORDERING axis just gained: a stance explains why a capability is on NO
  // surface, so a stance over one that IS delivered is a record whose subject has gone. `phantom` below catches a
  // stance naming a capability that does not exist; nothing caught a stance whose PREMISE no longer held.
  const delivered = Object.keys(STANCE).filter((n) => CAPS[n] && exposed.has(n));
  const missing = zero.filter((n) => !STANCE[n]);
  const thin = zero.filter((n) => STANCE[n] && String(STANCE[n][1]).trim().length < MIN_REASON);
  const phantom = Object.keys(STANCE).filter((n) => !CAPS[n]);
  if (missing.length || thin.length || phantom.length || delivered.length) {
    if (delivered.length) console.error('  ✗ stance explaining why a capability is on NO surface, while a surface delivers it: ' + delivered.join(', ') + ' — the record outlived its subject; remove it, or the register describes a tree that no longer exists');
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
