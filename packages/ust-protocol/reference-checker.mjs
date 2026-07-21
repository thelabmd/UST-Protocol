// SPDX-License-Identifier: Apache-2.0
// UST Authority REFERENCE CHECKER (L1) — the standalone realization of rnd/REFERENCE-CHECKER.md.
//
// The topology rule made executable: a caller submits ONLY a ProofPackage {term, witnesses} + a consumer Config; the
// checker RE-DERIVES every authority judgment from leaf crypto over content-addressed bytes. It imports ONLY leaf
// primitives (canon/H/keyId/edVerifyStrict/contentHash/verify + the pure Merkle verifiers) — NEVER the authority
// PRODUCER stack (verifiedGenesisContext / verifyAuthorityCheckpointChain / deriveCheckpointFreshness /
// verifyEvidenceReceipt / verifyCheckpointUniqueness / provePredicates / deriveAssurance). So this is a genuine
// independent second derivation, and the producer stack is demoted to an untrusted PROVER that only proposes terms.
//
// Closed enum of rules (one constructor = one inference rule). Total tri-state. Bounds + cycle guard before crypto.
// Conclusions/indices/support are COMPUTED bottom-up; the term carries no trusted conclusion. `C` is a rule INDEX,
// never read from the term. Checker Soundness: check_C(π,W)=VALID(J) ⇒ ∃ derivation of J whose leaves are crypto
// verifications over W (proof: structural induction on π). TCB = this file + the imported leaf primitives.
import { canon, H, keyId, edVerifyStrict, contentHash, verify, isValid, verifyKeylogTerminality,
  verifyCheckpointMapUniqueness, evidenceCaps, authorityScopeId, genesisEpoch,
  resolveKeys, buildKeylogCommitment, authorityCheckpointId, strictB64url, isPublicDnsShard,
  admitUtf8, anyLoneSurrogate, admitDeep } from './index.mjs';   // round-19 P1-01 — ONE Unicode byte-admission, shared with the discovery resolver. round-46 — admitDeep is the proven canon-transparent side-effect-free reduction for the PACKAGE domain (canon: string leaves); admitInert (below) is its canonJSON-domain sibling for the CONFIG (numeric leaves). Both read DATA descriptors and never execute a getter/toJSON.

export const REFERENCE_CHECKER_VERSION = '1.0.0-rc.37-L1-rev65';
// RULE_CONTRACTS (§2b) — the STRUCTURAL source of truth: exactly one inference rule per name, one switch branch per
// name, and a fixed (children arity, witness count, allowed params, conclusion kind). DecodeTerm enforces these on
// decode; a term with an extra child / extra witness / free param / unknown field / stored conclusion is rejected
// BEFORE any rule (M-DEC, closes P1-01). NO semantic security logic lives here — clock/scope/signature/identity checks
// stay in the rule interpreter, so the registry never becomes a second clever TCB. Grammar↔RULES parity derives from it.
const wc = (min, max = min) => ({ min, max });
const rp = { req: true, type: 'string' };   // a REQUIRED string param (M-ADT: params are a typed schema, not an allowed-name list)
// round-25 P0-04 — DEEP-freeze the structural registry: Object.freeze froze only the OUTER map, so a caller could mutate
// RULE_CONTRACTS.Corroborated.children after export and weaken the decoder → the SAME bytes flip VALID. Freeze the whole tree.
const deepFreeze = (o, seen = new WeakSet()) => { if (!o || typeof o !== 'object' || seen.has(o)) return o; seen.add(o); for (const k of Object.keys(o)) deepFreeze(o[k], seen); return Object.freeze(o); };
export const RULE_CONTRACTS = deepFreeze(Object.assign(Object.create(null), {   // null-proto (round-12 P0-01): RULE_CONTRACTS["constructor"] must be undefined, not the Object constructor
  Genesis:                 { children: 0, witnesses: wc(1),        params: {},                conclusion: 'Genesis' },
  CheckpointZero:          { children: 1, witnesses: wc(1),        params: {},                conclusion: 'Chain' },
  CheckpointStep:          { children: 1, witnesses: wc(1, 2),     params: {},                conclusion: 'Chain' },       // consistency witness optional
  ConnectorEvidence:       { children: 1, witnesses: wc(1),        params: { subject: rp },       conclusion: 'Evidence' },
  AfterOrder:              { children: 2, witnesses: wc(0),        params: {},                conclusion: 'After' },
  Corroborated:            { children: 4, witnesses: wc(1),        params: {},                conclusion: 'Freshness' },   // terminality is the head witness (folded)
  MapUnique:               { children: 1, witnesses: wc(1),        params: {},                conclusion: 'MapUnique' },   // coordinate FROM πChain (no params)
  QuorumAgreement:         { children: 1, witnesses: wc(0, Infinity), params: {},             conclusion: 'QuorumAgreement' }, // variadic admitted votes
  ReinforceMap:            { children: 2, witnesses: wc(0),        params: {},                conclusion: 'Freshness' },
  ReinforceQuorum:         { children: 2, witnesses: wc(0),        params: {},                conclusion: 'Freshness' },
  FutureGenesisCommitment: { children: 1, witnesses: wc(1),        params: {},                conclusion: 'FutureCommitted' },
  ActivateGenesis:         { children: 2, witnesses: wc(1),        params: {},                conclusion: 'EpochActivated' }, // requires the verified C0_B witness
  NameBound:               { children: 1, witnesses: wc(0, 1),     params: { doc_key_id: rp },    conclusion: 'Identity' },
  Anchored:                { children: 0, witnesses: wc(1),        params: { s: rp, subject: rp },  conclusion: 'Time' },
  ProjectAssurance:        { children: 3, witnesses: wc(0),        params: {},                conclusion: 'Assurance' },
}));
export const REFERENCE_CHECKER_RULES = Object.freeze(Object.keys(RULE_CONTRACTS));   // parity DERIVES from the registry
const RULES = new Set(REFERENCE_CHECKER_RULES);
const DEFAULT_LIMITS = { maxNodes: 512, maxDepth: 32, maxWitnesses: 1024, maxWitnessBytes: 1 << 20, maxPackageBytes: 1 << 22, maxWitnessRefs: 4096, maxConfigBytes: 1 << 20 };   // maxConfigBytes (round-14 P1-02): the config has its OWN independent 1 MiB ceiling, not silently the package limit   // maxWitnessRefs (round-13 P1-03): total witness REFERENCES across the term, independent of unique store count — bounds crypto ops
const isHash = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
export const witnessId = (obj) => H('ust:witness', canon(obj));   // content address a witness (for provers building packages)
// CanonicalSeq (§3): a sequence is a canonical decimal string, never a wire value coerced by Number(). Rejects "00",
// "01", "+1", "1.0", " 1" — so the P0-02 "00"→0 alias cannot form. Returns the canonical string, or null.
const decodeSeq = (x) => (typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x)) ? x
  : (typeof x === 'number' && Number.isInteger(x) && x >= 0 ? String(x) : null);
const seqSucc = (s) => (BigInt(s) + 1n).toString();   // CanonicalSeq successor via BigInt — Number() is forbidden in the TCB (M-SEQ, P0-04)
const strictPub = (p) => strictB64url(p, 32) !== null;   // Pub32: canonical unpadded base64url of exactly 32 bytes (P1-04)
// typed witness envelope: EXACTLY these keys, no extras (round-9 P0-04) — a validly-signed inner claim/body cannot smuggle
// an extra outer field the signature does not cover, and an attestation cannot forge a distinct claim at one coordinate.
const exactKeys = (o, ...keys) => o !== null && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
// closedRec (rev7, M-DEC-LEAF): a CLOSED typed record — a plain object whose keys ⊆ (req ∪ opt) and ⊇ req. This is the
// exactKeys generalization with OPTIONAL keys: it rejects ANY unknown field at the level it guards, so a validly-SIGNED
// inner body/claim/sig can no longer carry an extra field the interpreter ignores but the identity hash absorbs (round-10
// P0-02/P0-04/P0-05). Every witness envelope, claim, body, sig, and per-kind facts object is validated through this.
const closedRec = (o, req, opt = []) => {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
  for (const k of Object.keys(o)) if (!req.includes(k) && !opt.includes(k)) return false;   // no unknown key
  for (const k of req) if (!Object.prototype.hasOwnProperty.call(o, k)) return false;         // every required present
  return true;
};
// decodeRec (rev8, M-DEC-LEAF tightened, round-11): closure is NOT enough — a closed key-set with un-typed VALUES still
// admits version:"999", issued_at:"not-a-time", keylog:{root:"not-a-hash"}. Each leaf is now a TYPED decoder: a plain
// object whose keys ⊆ schema, every REQUIRED field present AND satisfying its predicate (an exact constant, a refined
// type, or a nested schema). Returns null (ok) or a 'code:field' tag. The identity/coordinate a rule computes is thus
// over a TYPED closed ADT, not a merely key-closed one. Predicates below reuse the leaf refinements (§2b).
const RFC3339Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
// round-46 self-audit — DELETED dead `pStr`/`pBool` type-predicates (defined, never referenced).
const pSeq = (x) => decodeSeq(x) !== null;                 // CanonicalSeq
const pSig64 = (x) => strictB64url(x, 64) !== null;        // Sig64
const pId = (x) => typeof x === 'string' && x.length > 0;  // a NON-EMPTY identifier (round-12 P0-04: subject/domain/proof_kind can't be "")
const pRFC = (x) => { if (typeof x !== 'string' || !RFC3339Z.test(x)) return false; const t = Date.parse(x); return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + 'Z' === x; };   // real calendar + canonical round-trip (round-12 P0-04: "2026-02-31T25:61:61Z" is shape-valid but not a real time)
const pHashArr = (x) => Array.isArray(x) && x.every(isHash);
const eq = (c) => (x) => x === c;                          // an EXACT constant (version, purpose)
const rec = (schema) => (x) => decodeRec(x, schema) === null;   // a nested typed record
// decodeRec membership is OWN-key only (round-12 P0-01): `k in schema` walks the prototype chain, so an inherited name
// (constructor, __proto__, toString, hasOwnProperty, valueOf) would count as a declared field and slip past the
// unknown-key gate — reopening head-id malleability and admitting judgments outside the ADT. Object.hasOwn closes the class.
function decodeRec(o, schema) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return 'E-REC-SHAPE';
  for (const k of Object.keys(o)) if (!Object.hasOwn(schema, k)) return 'unknown:' + k;       // no key the schema does not OWN
  for (const k of Object.keys(schema)) {
    const s = schema[k];
    if (!Object.hasOwn(o, k)) { if (!s.opt) return 'missing:' + k; continue; }
    if (!s.t(o[k])) return 'bad:' + k;                                                        // wrong type / constant / refined value
  }
  return null;
}
// Typed leaf schemas (§2b, round-11) — one source of truth for each SIGNED inner object. `head_id`/order/coordinate are
// computed over these CLOSED, TYPED ADTs, so no un-typed or extra field can shift an identity or slip a malformed value.
const SIG_ENV = { alg: { t: eq('Ed25519') }, key_id: { t: isHash }, pub: { t: strictPub }, sig: { t: pSig64 } };   // a signature wrapper (receipt/checkpoint/vote/transition)
const KEYLOG_COMMIT = { root: { t: isHash }, length: { t: pSeq }, head: { t: isHash } };                            // P0-03: root/head are HASHES, not arbitrary strings
const CHK_AUTHORITY = { current_key_id: { t: isHash }, next_key_id: { t: isHash, opt: true }, next_pub: { t: strictPub, opt: true }, effective_sequence: { t: pSeq, opt: true } };
const CHECKPOINT_BODY = { version: { t: eq('1') }, purpose: { t: eq('ust:authority-checkpoint') }, domain_shard: { t: pId }, genesis_epoch: { t: isHash }, sequence: { t: pSeq }, active_genesis: { t: isHash }, checkpoint_authority: { t: rec(CHK_AUTHORITY) }, keylog: { t: rec(KEYLOG_COMMIT) }, previous_checkpoint: { t: isHash, opt: true }, previous_epoch_final_checkpoint: { t: isHash, opt: true } };
const RECEIPT_CLAIM = { version: { t: eq('1') }, purpose: { t: eq('ust:evidence-receipt') }, domain_shard: { t: pId }, active_genesis: { t: isHash }, genesis_epoch: { t: isHash }, subject: { t: pId }, proof_kind: { t: pId }, facts: { t: (x) => x !== null && typeof x === 'object' && !Array.isArray(x) }, issued_at: { t: pRFC }, payload_digest: { t: isHash, opt: true } };
// to_genesis_epoch + to_checkpoint_authority are REQUIRED (round-12 P0-03): the SIGNED destination epoch/authority must be
// relevant — carried through FutureCommitted and unified with Genesis-B/C0-B at activation, so epoch A cannot sign a handoff
// to one authority while the checker activates another.
const TRANSITION_CLAIM = { purpose: { t: eq('ust:genesis-epoch-transition') }, domain_shard: { t: pId }, from_genesis_epoch: { t: isHash }, from_final_checkpoint: { t: isHash }, from_sequence: { t: pSeq }, to_active_genesis: { t: isHash }, to_initial_sequence: { t: pSeq }, to_genesis_epoch: { t: isHash }, to_checkpoint_authority: { t: rec({ key_id: { t: isHash }, pub: { t: strictPub } }) } };
const HEAD_PROOF = { index: { t: pSeq }, siblings: { t: pHashArr } };   // P1-02 terminality interior
const MAP_PROOF = { siblings: { t: pHashArr } };                        // P1-03 authenticated-map interior
const VOTE_CLAIM = { purpose: { t: eq('ust:checkpoint-uniqueness-attestation') }, domain_shard: { t: pId }, genesis_epoch: { t: isHash }, sequence: { t: pSeq }, checkpoint: { t: isHash } };
const isNFC = (s) => typeof s === 'string' && s.normalize('NFC') === s;   // a free-text config leaf must be NFC (canon requires it; validate at DECODE so it never reaches a throw — round-10 P1-02)
// FACTS_KEYS / ORDER_COORD (round-10 P0-03): the evidence `facts` object is a CLOSED ADT keyed by proof_kind, and the
// temporal order coordinate is read ONLY from that kind's authorized fields — a transparency-log's order is Position(
// log_id, index), a pow chain's Position(substrate, position), a tsa's Interval(clock_id, …). Planting a pow-style
// {substrate, position} on a transparency-log receipt is now a CLOSED-facts violation, not a silently-honored order.
// NULL-prototype registries (round-12 P0-01): keyed by an attacker-influenced proof_kind. A plain object would resolve
// FACTS_KEYS["toString"] / EVIDENCE_CAPS["constructor"] to an inherited FUNCTION (truthy), producing a judgment whose caps
// is a function — outside the ADT. Object.create(null) has NO prototype, so an inherited name resolves to undefined, and
// isKnownKind (own-key membership) is the CLOSED registry of admissible proof_kinds.
// FACTS_SCHEMA (round-13 P0-02): a TYPED per-kind facts ADT, not just a key-set — the rfc3161-tsa interval endpoints are
// REAL calendar times (pRFC), so an impossible 2026-02-31 interval is rejected at receipt decode, before orderSemantic.
const FACTS_SCHEMA = Object.freeze(Object.assign(Object.create(null), {
  'pow-header-chain':  { substrate: { t: pId }, position: { t: pSeq } },   // position/index are CANONICAL non-negative decimals (round-14 P1-01): "abc"/"00"/"-1" rejected
  'transparency-log':  { log_id: { t: pId }, index: { t: pSeq } },
  'rfc3161-tsa':       { clock_id: { t: pId }, not_before: { t: pRFC }, not_after: { t: pRFC } },
  'authenticated-map': {},
  'content-addressed': {},
}));
const isKnownKind = (proof_kind) => Object.hasOwn(FACTS_SCHEMA, proof_kind);   // the closed set of admissible proof_kinds (round-12 P0-01)
const ORDER_COORD = Object.freeze(Object.assign(Object.create(null), {
  'pow-header-chain': { kind: 'position', id: 'substrate', val: 'position' },
  'transparency-log': { kind: 'position', id: 'log_id',    val: 'index' },
  'rfc3161-tsa':      { kind: 'interval', id: 'clock_id',  lo: 'not_before', hi: 'not_after' },
}));
// round-46 self-audit — DELETED `inertRead` (a JSON.stringify-based admission that FIRED the input's getters/toJSON once).
// It is dead: every object boundary now reduces through `admitInert` (unsigned, DATA descriptors, no code executes) or
// `admitDeep` (signed, [[Get]]-once + content-hash) per Theorem R. A getter-firing admission has no place at the boundary.

// ── config normalization (total; §8/§10) — C is a WORLD PARAMETER, never in the term ──────────────────────────────
const isPlain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);   // a JSON object, never an array/null (round-9 P0-05)
const sortedSet = (a) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify(a);   // already sorted + de-duplicated as supplied (round-9 P1-01)
// DecodeConfig — a TOTAL, TYPED, CLOSED config ADT. Never throws (every malformed input → a stable E-CONFIG, round-9
// P1-02); each sub-object must be a plain object of the exact typed shape (an array no longer passes `typeof object`,
// P0-05); set-valued fields must be supplied sorted + de-duplicated (P1-01); unknown fields (top-level AND nested) are
// rejected; every free-string leaf is NFC. NO field is silently DEFAULTED (round-10 P0-01) — an absent value is PRESERVED
// through to config_id = H(canonical bytes) in decodeConfig, so decode is injective (distinct canonical bytes ⟺ distinct
// config_id) and an absent uniqueness_threshold fails quorum CLOSED rather than becoming a silent 2.
function normalizeConfig(raw) {
  if (!isPlain(raw)) return { err: 'E-CONFIG-SHAPE' };
  for (const k of Object.keys(raw)) if (k !== 'connectors' && k !== 'mapRoots' && k !== 'domains' && k !== 'witnesses' && k !== 'policy') return { err: 'E-CONFIG-FIELD:' + k };
  if (raw.connectors !== undefined && !isPlain(raw.connectors)) return { err: 'E-CONFIG-CONNECTORS' };
  const connectors = raw.connectors ?? {};
  for (const k of Object.keys(connectors)) {
    const v = connectors[k];
    if (!isPlain(v)) return { err: 'E-CONFIG-CONNECTOR:' + k };
    for (const ck of Object.keys(v)) if (ck !== 'pub' && ck !== 'allowed_proof_kinds' && ck !== 'trust_domain') return { err: 'E-CONFIG-CONNECTOR-FIELD:' + ck };
    if (!strictPub(v.pub)) return { err: 'E-CONFIG-CONNECTOR-PUB:' + k };
    if (keyId(v.pub) !== k) return { err: 'E-CONFIG-CONNECTOR-KEY:' + k };   // the map key IS keyId(pub) — no semantically-dead entry can perturb config_id (round-12 P1-01)
    if (!Array.isArray(v.allowed_proof_kinds) || !v.allowed_proof_kinds.every((x) => typeof x === 'string' && isNFC(x)) || !sortedSet(v.allowed_proof_kinds)) return { err: 'E-CONFIG-APK:' + k };
    if (v.trust_domain !== undefined && (typeof v.trust_domain !== 'string' || !isNFC(v.trust_domain))) return { err: 'E-CONFIG-TRUST-DOMAIN:' + k };   // NFC at decode → never a throw at config_id (P1-02)
  }
  if (raw.mapRoots !== undefined && !Array.isArray(raw.mapRoots)) return { err: 'E-CONFIG-MAPROOTS' };
  const mapRoots = raw.mapRoots ?? [];
  if (!mapRoots.every(isHash) || !sortedSet(mapRoots)) return { err: 'E-CONFIG-MAPROOTS' };
  if (raw.domains !== undefined && !isPlain(raw.domains)) return { err: 'E-CONFIG-DOMAINS' };
  const domains = raw.domains ?? {};
  for (const k of Object.keys(domains)) if (typeof domains[k] !== 'string' || !isNFC(domains[k])) return { err: 'E-CONFIG-DOMAIN:' + k };   // ControlDomain is a typed NFC STRING
  if (raw.witnesses !== undefined && !isPlain(raw.witnesses)) return { err: 'E-CONFIG-WITNESSES' };
  const witnesses = raw.witnesses ?? {};
  for (const k of Object.keys(witnesses)) { if (!strictPub(witnesses[k])) return { err: 'E-CONFIG-WITNESS:' + k }; if (keyId(witnesses[k]) !== k) return { err: 'E-CONFIG-WITNESS-KEY:' + k }; }   // key IS keyId(pub) (round-12 P1-01)
  for (const k of Object.keys(domains)) if (!Object.hasOwn(witnesses, k)) return { err: 'E-CONFIG-DOMAIN-UNADMITTED:' + k };   // a domain label for a non-witness issuer is a dead entry (round-12 P1-01)
  if (raw.policy !== undefined && !isPlain(raw.policy)) return { err: 'E-CONFIG-POLICY' };   // an array/string/null policy is rejected, never silently defaulted (round-10 P0-01)
  const policy = raw.policy ?? {};
  for (const k of Object.keys(policy)) if (k !== 'uniqueness_threshold' && k !== 'allowExperimentalAttested') return { err: 'E-CONFIG-POLICY-FIELD:' + k };
  if (policy.uniqueness_threshold !== undefined && !(Number.isInteger(policy.uniqueness_threshold) && policy.uniqueness_threshold >= 1)) return { err: 'E-CONFIG-THRESHOLD' };
  if (policy.allowExperimentalAttested !== undefined && typeof policy.allowExperimentalAttested !== 'boolean') return { err: 'E-CONFIG-POLICY-FLAG' };
  // NO threshold default (round-10 P0-01): an absent uniqueness_threshold means "no quorum threshold configured" and
  // QuorumAgreement fails CLOSED (INDETERMINATE), never a silent 2. allowExperimentalAttested absent = false (fail-closed).
  const C = Object.freeze({ connectors, mapRoots, domains, witnesses,
    policy: Object.freeze({ ...(policy.uniqueness_threshold !== undefined ? { uniqueness_threshold: policy.uniqueness_threshold } : {}), allowExperimentalAttested: policy.allowExperimentalAttested === true }) });
  // config_id identifies the NORMALIZED TRUST WORLD, not the input bytes (round-11 P2-01): it is H over a canonical
  // projection of C, so two byte-different configs with the SAME effective trust world ({} ≡ {connectors:{}} ≡
  // {policy:{allowExperimentalAttested:false}}) share one config_id — yet, because NO field is defaulted, two configs with
  // DIFFERENT behavior (absent vs present threshold) still differ (round-10 P1-01 preserved). canonJSON (not canon) so the
  // NFC-validated leaves never reach a throw (round-10 P1-02). The projection is INJECTIVE over C, so config_id ⟺ C.
  const config_id = H('ust:consumer-config', canonJSON({
    connectors: Object.fromEntries(Object.entries(connectors).map(([k, v]) => [k, { pub: v.pub, allowed_proof_kinds: v.allowed_proof_kinds, ...(v.trust_domain !== undefined ? { trust_domain: v.trust_domain } : {}) }])),
    mapRoots, domains, witnesses,
    policy: { ...(C.policy.uniqueness_threshold !== undefined ? { uniqueness_threshold: String(C.policy.uniqueness_threshold) } : {}), allowExperimentalAttested: C.policy.allowExperimentalAttested ? '1' : '0' } }));
  return { C, config_id };
}

// ── the byte boundary (§2, M-BYTE/M-DEC) — the TCB is over immutable octets ───────────────────────────────────────
const TEXT_ENC = new TextEncoder();
// strict UTF-8 decode (round-13 P0-01 / round-19 P1-01): a leading UTF-8 BOM (EF BB BF) is REJECTED — TextDecoder would
// silently strip it, aliasing two distinct immutable byte strings to one decoded object (the byte boundary must be
// injective, M-BYTE). The primitive is now the SHARED index.admitUtf8, so the byte checker and the discovery resolver
// have ONE Unicode domain (round-19 P1-01: a BOM/surrogate the checker rejects must not upgrade a doc via discovery);
// map its neutral marker to the byte-checker's error codes.
function utf8Strict(bytes) {
  const a = admitUtf8(bytes);
  return a.err === 'BOM' ? { err: 'E-BOM' } : a.err ? { err: 'E-UTF8' } : { text: a.text };
}
// lone-surrogate rejection (round-13 P1-04) is the SHARED index.anyLoneSurrogate (round-19 P1-01) — imported above, no
// second copy to drift: a JSON \uD800 escape yields a JS string holding an UNPAIRED surrogate (not a Unicode SCALAR), so
// other-language canonicalizers replace/reject it; checked ITERATIVELY over the parsed tree (keys + values).
// the intrinsic %TypedArray%.prototype.byteLength getter — it reads the [[ViewedArrayBuffer]] internal slot, so calling
// it on a Proxy (which has no such slot) THROWS. That distinguishes a NATIVE Uint8Array from a Proxy/subclass that only
// passes `instanceof` (round-8 P0-01).
const TA_BYTELENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;
const TA_BUFFER = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer').get;   // intrinsic buffer getter — bypasses any overridden accessor (round-9 P0-01)
// SnapshotBytes: accept ONLY a native Uint8Array (Uint8Array only, no string; a Proxy is rejected because the intrinsic
// getter throws), reject SharedArrayBuffer-backed views, and copy into a fresh immutable buffer. Once native is proven,
// `.buffer`/`.set` are trap-free. The theorem begins here.
function snapshotBytes(input, maxBytes, sizeErr) {
  if (!(input instanceof Uint8Array) || Object.getPrototypeOf(input) !== Uint8Array.prototype) return { error: 'E-BYTES-TYPE' };   // EXACT native Uint8Array — a subclass (its proto differs) or Proxy is rejected (round-9 P0-01)
  let len, buf; try { len = TA_BYTELENGTH.call(input); buf = TA_BUFFER.call(input); } catch { return { error: 'E-BYTES-TYPE' }; }   // intrinsic getters, never an overridden accessor
  if (typeof SharedArrayBuffer !== 'undefined' && buf instanceof SharedArrayBuffer) return { error: 'E-BYTES-SHARED' };
  if (maxBytes !== undefined && len > maxBytes) return { error: sizeErr || 'E-BYTES-SIZE' };   // round-15 P1-02: reject the ceiling from the intrinsic byteLength BEFORE allocating the copy — no oversize (32 MiB) copy on a package/config that is rejected next line anyway
  const copy = new Uint8Array(len); copy.set(input); return { bytes: copy };
}
// DecodeTerm (§2b, M-DEC): build the closed Term ADT strictly to each RULE_CONTRACTS entry — exact children arity, exact
// witness count, allowed params only, NO unknown fields / stored conclusion / extra children/witnesses/free params. A
// JSON value is a finite tree (no cycles/sharing to guard), so bounds are just depth + node count.
function decodeTerm(raw, L, depth, ctr) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { err: 'E-TERM-NODE' };
  if (depth > L.maxDepth) return { err: 'E-TERM-DEPTH' };
  if (++ctr.n > L.maxNodes) return { err: 'E-TERM-NODES' };
  for (const k of Object.keys(raw)) if (k !== 'rule' && k !== 'children' && k !== 'witnesses' && k !== 'params') return { err: 'E-TERM-FIELD:' + k };
  const contract = RULE_CONTRACTS[raw.rule];
  if (!contract) return { err: 'E-TERM-RULE:' + String(raw.rule) };
  const children = raw.children === undefined ? [] : raw.children;
  if (!Array.isArray(children) || children.length !== contract.children) return { err: 'E-TERM-ARITY:' + raw.rule };
  const witnesses = raw.witnesses === undefined ? [] : raw.witnesses;
  if (!Array.isArray(witnesses) || witnesses.length < contract.witnesses.min || witnesses.length > contract.witnesses.max) return { err: 'E-TERM-WITNESS:' + raw.rule };
  for (const w of witnesses) if (typeof w !== 'string') return { err: 'E-TERM-WITNESS-TYPE' };
  ctr.refs = (ctr.refs || 0) + witnesses.length; if (ctr.refs > L.maxWitnessRefs) return { err: 'E-TERM-REFS' };   // total references bounded (round-13 P1-03): duplicate refs cannot amplify crypto beyond the budget
  const params = raw.params === undefined ? {} : raw.params;
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return { err: 'E-TERM-PARAMS' };
  for (const pk of Object.keys(params)) {                                    // M-ADT: params are a TYPED schema, not an allowed-name list
    const spec = contract.params[pk];
    if (!spec) return { err: 'E-TERM-PARAM:' + pk };
    if (typeof params[pk] !== spec.type) return { err: 'E-TERM-PARAM-TYPE:' + pk };
  }
  for (const [pk, spec] of Object.entries(contract.params)) if (spec.req && !(pk in params)) return { err: 'E-TERM-PARAM-MISSING:' + pk };   // required present (P1-02)
  const kids = [];
  for (const c of children) { const dc = decodeTerm(c, L, depth + 1, ctr); if (dc.err) return dc; kids.push(dc.term); }
  // canonical node shape: params OMITTED when empty (one normal form), so params:{} vs absent cannot be two wire forms.
  return { term: { rule: raw.rule, children: kids, witnesses, ...(Object.keys(params).length ? { params } : {}) } };
}
// canonJSON — a canonical JSON encoder that ADMITS numbers/booleans (for CONFIG bytes, which carry a threshold): sorted
// keys, canonical numbers, no whitespace. Used for the config round-trip guard so ConfigBytes are language-neutral too.
export function canonJSON(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') { if (!Number.isFinite(v)) throw new Error('E-NUM'); return JSON.stringify(v); }
  if (t === 'boolean') return v ? 'true' : 'false';
  if (Array.isArray(v)) return '[' + v.map(canonJSON).join(',') + ']';
  if (t === 'object') { const ks = Object.keys(v).sort(); return '{' + ks.map((k) => JSON.stringify(k) + ':' + canonJSON(v[k])).join(',') + '}'; }
  throw new Error('E-TYPE');
}
// DecodePackage: bytes → strict UTF-8 → JSON.parse → canonical ROUND-TRIP guard (CanonicalEncode(V)==B) → exact Term ADT
// + content-addressed witness store. The round-trip guard rejects whitespace, key order, duplicate keys, numeric alias,
// non-NFC, padded crypto strings as a class (M-DEC). The parsed value is plain inert data (no getters/prototype/toJSON).
function decodePackage(bytes, L) {
  if (bytes.byteLength > L.maxPackageBytes) return { err: 'E-PACKAGE-SIZE' };
  const ub = utf8Strict(bytes); if (ub.err) return { err: ub.err }; const text = ub.text;
  let parsed; try { parsed = JSON.parse(text); } catch { return { err: 'E-JSON' }; }
  if (anyLoneSurrogate(parsed)) return { err: 'E-SURROGATE' };   // no unpaired UTF-16 surrogate (round-13 P1-04)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !parsed.term || typeof parsed.term !== 'object' || Array.isArray(parsed.term) || !parsed.witnesses || typeof parsed.witnesses !== 'object' || Array.isArray(parsed.witnesses))
    return { err: 'E-PACKAGE-SHAPE' };
  const td = decodeTerm(parsed.term, L, 0, { n: 0 }); if (td.err) return { err: td.err };
  const wkeys = Object.keys(parsed.witnesses);
  if (wkeys.length > L.maxWitnesses) return { err: 'E-WITNESS-COUNT' };
  // REACHABILITY (round-10 P1-03): every stored witness MUST be referenced by the decoded term. An unreferenced witness is
  // dead weight the proof_hash (over the term) does not cover — it would let two distinct package byte-strings carry the
  // SAME judgment + proof_hash. Requiring witnesses == referenced makes the decoded form canonical: term ⟹ witness id set
  // ⟹ (content-addressed) witness bytes ⟹ package bytes, so proof_hash is injective over the package.
  const referenced = new Set();
  (function walk(t) { for (const w of t.witnesses) referenced.add(w); for (const c of t.children) walk(c); })(td.term);
  const store = Object.create(null);
  for (const k of wkeys) {
    if (!referenced.has(k)) return { err: 'E-WITNESS-UNREFERENCED:' + k };   // no dangling witness
    const w = parsed.witnesses[k];
    let wb; try { wb = canon(w); } catch { return { err: 'E-WITNESS-NONCANONICAL' }; }
    if (Buffer.byteLength(wb, 'utf8') > L.maxWitnessBytes) return { err: 'E-WITNESS-SIZE' };   // over UTF-8 BYTES, not UTF-16 code units (round-8 P1-03)
    if (witnessId(w) !== k) return { err: 'E-WITNESS-ADDRESS' };
    store[k] = w;
  }
  // M-DEC: canonical round-trip over the DECODED ADT, not raw JSON — CanonicalEncode(decode(B)) == B. An extra top-level
  // field is absent from the ADT (re-encode differs); params:{} vs absent has one normal form (proof_hash injective).
  let reB; try { reB = canon({ term: td.term, witnesses: parsed.witnesses }); } catch { return { err: 'E-NONCANONICAL' }; }
  if (reB !== text) return { err: 'E-NONCANONICAL' };
  return { term: td.term, store };
}
function decodeConfig(bytes) {
  const ub = utf8Strict(bytes); if (ub.err) return { err: ub.err === 'E-BOM' ? 'E-CONFIG-BOM' : ub.err }; const text = ub.text;
  let parsed; try { parsed = JSON.parse(text); } catch { return { err: 'E-JSON' }; }
  if (anyLoneSurrogate(parsed)) return { err: 'E-CONFIG-SURROGATE' };   // no unpaired UTF-16 surrogate (round-13 P1-04)
  // M-DEC over ConfigBytes: the config must be canonical too — no whitespace / key order / duplicate keys / numeric
  // alias, so the consumer trust world is language-neutral, not parser-dependent (P0-01).
  let reB; try { reB = canonJSON(parsed); } catch { return { err: 'E-CONFIG-NONCANONICAL' }; }
  if (reB !== text) return { err: 'E-CONFIG-NONCANONICAL' };
  // the wire bytes must still be canonical (no whitespace/key-order/dup/alias — round-10 P0-01), but config_id itself is
  // over the normalized WORLD (computed in normalizeConfig, round-11 P2-01), not these bytes.
  return normalizeConfig(parsed);
}

// checkAuthorityProofBytes — THE NORMATIVE TCB. Immutable bytes in; VALID/INVALID/INDETERMINATE out. A live object never
// enters (M-BYTE): the package/config are decoded ONCE from bytes into inert typed values, then rules run over those.
export function checkAuthorityProofBytes(packageBytes, configBytes) {
  const L = DEFAULT_LIMITS;   // fixed internal bounds — no caller `limits` object, so CheckBytes is a PURE function of (packageBytes, configBytes) (round-8 P1-01/M-DET)
  const INVALID = (reason) => ({ result: 'INVALID', reason });
  try {
    const pb = snapshotBytes(packageBytes, L.maxPackageBytes, 'E-PACKAGE-SIZE'); if (pb.error) return INVALID('package bytes: ' + pb.error);   // round-15 P1-02: ceiling checked from byteLength BEFORE the copy
    const cb = snapshotBytes(configBytes, L.maxConfigBytes, 'E-CONFIG-SIZE'); if (cb.error) return INVALID('config bytes: ' + cb.error);   // config has its OWN ceiling (round-14 P1-02), now rejected before the copy too — no DoS via a giant config on a tiny package
    const nc = decodeConfig(cb.bytes); if (nc.err) return INVALID('config: ' + nc.err);
    const { C, config_id } = nc;
    const withCfg = (r) => (r && r.result !== 'VALID') ? { ...r, config_id } : r;   // config_id identifies the config USED, whatever the verdict (P1-02)
    const pd = decodePackage(pb.bytes, L); if (pd.err) return withCfg(INVALID(pd.err));
    const { term, store } = pd;
    // content-addressed witness fetch from the inert store — recompute H(canon) and match. own-keys via null proto.
    const W = (wid) => {
      const w = store[wid];
      if (w === undefined) return { err: 'missing witness ' + wid };
      if (witnessId(w) !== wid) return { err: 'witness_id mismatch (content address)' };
      return { w };
    };
    const R = checkTerm(term, C, W, new Map(), new WeakMap());   // content-keyed memo (round-14 P1-03) + a per-object nodeKey cache
    if (!R.j) return withCfg(R.result ? R : INVALID(R.reason || 'derivation failed'));
    return { result: 'VALID', judgment: R.j, proof_hash: H('ust:proof-term', canon(stripExpected(term))), config_id };
  } catch (e) { return INVALID('checker threw (should be total — please report): ' + (e && e.message ? e.message : String(e))); }
}

// EncodeLive — the UNTRUSTED encoding adapter (outside the TCB). It MAY run getters/toJSON; that only chooses the bytes
// (a caller could hand any bytes directly), never produces a proof. Package uses canonical string-leaf bytes (`canon`),
// config uses JSON. Part of choosing CANONICAL package bytes is PRUNING the witness store to those the term references
// (round-10 P1-03) — the same canonicalization the TCB then re-checks on the bytes; a caller who hands raw bytes with a
// dangling witness still gets E-WITNESS-UNREFERENCED. checkAuthorityProof(obj,cfg) := checkAuthorityProofBytes(EncodeLive…).
const referencedIds = (term) => { const r = new Set(); (function walk(t) { if (t && typeof t === 'object') { for (const w of (Array.isArray(t.witnesses) ? t.witnesses : [])) r.add(w); for (const c of (Array.isArray(t.children) ? t.children : [])) walk(c); } })(term); return r; };
// round-46 (the REDUCTION metatheorem) — the ONE side-effect-free reduction at the authority OBJECT boundary. It reads DATA
// descriptors only and REJECTS any accessor (getter/setter), function, symbol, non-plain prototype, or cycle, so NO caller code
// (a getter / a toJSON) EVER EXECUTES — an automaton reads its input as DATA, it never runs it. JSON scalars (number/boolean/
// null/string) are valid leaves (the authority domain is canonJSON, not the canon-string document domain). This SUPERSEDES the
// rev45 config-first ordering AND the JSON.stringify/inertRead admission (both of which FIRED the input's getters): a hostile
// getter that would rewrite the OTHER argument now never runs, so cross-argument mutation and admission ORDER are STRUCTURALLY
// impossible. Bounded depth (§13). Returns the inert null-proto clone (pollution-safe) or INERT_REJECT.
const INERT_REJECT = Symbol('inert-reject');
const admitInert = (v, seen = new WeakSet()) => {
  if (v === null) return null;
  const t = typeof v;
  if (t === 'string' || t === 'number' || t === 'boolean') return v;         // a JSON scalar leaf (the config is the canonJSON domain, not the canon string-only document domain)
  if (t !== 'object') return INERT_REJECT;                                    // function / symbol / bigint / undefined → reject (never a callable at the boundary)
  if (seen.has(v)) return INERT_REJECT;                                       // a TRUE cycle (v is its own ancestor) → refuse; a DAG (sibling re-reference) is fine via the finally-delete below
  seen.add(v);
  try {
    if (Array.isArray(v)) {
      const out = new Array(v.length);
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) continue;                                             // PRESERVE a hole (round-28 P1-01: canon/JSON treat a preserved hole the same as the original; densifying to null diverged)
        const d = Object.getOwnPropertyDescriptor(v, i);
        if (d.get || d.set) return INERT_REJECT;                             // an accessor element is REJECTED, NEVER executed
        const r = admitInert(d.value, seen); if (r === INERT_REJECT) return INERT_REJECT; out[i] = r;   // read DATA descriptor (the config is not a signature-verified object, so no [[Get]] face to snapshot — a descriptor read is side-effect-free AND sound here)
      }
      return Object.freeze(out);
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return INERT_REJECT;    // plain / null-proto ONLY (Date/Map/class instance rejected)
    const out = Object.create(null);
    for (const k of Object.keys(v)) {
      const d = Object.getOwnPropertyDescriptor(v, k);
      if (d.get || d.set) return INERT_REJECT;                               // a declared accessor at ANY depth → REJECTED, never executed (no getter/toJSON runs)
      const r = admitInert(d.value, seen); if (r === INERT_REJECT) return INERT_REJECT;
      Object.defineProperty(out, k, { value: r, enumerable: true });         // read-only own data via defineProperty (safe for __proto__ on a null-proto object)
    }
    return Object.freeze(out);
  } catch { return INERT_REJECT; }
  finally { seen.delete(v); }                                                 // ancestor-path tracking: a DAG (same object in sibling positions) is fine, only a true cycle is refused (matches admitDeep)
};
const encodeLive = (x, kind) => {
  try {
    let v = x;
    if (kind === 'package' && x && typeof x === 'object' && x.witnesses && typeof x.witnesses === 'object' && !Array.isArray(x.witnesses)) {
      const ref = referencedIds(x.term), w = {};
      for (const k of Object.keys(x.witnesses)) if (ref.has(k)) w[k] = x.witnesses[k];   // canonical package = only referenced witnesses
      v = { ...x, witnesses: w };
    }
    return { bytes: TEXT_ENC.encode(kind === 'package' ? canon(v) : canonJSON(v ?? null)) };
  } catch { return { error: 'E-ENCODE' }; }
};
// round-46 (Theorem R — ρ_package) — reduce a live proof object to its CANONICAL package form by reading it ONCE. Admit the
// term's [[Get]] face once (admitDeep — the SIGNED face, round-29 P0-01), collect the REFERENCED witness ids from the inert
// term, and admit each referenced witness [[Get]]-once; an UNREFERENCED witness is not part of the canonical package, so it is
// never read and never a reject surface (matching the encodeLive filter). The PROVEN encodeLive then canonicalizes the inert
// form (no getter can fire during canon). The whole package is read ONCE — a two-face term/witness cannot show one face to
// referencedIds and another to canon.
const reducePackage = (x) => {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) return { error: 'E-ENCODE' };
  let term; try { term = admitDeep(x.term); } catch { return { error: 'E-ENCODE' }; }
  if (typeof term === 'symbol') return { error: 'E-ENCODE' };
  const ref = referencedIds(term);
  const inert = Object.create(null);
  try {
    for (const k of Object.keys(x)) {                                          // every top-level field, [[Get]] once (term reused, not re-read)
      if (k === 'witnesses') continue;
      const r = (k === 'term') ? term : admitDeep(x[k]);
      if (typeof r === 'symbol') return { error: 'E-ENCODE' };
      inert[k] = r;
    }
    const wIn = x.witnesses, w = Object.create(null);
    if (wIn !== null && typeof wIn === 'object' && !Array.isArray(wIn))
      for (const id of ref) {                                                  // ONLY referenced witnesses, own keys, [[Get]] once each
        if (!Object.prototype.hasOwnProperty.call(wIn, id)) continue;
        const wi = admitDeep(wIn[id]);
        if (typeof wi === 'symbol') return { error: 'E-ENCODE' };
        w[id] = wi;
      }
    inert.witnesses = w;
  } catch { return { error: 'E-ENCODE' }; }
  return encodeLive(inert, 'package');                                          // encodeLive on the INERT form is byte-correct (re-filters harmlessly; no getter fires during canon)
};
// Theorem R made concrete: checkAuthorityProof = A ∘ (ρ_package, ρ_config). ρ_config (admitInert → canonJSON bytes) reads the
// UNSIGNED trust config as DATA (no getter/toJSON EVER executes); ρ_package reads the SIGNED proof's [[Get]] face ONCE; the two
// reductions are INDEPENDENT, so cross-argument mutation and admission ORDER are structurally impossible; A = checkAuthorityProofBytes.
export function checkAuthorityProof(obj, config) {
  const ci = admitInert(config); if (ci === INERT_REJECT) return { result: 'INVALID', reason: 'config: not an inert record — an accessor/getter/toJSON is REJECTED, never executed' };
  const c = encodeLive(ci, 'config'); if (c.error) return { result: 'INVALID', reason: 'config: ' + c.error };   // ρ_config: canonJSON over the inert config
  const p = reducePackage(obj); if (p.error) return { result: 'INVALID', reason: 'package: ' + p.error };         // ρ_package: read the proof ONCE ([[Get]] face) into the inert canonical form
  return checkAuthorityProofBytes(p.bytes, c.bytes);                                                              // A: the pure byte automaton
}

const stripExpected = (n) => ({ rule: n.rule, ...(n.params !== undefined ? { params: n.params } : {}), ...(n.witnesses ? { witnesses: n.witnesses } : {}), children: (n.children || []).map(stripExpected) });

// dispatch — each case RE-DERIVES its judgment. Rejections are structured; nothing throws to the caller. Memoized by
// node identity so a SHARED sub-proof (a proof DAG) is checked once, not re-checked per parent.
// content identity of a node (round-14 P1-03): equal subtrees at DIFFERENT positions are different OBJECTS (JSON decode is a
// tree), so an object-identity memo re-verifies a duplicated subproof — 25 syntactic copies of a quorum branch ran its full
// crypto 25×. A CONTENT key (rule + witness ids + params + child content keys) memoizes by MEANING: each unique subderivation
// runs its crypto ONCE. Sound: check_C is deterministic in (node content, C, W); W is content-addressed; C is fixed per check.
const nodeKey = (n, km) => {
  let k = km.get(n);
  if (k !== undefined) return k;
  k = n.rule + ' ' + JSON.stringify(n.witnesses || []) + ' ' + JSON.stringify(n.params || {}) + ' [' + (n.children || []).map((c) => nodeKey(c, km)).join('') + ']';
  km.set(n, k);
  return k;
};
function checkTerm(node, C, W, memo, km) {
  const key = nodeKey(node, km);
  const hit = memo.get(key); if (hit !== undefined) return hit;
  const R = checkTermInner(node, C, W, memo, km);
  memo.set(key, R);
  return R;
}
function checkTermInner(node, C, W, memo, km) {
  const ch = node.children || [], wt = node.witnesses || [], p = node.params || {};
  const bad = (reason) => ({ result: 'INVALID', reason: node.rule + ': ' + reason });
  const ind = (reason) => ({ result: 'INDETERMINATE', reason: node.rule + ': ' + reason });
  const sub = (i) => checkTerm(ch[i], C, W, memo, km);
  const wit = (i) => W(wt[i]);

  switch (node.rule) {
    case 'Genesis': {
      const g = wit(0); if (g.err) return bad(g.err);
      const doc = g.w;
      if (doc.state?.id?.class !== 'genesis') return bad('not class:genesis');
      if (!isValid(verify(doc, { context: 'genesis' }))) return bad('genesis integrity/signature invalid');
      if (!strictPub(doc.sig.pub) || keyId(doc.sig.pub) !== doc.state.id.key_id) return bad('genesis key not self-bound (non-canonical or mismatched pub)');   // P1-04
      // the genesis domain_shard is a TYPED identity: a self-certifying key-id (== key_id) OR a canonical public-DNS shard
      // (round-12 P1-02) — "bad name" (spaces / invalid A-label) is neither, so it cannot become an authority scope.
      const ds = doc.state.id.domain_shard;
      if (isHash(ds) ? ds !== doc.state.id.key_id : !isPublicDnsShard(ds)) return bad('genesis domain_shard is not a valid public-DNS shard or self-certifying key-id');
      const ca = doc.state?.data?.genesis?.value?.checkpoint_authority;
      if (!ca || !ca.key_id || !ca.pub || !strictPub(ca.pub) || keyId(ca.pub) !== ca.key_id) return bad('malformed checkpoint_authority');   // P1-04 strict pub
      const active_genesis = contentHash(doc);
      return { j: { kind: 'Genesis', s: authorityScopeId(active_genesis), domain: doc.state.id.domain_shard, active_genesis, chkAuth: { key_id: ca.key_id, pub: ca.pub }, genesis: doc } };
    }
    case 'CheckpointZero': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const c = wit(0); if (c.err) return bad(c.err);
      { const cc = closedCheckpoint(c.w); if (cc) return bad(cc); }
      const b = c.w.body;
      if (!b || b.purpose !== 'ust:authority-checkpoint' || decodeSeq(b.sequence) !== '0' || b.previous_checkpoint !== undefined || b.previous_epoch_final_checkpoint !== undefined) return bad('C0 must be a seq-0 checkpoint with no previous links');
      const sc = scopeOk(b, G.j); if (sc) return bad(sc);
      if (b.domain_shard !== G.j.domain) return bad('checkpoint domain_shard ≠ genesis domain (§2.y — a diagnostic wire field must agree with the scope)');
      const sg = sigOk(c.w, G.j.chkAuth); if (sg) return bad(sg);
      if (b.checkpoint_authority?.current_key_id !== G.j.chkAuth.key_id) return bad('current_key_id ≠ genesis checkpoint authority');
      const rot = rotationOk(b); if (rot) return bad(rot);
      if (!keylogWithinCeiling(b.keylog)) return bad('key-log length exceeds the §13 ceiling (' + KEYLOG_CEIL + ')');
      return { j: { kind: 'Chain', s: G.j.s, domain: G.j.domain, active_genesis: G.j.active_genesis, genesis_epoch: genesisEpoch(G.j.active_genesis), n: '0', keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, G.j.chkAuth) } };
    }
    case 'CheckpointStep': {
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      const c = wit(0); if (c.err) return bad(c.err);
      { const cc = closedCheckpoint(c.w); if (cc) return bad(cc); }
      const b = c.w.body, prev = CH.j;
      if (!b || b.purpose !== 'ust:authority-checkpoint') return bad('not an authority checkpoint');
      if (decodeSeq(b.sequence) !== seqSucc(prev.n)) return bad('sequence ≠ prev+1');
      if (b.previous_checkpoint !== prev.head_id) return bad('previous_checkpoint ≠ prior head');
      const sc = scopeOk(b, { s: prev.s, active_genesis: agFromScope(b) }); if (sc) return bad(sc);
      if (authorityScopeId(b.active_genesis) !== prev.s) return bad('checkpoint scope ≠ chain scope (cross-scope)');
      if (b.domain_shard !== prev.domain) return bad('checkpoint domain_shard changes within the chain (§2.y)');
      const sg = sigOk(c.w, prev.activeAuthority); if (sg) return bad('signer is not the resolved active authority: ' + sg);
      if (b.checkpoint_authority?.current_key_id !== prev.activeAuthority.key_id) return bad('current_key_id ≠ resolved authority');
      const rot = rotationOk(b); if (rot) return bad(rot);
      const ap = appendOnly(prev.keylog, b.keylog, wt[1] !== undefined ? W(wt[1]) : null); if (ap.err) return ap.ind ? ind(ap.err) : bad(ap.err);
      if (!keylogWithinCeiling(b.keylog)) return bad('key-log length exceeds the §13 ceiling (' + KEYLOG_CEIL + ')');
      return { j: { kind: 'Chain', s: prev.s, domain: prev.domain, active_genesis: prev.active_genesis, genesis_epoch: prev.genesis_epoch, n: seqSucc(prev.n), keylog: b.keylog, head_id: authorityCheckpointId(c.w), activeAuthority: nextAuthority(b, prev.activeAuthority) } };
    }
    case 'ConnectorEvidence': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const r = wit(0); if (r.err) return bad(r.err);
      { const e = closedReceipt(r.w); if (e) return bad(e); }   // CLOSED receipt ADT: envelope + sig + claim + per-kind facts (round-10 P0-02/P0-03; subsumes the round-8 unknown-field & banned-facts checks)
      const cl = r.w.claim, sig = r.w.sig;
      if (cl.purpose !== 'ust:evidence-receipt') return bad('not an evidence receipt');
      if (sig.alg !== 'Ed25519' || !strictPub(sig.pub) || keyId(sig.pub) !== sig.key_id || r.w.issuer_id !== sig.key_id) return bad('receipt signature not Ed25519 / issuer mismatch / non-canonical pub');   // P0-02 alg envelope + P1-04
      if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, canon({ purpose: 'ust:evidence-receipt-signature', claim: cl }), sig.sig)) return bad('receipt signature invalid');
      if (cl.active_genesis !== G.j.active_genesis || cl.genesis_epoch !== genesisEpoch(cl.active_genesis)) return bad('receipt scope ≠ genesis scope');
      if (cl.domain_shard !== G.j.domain) return bad('receipt domain_shard ≠ genesis domain (§2.y)');
      if (cl.subject !== p.subject) return bad('receipt subject ≠ required subject');
      // ADMISSION FROM C ONLY (never from the term): the issuer must be a consumer-admitted connector for this kind.
      const conn = C.connectors[sig.key_id];
      if (!conn || conn.pub !== sig.pub) return ind('issuer is not a consumer-admitted connector');
      if (!Array.isArray(conn.allowed_proof_kinds) || !conn.allowed_proof_kinds.includes(cl.proof_kind)) return ind('connector not admitted for proof_kind ' + cl.proof_kind);
      return { j: { kind: 'Evidence', s: G.j.s, e: wt[0], q: cl.subject, caps: evidenceCaps(cl.proof_kind), facts: cl.facts, proof_kind: cl.proof_kind } };   // e = content-addressed evidence identity (M-REL)
    }
    case 'AfterOrder': {
      const A = sub(0), B = sub(1);
      if (!A.j || A.j.kind !== 'Evidence') return A.j ? bad('child 0 must be Evidence') : A;
      if (!B.j || B.j.kind !== 'Evidence') return B.j ? bad('child 1 must be Evidence') : B;
      if (A.j.s !== B.j.s) return bad('evidences in different scopes');
      // §3 typed order: the comparable coordinate is derived ONLY from the proof_kind's authorized caps, NEVER from
      // whatever facts happen to be present. A rfc3161-tsa (time-only) cannot assert a substrate POSITION even with a
      // planted `position` fact; a position order and an interval order are incomparable and never prove-after (P0-07).
      const soC = orderSemantic(A.j.proof_kind, A.j.facts), soT = orderSemantic(B.j.proof_kind, B.j.facts);
      if (soC.kind === 'none' || soT.kind === 'none') return ind('evidence class cannot establish temporal order');
      if (soC.kind !== soT.kind || soC.id !== soT.id) return ind('incomparable order semantics (different order/clock identity)');   // P0-03: interval must share a clock; position a substrate
      // magnitude compare over the checker's OWN typed+namespaced coordinate — position by CanonicalSeq, interval by
      // real-calendar lower ≥ upper (both pre-validated by orderSemantic/FACTS_SCHEMA). Kept INDEPENDENT: the kernel does
      // NOT delegate its order verdict to the producer's compareEvidenceOrder (round-32 P0-01 — the public path mirrors
      // THIS decode, never the reverse).
      const provenAfter = soC.kind === 'position'
        ? BigInt(soC.facts.position) > BigInt(soT.facts.position)
        : soC.facts.not_before >= soT.facts.not_after;
      if (!provenAfter) return ind('commitment not proven-after the target');
      return { j: { kind: 'After', s: A.j.s, eC: A.j.e, eT: B.j.e, orderIdentity: soC.id } };   // M-REL: After indexed by the two evidences AND the order identity
    }
    case 'Corroborated': {
      const CH = sub(0), CM = sub(1), TG = sub(2), AF = sub(3);
      if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain') : CH;
      if (!CM.j || CM.j.kind !== 'Evidence') return CM.j ? bad('child 1 must be Evidence (commitment)') : CM;
      if (!TG.j || TG.j.kind !== 'Evidence') return TG.j ? bad('child 2 must be Evidence (target anchor)') : TG;
      if (!AF.j || AF.j.kind !== 'After') return AF.j ? bad('child 3 must be After') : AF;
      const tm = wit(0); if (tm.err) return bad(tm.err);                                 // terminality of the HEAD key-log
      if (!exactKeys(tm.w, 'headProof') || decodeRec(tm.w.headProof, HEAD_PROOF)) return bad('terminality witness must be exactly { headProof: { index, siblings } } typed (round-11 P1-02)');
      if (!verifyKeylogTerminality(CH.j.keylog, tm.w).terminal) return ind('key-log head terminality not proven');
      const s = CH.j.s;
      if (CM.j.s !== s || TG.j.s !== s || AF.j.s !== s) return bad('scope mismatch across freshness premises (cross-scope)');
      if (CM.j.q !== CH.j.head_id) return bad('commitment not bound to the checkpoint head');
      // M-REL: the After MUST order THESE two evidences, not a detached proven-after over unrelated ones (P0-01).
      if (AF.j.eC !== CM.j.e || AF.j.eT !== TG.j.e) return bad('After does not order the commitment/target evidences (detached After)');
      const support = [...new Set([...CM.j.caps, ...TG.j.caps])].sort();
      return { j: { kind: 'Freshness', s, q: TG.j.q, h: CH.j.head_id, n: CH.j.n, base: 'corroborated', aeq: {}, support } };
    }
    case 'MapUnique': {
      // Coordinate provenance (Cluster B.1): (γ,n,h) come FROM the proven Chain, never from term params — there is no
      // free checkpoint coordinate a term could pick, so P0-02 is closed STRUCTURALLY (not "non-canonical → caught").
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain (coordinate provenance)') : CH;
      const m = wit(0); if (m.err) return bad(m.err);
      if (!exactKeys(m.w, 'proof', 'mapRoot') || decodeRec(m.w.proof, MAP_PROOF) || !isHash(m.w.mapRoot)) return bad('map-uniqueness witness must be exactly { proof: { siblings }, mapRoot: hash } typed (round-11 P1-03)');
      const { proof, mapRoot } = m.w;
      if (!C.mapRoots.includes(mapRoot)) return ind('map root is not consumer-admitted (ρ ∉ C.mapRoots)');
      const u = verifyCheckpointMapUniqueness(proof, { domain_shard: CH.j.domain, genesis_epoch: CH.j.genesis_epoch, sequence: String(CH.j.n), checkpoint: CH.j.head_id, mapRoot });
      if (!u.attested) return ind('map non-membership not proven at the chain coordinate (γ,n,h)');
      return { j: { kind: 'MapUnique', s: CH.j.s, n: CH.j.n, h: CH.j.head_id, rho: mapRoot } };
    }
    case 'QuorumAgreement': {
      // Coordinate provenance (Cluster B.1): (γ,n,h) come FROM the proven Chain, never from term params.
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain (coordinate provenance)') : CH;
      const t = C.policy.uniqueness_threshold;
      if (t === undefined) return ind('no uniqueness_threshold configured — quorum fails closed (round-10 P0-01: never a silent default)');
      const n = String(CH.j.n), h = CH.j.head_id;
      // WitnessVote admission is a LOCAL sub-derivation of QuorumAgreement, performed independently per raw attestation
      // BEFORE grouping: authenticate + consumer-resolve + coordinate/domain-bind, THEN group by the ALREADY-VERIFIED
      // claim. An unadmitted or off-coordinate vote never influences the group — no quorum-poison via a pre-admission
      // reference claim (P1-01), no foreign-domain vote (P0-03); adding junk cannot break an agreement (monotonicity).
      const byClaim = new Map();                                                        // verified claim → Set(distinct domains)
      const seenWid = new Set();
      for (const wid of wt) {
        if (seenWid.has(wid)) continue; seenWid.add(wid);                              // dedupe (round-13 P1-03): ONE crypto verify per UNIQUE vote id — duplicates never change the set-based result (M-DET), no amplification
        const a = W(wid); if (a.err) continue;
        const { claim, issuer_id, sig } = a.w || {};
        if (!exactKeys(a.w, 'claim', 'issuer_id', 'sig')) continue;                    // typed attestation envelope (round-9 P0-04)
        if (decodeRec(claim, VOTE_CLAIM) || decodeRec(sig, SIG_ENV)) continue;   // typed vote claim + sig wrapper (round-11 P1-04)   // typed claim — no extra field can forge a DISTINCT claim at one coordinate (round-9 P0-02)
        if (!claim || !sig || claim.purpose !== 'ust:checkpoint-uniqueness-attestation') continue;
        if ('trust_domain' in claim || 'issuer_id' in claim) continue;               // no self-declared independence
        if (claim.domain_shard !== CH.j.domain) continue;                            // attested checkpoint must be in the chain domain (§2.y, P0-03)
        if (claim.genesis_epoch !== CH.j.genesis_epoch || String(claim.sequence) !== n || claim.checkpoint !== h) continue;   // coordinate FROM the chain
        const pub = C.witnesses[issuer_id];                                            // trust roots FROM C, never the term
        if (!pub || sig.alg !== 'Ed25519' || !strictPub(sig.pub) || pub !== sig.pub || keyId(sig.pub) !== issuer_id || sig.key_id !== issuer_id) continue;   // P0-02 alg envelope + P1-04 strict pub + round-13 P1-02: sig.key_id === issuer_id === keyId(pub)
        const cc = canon(claim);
        if (strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, cc, sig.sig)) continue;   // ADMIT (verify) before grouping
        const dom = C.domains[issuer_id]; if (dom === undefined) continue;              // consumer-resolved domain
        if (!byClaim.has(cc)) byClaim.set(cc, new Set());
        byClaim.get(cc).add(dom);                                                       // group by the VERIFIED claim
      }
      // winner SET (M-DET, P1-03): a QuorumAgreement exists ONLY if EXACTLY ONE distinct claim reaches the threshold —
      // 0 → not met, > 1 → ambiguous (two conflicting quorums). Never "first Map entry"; the result is order-independent.
      const winners = [...byClaim.values()].filter((doms) => doms.size >= t);
      if (winners.length === 0) return ind('quorum not met: no claim reaches ' + t + ' distinct domains');
      if (winners.length > 1) return ind('E-QUORUM-AMBIGUOUS: multiple distinct claims each reach the threshold at (γ,n,h)');
      return { j: { kind: 'QuorumAgreement', s: CH.j.s, n: CH.j.n, h, D: [...winners[0]].sort(), t } };
    }
    case 'ReinforceMap': {
      const F = sub(0), M = sub(1);
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 0 must be Freshness') : F;
      if (!M.j || M.j.kind !== 'MapUnique') return M.j ? bad('child 1 must be MapUnique') : M;
      if (F.j.s !== M.j.s || F.j.n !== M.j.n || F.j.h !== M.j.h) return bad('MapUnique does not unify with the freshness (s,n,h)');
      const priorM = F.j.aeq.map;   // conservation (M-SEP, round-9 P0-03): union map roots across reinforcements, never overwrite
      const roots = priorM ? [...new Set([...(priorM.roots || []), M.j.rho])].sort() : [M.j.rho];
      return { j: { ...F.j, aeq: { ...F.j.aeq, map: { roots } } } };   // aeq ONLY; EvidenceSupport unchanged (M-SEP)
    }
    case 'ReinforceQuorum': {
      const F = sub(0), Q = sub(1);
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 0 must be Freshness') : F;
      if (!Q.j || Q.j.kind !== 'QuorumAgreement') return Q.j ? bad('child 1 must be QuorumAgreement') : Q;
      if (F.j.s !== Q.j.s || F.j.n !== Q.j.n || F.j.h !== Q.j.h) return bad('QuorumAgreement does not unify with the freshness (s,n,h)');
      // conservation (M-SEP): the anti-equivocation basis is UNIONed across reinforcements, never overwritten — a second
      // ReinforceQuorum accumulates its domains, it does not erase the first (round-8 P0-05).
      const priorQ = F.j.aeq.quorum;
      const domains = priorQ ? [...new Set([...priorQ.domains, ...Q.j.D])].sort() : Q.j.D;
      return { j: { ...F.j, aeq: { ...F.j.aeq, quorum: { domains, threshold: String(Q.j.t) } } } };   // aeq ONLY; EvidenceSupport unchanged
    }
    case 'FutureGenesisCommitment': {
      const CH = sub(0); if (!CH.j || CH.j.kind !== 'Chain') return CH.j ? bad('child 0 must be Chain (epoch A)') : CH;
      const cm = wit(0); if (cm.err) return bad(cm.err);
      { const e = closedTransition(cm.w); if (e) return bad(e); }
      const { claim, sig } = cm.w;
      if (!claim || claim.purpose !== 'ust:genesis-epoch-transition') return bad('not an epoch-transition commitment');
      if (!isHash(claim.to_active_genesis)) return bad('commitment lacks a target genesis hash');
      // M-KEY total: the transition signature is a leaf like any other — strict Sig64 + alg, not a bare edVerifyStrict (P1-04).
      if (sig.key_id !== CH.j.activeAuthority.key_id || sig.pub !== CH.j.activeAuthority.pub || sig.alg !== 'Ed25519' || strictB64url(sig.sig, 64) === null || !edVerifyStrict(sig.pub, canon(claim), sig.sig)) return bad('commitment not signed by epoch-A authority (or non-canonical signature)');
      // M-ERA total: bind the FULL epoch-A coordinate — domain, final checkpoint, epoch, AND from_sequence = Chain.n; carry nA (P0-02).
      if (claim.domain_shard !== CH.j.domain) return bad('epoch transition domain_shard ≠ chain-A domain');
      if (claim.from_final_checkpoint !== CH.j.head_id) return bad('epoch transition from_final_checkpoint ≠ chain-A head');
      if (claim.from_genesis_epoch !== CH.j.genesis_epoch) return bad('epoch transition from_genesis_epoch ≠ chain-A epoch');
      if (decodeSeq(claim.from_sequence) !== CH.j.n) return bad('epoch transition from_sequence ≠ chain-A sequence');
      const toInitialSeq = decodeSeq(claim.to_initial_sequence); if (toInitialSeq === null) return bad('epoch transition to_initial_sequence is not a CanonicalSeq');
      // M-ERA (round-12 P0-03): the SIGNED destination epoch + authority must be RELEVANT — canonical to the target genesis
      // and self-bound — and are CARRIED so ActivateGenesis unifies them with the actual Genesis B (no sign-WX / activate-WB).
      if (claim.to_genesis_epoch !== genesisEpoch(claim.to_active_genesis)) return bad('epoch transition to_genesis_epoch ≠ genesisEpoch(to_active_genesis) (non-canonical destination epoch)');
      const authB = claim.to_checkpoint_authority;
      if (keyId(authB.pub) !== authB.key_id) return bad('to_checkpoint_authority key not self-bound (keyId(pub) ≠ key_id)');
      return { j: { kind: 'FutureCommitted', sA: CH.j.s, hA: CH.j.head_id, nA: CH.j.n, domain: CH.j.domain, hB: claim.to_active_genesis, epochB: claim.to_genesis_epoch, authB: { key_id: authB.key_id, pub: authB.pub }, toInitialSeq } };
    }
    case 'ActivateGenesis': {
      const FC = sub(0); if (!FC.j || FC.j.kind !== 'FutureCommitted') return FC.j ? bad('child 0 must be FutureCommitted') : FC;
      const GB = sub(1); if (!GB.j || GB.j.kind !== 'Genesis') return GB.j ? bad('child 1 must be a VERIFIED Genesis[sB] — a hash cannot introduce it') : GB;
      if (GB.j.active_genesis !== FC.j.hB) return bad('destination genesis contentHash ≠ committed target');
      if (GB.j.domain !== FC.j.domain) return bad('epoch transition crosses domains (AllowedTransition requires same domain)');   // P0-04 policy
      // M-ERA (round-12 P0-03): epoch-B genesis authority MUST equal the SIGNED transition-committed destination authority —
      // else epoch A appears to sign a handoff to one authority while the checker activates another.
      if (GB.j.chkAuth.key_id !== FC.j.authB.key_id || GB.j.chkAuth.pub !== FC.j.authB.pub) return bad('epoch-B genesis authority ≠ transition-committed destination authority');
      if (genesisEpoch(GB.j.active_genesis) !== FC.j.epochB) return bad('epoch-B genesis epoch ≠ transition-committed to_genesis_epoch');
      // EpochActivated cannot come from signer+hash equality alone — the epoch-B INITIAL checkpoint C0_B must be verified
      // under the epoch-B genesis authority and bound to the epoch-A final checkpoint at the committed sequence (P0-04).
      const c = wit(0); if (c.err) return bad('epoch-B initial checkpoint (C0_B) witness required: ' + c.err);
      { const cc = closedCheckpoint(c.w); if (cc) return bad(cc); }
      const b = c.w.body;
      if (!b || b.purpose !== 'ust:authority-checkpoint') return bad('C0_B is not an authority checkpoint');
      if (b.previous_checkpoint !== undefined) return bad('C0_B must not carry a same-epoch previous_checkpoint');
      if (b.previous_epoch_final_checkpoint !== FC.j.hA) return bad('C0_B previous_epoch_final_checkpoint ≠ epoch-A final checkpoint');
      if (decodeSeq(b.sequence) !== FC.j.toInitialSeq) return bad('C0_B sequence ≠ committed to_initial_sequence');
      const sc = scopeOk(b, { s: GB.j.s, active_genesis: GB.j.active_genesis }); if (sc) return bad('C0_B ' + sc);
      if (b.domain_shard !== GB.j.domain) return bad('C0_B domain_shard ≠ epoch-B genesis domain (§2.y)');
      const sg = sigOk(c.w, GB.j.chkAuth); if (sg) return bad('C0_B ' + sg);
      if (b.checkpoint_authority?.current_key_id !== GB.j.chkAuth.key_id) return bad('C0_B current_key_id ≠ epoch-B genesis authority');
      const rot = rotationOk(b); if (rot) return bad('C0_B ' + rot);
      if (!keylogWithinCeiling(b.keylog)) return bad('C0_B key-log exceeds the §13 ceiling');
      return { j: { kind: 'EpochActivated', sA: FC.j.sA, sB: GB.j.s, hA: FC.j.hA, nB: decodeSeq(b.sequence), hB0: authorityCheckpointId(c.w), chkAuthB: GB.j.chkAuth } };   // nB is a CanonicalSeq string (M-SEQ); authority from VERIFIED g_B + C0_B
    }
    case 'NameBound': {
      const G = sub(0); if (!G.j || G.j.kind !== 'Genesis') return G.j ? bad('child 0 must be Genesis') : G;
      const kl = wt.length ? W(wt[0]) : { w: [] };
      if (kl.err) return bad(kl.err);
      if (!Array.isArray(kl.w)) return bad('key-log witness must be an array (typed witness, round-8 P0-04)');   // no silent empty-keylog for a wrong-typed witness
      // every key-log entry MUST be scoped to the ROOTING genesis domain (round-13 P1-01): a foreign-domain class:key doc,
      // even validly chained + signed, cannot introduce a key into THIS scope — resolveKeys does not bind the entry domain.
      for (const e of kl.w) if (e?.state?.id?.domain_shard !== G.j.domain) return bad('key-log entry domain_shard ≠ genesis domain');
      const rk = resolveKeys(G.j.genesis, kl.w);
      if (rk.error || !rk.validKeys.has(p.doc_key_id)) return ind('document key not bound in the genesis key-log');
      return { j: { kind: 'Identity', s: G.j.s, key: p.doc_key_id, subject: null, rung: 'corroborated', caps: [] } };   // round-15 P0-01 (M-REL/M-ERA): Identity now carries the KEY it binds (the erased index is restored). `subject: null` — the MINIMAL NameBound proves ONLY that doc_key_id is name-bound in the domain, NOT that it produced any subject document; the producer-binding premise (subject ≠ null) is the reserved TOP-tier realization (UST-48p).
    }
    case 'Anchored': {
      const a = wit(0); if (a.err) return bad(a.err);
      // minimal: an anchor witness that self-declares inclusion+anchored is NOT trusted; a real substrate proof is a
      // registered direct-proof verifier (future). For L1 we admit only INDETERMINATE unless a direct verifier ran.
      return { j: { kind: 'Time', s: p.s, q: p.subject, rung: 'unproven' } };
    }
    case 'ProjectAssurance': {
      const I = sub(0), F = sub(1), T = sub(2);
      if (!I.j || I.j.kind !== 'Identity') return I.j ? bad('child 0 must be Identity') : I;
      if (!F.j || F.j.kind !== 'Freshness') return F.j ? bad('child 1 must be Freshness') : F;
      if (!T.j || T.j.kind !== 'Time') return T.j ? bad('child 2 must be Time') : T;
      if (I.j.s !== F.j.s || F.j.s !== T.j.s) return bad('assurance premises span different scopes');
      if (F.j.q !== T.j.q) return bad('freshness and time speak about different subjects (subject unification, P1-03)');
      // round-15 P0-01 (F.5.0 / A(d)): the AssuranceState A(d) is a PRODUCT of coordinates of ONE document d, and the tier
      // projection Π is defined ONLY on that single-document tuple. Identity, Freshness and Time must therefore all speak
      // about the SAME subject — sharing a domain scope is not enough. The minimal NameBound proves key-binding but not
      // that its key PRODUCED subject q (I.subject stays null), so stitching it here would form a CROSS-DOCUMENT product
      // (IdentityStrength(d′), FreshnessStrength(d), TimeStrength(d)) that is not in 𝓐. Fail closed until the TOP-tier
      // realization (UST-48p) gives NameBound the producer premise to bind I.subject = the subject its key authored.
      if (I.j.subject === null || I.j.subject !== F.j.q) return ind('identity not bound to the assured subject: A(d)/F.5.0 requires one document across Identity/Freshness/Time — NameBound proves key-binding, not that its key produced subject q (subject-production binding = TOP-tier realization, UST-48p)');
      const tier = (I.j.rung === 'authoritative' && T.j.rung === 'anchored') ? 'TOP' : (I.j.rung === 'authoritative' || I.j.rung === 'corroborated') ? 'HIGH' : 'LIGHT';
      const freshness = { base: F.j.base, anti_equivocation: { quorum: F.j.aeq.quorum || null, map: F.j.aeq.map || null } };
      return { j: { kind: 'Assurance', scope_id: I.j.s, subject: F.j.q, identity_key: I.j.key, tier, identity: I.j.rung, time: T.j.rung, freshness, support: [...new Set([...F.j.support, ...I.j.caps])].sort() } };   // identity_key carried (M-REL: the bound key is an index of the Assurance, no longer erased)
    }
    default: return bad('unreachable');
  }
}

// ── leaf helpers (re-derived here, independent of the producer stack) ─────────────────────────────────────────────
function scopeOk(b, gLike) {
  if (!isHash(b.active_genesis)) return 'active_genesis is not a hash';
  if (b.genesis_epoch !== genesisEpoch(b.active_genesis)) return 'genesis_epoch not canonical (M2)';
  if (gLike.active_genesis !== undefined && b.active_genesis !== gLike.active_genesis) return 'checkpoint active_genesis ≠ genesis (scope)';
  return null;
}
const agFromScope = (b) => b.active_genesis;
const KEYLOG_CEIL = 256;   // §13 key-log ceiling — enforced at every checkpoint introduction (P1-04)
function keylogWithinCeiling(kl) {
  if (!kl || kl.length === undefined) return false;
  const n = decodeSeq(kl.length);
  return n !== null && Number(n) <= KEYLOG_CEIL;
}
// §3 OrderSemantic (round-10 P0-03) — the order coordinate is fixed by the proof_kind (ORDER_COORD), NOT by whichever
// generic facts are present: pow → Position(substrate, position), transparency-log → Position(log_id, index), tsa →
// Interval(clock_id, not_before ≤ not_after). The identity is proof_kind-namespaced (NUL-delimited) so kinds never collide.
function orderSemantic(proof_kind, facts) {
  const c = ORDER_COORD[proof_kind], f = facts || {};
  if (!c) return { kind: 'none', id: null, facts: {} };   // round-10 P0-03: coordinate read ONLY from the kind's authorized fields
  // the order carries its IDENTITY (which substrate / which clock), and the identity must be PRESENT — a position needs a
  // substrate, an interval a clock_id; without it there is no comparable order (P0-03). id is an index of After.
  // the identity is NAMESPACED by the TRUSTED proof_kind (P0-04) — two different kinds reusing one `substrate` string do
  // NOT collide; and an interval must be well-formed lower ≤ upper (P1-06), else there is no order.
  if (c.kind === 'position') {
    if (typeof f[c.id] !== 'string' || typeof f[c.val] !== 'string') return { kind: 'none', id: null, facts: {} };
    return { kind: 'position', id: proof_kind + ' ' + f[c.id], facts: { substrate: f[c.id], position: f[c.val] } };
  }
  if (typeof f[c.id] !== 'string' || typeof f[c.lo] !== 'string' || typeof f[c.hi] !== 'string') return { kind: 'none', id: null, facts: {} };
  if (f[c.lo] > f[c.hi]) return { kind: 'none', id: null, facts: {} };   // ill-formed interval lower > upper -> no order (P1-06)
  return { kind: 'interval', id: proof_kind + ' ' + f[c.id], facts: { not_before: f[c.lo], not_after: f[c.hi] } };
}
// closedCheckpoint (round-10 P0-04/P0-05): the checkpoint witness is a CLOSED ADT at every level — envelope { body, sig },
// sig { alg, key_id, pub, sig }, body { the 8 authority-checkpoint fields } + optional prior links, and the nested
// checkpoint_authority / keylog. Because head_id = H(canon({body, sig})) hashes the CLOSED form, no extra field (a
// sig.wrapper_nonce, a body.extension_semantics) can shift the identity without being rejected here first.
function closedCheckpoint(cw) {
  if (!exactKeys(cw, 'body', 'sig')) return 'checkpoint witness must be exactly { body, sig }';
  const es = decodeRec(cw.sig, SIG_ENV); if (es) return 'checkpoint sig envelope not typed (round-11 ' + es + ')';
  const eb = decodeRec(cw.body, CHECKPOINT_BODY); if (eb) return 'checkpoint body not typed (round-11 ' + eb + ')';   // version==="1", keylog root/head HASHES, seqs typed (P0-02/P0-03)
  return null;
}
// closedReceipt (round-11 typed): a connector receipt is a CLOSED, TYPED ADT — envelope { claim, issuer_id, sig }, a typed
// sig wrapper, the claim's LEAF VALUES refined (version==="1", issued_at RFC3339-Z, active_genesis/genesis_epoch HASHES —
// not merely present, round-11 P0-01), and facts CLOSED to the proof_kind's schema (round-10 P0-03).
function closedReceipt(rw) {
  if (!closedRec(rw, ['claim', 'issuer_id', 'sig'])) return 'receipt envelope not closed';
  const es = decodeRec(rw.sig, SIG_ENV); if (es) return 'receipt sig envelope not typed (round-11 ' + es + ')';
  const cl = rw.claim;
  const ec = decodeRec(cl, RECEIPT_CLAIM); if (ec) return 'receipt claim not typed (round-11 ' + ec + ')';
  if (!isKnownKind(cl.proof_kind)) return 'receipt proof_kind is not a registered kind (round-12 P0-01)';   // closed registry — no prototype-name / unknown kind
  if (decodeRec(cl.facts, FACTS_SCHEMA[cl.proof_kind])) return 'receipt facts not typed for proof_kind (round-10 P0-03 / round-13 P0-02)';   // TYPED per-kind facts — tsa endpoints are real calendar times
  return null;
}
// closedTransition (round-11 P0-04/P1-01): an epoch-transition witness is a CLOSED, TYPED ADT — envelope { claim, sig,
// issuer_id? }, a typed sig wrapper, and the claim's leaf values refined (from_sequence a CanonicalSeq, to_active_genesis a
// HASH, no extra signed field). ONE wire schema shared with buildEpochTransition (issuer_id is the redundant field the
// official builder emits; it is accepted and bound to sig.key_id when present, so builder output drives the checker).
function closedTransition(cm) {
  if (!closedRec(cm, ['claim', 'sig'], ['issuer_id'])) return 'epoch-transition witness must be { claim, sig, issuer_id? }';
  const es = decodeRec(cm.sig, SIG_ENV); if (es) return 'epoch-transition sig envelope not typed (round-11 ' + es + ')';
  if (cm.issuer_id !== undefined && cm.issuer_id !== cm.sig.key_id) return 'epoch-transition issuer_id ≠ sig.key_id';
  const ec = decodeRec(cm.claim, TRANSITION_CLAIM); if (ec) return 'epoch-transition claim not typed (round-11 ' + ec + ')';
  return null;
}
function sigOk(cp, auth) {
  const s = cp.sig;
  if (!s || s.alg !== 'Ed25519' || !strictPub(s.pub) || s.key_id !== auth.key_id || s.pub !== auth.pub || keyId(s.pub) !== s.key_id) return 'signer ≠ resolved authority';   // P1-04 strict pub
  if (strictB64url(s.sig, 64) === null || !edVerifyStrict(s.pub, canon({ purpose: 'ust:authority-checkpoint-signature', body: cp.body }), s.sig)) return 'checkpoint signature invalid';
  return null;
}
function rotationOk(b) {
  const ca = b.checkpoint_authority || {};
  const rot = [ca.next_key_id, ca.next_pub, ca.effective_sequence].filter((x) => x !== undefined).length;
  if (rot !== 0 && rot !== 3) return 'rotation fields must be all-present or all-absent';
  if (rot === 3) { if (!strictPub(ca.next_pub) || keyId(ca.next_pub) !== ca.next_key_id) return 'keyId(next_pub) ≠ next_key_id (or non-canonical next_pub)'; if (ca.effective_sequence !== String(BigInt(b.sequence) + 1n)) return 'effective_sequence ≠ seq+1'; }   // P1-05 strict rotation pub
  return null;
}
const nextAuthority = (b, signer) => { const ca = b.checkpoint_authority || {}; return (ca.next_key_id !== undefined && ca.effective_sequence === String(BigInt(b.sequence) + 1n)) ? { key_id: ca.next_key_id, pub: ca.next_pub } : signer; };
function appendOnly(prevKl, newKl, entriesWit) {
  const Lp = BigInt(prevKl.length), Ln = BigInt(newKl.length);
  if (Ln < Lp) return { err: 'key-log rewind (length decreased)' };
  if (Ln === Lp) return (newKl.root === prevKl.root && newKl.head === prevKl.head) ? {} : { err: 'equal-length key-log with a different root/head (rewrite)' };
  // GROWTH requires the prefix-extension witness (the entry vector): both keylogs are prefix commitments of it.
  if (!entriesWit || entriesWit.err || !Array.isArray(entriesWit.w)) return { err: 'growth edge requires a prefix-extension witness', ind: true };
  const E = entriesWit.w;
  if (E.length > 256 || !E.every(isHash)) return { err: 'prefix witness malformed or over the §13 ceiling' };
  // the entry vector must actually CONTAIN the claimed new length (round-12 P0-02): E.slice(0, Ln) silently CLAMPS, so a
  // one-entry vector would "grow" a length-2 key-log by re-committing the same single element. Require E.length >= Ln and
  // that the recomputed commitment LENGTHS equal the claimed lengths — not only root/head.
  if (BigInt(E.length) < Ln) return { err: 'prefix witness has fewer entries than the claimed new length (phantom growth)', ind: true };
  const kp = buildKeylogCommitment(E.slice(0, Number(Lp))), kn = buildKeylogCommitment(E.slice(0, Number(Ln)));
  if (kp.length !== prevKl.length || kn.length !== newKl.length) return { err: 'recomputed key-log length ≠ claimed length (phantom growth)', ind: true };
  if (kp.root !== prevKl.root || kp.head !== prevKl.head || kn.root !== newKl.root || kn.head !== newKl.head) return { err: 'key-logs are not prefixes of one entry vector (append-only unproven)', ind: true };
  return {};
}

// ─── PROVER (untrusted) + demoted public bundle. The prover assembles a candidate proof term π from RAW bundle
//     inputs (no verdicts, no trust); check_C is the SOLE acceptance oracle. This is the round-4 demotion: the old
//     producer stack no longer HONORS a strong verdict — it only proposes a term, and check_C accepts or rejects.
export function buildAuthorityProof(inputs = {}) {
  const { genesis, checkpoints = [], commitment, target, terminality, uniqueness, keylogEntries } = inputs || {};
  const witnesses = {};
  // normalize each witness (drop undefined-valued fields the prover may carry, e.g. an optional terminality field) so
  // the content address is over canon-clean bytes; the checker re-addresses identically.
  const put = (o) => { const c = JSON.parse(JSON.stringify(o ?? {})); const id = witnessId(c); witnesses[id] = c; return id; };
  const N = (rule, children = [], wids = [], params) => ({ rule, children, witnesses: wids, ...(params ? { params } : {}) });
  if (!genesis || !checkpoints.length) return { term: N('Genesis', [], [genesis ? put(genesis) : 'sha256:' + '00'.repeat(32)]), witnesses };
  const πG = N('Genesis', [], [put(genesis)]);
  let πChain = N('CheckpointZero', [πG], [put(checkpoints[0])]);
  const entW = keylogEntries !== undefined ? put(keylogEntries) : undefined;
  for (let i = 1; i < checkpoints.length; i++) πChain = N('CheckpointStep', [πChain], entW !== undefined ? [put(checkpoints[i]), entW] : [put(checkpoints[i])]);
  const last = checkpoints[checkpoints.length - 1], head = authorityCheckpointId(last);
  const πC = N('ConnectorEvidence', [πG], [put(commitment)], { subject: head });
  const πT = N('ConnectorEvidence', [πG], [put(target?.anchor)], { subject: target?.subject });
  const πAfter = N('AfterOrder', [πC, πT]);
  let root = N('Corroborated', [πChain, πC, πT, πAfter], [put(terminality || {})]);
  if (uniqueness?.map) root = N('ReinforceMap', [root, N('MapUnique', [πChain], [put({ proof: uniqueness.map.proof, mapRoot: uniqueness.map.mapRoot })])]);   // coordinate FROM πChain (B.1)
  if (uniqueness?.attestations) root = N('ReinforceQuorum', [root, N('QuorumAgreement', [πChain], uniqueness.attestations.map(put))]);
  return { term: root, witnesses };
}
// The ONE public authority verdict — prover ∘ check_C. Trust (connectors/mapRoots/witnesses/domains/threshold) comes
// ONLY from config, never from inputs (§2.w / round-4 P0-02). D1: returns base + anti-equivocation basis, never a
// collapsed scalar `attested`; the legacy `attested` label is a projection requiring MapUnique behind the K1 gate.
export function verifyAuthorityBundle(inputs = {}, config = {}) {
 try {   // round-28 P1-02 — I4 totality: a hostile getter/Proxy in inputs/config yields a STRUCTURED result, never a host throw (this self-contained byte-checker cannot reach admitDeep; the inner decoders are already total, this is the outer boundary guard)
  // round-46 (the REDUCTION metatheorem) — reduce EACH argument through the ONE side-effect-free admission (admitDeep reads DATA
  // descriptors, REJECTS accessors, never executes a getter/toJSON), replacing JSON.stringify which FIRED the input's getters/
  // toJSON. No caller code runs at the boundary, so a hostile inputs.toJSON that would rewrite the consumer config is IMPOSSIBLE —
  // structurally, not by admission order. This is the automaton reading its input as DATA (rev45 order + rev44 one-read subsumed).
  const C = admitInert(config), I = admitDeep(inputs);   // config = canonJSON domain; inputs → buildAuthorityProof → package = canon domain
  if (C === INERT_REJECT || typeof I === 'symbol') return Object.freeze({ result: 'E-MALFORMED', detail: 'authority bundle inputs/config are not inert records — an accessor/getter/toJSON is REJECTED, never executed (round-46)' });
  const trust = C?.trust ?? {}, policy = C?.policy ?? {};
  if ((C?.trust != null && (typeof trust !== 'object' || Array.isArray(trust))) || (C?.policy != null && (typeof policy !== 'object' || Array.isArray(policy)))) return Object.freeze({ result: 'INVALID', reason: 'config: E-CONFIG-POLICY (round-45 P1-01 — a present malformed trust/policy record is rejected, never normalized away to {}; the adapter defers to the sole-checker contract)' });
  if (!I?.genesis) return Object.freeze({ result: 'INDETERMINATE', reason: 'authority_unresolved', detail: 'no genesis — an authority bundle roots in a verified genesis' });
  const chkCfg = { connectors: trust.connectors || {}, mapRoots: trust.mapRoots || [], witnesses: trust.witnesses || {}, domains: trust.domains || {},
    policy: { ...(trust.uniqueness_threshold !== undefined ? { uniqueness_threshold: trust.uniqueness_threshold } : {}), allowExperimentalAttested: policy.allowExperimentalAttested === true } };   // round-44 P0-01 — NO threshold DEFAULT: pass the consumer value THROUGH the admitted snapshot (absent → omitted → kernel INDETERMINATE fail-closed; malformed → passed → kernel E-CONFIG-THRESHOLD). The adapter must not MANUFACTURE a quorum threshold the consumer never selected — the sole-checker contract is the law.
  const r = checkAuthorityProof(buildAuthorityProof(I), chkCfg);
  if (r.result !== 'VALID' || !r.judgment || r.judgment.kind !== 'Freshness')
    return Object.freeze(r.result === 'VALID'
      ? { result: 'INDETERMINATE', reason: 'authority_unresolved', judgment_kind: r.judgment.kind }   // round-45 P1-01 — the authority bundle's SUCCESS is EXCLUSIVE to a Freshness judgment: a VALID Genesis-only proof (no checkpoints) is authority_unresolved, NOT a public VALID (a generic caller reading .result must not see success for a non-freshness derivation)
      : { result: r.result, ...(r.reason ? { reason: r.reason } : {}), ...(r.judgment ? { judgment_kind: r.judgment.kind } : {}) });
  const j = r.judgment, aeq = j.aeq || {};
  const label = aeq.map && aeq.quorum ? 'dual-attested' : aeq.map ? 'map-attested' : aeq.quorum ? 'witness-attested' : 'corroborated';
  // K1 legacy projection: the scalar `attested` requires MapUnique (cryptographic non-membership) AND the experimental opt-in.
  const legacy = (aeq.map && chkCfg.policy.allowExperimentalAttested) ? 'attested' : 'corroborated';
  return Object.freeze({ result: 'VALID', scope_id: j.s, subject: j.q, head: j.h,
    keylog_freshness: j.base, label, anti_equivocation: { quorum: aeq.quorum || null, map: aeq.map || null },
    ...(aeq.map && !chkCfg.policy.allowExperimentalAttested ? { attested_withheld: 'experimental-gate' } : {}),
    legacy_freshness: legacy, support: j.support, proof_hash: r.proof_hash, config_id: r.config_id });
 } catch { return Object.freeze({ result: 'E-MALFORMED', detail: 'authority bundle inputs/config are not inert records (round-28 P1-02 totality)' }); }
}
