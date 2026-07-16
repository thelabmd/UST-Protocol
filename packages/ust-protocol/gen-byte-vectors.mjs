// SPDX-License-Identifier: Apache-2.0
// Generate the LANGUAGE-NEUTRAL byte-vectors for the rev3 checker boundary + a security-condition coverage manifest.
// Each vector is { id, note, package_b64url, config_b64url, expected: { result, code? } } — pure BYTES in, verdict out,
// so ANY implementation (Node / Rust / Go / WASM / Lean-extracted) can run checkAuthorityProofBytes over one corpus.
// The manifest maps each security side-condition → ≥1 negative vector (owner completion criterion 8). Regenerate then
// `git diff --exit-code` the outputs (like arc-vectors) so the corpus is deterministic.
import * as P from './index.mjs';
import { witnessId, REFERENCE_CHECKER_VERSION } from './reference-checker.mjs';
import { writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const kp = (h) => { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(h, 'hex')]), format: 'der', type: 'pkcs8' }); const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url'); return { priv, pub, key_id: P.keyId(pub) }; };
const T = { generated_at: '2026-07-16T00:00:00Z', valid_from: '2026-07-16T00:00:00Z', valid_to: '2026-07-16T01:00:00Z' };
const b64u = (s) => Buffer.from(s, 'utf8').toString('base64url');
const G = kp('cc'.repeat(32)), KC = kp('64'.repeat(32)), Wa = kp('a1'.repeat(32)), Wb = kp('a2'.repeat(32)), KT = kp('7b'.repeat(32));
const gen = P.seal(P.buildGenesis({ domain_shard: 'good.example', ust_id: 'ust:20260716.00', key_id: G.key_id }, T, G.pub, undefined, undefined, undefined, { key_id: G.key_id, pub: G.pub }), G.priv, G.pub);
const AG = P.contentHash(gen), EP = P.genesisEpoch(AG);
const kl = P.buildKeylogCommitment(['sha256:' + 'ab'.repeat(32)]);
const C0 = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
const head = P.authorityCheckpointId(C0), term = { headProof: kl.headProof };
const rc = (subj, pos) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: 'pow-header-chain', facts: { substrate: 'bitcoin', position: String(pos) }, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pub);
const tsa = (subj, clk) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: 'rfc3161-tsa', facts: { clock_id: clk, not_before: '2026-02-01T00:00:00Z', not_after: '2026-02-01T00:00:00Z' }, issued_at: '2026-01-01T00:00:00Z' }, KT.priv, KT.pub);
const ua = (W) => P.buildUniquenessAttestation({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);

// an untrusted prover assembling a package OBJECT; we then emit its canonical BYTES (what a bytes-native caller submits)
const store = {};
const put = (o) => { const c = JSON.parse(JSON.stringify(o)); const id = witnessId(c); store[id] = c; return id; };
const N = (rule, children = [], witnesses = [], params) => ({ rule, children, witnesses, ...(params ? { params } : {}) });
const πG = N('Genesis', [], [put(gen)]);
const πChain = N('CheckpointZero', [πG], [put(C0)]);
const πC = N('ConnectorEvidence', [πG], [put(rc(head, 900))], { subject: head });
const πT = N('ConnectorEvidence', [πG], [put(rc('ust:target', 800))], { subject: 'ust:target' });
const πAfter = N('AfterOrder', [πC, πT]);
const πCorr = N('Corroborated', [πChain, πC, πT, πAfter], [put(term)]);
const pkg = (rootTerm) => ({ term: rootTerm, witnesses: store });
const CFG = { connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain', 'rfc3161-tsa'] } }, witnesses: { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub }, domains: { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b' }, policy: { uniqueness_threshold: 2 } };
const CFG_T = { connectors: { [KT.key_id]: { pub: KT.pub, trust_domain: 'tsa', allowed_proof_kinds: ['rfc3161-tsa'] } } };

// each vector supplies package bytes (canonical from an object, or a RAW string for byte-level malformed cases) + config.
const canonPkg = (rootTerm) => P.canon(pkg(rootTerm));
const V = [];
const add = (id, note, package_b64url, config_obj, expected) => V.push({ id, note, package_b64url, config_b64url: b64u(JSON.stringify(config_obj)), expected });

// positive
add('accept.corroborated', 'genuine corroborated proof', b64u(canonPkg(πCorr)), CFG, { result: 'VALID', judgment_kind: 'Freshness' });
const πWit = N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(ua(Wa)), put(ua(Wb))])]);
add('accept.reinforce-quorum', 'quorum basis in aeq; support carries no quorum', b64u(canonPkg(πWit)), CFG, { result: 'VALID', judgment_kind: 'Freshness' });

// M-BYTE / M-DEC — the byte boundary
add('bytes.noncanonical.whitespace', 'pretty-printed (non-canonical) package bytes', b64u(JSON.stringify(pkg(πCorr), null, 2)), CFG, { result: 'INVALID', code: 'E-NONCANONICAL' });
add('bytes.noncanonical.duplicate-key', 'duplicate JSON keys collapse on parse, fail round-trip', b64u(canonPkg(πCorr).replace('{', '{"__x":"1","__x":"2",', 1)), CFG, { result: 'INVALID', code: 'E-NONCANONICAL' });
add('bytes.utf8', 'invalid UTF-8 package bytes', Buffer.from([0xff, 0xfe, 0x00]).toString('base64url'), CFG, { result: 'INVALID', code: 'E-UTF8' });
add('bytes.shape', 'a JSON array is not a { term, witnesses } package', b64u('[]'), CFG, { result: 'INVALID', code: 'E-PACKAGE-SHAPE' });

// M-DEC — exact Term ADT (P1-01)
add('term.unknown-rule', 'a constructor outside RULE_CONTRACTS', b64u(canonPkg(N('PredicateGraph', [], []))), CFG, { result: 'INVALID', code: 'E-TERM-RULE' });
add('term.extra-child', 'Corroborated with a 5th child', b64u(canonPkg(N('Corroborated', [πChain, πC, πT, πAfter, πChain], [put(term)]))), CFG, { result: 'INVALID', code: 'E-TERM-ARITY' });
add('term.extra-witness', 'Corroborated with a 2nd witness', b64u(canonPkg(N('Corroborated', [πChain, πC, πT, πAfter], [put(term), put(term)]))), CFG, { result: 'INVALID', code: 'E-TERM-WITNESS' });
add('term.free-param', 'a coordinate param on QuorumAgreement (must derive from πChain)', b64u(canonPkg(N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(ua(Wa)), put(ua(Wb))], { n: '999' })]))), CFG, { result: 'INVALID', code: 'E-TERM-PARAM' });
add('term.stored-conclusion', 'a node carrying `expected`', b64u(P.canon({ term: { rule: 'Genesis', children: [], witnesses: [put(gen)], expected: { tier: 'TOP' } }, witnesses: store })), CFG, { result: 'INVALID', code: 'E-TERM-FIELD' });

// E — canonical refined types (M-ORDER / M-KEY)
const πTsaC = N('ConnectorEvidence', [πG], [put(tsa(head, 'tsa-A'))], { subject: head });
const πTsaT = N('ConnectorEvidence', [πG], [put(tsa('ust:target', 'tsa-B'))], { subject: 'ust:target' });
add('order.cross-clock', 'two intervals on different clocks cannot be ordered', b64u(canonPkg(N('Corroborated', [πChain, πTsaC, πTsaT, N('AfterOrder', [πTsaC, πTsaT])], [put(term)]))), CFG_T, { result: 'INDETERMINATE', code: 'order' });
const genPad = P.seal(P.buildGenesis({ domain_shard: 'good.example', ust_id: 'ust:20260716.00', key_id: G.key_id }, T, G.pub, undefined, undefined, undefined, { key_id: G.key_id, pub: G.pub + '=' }), G.priv, G.pub);
add('key.padded-pub', 'a padded (non-canonical) checkpoint_authority pub', b64u(canonPkg(N('Genesis', [], [put(genPad)]))), CFG, { result: 'INVALID', code: 'checkpoint_authority' });

// earlier-round security conditions (rounds 3-5), now as normative TCB byte-vectors (not only object-adapter asserts):
// M-REL detached-After — an After ordering UNRELATED evidences does not satisfy Corroborated over commit/target.
const o1 = N('ConnectorEvidence', [πG], [put(rc('ust:other', 500))], { subject: 'ust:other' });
const o2 = N('ConnectorEvidence', [πG], [put(rc('ust:other2', 100))], { subject: 'ust:other2' });
add('rel.detached-after', 'After orders unrelated evidences', b64u(canonPkg(N('Corroborated', [πChain, πC, πT, N('AfterOrder', [o1, o2])], [put(term)]))), CFG, { result: 'INVALID', code: 'detached After' });
// §2.y scope — a checkpoint whose domain_shard ≠ the genesis domain (even with the same active_genesis).
const c0evil = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'evil.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), G.priv, G.pub);
add('scope.foreign-domain', 'checkpoint domain_shard ≠ genesis domain', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0evil)]))), CFG, { result: 'INVALID', code: 'domain_shard' });
// §13 key-log ceiling — a C0 claiming a 257-length key-log.
const c0big = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: '257', head: kl.head } }), G.priv, G.pub);
add('keylog.over-ceiling', 'C0 key-log length 257 > 256', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0big)]))), CFG, { result: 'INVALID', code: 'ceiling' });
// P0-03 quorum domain binding — attestations for a FOREIGN domain are not counted.
const uaEvil = (W) => P.buildUniquenessAttestation({ domain_shard: 'evil.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);
add('quorum.foreign-domain', 'votes for a foreign domain are not counted', b64u(canonPkg(N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(uaEvil(Wa)), put(uaEvil(Wb))])]))), CFG, { result: 'INDETERMINATE', code: 'quorum not met' });
// P0-02(r4) self-trust — a quorum of attacker witnesses NOT admitted by the consumer config.
const Ez1 = kp('e1'.repeat(32)), Ez2 = kp('e2'.repeat(32));
const uaE = (W) => P.buildUniquenessAttestation({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head }, W.priv, W.pub);
add('quorum.self-trust', 'attacker witnesses not admitted by config', b64u(canonPkg(N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(uaE(Ez1)), put(uaE(Ez2))])]))), CFG, { result: 'INDETERMINATE', code: 'quorum not met' });
// P0-03(r4) content address — a witness tampered after addressing fails its content address.
const genW = put(gen);
add('witness.content-address', 'a tampered witness fails its content address', b64u(P.canon({ term: πChain, witnesses: { ...store, [genW]: { ...store[genW], __tamper: 'x' } } })), CFG, { result: 'INVALID', code: 'content address' });

// F — semantic invariants (M-CONFIG): same package, config with a swapped witness pub → a DIFFERENT config_id.
// swapping witness pub VALUES at the same key_ids BREAKS admission (the attestations no longer verify) → INDETERMINATE,
// AND the config_id must differ from the genuine one — proof that config_id is extensional over pub values (P1-02).
add('config.pub-swap', 'witness pubs swapped at the same key_ids: quorum breaks + config_id changes', b64u(canonPkg(πWit)), { ...CFG, witnesses: { [Wa.key_id]: Wb.pub, [Wb.key_id]: Wa.pub } }, { result: 'INDETERMINATE', config_id_differs_from: 'accept.reinforce-quorum' });

// ── security-condition coverage manifest (owner completion criterion 8) ──────────────────────────────────────────────
const MANIFEST = {
  note: 'Every security side-condition maps to ≥1 negative byte-vector; the runner asserts each vector exists and holds. In round-7 this feeds a mutation harness (remove the condition → the listed vector must start failing).',
  security_conditions: [
    { id: 'BYTES-IMMUTABLE-CANONICAL', rule: 'decodePackage', negative_vectors: ['bytes.noncanonical.whitespace', 'bytes.noncanonical.duplicate-key', 'bytes.utf8'] },
    { id: 'TERM-EXACT-ADT', rule: 'decodeTerm', negative_vectors: ['term.unknown-rule', 'term.extra-child', 'term.extra-witness', 'term.free-param', 'term.stored-conclusion'] },
    { id: 'ORDER-SAME-IDENTITY', rule: 'AfterOrder', negative_vectors: ['order.cross-clock'] },
    { id: 'KEY-STRICT-PUB32', rule: 'Genesis/sigOk/ConnectorEvidence/QuorumAgreement', negative_vectors: ['key.padded-pub'] },
    { id: 'CONFIG-EXTENSIONAL-OVER-PUB', rule: 'normalizeConfig', negative_vectors: ['config.pub-swap'] },
    { id: 'AFTER-RELATES-ITS-EVIDENCES', rule: 'Corroborated', negative_vectors: ['rel.detached-after'] },
    { id: 'SCOPE-DOMAIN-AGREEMENT', rule: 'CheckpointZero/CheckpointStep', negative_vectors: ['scope.foreign-domain'] },
    { id: 'KEYLOG-CEILING', rule: 'CheckpointZero/CheckpointStep', negative_vectors: ['keylog.over-ceiling'] },
    { id: 'QUORUM-DOMAIN-BINDING', rule: 'QuorumAgreement', negative_vectors: ['quorum.foreign-domain'] },
    { id: 'QUORUM-TRUST-FROM-CONFIG', rule: 'QuorumAgreement', negative_vectors: ['quorum.self-trust'] },
    { id: 'WITNESS-CONTENT-ADDRESS', rule: 'decodePackage/W', negative_vectors: ['witness.content-address'] },
  ],
};

const vectors = { protocol: 'UST', suite: 'checker-byte-vectors', reference_checker: REFERENCE_CHECKER_VERSION, note: 'language-neutral: decode base64url → bytes → checkAuthorityProofBytes(package, config); assert result and (for a negative) that reason contains code.', vectors: V };
writeFileSync(new URL('../../vectors/checker-byte-vectors.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
writeFileSync(new URL('../../vectors/checker-security-manifest.json', import.meta.url), JSON.stringify(MANIFEST, null, 2) + '\n');
console.log('wrote vectors/checker-byte-vectors.json (' + V.length + ' vectors) + vectors/checker-security-manifest.json (' + MANIFEST.security_conditions.length + ' conditions)');
