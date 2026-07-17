// SPDX-License-Identifier: Apache-2.0
// Generate the LANGUAGE-NEUTRAL byte-vectors for the rev3 checker boundary + a security-condition coverage manifest.
// Each vector is { id, note, package_b64url, config_b64url, expected: { result, code? } } — pure BYTES in, verdict out,
// so ANY implementation (Node / Rust / Go / WASM / Lean-extracted) can run checkAuthorityProofBytes over one corpus.
// The manifest maps each security side-condition → ≥1 negative vector (owner completion criterion 8). Regenerate then
// `git diff --exit-code` the outputs (like arc-vectors) so the corpus is deterministic.
import * as P from './index.mjs';
import { witnessId, canonJSON, REFERENCE_CHECKER_VERSION } from './reference-checker.mjs';
import { writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';

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
// canonical package = only the witnesses the term references (round-10 P1-03); the global `store` accumulates across
// vectors, so each package must be pruned to its own reachable set (an unreferenced witness is now E-WITNESS-UNREFERENCED).
const pkg = (rootTerm) => {
  const ref = new Set();
  (function walk(t) { for (const w of (t.witnesses || [])) ref.add(w); for (const c of (t.children || [])) walk(c); })(rootTerm);
  const witnesses = {};
  for (const k of Object.keys(store)) if (ref.has(k)) witnesses[k] = store[k];
  return { term: rootTerm, witnesses };
};
const CFG = { connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'btc-watch', allowed_proof_kinds: ['pow-header-chain', 'rfc3161-tsa'] } }, witnesses: { [Wa.key_id]: Wa.pub, [Wb.key_id]: Wb.pub }, domains: { [Wa.key_id]: 'op-a', [Wb.key_id]: 'op-b' }, policy: { uniqueness_threshold: 2 } };
const CFG_T = { connectors: { [KT.key_id]: { pub: KT.pub, trust_domain: 'tsa', allowed_proof_kinds: ['rfc3161-tsa'] } } };

// each vector supplies package bytes (canonical from an object, or a RAW string for byte-level malformed cases) + config.
const canonPkg = (rootTerm) => P.canon(pkg(rootTerm));
const V = [];
const add = (id, note, package_b64url, config_obj, expected) => V.push({ id, note, package_b64url, config_b64url: b64u(canonJSON(config_obj)), expected });

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

// rev4 round-7 cluster H (M-ORDER: identity namespaced by proof_kind; interval well-formedness).
const CFG_ORD = { connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'x', allowed_proof_kinds: ['pow-header-chain', 'transparency-log'] } } };
const evR = (subj, pk, facts) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: pk, facts, issued_at: '2026-01-01T00:00:00Z' }, KC.priv, KC.pub);
const πTlog = N('ConnectorEvidence', [πG], [put(evR(head, 'transparency-log', { substrate: 'shared-id', position: '900' }))], { subject: head });
const πPowShared = N('ConnectorEvidence', [πG], [put(evR('ust:target', 'pow-header-chain', { substrate: 'shared-id', position: '800' }))], { subject: 'ust:target' });
add('facts.wrong-kind', 'a transparency-log receipt carrying pow-style {substrate,position} facts (not its log_id/index) — closed-facts violation (round-10 P0-03)', b64u(canonPkg(N('Corroborated', [πChain, πTlog, πPowShared, N('AfterOrder', [πTlog, πPowShared])], [put(term)]))), CFG_ORD, { result: 'INVALID', code: 'facts not closed' });
const tsaIv = (subj, nb, na) => P.buildEvidenceReceipt({ domain_shard: 'good.example', active_genesis: AG, subject: subj, proof_kind: 'rfc3161-tsa', facts: { clock_id: 'clk', not_before: nb, not_after: na }, issued_at: '2026-01-01T00:00:00Z' }, KT.priv, KT.pub);
const πIvC = N('ConnectorEvidence', [πG], [put(tsaIv(head, '2026-12-31T00:00:00Z', '2026-01-01T00:00:00Z'))], { subject: head });
const πIvT = N('ConnectorEvidence', [πG], [put(tsaIv('ust:target', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'))], { subject: 'ust:target' });
add('order.inverted-interval', 'an interval with lower>upper yields no order', b64u(canonPkg(N('Corroborated', [πChain, πIvC, πIvT, N('AfterOrder', [πIvC, πIvT])], [put(term)]))), CFG_T, { result: 'INDETERMINATE', code: 'order' });

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
const caPkg = pkg(πChain); caPkg.witnesses[genW] = { ...caPkg.witnesses[genW], __tamper: 'x' };
add('witness.content-address', 'a tampered witness fails its content address', b64u(P.canon(caPkg)), CFG, { result: 'INVALID', code: 'E-WITNESS-ADDRESS' });

// F — semantic invariants (M-CONFIG): same package, config with a swapped witness pub → a DIFFERENT config_id.
// swapping witness pub VALUES at the same key_ids BREAKS admission (the attestations no longer verify) → INDETERMINATE,
// AND the config_id must differ from the genuine one — proof that config_id is extensional over pub values (P1-02).
add('config.pub-swap', 'witness pubs swapped at the same key_ids: quorum breaks + config_id changes', b64u(canonPkg(πWit)), { ...CFG, witnesses: { [Wa.key_id]: Wb.pub, [Wb.key_id]: Wa.pub } }, { result: 'INDETERMINATE', config_id_differs_from: 'accept.reinforce-quorum' });

// rev4 round-7 cluster G (M-DEC total + M-ADT): config canonicality, package closure over the decoded ADT, required params.
V.push({ id: 'config.noncanonical', note: 'whitespace-prefixed (non-canonical) config bytes', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u('  ' + canonJSON(CFG)), expected: { result: 'INVALID', code: 'E-CONFIG-NONCANONICAL' } });
add('package.extra-field', 'an extra top-level package field (schema not closed over raw JSON)', b64u(P.canon({ ...pkg(πCorr), __extra: 'x' })), CFG, { result: 'INVALID', code: 'E-NONCANONICAL' });
add('package.params-empty', 'an explicit params:{} node — a second wire form of the canonical (no-params) term', b64u(P.canon({ term: { ...πCorr, params: {} }, witnesses: pkg(πCorr).witnesses })), CFG, { result: 'INVALID', code: 'E-NONCANONICAL' });
add('term.missing-param', 'Anchored with required s/subject omitted', b64u(canonPkg(N('Anchored', [], [put(rc('ust:x', 1))]))), CFG, { result: 'INVALID', code: 'E-TERM-PARAM-MISSING' });
// cluster I (M-CONFIG P0-03): a trust domain is a typed VALUE — object domains are not typed strings, so they do not
// resolve and the quorum cannot be met (two structurally-identical objects never count as two distinct domains).
add('quorum.domain-object', 'object-valued trust domains are rejected at config decode (ControlDomain is a typed string)', b64u(canonPkg(πWit)), { ...CFG, domains: { [Wa.key_id]: { id: 'same' }, [Wb.key_id]: { id: 'same' } } }, { result: 'INVALID', code: 'E-CONFIG-DOMAIN' });

// rev5 round-8 — leaf totality (alg envelope), closed config schema, typed witnesses.
const algBad = (rcpt) => { const c = JSON.parse(JSON.stringify(rcpt)); c.sig.alg = 'NOT-ED25519'; return c; };
const rcAlgW = put(algBad(rc(head, 900))), πCAlg = N('ConnectorEvidence', [πG], [rcAlgW], { subject: head });
add('key.receipt-alg', 'a receipt whose sig.alg is not Ed25519 (valid sig bytes)', b64u(canonPkg(N('Corroborated', [πChain, πCAlg, πT, N('AfterOrder', [πCAlg, πT])], [put(term)]))), CFG, { result: 'INVALID', code: 'bad:alg' });
add('key.vote-alg', 'a quorum vote with sig.alg not Ed25519 is not admitted', b64u(canonPkg(N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(algBad(ua(Wa))), put(ua(Wb))])]))), CFG, { result: 'INDETERMINATE', code: 'quorum not met' });
V.push({ id: 'config.unknown-field', note: 'an unknown top-level config field', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, __junk: 'x' })), expected: { result: 'INVALID', code: 'E-CONFIG-FIELD' } });
V.push({ id: 'config.threshold-string', note: 'policy.uniqueness_threshold as a string is rejected, not silently defaulted', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, policy: { uniqueness_threshold: '999' } })), expected: { result: 'INVALID', code: 'E-CONFIG-THRESHOLD' } });
add('witness.namebound-object', 'NameBound key-log witness that is an object, not an array', b64u(canonPkg(N('NameBound', [πG], [put({ not: 'array' })], { doc_key_id: G.key_id }))), CFG, { result: 'INVALID', code: 'array' });
const rcExtraW = put((() => { const c = JSON.parse(JSON.stringify(rc(head, 900))); c.__extra = 'x'; return c; })()), πCX = N('ConnectorEvidence', [πG], [rcExtraW], { subject: head });
add('witness.receipt-extra-field', 'a receipt witness with an unknown outer field', b64u(canonPkg(N('Corroborated', [πChain, πCX, πT, N('AfterOrder', [πCX, πT])], [put(term)]))), CFG, { result: 'INVALID', code: 'not closed' });

// rev6 round-9 — typed witnesses for ALL kinds + a total/typed/closed config ADT.
const c0x = (() => { const c = JSON.parse(JSON.stringify(C0)); c.__extra = 'x'; return c; })();
add('witness.checkpoint-extra', 'a checkpoint witness with an unknown outer field', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0x)]))), CFG, { result: 'INVALID', code: 'checkpoint witness must be exactly' });
const termX = { headProof: kl.headProof, __extra: 'x' };
add('witness.terminality-extra', 'a terminality witness with an unknown field', b64u(canonPkg(N('Corroborated', [πChain, πC, πT, πAfter], [put(termX)]))), CFG, { result: 'INVALID', code: 'terminality witness must be exactly' });
const uaX = (W) => { const a = JSON.parse(JSON.stringify(ua(W))); a.claim.__x = 'x'; return a; };   // extra CLAIM field (would forge a distinct claim)
add('witness.attestation-extra-claim', 'a uniqueness attestation whose claim has an extra field is not admitted', b64u(canonPkg(N('ReinforceQuorum', [πCorr, N('QuorumAgreement', [πChain], [put(uaX(Wa)), put(uaX(Wb))])]))), CFG, { result: 'INDETERMINATE', code: 'quorum not met' });
V.push({ id: 'config.connector-string', note: 'a connector value that is a string, not an object', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, connectors: { [KC.key_id]: 'not-an-object' } })), expected: { result: 'INVALID', code: 'E-CONFIG-CONNECTOR' } });
V.push({ id: 'config.policy-array', note: 'policy is an array, not an object', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, policy: ['x'] })), expected: { result: 'INVALID', code: 'E-CONFIG-POLICY' } });
V.push({ id: 'config.apk-unsorted', note: 'allowed_proof_kinds not sorted/de-duplicated', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, connectors: { [KC.key_id]: { pub: KC.pub, trust_domain: 'x', allowed_proof_kinds: ['rfc3161-tsa', 'pow-header-chain'] } } })), expected: { result: 'INVALID', code: 'E-CONFIG-APK' } });

// ── rev7 round-10 — the typed decode boundary carried to every leaf (config policy / NFC / checkpoint body+sig / receipt claim / reachability) ──
// P0-01: an EMPTY policy array slipped past the (botched) shape guard and became a silent default-2 threshold; now rejected.
V.push({ id: 'config.policy-empty-array', note: 'policy:[] (empty array) must not become a silent default threshold (round-10 P0-01)', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ ...CFG, policy: [] })), expected: { result: 'INVALID', code: 'E-CONFIG-POLICY' } });
// P1-02: a non-NFC free-string config leaf is a STABLE E-CONFIG at decode, never an internal canon() throw.
V.push({ id: 'config.non-nfc-trust-domain', note: 'a decomposed (non-NFC) trust_domain → stable E-CONFIG, not a throw (round-10 P1-02)', package_b64url: b64u(canonPkg(πCorr)), config_b64url: b64u(canonJSON({ connectors: { [KC.key_id]: { pub: KC.pub, allowed_proof_kinds: ['pow-header-chain'], trust_domain: 'café' } } })), expected: { result: 'INVALID', code: 'E-CONFIG-TRUST-DOMAIN' } });
// P0-04: an extra field on the checkpoint SIG wrapper (no re-sign) is rejected — head_id cannot be shifted off one signature.
const c0SigX = { ...C0, sig: { ...C0.sig, wrapper_nonce: 'attacker-controlled' } };
add('checkpoint.sig-extra', 'a checkpoint sig wrapper carrying an extra field (round-10 P0-04)', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0SigX)]))), CFG, { result: 'INVALID', code: 'sig envelope not typed' });
// P0-05: an unknown checkpoint BODY field, even authority-signed, is rejected — the coordinate is over the CLOSED body.
const c0BodyX = P.sealAuthorityCheckpoint({ ...P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), extension_semantics: 'changes-head-but-not-the-rule' }, G.priv, G.pub);
add('checkpoint.body-extra', 'an authority-signed checkpoint body with an unknown field (round-10 P0-05)', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0BodyX)]))), CFG, { result: 'INVALID', code: 'body not typed' });
// P0-02: a receipt claim missing a required field (issued_at), re-signed by the issuer, is rejected — the claim ADT is closed.
const baseRc = rc(head, 900), incClaim = { ...baseRc.claim }; delete incClaim.issued_at;
const rcInc = { ...baseRc, claim: incClaim, sig: { ...baseRc.sig, sig: edSign(null, Buffer.from(P.canon({ purpose: 'ust:evidence-receipt-signature', claim: incClaim }), 'utf8'), KC.priv).toString('base64url') } };
const πCInc = N('ConnectorEvidence', [πG], [put(rcInc)], { subject: head });
add('receipt.claim-incomplete', 'a receipt claim missing issued_at, re-signed by the issuer (round-10 P0-02)', b64u(canonPkg(N('Corroborated', [πChain, πCInc, πT, N('AfterOrder', [πCInc, πT])], [put(term)]))), CFG, { result: 'INVALID', code: 'claim not typed' });
// P1-03: a content-addressed witness the term does NOT reference is dead weight the proof_hash can't cover → rejected.
add('witness.unreferenced', 'a content-addressed witness not referenced by the term (round-10 P1-03)', b64u(P.canon({ term: πChain, witnesses: { ...pkg(πChain).witnesses, [witnessId(JSON.parse(JSON.stringify(rc('ust:dangling', 1))))]: JSON.parse(JSON.stringify(rc('ust:dangling', 1))) } })), CFG, { result: 'INVALID', code: 'E-WITNESS-UNREFERENCED' });

// ── rev8 round-11 — TYPED leaf decoders: closure is not enough, each leaf VALUE is refined (constants/hash/seq) + interiors closed ──
// P0-01 receipt leaf VALUES are typed, not just present (version==="1", issued_at RFC3339-Z), re-signed by the issuer.
const reReceipt = (mut) => { const base = rc(head, 900), claim = { ...base.claim, ...mut }; return { ...base, claim, sig: { ...base.sig, sig: edSign(null, Buffer.from(P.canon({ purpose: 'ust:evidence-receipt-signature', claim }), 'utf8'), KC.priv).toString('base64url') } }; };
const πCVer = N('ConnectorEvidence', [πG], [put(reReceipt({ version: '999' }))], { subject: head });
add('receipt.version-not-typed', 'a re-signed receipt claim with version:"999" (leaf value not typed, round-11 P0-01)', b64u(canonPkg(N('Corroborated', [πChain, πCVer, πT, N('AfterOrder', [πCVer, πT])], [put(term)]))), CFG, { result: 'INVALID', code: 'claim not typed' });
const πCIat = N('ConnectorEvidence', [πG], [put(reReceipt({ issued_at: 'not-a-time' }))], { subject: head });
add('receipt.issued-at-not-typed', 'a re-signed receipt with issued_at:"not-a-time" (not RFC3339-Z, round-11 P0-01)', b64u(canonPkg(N('Corroborated', [πChain, πCIat, πT, N('AfterOrder', [πCIat, πT])], [put(term)]))), CFG, { result: 'INVALID', code: 'claim not typed' });
// P0-02 checkpoint version typed; P0-03 keylog root/head are HASHES (authority-signed, so the closure must catch them).
const c0Ver = P.sealAuthorityCheckpoint({ ...P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: kl.root, length: kl.length, head: kl.head } }), version: '999' }, G.priv, G.pub);
add('checkpoint.version-not-typed', 'an authority-signed checkpoint body with version:"999" (round-11 P0-02)', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0Ver)]))), CFG, { result: 'INVALID', code: 'body not typed' });
const c0Kl = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', active_genesis: AG, current_key_id: G.key_id, keylog: { root: 'not-a-hash', length: '0', head: 'also-not-a-hash' } }), G.priv, G.pub);
add('checkpoint.keylog-not-hash', 'an authority-signed checkpoint with a keylog root/head that are not hashes (round-11 P0-03)', b64u(canonPkg(N('CheckpointZero', [πG], [put(c0Kl)]))), CFG, { result: 'INVALID', code: 'body not typed' });
// P1-02 / P1-03 / P1-04 — inner proof/sig interiors are closed.
add('terminality.headproof-extra', 'a terminality headProof with an extra interior field (round-11 P1-02)', b64u(canonPkg(N('Corroborated', [πChain, πC, πT, πAfter], [put({ headProof: { ...kl.headProof, extension: 'ignored' } })]))), CFG, { result: 'INVALID', code: 'terminality witness' });
const r11leaf = P.checkpointMapLeaf({ domain_shard: 'good.example', genesis_epoch: EP, sequence: '0', checkpoint: head });
const r11map = P.buildVerifiableMap([r11leaf]);
add('map.proof-extra', 'an authenticated-map proof with an extra interior field (round-11 P1-03)', b64u(canonPkg(N('MapUnique', [πChain], [put({ proof: { ...r11map.prove(r11leaf.key), extension: 'ignored' }, mapRoot: r11map.root })]))), { mapRoots: [r11map.root] }, { result: 'INVALID', code: 'map-uniqueness witness' });
const voteX = (() => { const v = JSON.parse(JSON.stringify(ua(Wa))); v.sig.extension = 'ignored'; return v; })();
add('vote.sig-extra', 'a uniqueness vote whose sig wrapper carries an extra field → not counted (round-11 P1-04)', b64u(canonPkg(N('QuorumAgreement', [πChain], [put(voteX)]))), { witnesses: { [Wa.key_id]: Wa.pub }, domains: { [Wa.key_id]: 'op-a' }, policy: { uniqueness_threshold: 1 } }, { result: 'INDETERMINATE', code: 'quorum not met' });
// P0-04 epoch-transition claim is closed+typed (an extra signed field is rejected).
const WB11 = kp('b0'.repeat(32));
const genB11 = P.seal(P.buildGenesis({ domain_shard: 'good.example', ust_id: 'ust:20260716.01', key_id: WB11.key_id }, T, WB11.pub, undefined, undefined, undefined, { key_id: WB11.key_id, pub: WB11.pub }), WB11.priv, WB11.pub);
const txClaim = { purpose: 'ust:genesis-epoch-transition', domain_shard: 'good.example', from_genesis_epoch: EP, from_final_checkpoint: head, from_sequence: '0', to_active_genesis: P.contentHash(genB11), to_initial_sequence: '0', extension_semantics: 'signed-but-not-in-ADT' };
const txW = { claim: txClaim, sig: { alg: 'Ed25519', key_id: G.key_id, pub: G.pub, sig: edSign(null, Buffer.from(P.canon(txClaim), 'utf8'), G.priv).toString('base64url') } };
add('transition.claim-extra', 'an epoch-transition claim carrying an extra signed field (round-11 P0-04)', b64u(canonPkg(N('FutureGenesisCommitment', [πChain], [put(txW)]))), {}, { result: 'INVALID', code: 'claim not typed' });

// ── security-condition coverage manifest (owner completion criterion 8) ──────────────────────────────────────────────
const MANIFEST = {
  note: 'Every security side-condition maps to ≥1 negative byte-vector; the runner asserts each vector exists and holds. In round-7 this feeds a mutation harness (remove the condition → the listed vector must start failing).',
  security_conditions: [
    { id: 'BYTES-IMMUTABLE-CANONICAL', rule: 'decodePackage', negative_vectors: ['bytes.noncanonical.whitespace', 'bytes.noncanonical.duplicate-key', 'bytes.utf8'] },
    { id: 'TERM-EXACT-ADT', rule: 'decodeTerm', negative_vectors: ['term.unknown-rule', 'term.extra-child', 'term.extra-witness', 'term.free-param', 'term.stored-conclusion'] },
    { id: 'ORDER-SAME-IDENTITY', rule: 'AfterOrder', negative_vectors: ['order.cross-clock'] },
  { id: 'FACTS-CLOSED-PER-KIND', rule: 'ConnectorEvidence/closedReceipt', negative_vectors: ['facts.wrong-kind'] },
    { id: 'ORDER-INTERVAL-WELLFORMED', rule: 'AfterOrder/orderSemantic', negative_vectors: ['order.inverted-interval'] },
    { id: 'KEY-STRICT-PUB32', rule: 'Genesis/sigOk/ConnectorEvidence/QuorumAgreement', negative_vectors: ['key.padded-pub'] },
    { id: 'CONFIG-EXTENSIONAL-OVER-PUB', rule: 'normalizeConfig', negative_vectors: ['config.pub-swap'] },
    { id: 'AFTER-RELATES-ITS-EVIDENCES', rule: 'Corroborated', negative_vectors: ['rel.detached-after'] },
    { id: 'SCOPE-DOMAIN-AGREEMENT', rule: 'CheckpointZero/CheckpointStep', negative_vectors: ['scope.foreign-domain'] },
    { id: 'KEYLOG-CEILING', rule: 'CheckpointZero/CheckpointStep', negative_vectors: ['keylog.over-ceiling'] },
    { id: 'QUORUM-DOMAIN-BINDING', rule: 'QuorumAgreement', negative_vectors: ['quorum.foreign-domain'] },
    { id: 'QUORUM-TRUST-FROM-CONFIG', rule: 'QuorumAgreement', negative_vectors: ['quorum.self-trust'] },
    { id: 'WITNESS-CONTENT-ADDRESS', rule: 'decodePackage/W', negative_vectors: ['witness.content-address'] },
    { id: 'CONFIG-CANONICAL', rule: 'decodeConfig', negative_vectors: ['config.noncanonical'] },
    { id: 'PACKAGE-CLOSURE-DECODED-ADT', rule: 'decodePackage', negative_vectors: ['package.extra-field', 'package.params-empty'] },
    { id: 'TERM-REQUIRED-PARAMS', rule: 'decodeTerm', negative_vectors: ['term.missing-param'] },
    { id: 'QUORUM-DOMAIN-VALUE', rule: 'normalizeConfig/QuorumAgreement', negative_vectors: ['quorum.domain-object'] },
    { id: 'SIG-ALG-ENVELOPE', rule: 'ConnectorEvidence/QuorumAgreement', negative_vectors: ['key.receipt-alg', 'key.vote-alg'] },
    { id: 'CONFIG-CLOSED-SCHEMA', rule: 'normalizeConfig', negative_vectors: ['config.unknown-field', 'config.threshold-string'] },
    { id: 'TYPED-WITNESS', rule: 'NameBound/ConnectorEvidence', negative_vectors: ['witness.namebound-object', 'witness.receipt-extra-field'] },
    { id: 'TYPED-WITNESS-ALL-KINDS', rule: 'CheckpointZero/Corroborated/QuorumAgreement', negative_vectors: ['witness.checkpoint-extra', 'witness.terminality-extra', 'witness.attestation-extra-claim'] },
    { id: 'POLICY-CLOSED-NO-DEFAULT', rule: 'normalizeConfig/QuorumAgreement', negative_vectors: ['config.policy-empty-array'] },
  { id: 'CONFIG-NFC-LEAVES', rule: 'normalizeConfig', negative_vectors: ['config.non-nfc-trust-domain'] },
  { id: 'CHECKPOINT-SIG-CLOSED', rule: 'CheckpointZero/closedCheckpoint', negative_vectors: ['checkpoint.sig-extra'] },
  { id: 'CHECKPOINT-BODY-CLOSED', rule: 'CheckpointZero/closedCheckpoint', negative_vectors: ['checkpoint.body-extra'] },
  { id: 'RECEIPT-CLAIM-CLOSED', rule: 'ConnectorEvidence/closedReceipt', negative_vectors: ['receipt.claim-incomplete'] },
  { id: 'WITNESS-REACHABILITY', rule: 'decodePackage', negative_vectors: ['witness.unreferenced'] },
  { id: 'RECEIPT-LEAF-TYPED', rule: 'ConnectorEvidence/decodeRec', negative_vectors: ['receipt.version-not-typed', 'receipt.issued-at-not-typed'] },
  { id: 'CHECKPOINT-LEAF-TYPED', rule: 'CheckpointZero/decodeRec', negative_vectors: ['checkpoint.version-not-typed', 'checkpoint.keylog-not-hash'] },
  { id: 'TERMINALITY-INTERIOR-CLOSED', rule: 'Corroborated/HEAD_PROOF', negative_vectors: ['terminality.headproof-extra'] },
  { id: 'MAP-INTERIOR-CLOSED', rule: 'MapUnique/MAP_PROOF', negative_vectors: ['map.proof-extra'] },
  { id: 'VOTE-SIG-CLOSED', rule: 'QuorumAgreement/SIG_ENV', negative_vectors: ['vote.sig-extra'] },
  { id: 'TRANSITION-CLAIM-TYPED', rule: 'FutureGenesisCommitment/closedTransition', negative_vectors: ['transition.claim-extra'] },
  { id: 'CONFIG-TOTAL-TYPED', rule: 'normalizeConfig', negative_vectors: ['config.connector-string', 'config.policy-array', 'config.apk-unsorted'] },
  ],
  note_positive_shape: 'Positive-shape / arg-dependent invariants (config_id set-order equality P1-07; limits-getter totality P1-01; Uint8Array-only P2-01; single-read reads===1; carrier separation; permutation invariance) are covered by JS property tests in reference-checker.test.mjs, not negative byte-vectors — the {result,code} byte form cannot express a positive equality or a non-bytes input.',
};

const vectors = { protocol: 'UST', suite: 'checker-byte-vectors', reference_checker: REFERENCE_CHECKER_VERSION, note: 'language-neutral: decode base64url → bytes → checkAuthorityProofBytes(package, config); assert result and (for a negative) that reason contains code.', vectors: V };
writeFileSync(new URL('../../vectors/checker-byte-vectors.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
writeFileSync(new URL('../../vectors/checker-security-manifest.json', import.meta.url), JSON.stringify(MANIFEST, null, 2) + '\n');
console.log('wrote vectors/checker-byte-vectors.json (' + V.length + ' vectors) + vectors/checker-security-manifest.json (' + MANIFEST.security_conditions.length + ' conditions)');
