// SPDX-License-Identifier: Apache-2.0
// ust-mcp — the agent-facing MCP surface over `ust-protocol` (+ `@ust-protocol/operator`). Two surfaces (bd 9oov):
//   PROTOCOL MCP = universal (create/verify/combine/resolve/anchor/verify-stream over the stateless base) — built here.
//   PRODUCT MCP  = noosphere business (pricing, archive depth, receipts) — separate, stubbed below.
// Methods are derived FROM the record's fields. This module is TRANSPORT-AGNOSTIC: it exports the tool
// registry + `dispatch()`; the stdio/SSE JSON-RPC server (via @modelcontextprotocol/sdk) is a thin shell the
// engine/deploy wires around `listTools()` + `dispatch(name, args)`.
import * as P from 'ust-protocol';
import { makeSsrfSafeFetch } from './ssrf-guard.mjs';
import { randomBytes } from 'node:crypto';

// #69 E4 — the MCP takes UNTRUSTED documents from agents and auto-fetches their domain_shard, so the discovery
// egress is resolution-guarded (a public NAME resolving to a private ADDRESS is refused) on top of the core's
// lexical SSRF floor. A single shared wrapper over global fetch, passed as resolveByDiscovery's fetchImpl.
// #43 — this surface supplies its OWN fetchImpl into the core, so it bypasses the core's signed default: a caller
// that brings its own client is not relabelled, and here the caller is US. Signed at the point it is built, so the
// SSRF guard and the label travel together and neither can be added without the other.
const ssrfSafeFetch = P.labelledFetch('ust-mcp', '1.0.0-rc.63', makeSsrfSafeFetch());

const doc1 = (state) => ({ ust: '1.0', state });
// build tools return the UNSIGNED state + the exact `signing_input` bytes; the caller (agent/operator) signs
// with its OWN Ed25519 key and assembles { ust, state, sig:{alg:'Ed25519', key_id, pub, sig} }. No key here.
const buildResult = (state) => ({ state, content_hash: P.contentHash(doc1(state)), signing_input: P.signedContent(doc1(state)) });

// §10 PRIVATE PARTITIONS FOR AGENTS (#178). The agent is the protocol's PRINCIPAL audience, and `blinded` is the
// mode it needs most: publish existence, time and integrity WITHOUT the value — prove what you did without
// disclosing what it was. It needs no key at all, only a nonce, so the reason that kept it off this surface
// ("key material does not belong in an agent's argument list") was true of `encrypted` and simply false here.
//
// PRIVACY IS DECLARED IN THE DATA, exactly as `ust sign` takes it and exactly as the wire carries it: a shard
// mixing open and closed members is the ordinary case, so a flag over the whole document would be the wrong
// shape. This is a translator, not a policy.
//
// THE ENVELOPE COMES BACK IN THE SAME OBJECT, and that is the structural form of an obligation the CLI can only
// state. §10 requires the nonce be freshly random, unique and never derived from the value; it is generated HERE,
// so a tool that returned the state without it would leave the agent holding a commitment nobody can ever open —
// not the reader, not itself. An agent cannot receive the one without the other, so the obligation cannot be
// declined rather than merely being documented.
//
// `encrypted` is not produced by THIS branch, and the reason is a claim about the ACT rather than about agents:
// CLOSED 2026-09-03 by `ust_sealing_request` + `ust_attach_encryption`, which give the agent both key-free
// halves and leave only the sealing with whoever owns the key. Historically the whole mode was withheld: the key
// would travel as a tool argument, hence through the model's context and into every transcript that records it.
// The owner's split is the answer and it is a separate piece of work — the agent computes the commitment and the
// canonical plaintext, a key-holder seals that exact string, and the key never enters the agent's context.
const withPrivacy = (data, domain_shard, ust_id) => {
  const out = {}, disclosures = {};
  for (const [name, decl] of Object.entries(data || {})) {
    if (!decl || typeof decl !== 'object' || decl.privacy === undefined) { out[name] = decl; continue; }
    // A DECLARATION carries `value` and asks to be turned into a partition; a partition already built — by the
    // key-holder split, or by any producer — carries `commit` and no plaintext, and passes through untouched.
    // Measured 2026-09-03 (#178) — CLOSED here: the round-257 branch keyed on the MODE alone, so a partition
    // assembled through the split was refused by the very builder it was assembled for. Telling a declaration
    // from a result by the mode is the same "one word, two mechanisms" the rule two rounds ago is about.
    if (decl.value === undefined && decl.commit !== undefined) { out[name] = decl; continue; }
    if (decl.privacy !== 'blinded')
      throw Object.assign(new Error(`partition \`${name}\` declares privacy \`${decl.privacy}\` — this surface produces \`blinded\` only. An \`encrypted\` partition needs an AEAD key, and a key passed as a tool argument travels through the agent's context; use the key-holder split (#178) or build it with ust-protocol directly.`), { code: 'E-UNSUPPORTED' });
    if (decl.value === undefined) throw new Error(`private partition \`${name}\` has no \`value\` — this tool commits to a value you supply; it cannot commit to nothing`);
    const nonce = randomBytes(16).toString('base64url');            // §10: freshly random, unique, never value-derived
    out[name] = P.blindPartition(name, decl.value, { domain_shard, ust_id, nonce, kind: decl.kind || 'captured' }).partition;
    disclosures[name] = { nonce, value: decl.value };
  }
  return { data: out, disclosures };
};

// ─── PROTOCOL MCP tools (universal) ──────────────────────────────────────────────────────────────────

// AUTO-RESOLUTION is the DEFAULT (owner: an agent gets a HIGH UST and by default sees LIGHT — or, above
// the floor, nothing; over MCP that is a total failure). The single P.resolveByDiscovery (rc.13) carries
// the SSRF guard + the one-copy resolve flow; this tool just calls it. Never silently authoritative:
// HIGH needs POSITIVE no-fork — collected automatically from the publisher's witness log (§12.1a, anchors
// cross-checked against Rekor/Bitcoin via the opt-in plugins) or, failing that, an explicit noForkConfirmed.

export const tools = [
  {
    name: 'ust_verify',
    description: 'VERIFY a UST document — ONE call, resolution included. If the document exceeds the anonymous 64-partition floor or claims a name, the tool AUTOMATICALLY fetches the publisher\'s §20.1 discovery surfaces (/.well-known/ust-genesis + ust-keylog + ust-witness) from the claimed name, resolves genesis→key-log, cross-checks the witness anchors against their substrate (Rekor/Bitcoin), and re-verifies with the capacity grant — you do NOT need to pre-fetch anything, and a witness-confirmed no-fork yields VALID:HIGH automatically (the result\'s `resolution.noFork` tells you how it was established: witness-confirmed / caller-asserted / unconfirmed). Pass offline:true to forbid the network (then supply genesis+keylog yourself; noForkConfirmed:true is YOUR air-gap assertion that no rival genesis exists). The verdict CARRIES ITS TIER — VALID:LIGHT | VALID:HIGH | VALID:TOP (or INVALID / INDETERMINATE); `publisher` is returned ONLY when authoritative, otherwise `publisher_claimed` (never attribute a claimed label as the real publisher). For UNTRUSTED transcripts pass `json` (raw text), not `doc` — it scans duplicate keys + non-NFC before parsing.',
    inputSchema: { type: 'object', properties: { doc: { type: 'object' }, json: { type: 'string' }, offline: { type: 'boolean', description: 'true = never touch the network (no discovery auto-fetch)' }, pinnedKeys: { type: 'array' }, genesis: { type: 'object' }, keylog: { type: 'array' }, proof: { type: 'object' }, disclosures: { type: 'object', description: '§10 BLINDED partitions: {partition: {nonce, value}} — the committed pair, which the verifier re-commits and compares. A wrong pair cannot forge, only fail to reveal.' }, decKeys: { type: 'object', description: '§10 ENCRYPTED partitions: {key_id: base64url-key}. Without it an encrypted partition stays opaque and the document still verifies at its full tier; with it the AEAD channel is checked against the commitment (E-COMMIT if the two disagree). Pass BOTH this and `disclosures` to reach both privacy modes in one call.' }, noForkConfirmed: { type: 'boolean' }, noForkEvidence: { type: 'object', description: 'consumer-supplied WITNESS-signed no-fork attestation (offline/air-gapped path); with trustRoots ⇒ INDEPENDENT authoritative, not the weaker consumer-override of noForkConfirmed' }, trustRoots: { type: 'object', description: 'witness/authority pubkeys the CONSUMER trusts, { key_id: pubB64 } — consumer-rooted, NEVER from the doc/evidence (P0-01)' }, trust: { type: 'object', description: 'consumer trust config e.g. { mapRoots: [root] } — admits an authenticated-map root for map-based uniqueness (§12.3.4)' }, nameMap: { type: 'object', description: 'authenticated-map proof for domain→active-genesis uniqueness ⇒ identity authoritative (map basis, §12.3)' }, requireAuthoritative: { type: 'boolean', description: 'floor at HIGH — reject anything not name-authoritative (E-GENESIS)' }, requireAnchored: { type: 'boolean', description: 'floor at TOP — reject anything not anchored (downgrade resistance, §3.1/F.5b): a stripped/absent anchor ⇒ E-ANCHOR, a substrate-unavailable one ⇒ INDETERMINATE, never a silent lower-tier accept' }, soft: { type: 'boolean', description: '#44 agent-safety: by DEFAULT an INVALID verdict is returned as an ERROR response (isError) you MUST acknowledge — you cannot skip it as a data field. Set soft:true to OPT IN to the advisory path (INVALID returned as data). The structured verdict rides the error either way.' }, requireFreshKeylog: { type: 'boolean', description: '#40 floor: reject a possibly-stale key-log (freshness unverified) ⇒ INDETERMINATE stale_keylog (re-fetch from discovery), never a silent accept on a cached view that may miss a revocation.' }, keylogFreshAsOf: { type: 'string', description: '#40 (round-16 P0-02) a raw timestamp is a CALLER CLAIM and can NOT mint freshness:fresh — fresh is EARNED only by an authenticated discovery fetch (resolveByDiscovery). A bare value stays freshness:unverified.' }, keylogHeadAnchor: { type: 'object', description: '#40 a VERIFIED anchor inclusion proof for the key-log HEAD (checked against the substrate: inclusion + final ⇒ freshness:attested). A raw head hash is NOT accepted — it proves nothing (rc.28 audit).' }, capacity: { type: 'object', description: 'trusted capacity grant {maxPartitions?, maxTranscriptBytes?} — pass what resolveAuthority returned as .capacity (rc.12)' }, maxSupportedBytes: { type: 'number' } } },
    handler: async ({ doc, json, offline, pinnedKeys, genesis, keylog, proof, disclosures, decKeys, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, requireAuthoritative, requireAnchored, soft, requireFreshKeylog, keylogFreshAsOf, keylogHeadAnchor, capacity, maxSupportedBytes }) => {
      const o = { pinnedKeys, genesis, keylog, disclosures, decKeys, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, requireAuthoritative, requireAnchored, requireFreshKeylog, keylogFreshAsOf, keylogHeadAnchor, capacity, maxSupportedBytes, context: 'data' };
      // #44/#75 P1-04 throw-on-non-VALID: ANY non-VALID verdict (INVALID *or* INDETERMINATE) becomes an isError
      // response (dispatch catches the throw) unless soft:true — matching spec §15.1. A lazy agent must NOT be able
      // to read INDETERMINATE as a data field and proceed as if it got an answer (that is the exact footgun #44
      // closes). isError forces acknowledgment; the structured `verdict` (carried by dispatch) says reject vs retry:
      // INVALID (`error`) ⇒ reject; INDETERMINATE (`reason`) ⇒ cannot-decide, retry/degrade — never proceed.
      const gate = (v) => {
        if (!soft && typeof v?.result === 'string' && !v.result.startsWith('VALID:')) {
          const retry = v.result === 'INDETERMINATE';
          throw Object.assign(new Error(retry
            ? 'UST INDETERMINATE (' + (v.reason || 'unavailable') + ') — cannot decide; retry or degrade, do NOT proceed' + (v.detail ? ': ' + v.detail : '')
            : 'UST verification failed: ' + (v.error || 'INVALID') + (v.detail ? ' — ' + v.detail : '')), { verdict: v });
        }
        return v;
      };
      // `json` (raw text) = the safe conformance boundary — duplicate-key + NFC scan BEFORE parse (F7).
      const ro = { ...o, offline };
      const _plugins = [], _incPlugins = [];
      for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify', '@ust-protocol/rfc6962-verify']) {
        try { const m = await import(pkg); if (m.substrateVerify) _plugins.push(m.substrateVerify); if (m.inclusionVerify) _incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
      }
      const substrateVerify = _plugins.length ? P.combineSubstrates(_plugins) : undefined;
      // #95 — the SAME installed plugins, asked the OTHER question. Safe to pass unconditionally: a router that claims
      // nothing returns null and the seam falls through to the bundled walk, so the caller need not know what it holds.
      const inclusionVerify = _incPlugins.length ? P.combineInclusion(_incPlugins) : undefined;
      if (json !== undefined) {
        const raw = P.verifyJson(json, o);
        if (offline || genesis !== undefined || !(raw.result === 'VALID:LIGHT' || (raw.result === 'INDETERMINATE' && raw.reason === 'unavailable'))) return gate(raw);
        let parsed; try { parsed = JSON.parse(json); } catch { return gate(raw); }
        const { verdict, resolution } = await P.resolveByDiscovery(parsed, { ...ro, inclusionVerify }, { substrateVerify, fetchImpl: ssrfSafeFetch });
        return gate(resolution ? { ...verdict, resolution } : verdict);
      }
      // an embedded doc.proof is verified INSIDE verify (present-bad ⇒ E-ANCHOR); a separately-passed proof merges in.
      const d = (proof !== undefined && doc && doc.proof === undefined) ? { ...doc, proof } : doc;
      if (offline || genesis !== undefined) return gate(P.verify(d, o));
      const { verdict, resolution } = await P.resolveByDiscovery(d, { ...ro, inclusionVerify }, { substrateVerify, fetchImpl: ssrfSafeFetch });
      return gate(resolution ? { ...verdict, resolution } : verdict);
    },
  },
  {
    name: 'ust_build_observation',
    description: 'CREATE (build, unsigned) an observation State from partitions; returns state + content_hash + signing_input to sign with your own Ed25519 key.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data }) => { const w = withPrivacy(data, domain_shard, ust_id); return { ...buildResult(P.buildState({ domain_shard, ust_id, key_id, class: 'observation' }, time, w.data)), ...(Object.keys(w.disclosures).length ? { disclosures: w.disclosures } : {}) }; },
  },
  {
    name: 'ust_sealing_request',
    description: 'PREPARE an `encrypted` partition WITHOUT holding a key: returns the commitment, the exact plaintext a key-holder must seal, and the IV that commitment implies. Hand the request to whoever owns the key, then pass their {alg,key_id,ct} back through `ust_attach_encryption`. The nonce is generated here and returned — keep it, or the commitment can never be opened.',
    inputSchema: { type: 'object', required: ['name', 'value', 'domain_shard', 'ust_id'], properties: { name: { type: 'string' }, value: { type: 'object' }, domain_shard: { type: 'string' }, ust_id: { type: 'string' }, nonce: { type: 'string', description: 'optional — generated here when absent, and returned either way' }, alg: { type: 'string' } } },
    // #178 — the owner's split. `encryptPartition` derives what must be sealed AND seals it; only the second half
    // needs a key, and a key passed as a tool argument travels through the model's context into every transcript
    // recording it. So the agent does the first half and the key-holder does the second.
    //
    // F.7a.2's producer corollary demands ONE derivation, not one process: the sealer receives exactly the string
    // the commitment was taken over, so the two channels cannot drift — measured, the split's output is
    // BYTE-IDENTICAL to `encryptPartition`'s.
    //
    // The key-holder receives the PLAINTEXT. Inherent — they are the party entitled to read it — but when the
    // key-holder is a third party rather than the publisher's own operator, the value travels somewhere it did
    // not before. Choose the key-holder accordingly.
    handler: ({ name, value, domain_shard, ust_id, nonce, alg }) => {
      const n = typeof nonce === 'string' && nonce ? nonce : randomBytes(16).toString('base64url');
      return { ...P.sealingRequest(name, value, { domain_shard, ust_id, nonce: n, ...(alg ? { alg } : {}) }), nonce: n, disclosures: { [name]: { nonce: n, value } } };
    },
  },
  {
    name: 'ust_attach_encryption',
    description: 'ASSEMBLE an `encrypted` partition from a block a key-holder sealed. No key here and none needed — and it CHECKS the seam: the ciphertext must carry the IV the commitment implies, so a sealer that worked from its own derivation is caught by a caller holding no key.',
    inputSchema: { type: 'object', required: ['name', 'commit', 'key_id', 'ct'], properties: { name: { type: 'string' }, commit: { type: 'string' }, key_id: { type: 'string' }, ct: { type: 'string' }, alg: { type: 'string' }, kind: { type: 'string' } } },
    handler: ({ name, commit, key_id, ct, alg, kind }) => P.attachEncryption(name, { commit, key_id, ct, ...(alg ? { alg } : {}), ...(kind ? { kind } : {}) }),
  },
  {
    name: 'ust_seal',
    description: 'ASSEMBLE a signed transcript from a signature you made yourself. Pass the state you built, your base64url `pub`, and the signature over `signing_input`. The PRIVATE KEY NEVER TRAVELS — this tool derives key_id from pub, assembles the envelope and VERIFIES it, refusing to hand back a document a reader would reject.',
    inputSchema: { type: 'object', required: ['state', 'pub', 'sig'], properties: { state: { type: 'object' }, pub: { type: 'string', description: 'base64url raw Ed25519 public key — key_id is DERIVED from it, never supplied' }, sig: { type: 'string', description: 'base64url Ed25519 signature over the `signing_input` a build tool returned' } } },
    // #178 — the signing key is the one secret that must never reach an agent's argument list, and it does not
    // here: this is the ASSEMBLY half of `seal`, which needs no key at all. The half that does stays outside,
    // exactly where it already was. What changes is that the surface now takes something BACK — before this,
    // `signing_input` went out and nothing returned, so nowhere in the flow was "the parts you assembled actually
    // verify" ever checked. An agent that skipped its own verification published documents every reader refuses.
    handler: ({ state, pub, sig }) => { const doc = P.attachSignature(state, { pub, sig }); return { doc, content_hash: P.contentHash(doc) }; },
  },
  {
    name: 'ust_combine_derivation',
    description: 'COMBINE: build (unsigned) a derivation that chains to other records by content_hash (based_on) with an auto-computed order-bearing seed.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data', 'based_on'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' }, based_on: { type: 'array' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data, based_on }) => { const w = withPrivacy(data, domain_shard, ust_id); return { ...buildResult(P.buildDerivation({ domain_shard, ust_id, key_id }, time, w.data, based_on)), ...(Object.keys(w.disclosures).length ? { disclosures: w.disclosures } : {}) }; },
  },
  {
    name: 'ust_combine_attestation',
    description: 'COMBINE: build (unsigned) an attestation over N constituent content_hashes with an auto-computed Merkle root.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data', 'constituents'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' }, constituents: { type: 'array' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data, constituents }) => { const w = withPrivacy(data, domain_shard, ust_id); return { ...buildResult(P.buildAttestation({ domain_shard, ust_id, key_id }, time, w.data, constituents)), ...(Object.keys(w.disclosures).length ? { disclosures: w.disclosures } : {}) }; },
  },
  {
    name: 'ust_build_genesis',
    description: 'CEREMONY (build, unsigned): a name-binding GENESIS — the self-signed root that weds a domain to a key (§12.1). Returns the unsigned genesis State + content_hash + signing_input; the operator signs it with its OWN ROOT key (this tool holds NO key — a shared signing key would be a forgery oracle). Then publish at https://<domain>/.well-known/ust-genesis + mirrors, and anchor its content_hash. Optional signed `max_partitions` declares the operator\'s partition capacity (bounds earned by ceremony).',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'pub', 'time'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string', description: 'the ROOT key_id (self-signed: must equal the signing key)' }, pub: { type: 'string' }, time: { type: 'object' }, max_partitions: { type: 'number' } } },
    handler: ({ domain_shard, ust_id, key_id, pub, time, max_partitions }) => {
      const value = { pub, role: 'name-binding-root', ...(max_partitions ? { max_partitions: String(max_partitions) } : {}) };
      return buildResult(P.buildState({ domain_shard, ust_id, key_id, class: 'genesis' }, time, { genesis: { kind: 'captured', value } }));
    },
  },
  {
    name: 'ust_build_key_log',
    description: 'CEREMONY (build, unsigned): a KEY-LOG entry (§12.2) that ADDs or REVOKEs a key — there is deliberately no `rotate` op (rev97: a self-authorized succession let a compromised key name its own successor); a replacement is `add(supersedes=s)` then `revoke(s, retired)`, prev-chained to the previous entry (or the genesis content_hash for the first). Returns the unsigned State + signing_input; sign with the CURRENTLY-VALID key. This is how a genesis root delegates to daily operational keys and how compromise is revoked.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'key_op', 'prev'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, key_op: { type: 'object', description: '{ op:"add", pub, new_key_id?, supersedes?, role? } | { op:"revoke", pub, reason, compromised_since? } | { op:"reroot", to_genesis } — `supersedes` NAMES the key being replaced (never inferred from position); `role` is admissible only if the genesis DECLARES roles; `reroot` is the SIGNED half of a §12.1 P2 supersession and is TERMINAL — no entry may follow it' }, prev: { type: 'string', description: 'content_hash of the prior key-log entry, or of the genesis for the first' } } },
    handler: ({ domain_shard, ust_id, key_id, time, key_op, prev }) => buildResult(P.buildKeyLogEntry({ domain_shard, ust_id, key_id }, time, key_op, prev)),
  },
  {
    name: 'ust_build_cadence',
    description: 'CEREMONY (build, unsigned): a CADENCE entry (§11.3) declaring the stream grid in seconds from effective_from onward, prev-chained from the GENESIS content_hash for the first entry — the cadence log is its OWN chain, not a continuation of the key-log. Sign it with a key ACTIVE in the key-log; the genesis key qualifies by construction, so declaring a cadence needs no warm operational key. effective_from MUST be a FUTURE slot: a change never rewrites the grid of slots already published, and older ranges keep verifying under the cadence in force at their own time.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'cadence', 'effective_from', 'prev'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, cadence: { type: 'string', description: 'seconds as a canonical positive-integer STRING (§11.3): "30", never 30 or "1.5" or "030"' }, effective_from: { type: 'string', description: 'the ust_id slot this cadence takes effect at — a FUTURE one' }, prev: { type: 'string', description: 'content_hash of the previous cadence entry, or of the GENESIS for the first' } } },
    handler: ({ domain_shard, ust_id, key_id, time, cadence, effective_from, prev }) => buildResult(P.buildCadenceEntry({ domain_shard, ust_id, key_id }, time, cadence, effective_from, prev)),
  },
  {
    name: 'ust_resolve_cadence',
    description: 'WHAT GRID DOES THIS PUBLISHER DECLARE at a given moment? Resolves the §11.3 cadence in force at `at` from the genesis value plus the signed cadence log, verifying every entry (signature, class, domain, prev-chain from the genesis content_hash, a CURRENTLY-ACTIVE signer, monotonic effective_from). Returns {cadence} — and a null cadence is a POSITIVE fact: this publisher declares no grid, so its stream can never earn better than chain-consistent (no-deletion) and a no-omission claim is unavailable to it. Feed the same log to ust_verify_stream for the completeness verdict itself.',
    inputSchema: { type: 'object', required: ['genesis', 'at'], properties: { genesis: { type: 'object' }, cadence_log: { type: 'array', description: 'entries from /.well-known/ust-cadence in chain order; omit or [] when the publisher serves none' }, at: { type: 'string', description: 'the ust_id (or RFC3339 instant) to resolve AT — the answer is time-relative by design' }, keylog: { type: 'array', description: 'REQUIRED to authorize a signer other than the genesis key; without it only the genesis key can move the grid (fail-closed)' } } },
    handler: ({ genesis, cadence_log, at, keylog }) => P.resolveCadence(genesis, cadence_log ?? [], at, { keylog: keylog ?? [] }),
  },
  {
    name: 'ust_resolve',
    description: 'RESOLVE name authority: given a document, its publisher genesis + key-log, and CONSUMER-supplied no-fork evidence, return the identity strength (authoritative / corroborated / consumer-override / self-asserted) + status. INDEPENDENT authoritative needs witness noForkEvidence (or an authenticated nameMap) validated against consumer trustRoots; a bare noForkConfirmed is only a consumer-override, NOT authoritative.',
    inputSchema: { type: 'object', required: ['doc', 'genesis', 'keylog'], properties: { doc: { type: 'object' }, genesis: { type: 'object' }, keylog: { type: 'array' }, noForkConfirmed: { type: 'boolean' }, noForkEvidence: { type: 'object', description: 'consumer-supplied WITNESS-signed no-fork attestation; with trustRoots ⇒ INDEPENDENT authoritative, not the weaker consumer-override of noForkConfirmed' }, trustRoots: { type: 'object', description: 'witness/authority pubkeys the CONSUMER trusts, { key_id: pubB64 } — consumer-rooted, NEVER from the doc/evidence (P0-01)' }, trust: { type: 'object', description: 'consumer trust config e.g. { mapRoots: [root] } — admits an authenticated-map root for map-based uniqueness (§12.3.4)' }, nameMap: { type: 'object', description: 'authenticated-map proof for domain→active-genesis uniqueness ⇒ identity authoritative (map basis, §12.3)' }, anchorTime: { type: "string", description: "(round-17 P0-02) a raw timestamp is a CALLER CLAIM and is NOT honored as the proven K_n(t) upper bound — the temporal window needs a VERIFIED anchor. Use the verify tool with the document proof; a bare value is ignored (fail-closed)." }, keylogFreshAsOf: { type: 'string', description: '#40 (round-16 P0-02) a raw string is a caller claim, NOT freshness:fresh — earned only via an authenticated discovery fetch; a bare value stays unverified' }, keylogHeadAnchor: { type: 'object', description: '#40 a verified anchor inclusion proof for the key-log head → freshness:attested (a raw hash is not accepted, rc.28)' } } },
    handler: ({ doc, genesis, keylog, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, anchorTime, keylogFreshAsOf, keylogHeadAnchor }) => P.resolveAuthority(doc, { genesis, keylog, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, anchorTime, keylogFreshAsOf, keylogHeadAnchor }),
  },
  {
    name: 'ust_anchor_verify',
    description: 'ANCHOR: verify a self-contained time proof — recompute the Merkle inclusion path from a content_hash to the anchored root (substrate verification is delegated).',
    inputSchema: { type: 'object', required: ['content_hash', 'proof'], properties: { content_hash: { type: 'string' }, proof: { type: 'object' } } },
    handler: ({ content_hash, proof }) => P.verifyAnchor(content_hash, proof),
  },
  {
    name: 'ust_verify_stream',
    description: 'VERIFY A RANGE as one authority\'s stream — e.g. you fetched ust(001)…ust(007) from an archive: every frame LIGHT-verifies, they are prev-chained, all belong to ONE publisher (mixed publishers → E-AUTHORITY), and a covering checkpoint closes the interval. Returns { complete: "complete" | "chain-consistent" | "provisional" | "none" } or an error (E-PREV broken/forked chain · E-AUTHORITY mixed authority · E-SIG bad frame). #69 C: "chain-consistent" proves NO-DELETION over the shown chain; "complete" (no-OMISSION) is stronger and is reached ONLY when the publisher\'s genesis carries a SIGNED cadence and the covering checkpoint carries interval bounds (from,to) — then every expected grid slot must be a frame or a signed gap record (data.gap); any hole → "chain-consistent" + names the hole. The signed cadence (not a per-checkpoint choice) is what stops a publisher claiming a coarser grid to hide slots. Retrieval is NOT the protocol\'s job — pass the records you already have.',
    inputSchema: { type: 'object', required: ['frames'], properties: { frames: { type: 'array' }, genesis: { type: 'object' }, keylog: { type: 'array', description: 'the publisher key-log — REQUIRED to authorize a cadenceLog (a cadence change must be signed by a genesis/key-log key, not any doc with the same domain)' }, checkpoint: { type: 'object' }, cadenceLog: { type: 'array', description: '§11.3 cadence-log entries — resolves the cadence in force at the interval so `complete` survives a cadence change (old data stays complete under its old cadence)' } } },
    handler: ({ frames, genesis, keylog, checkpoint, cadenceLog }) => P.verifyStream(frames, { genesis, keylog, checkpoint, cadenceLog }),
  },
  {
    name: 'ust_fork_choice',
    description: 'FORK-CHOICE for one ust_id — when you hold TWO OR MORE documents that claim the SAME ust_id with DIFFERENT content (a dual-writer race: main + failover both sealed the slot; or an adversary offering two states), this decides WHICH is canonical so you never accept both. The rule (§3.1/F.5c): canonical = the one whose content_hash is INCLUDED in the authority\'s anchored hour root. Returns { result:"CANONICAL", canonical, content_hash, losers } when exactly one is anchor-included; "INDETERMINATE" when none is anchored yet (wait for the hour anchor or resolve at HIGH); "E-PREV" when one authority anchored TWO distinct states for the slot (operator equivocation — a punishable fault); "MULTI_AUTHORITY" when distinct names share the ust_id string (not a fork); "E-MALFORMED" if the candidates do not all share one ust_id. Deterministic: the chain decides, never local fetch order. Pass all candidate documents (each with its own embedded proof); the tool cross-checks each anchor against its substrate automatically.',
    inputSchema: { type: 'object', required: ['candidates'], properties: { candidates: { type: 'array', description: 'the competing documents for one ust_id, each with its embedded `proof`' }, genesis: { type: 'object' }, keylog: { type: 'array' }, noForkConfirmed: { type: 'boolean' }, offline: { type: 'boolean' } } },
    handler: async ({ candidates, genesis, keylog, noForkConfirmed, offline }) => {
      const _plugins = [], _incPlugins = [];
      if (!offline) for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify', '@ust-protocol/rfc6962-verify']) {
        try { const m = await import(pkg); if (m.substrateVerify) _plugins.push(m.substrateVerify); if (m.inclusionVerify) _incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
      }
      const substrateVerify = _plugins.length ? P.combineSubstrates(_plugins) : undefined;
      // #95 — the SAME installed plugins, asked the OTHER question. Safe to pass unconditionally: a router that claims
      // nothing returns null and the seam falls through to the bundled walk, so the caller need not know what it holds.
      const inclusionVerify = _incPlugins.length ? P.combineInclusion(_incPlugins) : undefined;
      return P.forkChoice(candidates, { genesis, keylog, noForkConfirmed, offline, context: 'data', substrateVerify, inclusionVerify });
    },
  },
  {
    name: 'ust_key_id',
    description: 'Derive the key_id for a public key: H("ust:keylog", raw_pubkey_bytes) — domain-separated over the base64url-decoded key.',
    inputSchema: { type: 'object', required: ['pub'], properties: { pub: { type: 'string' } } },
    handler: ({ pub }) => ({ key_id: P.keyId(pub) }),
  },
  {
    name: 'ust_canon',
    description: 'Canonicalize a JSON value (JCS tightened): the exact bytes UST hashes/signs. Utility for building your own signer.',
    inputSchema: { type: 'object', required: ['value'], properties: { value: {} } },
    handler: ({ value }) => ({ canonical: P.canon(value) }),
  },
];

const toolMap = Object.fromEntries(tools.map(t => [t.name, t]));
export const listTools = () => tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema }));
// dispatch a tool call → MCP-style result. ASYNC (rc.11: auto-resolution fetches the discovery pair);
// never throws — a handler error OR rejection becomes an isError result (fail-closed).
export async function dispatch(name, args = {}) {
  const t = toolMap[name];
  if (!t) return { isError: true, error: 'unknown tool: ' + name };
  try { return { result: await t.handler(args) }; }
  catch (e) { return { isError: true, error: e.message || String(e), ...(e.verdict ? { verdict: e.verdict } : {}) }; }   // #44: a structured verdict rides the error so the agent can branch, not just see a string
}

// ─── PRODUCT MCP (noosphere business) — separate surface, stubbed. Never mixed with the universal protocol MCP.
export const productTools = [
  { name: 'noosphere_price', description: 'Quote a receipt/archive-depth price (x402 unit-of-sale). [stub — product MCP]', stub: true },
  { name: 'noosphere_receipt', description: 'Issue a signed receipt for a UST derivation/attestation. [stub — product MCP]', stub: true },
  { name: 'noosphere_archive', description: 'Fetch temporal-depth history behind the paywall. [stub — product MCP]', stub: true },
];
