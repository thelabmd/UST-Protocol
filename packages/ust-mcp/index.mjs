// SPDX-License-Identifier: Apache-2.0
// ust-mcp — the agent-facing MCP surface over `ust-protocol` (+ `ustate`). Two surfaces (bd 9oov):
//   PROTOCOL MCP = universal (create/verify/combine/resolve/anchor/verify-stream over the stateless base) — built here.
//   PRODUCT MCP  = noosphere business (pricing, archive depth, receipts) — separate, stubbed below.
// Methods are derived FROM the record's fields. This module is TRANSPORT-AGNOSTIC: it exports the tool
// registry + `dispatch()`; the stdio/SSE JSON-RPC server (via @modelcontextprotocol/sdk) is a thin shell the
// engine/deploy wires around `listTools()` + `dispatch(name, args)`.
import * as P from 'ust-protocol';
import { makeSsrfSafeFetch } from './ssrf-guard.mjs';

// #69 E4 — the MCP takes UNTRUSTED documents from agents and auto-fetches their domain_shard, so the discovery
// egress is resolution-guarded (a public NAME resolving to a private ADDRESS is refused) on top of the core's
// lexical SSRF floor. A single shared wrapper over global fetch, passed as resolveByDiscovery's fetchImpl.
const ssrfSafeFetch = makeSsrfSafeFetch();

const doc1 = (state) => ({ ust: '1.0', state });
// build tools return the UNSIGNED state + the exact `signing_input` bytes; the caller (agent/operator) signs
// with its OWN Ed25519 key and assembles { ust, state, sig:{alg:'Ed25519', key_id, pub, sig} }. No key here.
const buildResult = (state) => ({ state, content_hash: P.contentHash(doc1(state)), signing_input: P.signedContent(doc1(state)) });

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
    inputSchema: { type: 'object', properties: { doc: { type: 'object' }, json: { type: 'string' }, offline: { type: 'boolean', description: 'true = never touch the network (no discovery auto-fetch)' }, pinnedKeys: { type: 'array' }, genesis: { type: 'object' }, keylog: { type: 'array' }, proof: { type: 'object' }, disclosures: { type: 'object' }, noForkConfirmed: { type: 'boolean' }, noForkEvidence: { type: 'object', description: 'consumer-supplied WITNESS-signed no-fork attestation (offline/air-gapped path); with trustRoots ⇒ INDEPENDENT authoritative, not the weaker consumer-override of noForkConfirmed' }, trustRoots: { type: 'object', description: 'witness/authority pubkeys the CONSUMER trusts, { key_id: pubB64 } — consumer-rooted, NEVER from the doc/evidence (P0-01)' }, trust: { type: 'object', description: 'consumer trust config e.g. { mapRoots: [root] } — admits an authenticated-map root for map-based uniqueness (§12.3.4)' }, nameMap: { type: 'object', description: 'authenticated-map proof for domain→active-genesis uniqueness ⇒ identity authoritative (map basis, §12.3)' }, requireAuthoritative: { type: 'boolean', description: 'floor at HIGH — reject anything not name-authoritative (E-GENESIS)' }, requireAnchored: { type: 'boolean', description: 'floor at TOP — reject anything not anchored (downgrade resistance, §3.1/F.5b): a stripped/absent anchor ⇒ E-ANCHOR, a substrate-unavailable one ⇒ INDETERMINATE, never a silent lower-tier accept' }, soft: { type: 'boolean', description: '#44 agent-safety: by DEFAULT an INVALID verdict is returned as an ERROR response (isError) you MUST acknowledge — you cannot skip it as a data field. Set soft:true to OPT IN to the advisory path (INVALID returned as data). The structured verdict rides the error either way.' }, requireFreshKeylog: { type: 'boolean', description: '#40 floor: reject a possibly-stale key-log (freshness unverified) ⇒ INDETERMINATE stale_keylog (re-fetch from discovery), never a silent accept on a cached view that may miss a revocation.' }, keylogFreshAsOf: { type: 'string', description: '#40 (round-16 P0-02) a raw timestamp is a CALLER CLAIM and can NOT mint freshness:fresh — fresh is EARNED only by an authenticated discovery fetch (resolveByDiscovery). A bare value stays freshness:unverified.' }, keylogHeadAnchor: { type: 'object', description: '#40 a VERIFIED anchor inclusion proof for the key-log HEAD (checked against the substrate: inclusion + final ⇒ freshness:attested). A raw head hash is NOT accepted — it proves nothing (rc.28 audit).' }, capacity: { type: 'object', description: 'trusted capacity grant {maxPartitions?, maxTranscriptBytes?} — pass what resolveAuthority returned as .capacity (rc.12)' }, maxSupportedBytes: { type: 'number' } } },
    handler: async ({ doc, json, offline, pinnedKeys, genesis, keylog, proof, disclosures, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, requireAuthoritative, requireAnchored, soft, requireFreshKeylog, keylogFreshAsOf, keylogHeadAnchor, capacity, maxSupportedBytes }) => {
      const o = { pinnedKeys, genesis, keylog, disclosures, noForkConfirmed, noForkEvidence, trustRoots, trust, nameMap, requireAuthoritative, requireAnchored, requireFreshKeylog, keylogFreshAsOf, keylogHeadAnchor, capacity, maxSupportedBytes, context: 'data' };
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
      const _plugins = [];
      for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
        try { const m = await import(pkg); if (m.substrateVerify) _plugins.push(m.substrateVerify); } catch { /* absent */ }
      }
      const substrateVerify = _plugins.length ? P.combineSubstrates(_plugins) : undefined;
      if (json !== undefined) {
        const raw = P.verifyJson(json, o);
        if (offline || genesis !== undefined || !(raw.result === 'VALID:LIGHT' || (raw.result === 'INDETERMINATE' && raw.reason === 'unavailable'))) return gate(raw);
        let parsed; try { parsed = JSON.parse(json); } catch { return gate(raw); }
        const { verdict, resolution } = await P.resolveByDiscovery(parsed, ro, { substrateVerify, fetchImpl: ssrfSafeFetch });
        return gate(resolution ? { ...verdict, resolution } : verdict);
      }
      // an embedded doc.proof is verified INSIDE verify (present-bad ⇒ E-ANCHOR); a separately-passed proof merges in.
      const d = (proof !== undefined && doc && doc.proof === undefined) ? { ...doc, proof } : doc;
      if (offline || genesis !== undefined) return gate(P.verify(d, o));
      const { verdict, resolution } = await P.resolveByDiscovery(d, ro, { substrateVerify, fetchImpl: ssrfSafeFetch });
      return gate(resolution ? { ...verdict, resolution } : verdict);
    },
  },
  {
    name: 'ust_build_observation',
    description: 'CREATE (build, unsigned) an observation State from partitions; returns state + content_hash + signing_input to sign with your own Ed25519 key.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data }) => buildResult(P.buildState({ domain_shard, ust_id, key_id, class: 'observation' }, time, data)),
  },
  {
    name: 'ust_combine_derivation',
    description: 'COMBINE: build (unsigned) a derivation that chains to other records by content_hash (based_on) with an auto-computed order-bearing seed.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data', 'based_on'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' }, based_on: { type: 'array' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data, based_on }) => buildResult(P.buildDerivation({ domain_shard, ust_id, key_id }, time, data, based_on)),
  },
  {
    name: 'ust_combine_attestation',
    description: 'COMBINE: build (unsigned) an attestation over N constituent content_hashes with an auto-computed Merkle root.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'data', 'constituents'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, data: { type: 'object' }, constituents: { type: 'array' } } },
    handler: ({ domain_shard, ust_id, key_id, time, data, constituents }) => buildResult(P.buildAttestation({ domain_shard, ust_id, key_id }, time, data, constituents)),
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
    description: 'CEREMONY (build, unsigned): a KEY-LOG entry (§12.2) that add|rotate|revoke a key, prev-chained to the previous entry (or the genesis content_hash for the first). Returns the unsigned State + signing_input; sign with the CURRENTLY-VALID key. This is how a genesis root delegates to daily operational keys and how compromise is revoked.',
    inputSchema: { type: 'object', required: ['domain_shard', 'ust_id', 'key_id', 'time', 'key_op', 'prev'], properties: { domain_shard: { type: 'string' }, ust_id: { type: 'string' }, key_id: { type: 'string' }, time: { type: 'object' }, key_op: { type: 'object', description: '{ op:"add"|"rotate"|"revoke", pub, new_key_id?, reason?, compromised_since? }' }, prev: { type: 'string', description: 'content_hash of the prior key-log entry, or of the genesis for the first' } } },
    handler: ({ domain_shard, ust_id, key_id, time, key_op, prev }) => buildResult(P.buildKeyLogEntry({ domain_shard, ust_id, key_id }, time, key_op, prev)),
  },
  {
    name: 'ust_resolve',
    description: 'RESOLVE name authority: given a document, its publisher genesis + key-log, and CONSUMER-supplied no-fork evidence, return the identity strength (authoritative / corroborated / consumer-override / pinned / self-asserted) + status. INDEPENDENT authoritative needs witness noForkEvidence (or an authenticated nameMap) validated against consumer trustRoots; a bare noForkConfirmed is only a consumer-override, NOT authoritative.',
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
      const _plugins = [];
      if (!offline) for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
        try { const m = await import(pkg); if (m.substrateVerify) _plugins.push(m.substrateVerify); } catch { /* absent */ }
      }
      const substrateVerify = _plugins.length ? P.combineSubstrates(_plugins) : undefined;
      return P.forkChoice(candidates, { genesis, keylog, noForkConfirmed, offline, context: 'data', substrateVerify });
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
