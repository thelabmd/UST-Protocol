// SPDX-License-Identifier: Apache-2.0
// ust-mcp — the agent-facing MCP surface over `ust-protocol` (+ `ustate`). Two surfaces (bd 9oov):
//   PROTOCOL MCP = universal (create/verify/combine/resolve/anchor/verify-stream over the stateless base) — built here.
//   PRODUCT MCP  = noosphere business (pricing, archive depth, receipts) — separate, stubbed below.
// Methods are derived FROM the record's fields. This module is TRANSPORT-AGNOSTIC: it exports the tool
// registry + `dispatch()`; the stdio/SSE JSON-RPC server (via @modelcontextprotocol/sdk) is a thin shell the
// engine/deploy wires around `listTools()` + `dispatch(name, args)`.
import * as P from 'ust-protocol';

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
    inputSchema: { type: 'object', properties: { doc: { type: 'object' }, json: { type: 'string' }, offline: { type: 'boolean', description: 'true = never touch the network (no discovery auto-fetch)' }, pinnedKeys: { type: 'array' }, genesis: { type: 'object' }, keylog: { type: 'array' }, proof: { type: 'object' }, disclosures: { type: 'object' }, noForkConfirmed: { type: 'boolean' }, requireAuthoritative: { type: 'boolean' }, capacity: { type: 'object', description: 'trusted capacity grant {maxPartitions?, maxTranscriptBytes?} — pass what resolveAuthority returned as .capacity (rc.12)' }, maxSupportedBytes: { type: 'number' } } },
    handler: async ({ doc, json, offline, pinnedKeys, genesis, keylog, proof, disclosures, noForkConfirmed, requireAuthoritative, capacity, maxSupportedBytes }) => {
      const o = { pinnedKeys, genesis, keylog, disclosures, noForkConfirmed, requireAuthoritative, capacity, maxSupportedBytes, context: 'data' };
      // `json` (raw text) = the safe conformance boundary — duplicate-key + NFC scan BEFORE parse (F7).
      const ro = { ...o, offline };
      const _plugins = [];
      for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
        try { const m = await import(pkg); if (m.substrateVerify) _plugins.push(m.substrateVerify); } catch { /* absent */ }
      }
      const substrateVerify = _plugins.length ? P.combineSubstrates(_plugins) : undefined;
      if (json !== undefined) {
        const raw = P.verifyJson(json, o);
        if (offline || genesis !== undefined || !(raw.result === 'VALID:LIGHT' || (raw.result === 'INDETERMINATE' && raw.reason === 'unavailable'))) return raw;
        let parsed; try { parsed = JSON.parse(json); } catch { return raw; }
        const { verdict, resolution } = await P.resolveByDiscovery(parsed, ro, { substrateVerify });
        return resolution ? { ...verdict, resolution } : verdict;
      }
      // an embedded doc.proof is verified INSIDE verify (present-bad ⇒ E-ANCHOR); a separately-passed proof merges in.
      const d = (proof !== undefined && doc && doc.proof === undefined) ? { ...doc, proof } : doc;
      if (offline || genesis !== undefined) return P.verify(d, o);
      const { verdict, resolution } = await P.resolveByDiscovery(d, ro, { substrateVerify });
      return resolution ? { ...verdict, resolution } : verdict;
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
    description: 'RESOLVE name authority: given a document, its publisher genesis + key-log, and a witness no-fork confirmation, return the identity strength (authoritative / pinned / self-asserted) and status.',
    inputSchema: { type: 'object', required: ['doc', 'genesis', 'keylog'], properties: { doc: { type: 'object' }, genesis: { type: 'object' }, keylog: { type: 'array' }, noForkConfirmed: { type: 'boolean' }, anchorTime: { type: 'string' } } },
    handler: ({ doc, genesis, keylog, noForkConfirmed, anchorTime }) => P.resolveAuthority(doc, { genesis, keylog, noForkConfirmed, anchorTime }),
  },
  {
    name: 'ust_anchor_verify',
    description: 'ANCHOR: verify a self-contained time proof — recompute the Merkle inclusion path from a content_hash to the anchored root (substrate verification is delegated).',
    inputSchema: { type: 'object', required: ['content_hash', 'proof'], properties: { content_hash: { type: 'string' }, proof: { type: 'object' } } },
    handler: ({ content_hash, proof }) => P.verifyAnchor(content_hash, proof),
  },
  {
    name: 'ust_verify_stream',
    description: 'VERIFY A RANGE as one authority\'s complete stream — e.g. you fetched ust(001)…ust(007) from an archive: every frame LIGHT-verifies, they are prev-chained with no gaps, all belong to ONE publisher (mixed publishers → E-AUTHORITY), and with a covering checkpoint the interval is provably complete. Returns { complete: "proven" | "provisional" | "none" } or an error (E-PREV broken/forked chain · E-AUTHORITY mixed authority · E-SIG bad frame). Retrieval is NOT the protocol\'s job — pass the records you already have.',
    inputSchema: { type: 'object', required: ['frames'], properties: { frames: { type: 'array' }, genesis: { type: 'object' }, checkpoint: { type: 'object' } } },
    handler: ({ frames, genesis, checkpoint }) => P.verifyStream(frames, { genesis, checkpoint }),
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
  catch (e) { return { isError: true, error: e.message || String(e) }; }
}

// ─── PRODUCT MCP (noosphere business) — separate surface, stubbed. Never mixed with the universal protocol MCP.
export const productTools = [
  { name: 'noosphere_price', description: 'Quote a receipt/archive-depth price (x402 unit-of-sale). [stub — product MCP]', stub: true },
  { name: 'noosphere_receipt', description: 'Issue a signed receipt for a UST derivation/attestation. [stub — product MCP]', stub: true },
  { name: 'noosphere_archive', description: 'Fetch temporal-depth history behind the paywall. [stub — product MCP]', stub: true },
];
