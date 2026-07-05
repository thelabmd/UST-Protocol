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
export const tools = [
  {
    name: 'ust_verify',
    description: 'VERIFY a UST document (three outcomes: VALID / INVALID / INDETERMINATE-unavailable). Reports identity strength (self-asserted / pinned / authoritative), time strength, and disclosures. The domain is returned as `publisher` ONLY when authoritative; otherwise as `publisher_claimed` (a self-asserted label — never attribute it as the real publisher). Supply `pinnedKeys` (an array of trusted key_ids, TOFU) to accept only known keys; `genesis`+`keylog` for HIGH name-authority; `proof` for TOP anchored time.',
    inputSchema: { type: 'object', required: ['doc'], properties: { doc: { type: 'object' }, pinnedKeys: { type: 'array' }, genesis: { type: 'object' }, keylog: { type: 'array' }, proof: { type: 'object' }, disclosures: { type: 'object' }, noForkConfirmed: { type: 'boolean' }, requireAuthoritative: { type: 'boolean' } } },
    handler: ({ doc, pinnedKeys, genesis, keylog, proof, disclosures, noForkConfirmed, requireAuthoritative }) => {
      const r = P.verify(doc, { pinnedKeys, genesis, keylog, disclosures, noForkConfirmed, requireAuthoritative, context: 'data' });
      if (proof && r.result === 'VALID') { const a = P.verifyAnchor(r.content_hash, proof); r.time = { strength: a.time, status: a.status, inclusion: a.inclusion }; }
      return r;
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
// dispatch a tool call → MCP-style result. Never throws; a handler error becomes an isError result (fail-closed).
export function dispatch(name, args = {}) {
  const t = toolMap[name];
  if (!t) return { isError: true, error: 'unknown tool: ' + name };
  try { return { result: t.handler(args) }; }
  catch (e) { return { isError: true, error: e.message || String(e) }; }
}

// ─── PRODUCT MCP (noosphere business) — separate surface, stubbed. Never mixed with the universal protocol MCP.
export const productTools = [
  { name: 'noosphere_price', description: 'Quote a receipt/archive-depth price (x402 unit-of-sale). [stub — product MCP]', stub: true },
  { name: 'noosphere_receipt', description: 'Issue a signed receipt for a UST derivation/attestation. [stub — product MCP]', stub: true },
  { name: 'noosphere_archive', description: 'Fetch temporal-depth history behind the paywall. [stub — product MCP]', stub: true },
];
