# @ust-protocol/mcp

**An MCP server that lets an agent verify, create, and combine UST records — using only this server and its own key.**

`@ust-protocol/mcp` exposes [`ust-protocol`](https://www.npmjs.com/package/ust-protocol) as
[Model Context Protocol](https://modelcontextprotocol.io) tools, so any MCP-capable agent can check that a piece
of state is what it claims — who published it, when, unchanged — without trusting whoever served the bytes.

> **Release candidate.** The wire format `ust:"1.0"` is stable across all rc's; this package pins its own rc on npm — pin exact versions. Extensively
> red-teamed; multiple external AI reviews folded in structurally; an independent human cryptographic audit is
> pending. Suitable for evaluation. Pin exact versions.

## Run

```
npx -y @ust-protocol/mcp@rc
```

## Add to Claude Code

```
claude mcp add ust -- npx -y @ust-protocol/mcp@rc
```

Or in any MCP client config:

```json
{ "mcpServers": { "ust": { "command": "npx", "args": ["-y", "@ust-protocol/mcp@rc"] } } }
```

## Tools

| Tool | Does |
|------|------|
| `ust_verify` | Verify a document — ONE call, resolution included: auto-fetches the publisher's discovery + witness surfaces, cross-checks witness anchors against their substrate (Rekor/Bitcoin), and reaches `VALID:HIGH` automatically when the no-fork evidence confirms (`resolution.noFork`: witness-confirmed / caller-asserted / unconfirmed). `offline:true` forbids the network (supply `genesis`+`keylog` yourself); `proof` adds anchored time |
| `ust_build_observation` | Build (unsigned) an observation; returns `state` + `content_hash` + `signing_input` |
| `ust_combine_derivation` | Build a derivation chained to other records by content-hash (auto seed) |
| `ust_combine_attestation` | Build an attestation over N constituents (auto Merkle root) |
| `ust_resolve` | Resolve name authority → `authoritative` / `self-asserted` |
| `ust_anchor_verify` | Verify a time-anchor's Merkle inclusion proof |
| `ust_verify_stream` | Verify a RANGE (e.g. ust(001)…ust(007) fetched from an archive) as one authority's complete, prev-chained stream → `proven`/`provisional` (retrieval is the product's job, not the protocol's) |
| `ust_key_id` | Derive a `key_id` from a public key |
| `ust_canon` | Canonicalize a value (the exact bytes UST hashes/signs) |

## The agent flow — build → sign → verify, entirely through the MCP

1. `ust_build_observation` → returns the unsigned `state` and the exact `signing_input` bytes.
2. **You** sign `signing_input` with your own Ed25519 key.
3. `ust_verify` → `VALID`.

The server **never holds your key**. An agent needs only this MCP and its own key.

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged* — not that
the data is *correct*. You learn **whom to hold accountable** and **that nothing was tampered**. The final Bitcoin
time-anchor confirmation is a substrate step delegated to the operator (it needs Bitcoin access), so it is
deliberately not a stateless protocol tool — `ust_anchor_verify` proves *inclusion*, you (or the operator) confirm
the root on-chain.

## Two surfaces

This is the **protocol MCP** — universal, publisher-agnostic. A separate **product MCP** (pricing, receipts,
archive depth) is operated by publishers such as noosphere; the two are never mixed.

Depends on [`ust-protocol`](https://www.npmjs.com/package/ust-protocol). Spec: **https://github.com/thelabmd/UST-Protocol/blob/main/spec/UST-1.0.md**

## License

Apache-2.0 · © 2026 THE LAB
