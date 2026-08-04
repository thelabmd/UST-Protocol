<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the MCP server

```

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

     ▄▀▀▀▀▀▀▀▀▀▀▀▀█▄
    █ ▄▄      ▄▄    █              UST Protocol
  ▄▄▀ ▀▀ ▄▄▄  ▀▀    █              RSS for State
  ▄█▀▀ ▀█▄▀▄▄▀ ▀█▀  █    █▀▄   ▄▄
   ▀█               █▄   █▄ ██▀ █
     █               ▀▄▄  █   ▄█
     █                  ▀▀   █▀
     █▄      ▄              █▀
     ███▄    █    █       ▄█▀
   ▄▀▀  ██▄▄▄█     ▀▄▄▄▄█▀▀
   ▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀
```

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same however it reached you. TLS secures the
pipe; **UST secures the payload**, so the guarantee travels with the data instead of with the connection.

**An MCP server that lets an agent verify, create, and combine UST records — using only this server and its own key.**

`@ust-protocol/mcp` exposes [`ust-protocol`](https://www.npmjs.com/package/ust-protocol) as
[Model Context Protocol](https://modelcontextprotocol.io) tools, so any MCP-capable agent can check that a piece
of state is what it claims — who published it, when, unchanged — without trusting whoever served the bytes.

> **Release candidate.** The wire format `ust:"1.0"` is stable across all rc's; this package pins its own rc on npm — pin exact versions. Extensively
> red-teamed; multiple external AI reviews folded in structurally; an independent human cryptographic audit is
> pending. Suitable for evaluation. Pin exact versions.

## Install

```bash
npm i @ust-protocol/mcp
```

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
| `ust_build_genesis` | CEREMONY (build, unsigned): the name-binding GENESIS — the self-signed root that weds a domain to a key. The MCP holds no key: it returns the unsigned state + `signing_input`, and the operator signs |
| `ust_build_key_log` | CEREMONY (build, unsigned): a key-log entry that ADDs or REVOKEs a key. There is deliberately no `rotate` op — a self-authorized succession would let a compromised key name its own successor |
| `ust_build_cadence` | CEREMONY (build, unsigned): declare the stream grid in seconds from `effective_from` onward, prev-chained from the genesis for the first entry |
| `ust_resolve_cadence` | What grid does this publisher declare at a given moment? Resolves the cadence in force at `at` from the genesis plus the signed cadence log, verifying every entry |
| `ust_fork_choice` | Fork-choice for ONE `ust_id` when you hold two or more documents claiming it with different content — a dual-writer race, or an adversary. The anchor decides, never the candidates |
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
