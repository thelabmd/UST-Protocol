<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the MCP server

```
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

**Browser: node-only.** This package does **not** run in a browser, and that is a decision rather than an omission. See `ust:browser.why` in its `package.json` for the reason, and UST-Protocol#148 for what a browser can and cannot reach without it.

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same however it reached you. TLS secures the
pipe; **UST secures the payload**, so the guarantee travels with the data instead of with the connection.

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

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
| `ust_profile_declares` | **§20.1 / F.5p.1** — what does a publisher's operator profile BIND? The CLOSED half only: `{serves, substrates, copies, commitment_rhythm}`. Prose is dropped by POSITION, never by a naming convention, so an added line of operator text can never start binding. A malformed declaration is an **error**, not a weaker profile. |
| `ust_replication_agreement` | **§20.1 / F.5o** — do the copies a publisher NAMED agree byte for byte? `attested` only when there was something to compare *and* nothing disagreed. What it **refuses** is the point: `independent`, `trust_domain`, `vendor`, `assurance`, `strength` are rejected — independence is not decidable from bytes and may not ride in on a locator list. |
| `ust_serving_verdict` | **§20.1** — the 2×2 for one served surface: declared-and-absent is a promise **not kept**; undeclared-and-absent is `not-offered`; observing a surface attests it whether or not it was declared. |
| `ust_anchor_rollup` | **§20.1** — the same 2×2 rolled over declared substrates: `printing`, `partial`, `dark`, or `unknown` when nothing was declared and there is no universal claim to judge. |
| `ust_keylog_commitment` | **§12.2** — commit a key log: the Merkle root over its entry hashes, its length, its head, and the head's inclusion proof. What a publisher ANCHORS so a later log cannot quietly drop an entry. The library returns `prove` as a *function*; over the wire you ask for the indices you need and the proofs come back as data. |
| `ust_keylog_terminality` | **§12.2** — is the head you were shown the LAST entry of the committed log, or is there more the publisher is not showing? A check, never a build. |
| `ust_shard_check` | Is this `domain_shard` a name a verifier will DISCOVER under? A key-form shard is self-certifying and has no name to serve a genesis under (§4.3a, §20.1) — a false answer means `/.well-known` is not the route to you, never that the identity is weaker. |
| `ust_name_report` | **F.5t** — does anything you PUBLISH wear the protocol name without being a document of it? An artifact that says `ust` instructs a machine to verify it; if it is not a document, every consumer that tries gets `E-MALFORMED` — the signal of a *damaged* document — for something that was never one. Hand the set as `[{id, raw}]` with `raw` the exact SERVED TEXT: the question is about the bytes a consumer fetches, so a parsed document is refused rather than judged. |
| `ust_explain` | The LADDER, not the verdict: where a document sits, and for every input the verifier did NOT receive, who could supply it and what it would buy. Answers *why am I not seeing HIGH* without guessing — the difference between **not attempted** and **refused** is the whole point, and a verdict alone leaves it to be inferred. |
| `ust_sealing_request` | PREPARE an `encrypted` partition **without holding a key**: returns the commitment, the exact plaintext a key-holder must seal, and the IV that commitment implies. The nonce is generated here and returned — keep it, or the commitment can never be opened. The key-holder sees the plaintext by construction; choose the key-holder accordingly. |
| `ust_attach_encryption` | ASSEMBLE the partition from the `{alg,key_id,ct}` a key-holder returned. No key here and none needed — and it CHECKS the seam: the ciphertext must carry the IV the commitment implies, so a sealer working from its own derivation is caught by a caller holding no key. |
| `ust_seal` | ASSEMBLE a signed transcript from a signature you made yourself: pass the state, your base64url `pub` and the signature over `signing_input`. **The private key never travels** — this is the assembly half of `seal`, which needs no key. `key_id` is DERIVED from `pub`, so a caller cannot state one that disagrees, and the tool VERIFIES what it assembled, refusing to hand back a document a reader would reject. |
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
