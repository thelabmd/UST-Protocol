# UST Protocol — the operator layer

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

> `§` refers to [`spec/UST-1.0.md`](../../spec/UST-1.0.md) throughout.

`@ust-protocol/operator` = "UST state": working with the protocol's STATE over time. Builds ON `ust-protocol` (the stateless
base). Each piece PRODUCES exactly what `ust-protocol` VERIFIES — round-trip `conformance.mjs`: 16/16 PASS, 0 fail — and it runs in CI now, which is why the number moved.

## Built
- **`Stream`** — prev-chain per `(domain_shard, tier)` + checkpoints + `gap()`/`resume()` (§11.3/§11.1). ↔ `verifyStream`.
- **`KeyLog`** — genesis-rooted append-only `class:"key"` chain: add/revoke (§12.2 — `rotate` was retired in rev97; replacement is `add(supersedes)` + `revoke`). ↔ `resolveAuthority`.
- **`AnchorBatch`** — content_hashes → Merkle root → per-doc `AnchorProof` (§11.1/§11.2). ↔ `verifyAnchor`.
- **`walkChain`** — walk `based_on`/`constituents` via a `fetch`, verify each, bounded + acyclic (§9.5).
- **`sealLayerChain`/`assembleLayers`** — shard-chain LAYERS / selective disclosure; outer seed commits
  subordinates' content_hashes (G20, no self-reference); each layer verified independently (E4) (§10a).
- **`substrates` / `substrateVerifier(deps)`** — anchor-substrate registry; `bitcoin-ots` (OTS→Bitcoin header,
  ≥6 conf). OTS parsing + Bitcoin header access are INJECTED (`deps`) — the `substrateVerify` callback
  `ust-protocol.verifyAnchor` delegates to.
- **`Tiers`** — one prev-stream per tier + cross-tier resumption (continuation, never re-genesis, P6).

## Delegated / engine-wired (by design)
- The real `opentimestamps` + Bitcoin header source behind `substrateVerifier` deps (external Bitcoin access).
- The store abstraction (where docs live) — `@ust-protocol/operator` is store-agnostic; the engine wires the store + ingest.

## Layering (proven)
`ust-protocol` (stateless base, public) ← `@ust-protocol/operator` (this, stateful operator) ← engine. Both packages
complete; next is the MCP wrapper (gh#99) over both.
