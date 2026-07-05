# UST — Universal State Transcript

**Verify machine-readable state without trusting whoever handed it to you.**

UST is trust infrastructure for data: a signed, canonical, tamper-evident record of *state* — some data about
the world at a moment — that verifies the same no matter how it reached you (a cache, a mirror, another agent, a
file on disk). TLS secures the pipe; **UST secures the payload**, and the guarantee travels *with* the data.

This repository is the specification, the conformance vectors, and the reference implementations.

## Layout

| Path | What |
|------|------|
| `spec/UST-1.0.md` | the specification (release candidate) |
| `vectors/` | deterministic conformance vectors — any implementation should pass them |
| `packages/ust-protocol/` | the stateless reference verifier + producer ([npm](https://www.npmjs.com/package/ust-protocol)) |
| `packages/ust-mcp/` | an MCP server exposing UST to agents ([npm](https://www.npmjs.com/package/ust-mcp)) |
| `examples/` | sample documents (valid + tampered) and verification recipes |

## Status

Release candidate — **`1.0.0-rc.1`**. The specification has been extensively red-teamed; an independent external
cryptographic audit is pending. Suitable for evaluation and integration testing. Pin exact versions.

## Quickstart

```
npm install
npm test          # runs ust-protocol against the conformance vectors
```

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this time, unchanged.* It does
**not** prove the data is *correct* — a publisher can sign a wrong reading. You learn **whom to hold accountable**
and **that nothing was tampered** — a real, bounded guarantee, not an oracle of truth.

## License

Apache-2.0 · © 2026 THE LAB
