<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ust — the reference CLI

One entrypoint for [UST 1.0](https://github.com/thelabmd/UST-Protocol). The Go binary reproduces this surface, so `ust` is one static, language-agnostic tool.

```
ust verify <file|->          verify a transcript (blob / base64 / json). exit 0 = VALID, 1 = not.
ust canon  <file|->          print the canonical bytes + hash — diff your other-language impl against this
ust genesis --domain <d>     run the HIGH genesis ceremony
```

## `ust genesis`
```
ust genesis --domain noosphere.md --profile silver --dns cf-api
```
- `--profile bronze|silver|gold` — capacity/rigor ladder (gold forces a passphrase-encrypted backup + warns `ASSURANCE LIMIT: software-generated extractable root` unless `--signer` supplies a hardware root)
- `--dns manual` prints the `_ust` TXT to paste; `--dns cf-api` upserts it via the Cloudflare API (zone-scoped `CF_TOKEN`, never account-wide) and **confirms it with a DNS-over-HTTPS readback** before proceeding — Vercel-style, idempotent
- `--max-partitions N` — the signed capacity in the genesis (bounds earned by ceremony)
- `--witness url,url` — witnesses to fetch + byte-match

The ceremony: generate the root key → build the self-signed genesis + a key-log adding an operational key → back up the root (split + cold) → publish `.well-known/ust-genesis` (the CLI fetches it, **verifies it, and matches its content_hash** — fail-closed) → then PREPARES the witness + anchor stage (the operator executes those). Outputs: **two verifiable UST** (`ust-genesis`, `ust-keylog-0` — `ust verify` them) + an **encrypted PKCS#8 root-key backup** (`genesis-key.enc.b64` — NOT a UST) for operator-managed split cold storage. The CLI self-verifies its outputs before finishing.

The MCP holds no key; this CLI signs locally with a key that stays on your machine.
