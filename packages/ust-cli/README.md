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
- `--profile bronze|silver|gold` — capacity/rigor ladder (gold forces a passphrase-encrypted root-key backup)
- `--dns manual` prints the `_ust` TXT to paste; `--dns cf-api` writes it via the Cloudflare API (needs a **zone-scoped** `CF_TOKEN`, never account-wide) — Vercel-style one click
- `--max-partitions N` — the signed capacity in the genesis (bounds earned by ceremony)
- `--witness url,url` — witnesses to fetch + byte-match

The ceremony: generate the root key → build the self-signed genesis + a key-log adding an operational key → back up the root (split + cold) → publish `.well-known/ust-genesis` (the CLI fetches it and byte-matches, **fail-closed**) → witnesses + anchor. Outputs `ust-genesis`, `ust-keylog-0`, and the encrypted key backup — all UST, re-verifiable with `ust verify`.

The MCP holds no key; this CLI signs locally with a key that stays on your machine.
