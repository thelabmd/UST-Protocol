<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ust — the reference CLI

One entrypoint for [UST 1.0](https://github.com/thelabmd/UST-Protocol) — verify machine-readable state, run the genesis ceremony, attest the discovery serving contract. The Go binary reproduces this surface, so `ust` is one static, language-agnostic tool.

```bash
npm i -g @ust-protocol/cli               # installs the `ust` command
npx @ust-protocol/cli verify doc.json    # or one-shot, no install
```

## Commands

| command | what it does |
|---|---|
| `ust verify <file\|->` | verify a transcript (blob / base64 / json). exit 0 = VALID, 1 = not |
| `ust verify <doc> --genesis <f> --keylog <f,f…> [--no-fork-confirmed]` | resolve the trust chain → **VALID:HIGH** (name becomes authoritative) |
| `ust canon <file\|->` | print canonical bytes + hash — diff any other-language implementation against this |
| `ust genesis --domain <d>` | run the HIGH genesis ceremony (interactive; see the road below) |
| `ust discovery <domain> [--mirror url,url] [--expect sha256:…]` | attest the §20.1 serving contract on ANY infrastructure |
| `ust publish cf --domain <d> --genesis <f> [--auth wrangler] [--flip-proxy]` | deploy the Cloudflare serving adapter for an existing genesis |

## The tier ladder (what verify can prove)

```
LIGHT  — a lone document: signed + intact under the key it carries (self-asserted)
HIGH   — + name authority: the verifier RESOLVES genesis → key-log (+ no-fork witness)
TOP    — + anchored time: the stream is provably ordered and complete (e.g. bitcoin-ots)
```

A lone document can only ever prove LIGHT — that is the **expected** result for a fresh `ust-genesis` file. HIGH is a property of *resolution*, not of the file:

```bash
ust verify slot.json --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed
```

## `ust genesis` — the ceremony road

```
  1/5 🔑 ROOT key          the crown of your name — signs ONLY genesis & rotations; stays cold
  2/5 📜 genesis + key-log identity is born; a WARM operational key is added for daily signing
  3/5 🌐 DNS binding       _ust.<domain> TXT carries the genesis hash — tamper-evident, outside HTTP
  4/5 📡 serving + gate    https://<domain>/.well-known/ust-genesis serves EXACTLY these bytes
                           (checked fail-closed, with propagation retries)
  5/5 ⚓ witness / anchor  PREPARED for HIGH / TOP — the operator runs these; the CLI never claims them
```

The ceremony is **interactive**: it prints this map at every step, explains each human moment (what the passphrase protects, what each file is), and ends with a summary — identity, custody table, tier ladder, next moves.

### Two roads, one contract

The serving contract is infrastructure-agnostic (properties, not vendors). The ceremony asks which road you want — or preselect with flags:

- **By hand on YOUR infra** (default) — exact instructions for any DNS panel and any web stack (static host, nginx, corporate cloud). The CLI then verifies fail-closed: DoH readback for the TXT, live content-hash match for the well-known.
- **Cloudflare one-click** (`--dns cf-api --publish cf --auth wrangler`) — the combined minimal-credential flow:
  1. `npx wrangler login --scopes account:read user:read workers_scripts:write workers_routes:write zone:read` — browser OAuth, **5 scopes, not wrangler's default 28**
  2. a **DNS-only** API token (the CLI prints a prefilled creation link; ~1 h TTL recommended, revoke after)
  3. the worker embeds your genesis (no bucket, no origin), the route serves `/.well-known/ust-genesis`, the edge cache key is the **path** — unknown `?query` params can never mint cache entries

`--flip-proxy` is explicit because it changes how your WHOLE site is served (apex goes behind the proxy).

### Outputs & custody

| file | class | custody |
|---|---|---|
| `ust-genesis`, `ust-keylog-0` | PUBLIC | verifiable by anyone — `ust verify` them |
| `genesis-key.enc.b64` | 🧊 COLD | crown backup — keep the file and its passphrase APART; needed ~yearly (rotate/revoke) |
| `operational-key.b64` | 🔥 WARM | your producer's signing-key secret (an env var of YOUR naming), then **DELETE the file** |

Other flags: `--profile bronze|silver|gold` (gold forces a passphrase-encrypted root backup and warns `ASSURANCE LIMIT` unless `--signer` supplies a hardware root) · `--max-partitions N` (signed capacity — bounds earned by ceremony) · `--witness url,url` (prepared, never executed).

## `ust discovery` — attest any stack

Four probes of the §20.1 serving contract, fail-closed, honest verdict:

```
✅ well-known verifies (§14) and matches the expected hash
✅ _ust TXT carries the same hash        (mismatch = FAILED, absence = NOT ATTESTED)
✅ query-robustness: a random unknown ?param returns byte-identical bytes
⬜ vendor-independence: every declared --mirror carries the same content_hash
```

Verdict: `ATTESTED` (everything ran and passed) / `PARTIAL` (no violation, but unchecked properties remain — with targeted hints) / `FAILED` (exit 1). Conformance is never granted on unchecked properties.

## Custody model

The MCP holds no key; this CLI signs locally with keys that never leave your machine. The ceremony tool never emits an output it has not verified, and never claims a stage it did not run.
