<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST Protocol — the reference CLI

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

**Verify machine-readable state without trusting whoever handed it to you.**

UST (Universal State Transcript) is trust infrastructure for data: a signed, canonical, tamper-evident record of
*state* — some data about the world at a moment — that verifies the same no matter how it reached you: a cache, a
mirror, another agent, a file on a stick. TLS secures the pipe; **UST secures the payload**, so the guarantee
travels *with* the data instead of with the connection.

`ust` is the reference implementation: one command that reads those records and answers with a **verdict**, plus
the tools to become a publisher of them yourself. The Go binary reproduces this same surface, so `ust` is one
static, language-agnostic tool.

## What it proves — and what it doesn't

UST proves **fixation, not truth**: *this publisher committed to this data, at this moment, unchanged.* It does
not prove the data is *correct* — a publisher can sign a wrong reading and the signature will be perfectly valid.
What you learn is **whom to hold accountable** and **that nothing was altered on the way**. That is a real,
bounded guarantee rather than an oracle of truth, and the CLI is careful never to claim more than it checked.

## What you can do with it

| | |
|---|---|
| **Read and judge** | Point it at a document and get `VALID` / `INVALID` / `INDETERMINATE` — never a bare "ok". Print canonical bytes to compare another language's implementation. Judge a whole RANGE of documents at once — chain, forks, completeness. When two documents claim the same moment, decide which is canonical. **None of this touches anything.** |
| **Become a publisher** | Run the ceremony that binds your domain to a key, add and retire keys as your operation changes, and declare the grid your stream follows. **Needs your root key**, and the tool never emits an artifact it has not verified first. |
| **Serve what you published** | Deploy the serving surface on your own stack or one-click on Cloudflare, mirror it to a second vendor so your identity does not rest on one provider, and log it in a public transparency log. **This writes to the world.** |

## Why run it at all

A verdict from this tool is worth something specific: it says *how much* trust was actually earned rather than
just passing or failing. A lone document gets you integrity and a **claimed** publisher. Bring the publisher's
genesis and key-log and the name becomes **provably** theirs. Add anchored time and the document is proven to
have existed by a real moment. The tier is part of the answer, so you can tell an unchecked property from a
confirmed one — which is the whole difference between a check and a reassurance.

```bash
npx -y @ust-protocol/cli                 # run it, no install — the command surface
npx -y @ust-protocol/cli verify doc.json # verify something straight away
```

Install it permanently if you use it often:

```bash
npm i -g @ust-protocol/cli               # installs the `ust` command
ust                                      # same surface, shorter to type
```

> `npm i -g` writes into node's global prefix, and on a stock macOS or Linux node that directory belongs to root —
> the install then fails with `EACCES: permission denied`. Do **not** fix it with `sudo`: packages installed as root
> leave files your user cannot update later. Point the prefix at your own home once instead —
> `npm config set prefix ~/.npm-global` and add `~/.npm-global/bin` to your `PATH` — or just keep using `npx`, which
> needs no install at all.

## Commands

Three groups, by what a command DOES TO YOU — the same order the tool prints on its first screen.
The tool shows the protocol version there, derived from the core; this page deliberately does not, because a
version typed into a README is a claim that goes stale in silence.

### READ & VERDICT — safe, touches nothing

| command | what it does |
|---|---|
| `ust verify <file\|->` | verify a transcript (blob / base64 / json). exit 0 = VALID, 1 = not. Auto-resolves the publisher's discovery + witness surfaces and cross-checks witness anchors (Rekor/Bitcoin) → **VALID:HIGH out of the box** when the no-fork evidence confirms |
| `ust verify <doc> --genesis <f> --keylog <f,f…> [--no-fork-confirmed]` | the OFFLINE road: supply the trust chain yourself; `--no-fork-confirmed` is your air-gap assertion → **VALID:HIGH** |
| `ust stream <frames…> [--genesis <f>] [--checkpoint <f>]` | a verdict about a RANGE, not one document — chain · forks · **completeness** (a stream property, never a single document's) |
| `ust canon <file\|->` | print canonical bytes + hash — diff any other-language implementation against this |
| `ust forkchoice <docs…>` | pick the CANONICAL document among candidates for ONE `ust_id` — canonical means anchor-included, so the choice is decided outside the candidates themselves |
| `ust discovery <domain> [--mirror url,url] [--expect sha256:…]` | probe a domain's serving surface and report an honest verdict — on ANY infrastructure |

### CEREMONY — touches your identity, needs the root key

| command | what it does |
|---|---|
| `ust genesis --domain <d>` | run the HIGH genesis ceremony (interactive; see the road below) |
| `ust key add --domain <d> --root <enc> --role <data\|issuance>` | ADD a key BESIDE the current one — never replaces it. The ROLE is fixed at genesis and is a partition of the active set, not a label the entry chooses |
| `ust rotate --domain <d> --root <enc>` | APPEND a key rotation to the served log. Never re-mints: documents signed by the old key stay valid, because succession is STATED in the log rather than inferred |
| `ust cadence --domain <d> --root <enc> --seconds <n> --effective-from <slot>` | DECLARE the signed grid your stream follows — what a completeness verdict is measured against, signed rather than assumed |

### PUBLISH — writes to the world

| command | what it does |
|---|---|
| `ust publish cf --domain <d> --genesis <f> [--auth wrangler] [--flip-proxy]` | deploy the Cloudflare serving adapter for an existing genesis |
| `ust mirror <domain> [--publish gh --repo o/r]` | publish and attest a SECOND-vendor copy, so your identity does not rest on one provider |
| `ust witness rekor --domain <d> [--deploy]` | log the genesis to Sigstore Rekor (a fast, independent witness substrate) and, with `--deploy`, serve/refresh `/.well-known/ust-witness` |

### Key operations are ROOT-only

`key add`, `rotate` and `cadence` all take `--root`: they are signed by the crown, never by the warm key they
govern. A self-authorized succession would let a compromised key name its own successor, so the protocol removed
that path rather than guard it — `rotate` as a *key-log op* does not exist, and `ust rotate` appends a rotation
that the ROOT states.

## The tier ladder (what verify can prove)

```
LIGHT  — a lone document: signed + intact under the key it carries (self-asserted)
HIGH   — + name authority: the verifier RESOLVES genesis → key-log (+ no-fork witness)
TOP    — + anchored time: each document provably EXISTED by a real moment (e.g. bitcoin-ots)
```

**Completeness is a separate RANGE verdict** (`ust stream` over frames + a covering checkpoint) — `VALID:TOP` speaks about a document's anchored time, never about a stream being complete.

HIGH is a property of *resolution*, not of the file — and resolution is the DEFAULT: a bare
`ust verify slot.json` fetches the publisher's `/.well-known/ust-genesis`, `ust-keylog` and `ust-witness`,
cross-checks the witness anchors against their substrate (Bitcoin via `@ust-protocol/ots-verify`, Rekor via
`@ust-protocol/rekor-verify` — both auto-detected when installed), and grants HIGH only on POSITIVE no-fork
evidence. Air-gapped, supply the chain yourself:

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
  5/5 ⚓ witness / anchor  PREPARED at ceremony time — executed for real by `ust witness rekor`
                           (+ your Bitcoin/OTS stamp); the CLI never claims a stage it did not run
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

### Profiles — each tier is about its own thing

| profile | root | backup |
|---|---|---|
| `bronze` | software | plain b64 (quick floor) |
| `silver` | software | **passphrase-encrypted** (the standard operator ceremony) |
| `gold` | **hardware** (pkcs11 / air-gapped) | — this CLI cannot drive a hardware signer yet and **refuses honestly** instead of pretending; a silver root can be superseded by a hardware one later, without invalidating anything already signed |

Other flags: `--max-partitions N` (signed capacity — bounds earned by ceremony) · `--witness url,url` (prepared at ceremony; execute later with `ust witness rekor`). Every option is also asked interactively — flags only preselect.

## `ust discovery` — attest any stack

Four probes of what a publisher must SERVE for anyone to resolve their identity — fail-closed, honest verdict:

```
✅ the served genesis verifies on its own and matches the expected hash
✅ _ust TXT carries the same hash        (mismatch = FAILED, absence = NOT ATTESTED)
✅ query-robustness: a random unknown ?param returns byte-identical bytes
⬜ vendor-independence: every declared --mirror carries the same content_hash
```

Verdict: `ATTESTED` (everything ran and passed) / `PARTIAL` (no violation, but unchecked properties remain — with targeted hints) / `FAILED` (exit 1). Conformance is never granted on unchecked properties.

## Custody model

The MCP holds no key; this CLI signs locally with keys that never leave your machine. The ceremony tool never emits an output it has not verified, and never claims a stage it did not run.
