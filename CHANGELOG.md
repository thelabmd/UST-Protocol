<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Changelog

The wire format `ust:"1.0"` is **stable across every release candidate** — pin exact package versions. This log
tracks two lines: the **reference checker (L1 TCB)** rev-ladder — a recurring diverse-model adversarial audit →
math-first remediation — and the **protocol milestones**. The normative source is the git history plus the
conformance vectors; this file is the readable map.

## [Unreleased] — rc.37 line

### Reference checker (L1) — the audit rev-ladder

Each rev independently reproduces an external model's findings, adjudicates each against the formal model, and
fixes **structurally, not point-wise**. The conformance vectors + byte corpus + robustness fuzz witness every fix.

| rev | round | what closed |
|-----|-------|-------------|
| **rev26** | 26 (step 3 of 4) | **scalar decoder sweep — the CanonicalSeq class completed.** The rev23 `isSeq` guard reached the sequence coordinates but not every signed scalar; this rev routes the last three through it: the key-log **length** (`BigInt(["1"]) === 1n` coerced an array → now `isSeq` before `BigInt`), the **Merkle proof index** (`String(hp.index)` → `isSeq` + `BigInt` compare), and the stream **frame_count** (`String(a.frame_count)` → `isSeq`). A coercible `["N"]` on any of them no longer decodes to the canonical value. Class E (policy threading through the call graph + the `model-lockstep` gate, L4) is the last step — AUDIT-PLAN. |
| **rev25** | 26 (step 2 of 4) | **one authority root.** A branded `context` (`GenesisHandle`) supplied to `verifyAuthorityCheckpointChain` / `deriveCheckpointFreshness` is now the SOLE root: the entire raw authority-root family (`pinnedPrior`, `genesis`, `genesisAuthority`, `recoveryKeys`, `recoveryThreshold`) alongside it is rejected `E-AUTHORITY`. Closes **P0-01** (a foreign `pinnedPrior` seized the chain scope/authority while still reporting `verified-context`) and **P0-02** (raw recovery INJECTED when the context carried none). Two formal-model **lockstep-lies** closed with public-entry adversarial checks: M2 "every downstream layer takes the derived context, **never raw fields**" (L1) and F.5l recovery "immutable within the epoch" (L2) — the positive C1 test never exercised the mixed-configuration attack. Classes B (scalar decoder) and E (policy threading + the `model-lockstep` gate) remain — AUDIT-PLAN. |
| **rev24** | 26 (step 1 of 4) | **the ONE input boundary** — round-26 found the recurring classes on new surfaces; this rev closes the two that share a seam. `admitDeep` takes a single inert DEEP snapshot of a caller object at entry: every value is read ONCE, so a getter cannot return the signed value during verification and an unsigned value during handle construction (the **getter-TOCTOU** that minted a genuine `EvidenceHandle` / genesis context with unsigned facts — P0-03; `verifyEvidenceReceipt` + `verifiedGenesisContext` snapshot at entry) — and an accessor / non-plain proto / cycle is structured-rejected, so **malformed non-null totality** extends past the null matrix to trailing args (`verifyJson` opts, `resolveCadence` 4th arg, `witnessNoFork` opts). Two formal-model **lockstep-lies** closed with PUBLIC-entry adversarial checks: M3 "preserves the exact verified facts" (L3) and I4 "TOTAL" beyond null config (L5). Classes A (one authority root), B (scalar decoder) and E (policy threading) are the next revs — tracked in the binding audit plan. |
| **rev23** | 25 | the recurring classes on the surfaces round-24 hadn't reached: the exported `provePredicates` was a **public brand-minting oracle** (it minted the `PredicateGraph` brand from caller-shaped labels → `deriveAssurance` blessed TOP with zero verified evidence) — now it is the UNBRANDED pure mapper and only `verify()` (a module-private seal) mints the brand; a verified-genesis context's **recovery roots/threshold can no longer be overridden** by raw config (E-AUTHORITY); `deepFreeze` now uses a **visited-set** so a shallow-frozen subtree inside an EvidenceHandle is fully frozen; the TCB structural registries (`ASSURANCE_AXES`/`REGISTRY`/`EVIDENCE_CAPS`/`RULE_CONTRACTS`) are **deep-frozen** (a nested array could change tier ranks in-process); **one CanonicalSeq decoder** (`isSeq`) at every signed sequence coordinate — a coercible `["0"]`/`["1"]` no longer attests uniqueness / authorizes a recovery / seeds an epoch, and a transition now REQUIRES the verified prior-chain final sequence (no partial verification); **malformed non-null totality** extended past the null matrix (a numeric-extra claim, a null proof, a null seam arg, and a non-binary `verifyJson` all return structured verdicts, never a host throw); the whole-operation witness budget is now `min(reference 30 s, consumer deadline)` (ρ_v belongs to the verifier, F.9) |
| **rev22** | 24 | every recurring class on the surfaces it had never reached: branded handles **deep-frozen** (a nested authority could be mutated after verification → forgery); signed genesis capacity/recovery fields decoded by a **canonical uint** decoder (`["4096"]`/`"0x80"` no longer coerce via `Number()`); quorum trust-domains reject **lone surrogates**; **null-totality** swept across 9 public proof surfaces (+2 the self-audit found: `deriveCheckpointFreshness`, `verifyStream`); the signed epoch `from_sequence` is checked; `evidenceCaps` returns a **frozen copy**; a **whole-operation** connector deadline (per-leaf alone let a legal witness burn ~21 min) |
| **rev21** | 23 | the recurring class applied to the **quorum** surface it never touched: object trust-domains faked an independent quorum (now NFC-string admission), the M5 result was arrival-ordered (now sorted voters/tags), and quorum functions threw on `null` config (now `admitOpts`). `forkChoice` order key made total via `JSON.stringify` (canon could throw on proof extras → arrival order); every diagnostic array tie-broken by full record. `combineSubstrates`/`anchoredByProofs` bound each connector by a deadline so a never-settling plugin can't block forever |
| **rev20** | 22 | the rev18/19 witness fix *still* projected before UNION (it filtered `superseded_by` before grouping — an active+superseded rival hid its anchor) and used concat not set-union; now the equivalence class is grouped by `content_hash` first, status is reconciled (active+superseded = contradiction, fail-closed), and proofs are set-unioned by canon. `combineSubstrates` isolates a throwing plugin. `forkChoice` returns a deterministic full document (min-canon winner + sorted diagnostic arrays) so the same set in any order emits byte-identical output |
| **rev19** | 21 (self-catch) | the rev18 P1-02 `forkChoice` content-hash dedupe was itself *lossy* — `content_hash` covers state, not `proof`, so a candidate with a valid anchor proof was dropped behind a same-state one with an invalid proof, hiding an equivocation; dedupe removed (the candidate budget alone caps the fan-out) |
| **rev18** | 21 | the rev17 witness fan-out fix was *lossy* — first-wins dedupe + `slice()` truncation discarded a rival's anchor then minted HIGH; now the served list is UNIONed (no `anchor`/`anchors` shadow) and an over-budget input is REFUSED (`resource_limit`), never truncated; witness connector throws are caught (unavailable, not a host exception); `forkChoice` candidate budget + content-hash dedupe |
| **rev17** | 20 | witness crosses the same raw-byte dup-member boundary as genesis/key-log; null-proto `admitOpts` (`__proto__` injection); F.9 structural fan-out budget; `forkChoice` admits opts |
| **rev16** | 19 | `forkChoice` snapshot-before-every-read (no live fallback); substrate closed-ADT own-data; ONE Unicode byte-admission shared with the byte checker |
| **rev15** | 18 | `forkChoice` snapshot-through; ONE substrate decoder; present≠absent key-log → `resource_limit`; total-for-null; strict-UTF-8 discovery |
| **rev14** | 17 | snapshot-before-await; proven-anchor token `U`; typed substrate leaf; total resolvers; bounded discovery |
| **rev13** | 16 | proven-`U`-only `K_n(t)`; earned key-log freshness; nondecreasing key-log timeline |
| **rev12** | 15 | identity relevance to subject; two-sided `K_n(t)` intervals; reducer-as-TCB-unit; ceiling-before-copy |
| **rev11** | 14 | monotonic compromise; canonical order coordinate; total resource bounds |
| **rev10** | 13 | byte injectivity (BOM/surrogate); real calendar values; reference budget |
| **rev9** | 12 | own-key membership + value validity (prototype-safe typed decode) |
| **rev8** | 11 | typed leaf decoders — key-closure is not value-typing |
| **rev7** | 10 | typed decode carried to every leaf; inner signed objects closed |
| **rev6** | 9 | total closed config ADT + a witness ADT per kind |
| **rev5** | 8 | total decode boundary over witnesses / config / limits |
| **rev4** | 7 | M-DEC / M-KEY / M-ORDER / M-CONFIG / M-BYTE total over their domain |
| **rev3** | 3–6 | the byte-boundary TCB: `checkAuthorityProofBytes` + exact Term ADT + `RULE_CONTRACTS` + language-neutral byte vectors |

### Milestones

- **LIGHT** — the byte-verdict floor · **done**
- **HIGH** — name-binding authority · **done**
- **TOP** — anchored time · protocol done, operator wiring pending
- **Formal model** — assurance product-lattice · human + machine audit pending
- **Chains** — state linked by provenance · in progress
- **Tools & surfaces** — MCP / CLI / web-signer / connectors · shipped

See [milestones](https://github.com/thelabmd/UST-Protocol/milestones) for the live status.

### Supply chain

- **Zero third-party dependencies by default.** `ust-protocol`, `ust-rekor-verify`, `ust-web-signer` and `ust-lite`
  are dependency-free. `ust-ots-verify` (`rc.9`) moved `opentimestamps` from `optionalDependencies` (which npm
  auto-installs, pulling the deprecated `request`/`bitcore-lib` tree, ~87 packages with CVEs) to an **optional peer**
  — it is lazily loaded only if the operator installs it, so a default install is dependency-free.
- **`@ust-protocol/cli` (`rc.41`) no longer shells out via `npx`.** The `ust publish cf` ceremony calls a locally
  installed `wrangler` (declared as an optional peer) rather than `npx wrangler`, which would download-and-run it
  ad-hoc. `gh` remains a documented external system tool. No package has install scripts.
- `@ust-protocol/mcp` requires the official `@modelcontextprotocol/sdk` — that (and only that) surface carries a
  third-party tree, by necessity.

## Earlier (rc.6 → rc.36)

- **Assurance product-lattice** — the measure-theoretic model; the tier as one monotone policy projection (#76, #78).
- **Authority-checkpoint** normative wire specification (#77).
- **HIGH / TOP evidence layer** — witness no-fork as the honest default; substrate anchors (Bitcoin/OTS, Rekor) with fabricatable-proof overclaims closed (#68, #69, #70, #71).
- **Bounds earned by ceremony** — the §13 size / capacity / resource ladder; canonical size semantics (#59, #61, #63).
- **Downgrade-resistance + fork-choice** — canonical = anchor-included (#45); agent-safety SDK patterns (#44).
- **Identity & portability** — IDN/homograph `domain_shard`, key-log freshness/revocation; the JCS canonicalization trap (#40, #41).
- **Negative / absence observation** — signing "nothing happened" / "source was down" (#39).

[milestones]: https://github.com/thelabmd/UST-Protocol/milestones
