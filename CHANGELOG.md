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

## Earlier (rc.6 → rc.36)

- **Assurance product-lattice** — the measure-theoretic model; the tier as one monotone policy projection (#76, #78).
- **Authority-checkpoint** normative wire specification (#77).
- **HIGH / TOP evidence layer** — witness no-fork as the honest default; substrate anchors (Bitcoin/OTS, Rekor) with fabricatable-proof overclaims closed (#68, #69, #70, #71).
- **Bounds earned by ceremony** — the §13 size / capacity / resource ladder; canonical size semantics (#59, #61, #63).
- **Downgrade-resistance + fork-choice** — canonical = anchor-included (#45); agent-safety SDK patterns (#44).
- **Identity & portability** — IDN/homograph `domain_shard`, key-log freshness/revocation; the JCS canonicalization trap (#40, #41).
- **Negative / absence observation** — signing "nothing happened" / "source was down" (#39).

[milestones]: https://github.com/thelabmd/UST-Protocol/milestones
