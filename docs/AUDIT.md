# UST 1.0.0-rc.6 — External Audit Brief

_For an independent cryptographic-protocol reviewer._

## 1. What we are asking for

An **independent cryptographic protocol review** of UST 1.0 — the design and its reference implementation —
plus an **adversarial attempt to break the trust claims**. Concretely, answer four questions:

1. **Is the design sound?** Canonicalization, domain-separated hashing, signature scope, the tier ladder, chains,
   privacy commitments, anchoring — correct and composed without gaps.
2. **Are the tier claims HONEST?** The spec's own governing rule (§1): _a tier must never let a consumer read
   "signed" as "true," "anchored" as "correct," or "agreeing" as "independent."_ Find any place it does.
3. **Is the reference implementation FAITHFUL to the spec?** Does `ust-protocol` implement exactly the normative
   rules — no more, no less?
4. **What is the residual risk?** After the above, what remains — and how would you rank it?

We have already done extensive **self**-review (§6). We are buying the thing self-review cannot give: an
**uncorrelated adversarial eye**. Assume we are wrong somewhere; your job is to find where.

## 2. Scope

**IN scope**
- The protocol specification: `spec/UST-1.0.md`.
- The reference verifier + producer: `ust-protocol` (npm) — canon, hashing, signing, LIGHT/HIGH/TOP verify.
- The conformance vectors: `vectors/conformance-vectors.json`.
- The agent surface: `ust-mcp` (thin MCP wrapper over `ust-protocol`; audit the exposure, not new crypto).

**OUT of scope (by design)**
- **Data correctness** — UST proves _fixation, not truth_; a publisher may sign a wrong reading. Not a flaw.
- The **substrate's** own security (e.g. Bitcoin/OpenTimestamps) — trusted as an external anchor.
- The **operator's key custody** (genesis ceremony, HSM) — an operational concern, not the protocol.
- `ustate` (operator toolkit, unpublished), noosphere business logic/pricing, and any web/frontend pentest.

## 3. Where to get everything

```
npm     npm i ust-protocol@rc          # the reference verifier + producer (Apache-2.0, zero-dep, node:crypto)
        npx -y ust-mcp@rc              # the MCP server (9 tools)
        npm i ust-web-signer@rc        # the WebCrypto browser signer (producer side)
git     github.com/thelabmd/UST-Protocol   # monorepo — everything below in one clone
          spec/UST-1.0.md              # the normative specification (this is the source of truth)
          vectors/conformance-vectors.json   # deterministic test vectors (26; the runner adds behavioral checks — 56 total)
          packages/ust-protocol/       # reference impl + its conformance runner
          examples/                    # sample docs (valid + tampered) + verify recipes
web     thelabmd.github.io/UST-Protocol # in-browser verifier (client-side) + llms.txt (machine instructions)
```
On request (kept out of the public repo): the **second, clean-room implementation** (`ust-verify-web`, WebCrypto,
written from the spec without importing `ust-protocol`) and the **red-team dossier** (the six passes below, in full).

## 4. How to test

```
git clone github.com/thelabmd/UST-Protocol && cd UST-Protocol && npm install
npm test                               # runs ust-protocol against all conformance vectors
```
- **Cross-examine two implementations.** Run `ust-protocol` and the clean-room `ust-verify-web` against the same
  vectors. Any divergence is a finding. Best of all: **write your own third implementation** from the spec —
  three independent impls agreeing (or not) on the vectors is the strongest signal either way.
- **Forge attempts.** Try to construct a document that verifies but should not (or fails but should not). Try to
  make a LIGHT doc read as HIGH, a self-asserted key read as authoritative, or an unanchored doc read as anchored.
- **Determinism.** The vectors are seeded and deterministic; re-derive them and confirm every hash/signature.

## 5. Threat model — what each tier CLAIMS (attack these)

The single honest claim: **UST proves that a publisher committed to specific bytes, for a time-frame, unchanged —
not that the data is correct.** Trust is graduated:

```
LIGHT  integrity + a CLAIMED publisher (self-asserted). The doc is unchanged since signing; the name is unproven.
HIGH   the signing key is PROVABLY bound to the publisher's domain (genesis + key-log + no-fork witness).
TOP    the doc provably existed by a point in time (anchor inclusion) and a stream is provably complete.
```
Break any of: signed⇒true, anchored⇒correct, agreeing⇒independent, self-asserted⇒authoritative,
present⇒complete, hidden-value⇒hidden-activity. Each is a claim the spec must NOT let a consumer over-read.

## 6. The six attack vectors we already ran (go deeper — find what we missed)

The v1.0 final form was hammered by six adversarial passes (REV 13–22) plus a global consistency sweep (REV 23),
after four earlier passes on the v0.29 predecessor. Each is a **dimension**, not a checklist — please re-attack
each and, more importantly, find a **seventh** we didn't think of.

```
① STRUCTURAL / crypto-integrity      canon (JCS) injectivity · domain-separated hashing · content_hash
   (REV13)                            UNIQUENESS as a document descriptor · strict Ed25519 (reject non-canonical S)
                                      · data⇄hashes bijection.  Repr. finding we caught: F1 — a two-scope split
                                      had made content_hash frame-identity while anchor/chain/prev/revocation need
                                      document-uniqueness → reverted to a single unique content_hash.

② SEMANTIC / mechanism holes         internally consistent as TEXT but exploitable. Repr: K1 — "unknown members
   (REV14)                            ignored" created an UNSIGNED surface adjacent to a VALID verdict → closed by
                                      total-signature-coverage (I1) + reserved-key discipline.

③ MECHANISM INTERACTIONS             features safe ALONE that compose into a kill-chain — privacy × chain,
   (REV15)                            anchor × revocation, seed × layers, tier × availability.

④ ECONOMIC / OPERATIONAL / AT-SCALE  not "can it be forged" but "is the trust claim exploitable at scale, under
   (REV16)                            collusion, or economically" — cheap-to-mint attestations, griefing, etc.

⑤ PRIVACY / METADATA-LEAK AT SCALE   the confidentiality claim is narrower than it reads. Repr: Z1 — plaintext
   (REV17)                            metadata (partition names, timing, ust_id cadence) leaks the ACTIVITY
                                      PATTERN even when every value is blinded/encrypted.

⑥ HIGH-tier IDENTITY × AVAILABILITY  name authority under an active attacker + partial availability. Repr: W1 —
   (REV22)                            "suppress-the-witness" granted `authoritative` without a POSITIVE no-fork
                                      confirmation → now authoritative REQUIRES positive no-fork, else INDETERMINATE.
                                      Also: key-log/genesis forks, revocation window (X1: anchored-time vs
                                      compromised_since).

   GLOBAL CONSISTENCY (REV23)         whole-spec coherence — clause-vs-clause contradictions, examples vs schema.
```

## 7. Reference material (for judging our fixes — not for redoing)

- **Design invariants I1–I14** (spec §3/§16) — e.g. I1 total-signature-coverage, I3 namespace isolation, I10
  fail-closed, I11 named-genesis authority, I12 self-contained time, I13 domain-controlled authority + time-bound
  revocation, I14 bounded verification (depth-0 default).
- **Outcome vocabulary (E-codes):** E-MALFORMED, E-CANON, E-SIG, E-KEY, E-COMMIT, E-ROOT, E-PREV, E-GENESIS,
  E-AUTHORITY, E-ANCHOR, E-BOUNDS, E-CYCLE, E-BINDING, E-MODEL. Verification is fail-closed and returns one of
  three outcomes: **VALID:LIGHT | VALID:HIGH | VALID:TOP / INVALID / INDETERMINATE** — the verdict CARRIES its
  tier; a bare `VALID` is never emitted (availability is never confused with failure).
- The six red-team passes + the v0.29 passes are available in full (with every finding and how it was closed
  STRUCTURALLY) so you can judge the fixes rather than re-derive the findings.

## 8. What we want back (deliverable format)

**Per finding:**
```
Title            one line
Severity         CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
Category         SPEC design flaw  |  IMPL bug (ust-protocol)  |  DOC ambiguity
Location         spec §clause  or  file:line
Repro / PoC      concrete steps, a failing/forged document, or a divergence between implementations
Recommendation   the structural fix (we prefer root-cause fixes over patches)
```
**Overall verdict:** is the design sound? are the tier claims honest? is the reference impl faithful? What is the
residual risk, and what would you require before a `1.0.0` final tag?

## 9. What we have already done (so you go deeper, not sideways)

- **Six adversarial red-team passes** on the v1.0 final form + four on the v0.29 predecessor — all self-review.
- **26 deterministic conformance vectors** plus a behavioral conformance runner (56 checks total), and the reference impl passes them (one known note: duplicate-key
  rejection needs a raw-bytes JSON parser — `JSON.parse` collapses dups — a harness limitation, not an impl flaw).
- **Two independent implementations** (`ust-protocol` node + `ust-verify-web` clean-room WebCrypto) cross-checked: **32/32 agree, 0 divergence**.
- **Five external AI reviews folded in (rc.1 → rc.6):** ChatGPT code + Gemini spec + Gemini 3.1 architecture + ChatGPT 5.5 Max adversarial (details in the on-request `FINDINGS-rc1-to-rc6.md`).
- **Honest disclosure:** all of the above is one team's work → correlated blind spots. That is precisely the gap
  an external adversarial review closes. Please assume the design is wrong somewhere and find it.
```
Contact / coordination: thelabmd@proton.me
```
