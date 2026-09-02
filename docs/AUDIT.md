# UST 1.0 — External Audit Brief

_For an independent cryptographic-protocol reviewer._

> **Two rules this protocol does not trade away.**
> **A minor only ADDS.** Anything that changes the meaning of what an earlier minor already defines is a MAJOR — there is no third option, because an older verifier evaluating under older rules must still be RIGHT about what it evaluated.
> **A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands; newer material it does not implement is reported as NOT EVALUATED — never as invalid, never silently passed. Whether that reach is enough is the CONSUMER's policy, not the protocol's coercion.
> *Both hold today: a newer minor answers `INDETERMINATE(unsupported_minor)` and a different major `INDETERMINATE(unsupported_major)` — never `INVALID`, which means only "I applied MY rules and they were violated".*

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
- The agent surface: `@ust-protocol/mcp` (thin MCP wrapper over `ust-protocol`; audit the exposure, not new crypto).

**OUT of scope (by design)**
- **Data correctness** — UST proves _fixation, not truth_; a publisher may sign a wrong reading. Not a flaw.
- The **substrate's** own security (e.g. Bitcoin/OpenTimestamps) — trusted as an external anchor.
- The **operator's key custody** (genesis ceremony, HSM) — an operational concern, not the protocol.
- `@ust-protocol/operator` (operator toolkit, unpublished), noosphere business logic/pricing, and any web/frontend pentest.

## 3. Where to get everything

```
npm     npm i ust-protocol@rc          # the reference verifier + producer (Apache-2.0, zero-dep, node:crypto)
        npx -y @ust-protocol/mcp@rc   # the MCP server (14 tools)
        npm i @ust-protocol/web-signer@rc  # the WebCrypto browser signer (producer side)
git     github.com/thelabmd/UST-Protocol   # monorepo — everything below in one clone
          spec/UST-1.0.md              # the normative specification (this is the source of truth)
          vectors/conformance-vectors.json   # deterministic test vectors (26; the runner adds behavioral checks — 56 total)
          packages/ust-protocol/       # reference impl + its conformance runner
          examples/                    # sample docs (valid + tampered) + verify recipes
web     verify.ustprotocol.com # in-browser verifier (client-side) + llms.txt (machine instructions)
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

### A refusal may be about YOUR INPUT, not about the protocol — we got this wrong three times in one day

This is the failure mode we expect an auditor to hit first, so here is our own record of it rather than a warning
in the abstract. All three happened on 2026-08-05, all three were reported internally as protocol findings, and
all three were wrong.

1. **"HIGH is unreachable without a third party."** Measured, stated twice, emphatically. The measurement never
   passed `acceptConsumerOverride`, which lifts a liftable consumer-override to `authoritative`. A consumer that
   consciously honours its own no-fork determination reaches `VALID:HIGH` — with `independently_verified: false`
   in the verdict, which is the honesty mechanism, not a downgrade.
2. **"TOP is unreachable even with an anchor."** The substrate connector returned `time` as epoch milliseconds.
   The core expects RFC3339. The result was `status: unavailable`, which was read as *the protocol refuses* rather
   than *this connector returned a shape the core cannot admit*. With a string it reaches `VALID:TOP`.
3. **"There is no input for a publisher's served witness log — a protocol gap."** There is. It is not an option
   because it cannot be one: only `resolveByDiscovery`, which actually performed the fetch and the anchor
   cross-check, can mint the token that reaches `corroborated`. A plain `{confirmed: true}` from a caller is
   `served-lookalike` and lifts nothing. *"I checked"* is deliberately not expressible as a boolean.

**The single generator:** an input constructed from a mental model of the system, a refusal, and the refusal
reported as a property of the system instead of being read. The refusals were all specific and all correct.

**How to tell the difference, in order of cost:**

- **Read the refusal text.** It names the axis and usually the missing input verbatim. `status: unavailable` on
  the time axis means the substrate answer was not admitted; it does not mean anchoring is unsupported.
- **Call `explainLadder(doc, opts)`.** It reports the inputs ABSENT FROM YOUR CALL, computed from the call itself,
  split by which party may move each one. If an input you believe you supplied appears under `absent`, the
  disagreement is about your input, not about the ladder.
- **Do not enumerate the option surface by grepping `opts.<name>`.** Several options are read by DESTRUCTURING
  and never appear in that form — `keylog`, `nameMap`, `corroborated`, `servedNoFork`, `keylogFreshAsOf`,
  `keylogHeadAnchor`, `trust`. Our own gate made exactly this mistake and shipped blind for a round; the fix and
  the live defect it then found are round 180 in `CHANGELOG.md`.

None of this makes a refusal trustworthy. If you read a refusal, supply what it names, and it still refuses —
that is a finding, and it is the kind we most want.

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
- **274 deterministic conformance vectors** plus a behavioral conformance runner (**1078 registered checks**), and the reference impl passes them (one known note: duplicate-key
  rejection needs a raw-bytes JSON parser — `JSON.parse` collapses dups — a harness limitation, not an impl flaw).
- **Two independent implementations** (`ust-protocol` node + a clean-room WebCrypto verifier in `docs/`) run
  side by side on every case of the parity suite and must agree on the verdict, including the tier: **13 cases,
  0 divergences** as of rev64. The previous wording claimed 32/32; that number came from an older harness and no
  longer corresponded to anything this tree runs, so it is replaced by what `npm run test:docs-parity` prints
  today. A count of independent agreements is the one number an auditor weighs most, and it was overstated.
- **253 recorded rounds** in `CHANGELOG.md`, carrying the reference-checker from `rev3` to `rev94`. The adversarial
  ones are folded in STRUCTURALLY rather than patched: each round that found something states the MECHANISM, not
  the instance, and closes it with a check that fails on the next instance of the same class. The round count and
  the revision range are both measurable from this tree; "how adversarial" is a judgement and is left to you.
- **Honest disclosure:** all of the above is one team's work → correlated blind spots. That is precisely the gap
  an external adversarial review closes. Please assume the design is wrong somewhere and find it.
```
Contact / coordination: thelabmd@proton.me
```
